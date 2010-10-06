/*
 * TCP-aNCR reordering response
 *
 * Inspired by ideas from TCP-NCR and the paper
 * "Enhancing TCP Performance to Persistent Packet Reordering"
 * by Ka-Cheong Leung and Changming Ma
 *
 * Changes:
 *		Lennart Schulte: burst protection in elt
 *		Lennart Schulte: max factor instead of max reordering length
 */

#include <linux/mm.h>
#include <linux/module.h>
#include <linux/skbuff.h>

#include <net/tcp.h>

#define MIN_DUPTHRESH 2
#define FIXED_POINT_SHIFT 8

// copied from tcp_input.c
#define FLAG_DATA_SACKED    0x20 // New SACK.

/* ancr variables */
struct ancr {
	u8  reorder_mode;
	u8  elt_flag;
	u8  lt_f;
	u32 dupthresh;
	u32 max_factor;
};

static inline void tcp_ancr_init(struct sock *sk)
{
	struct ancr *ro = inet_csk_ro(sk);

	if (ro->reorder_mode == 2) {
		ro->lt_f = 4;
	} else {
		ro->lt_f = 3;
		ro->reorder_mode = 1;
	}
	ro->elt_flag = 0;
	ro->dupthresh = MIN_DUPTHRESH;
	ro->max_factor = 0;
}

/* New reordering event, recalculate avg and mdev (and dupthresh)
 */
static void tcp_ancr_reordering_detected_factor(struct sock *sk, int factor)
{
	struct ancr *ro = inet_csk_ro(sk);

	//1st condition: use biggest sample ever seen
	//2nd condition: ncr upper bound (if normalized sample is 1 this is the same
	//				 as ncr)
	if (factor > ro->max_factor && factor <= (1 << FIXED_POINT_SHIFT)) {
		printk(KERN_INFO "new factor = %u", factor);
		ro->max_factor = factor;
	}
}

/* Test if TCP-ancr may be used
 */
static int tcp_ancr_test(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);

	return tcp_is_sack(tp) && !(tp->nonagle & TCP_NAGLE_OFF);
}

/* Set the dupthresh
 */
static void tcp_ancr_calc_dupthresh(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct ancr *ro = inet_csk_ro(sk);

	/* Minimum is always MIN_DUPTHRESH.
	 * Maximum is the new dupthresh.
	 * At the beginning of disorder the dupthresh has to be lower than the new
	 * dupthresh, since it would never retransmit if no new packets would be
	 * send during elt.
	 */
	u32 new = (ro->max_factor * tp->prior_packets_out) >> FIXED_POINT_SHIFT;
	u32 ncr = (2 * tp->packets_out)/ro->lt_f;

	ro->dupthresh = max_t(u32,
						min_t(u32, new, ncr),
						MIN_DUPTHRESH);
}

/* Initiate Extended Limited Transmit
 */
static void tcp_ancr_elt_init(struct sock *sk, int how)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct ancr *ro = inet_csk_ro(sk);

	if (!how) {
		tp->prior_packets_out = tp->packets_out;
	}
	ro->elt_flag = 1;
	tcp_ancr_calc_dupthresh(sk);
}

/* Extended Limited Transmit
 *
 * tcp_cwnd_down() is not meant to be used in the disorder phase. It is
 * implemented under assumptions only valid in the recovery phase.
 * So, we need our own version for ELT, similar to the "E"-steps in RFC 4653
 */
static void tcp_ancr_elt(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct ancr *ro = inet_csk_ro(sk);
	u32 sent;
	u32 room = tp->prior_packets_out > tcp_packets_in_flight(tp) ?
		tp->prior_packets_out - tcp_packets_in_flight(tp) :
		0;

	if (ro->reorder_mode == 1) {
		//pkts sent during elt up to now
		sent = tp->packets_out > tp->prior_packets_out ?
			tp->packets_out - tp->prior_packets_out :
			0;
		room = room > sent ?
			room - sent :
			0;
		if (room > 1)	//only happens with ACK loss/reordering
			room = (room+1)/2;	//prevent ACK loss/reordering to trigger
							//too large packet burst which is followed by
							//a long sending pause
	}

	tp->snd_cwnd = tcp_packets_in_flight(tp) + min_t(u32, room, 3); // burst protection
	tp->snd_cwnd_stamp = tcp_time_stamp;

	tcp_ancr_calc_dupthresh(sk);
}

/* Terminate Extended Limited Transmit
 */
static void tcp_ancr_elt_end(struct sock *sk, int flag , int cumack)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	struct ancr *ro = inet_csk_ro(sk);

	tp->snd_cwnd = min(tcp_packets_in_flight(tp) + 1, tp->prior_packets_out);
	tp->snd_cwnd_stamp = tcp_time_stamp;
	if (cumack) {
		/* New cumulative ACK during ELT, it is reordering.
		   The following condition will only be true, if we were previously in
		   congestion avoidance. In that case, set ssthresh to allow slow
		   starting quickly back to the previous operating point. Otherwise,
		   don't touch ssthresh to allow slow start to continue to the point
		   it was previously supposed to. */
		if (tp->snd_ssthresh < tp->prior_packets_out)
			tp->snd_ssthresh = tp->prior_packets_out;
		if (flag & FLAG_DATA_SACKED)
			tcp_ancr_elt_init(sk, 1);
		else
			ro->elt_flag = 0;
	} else {
		/* Dupthresh is reached, start recovery, set ssthresh to an
		 * appropriate value to start with ratehalving */
		tp->snd_ssthresh = icsk->icsk_ca_ops->ssthresh(sk);
		ro->elt_flag = 0;
	}
}

/* Return the dupthresh.
 * If everything is right, return ancr's dupthresh.
 * Else, fall back to native
 */
static u32 tcp_ancr_dupthresh(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct ancr *ro = inet_csk_ro(sk);

	if (tcp_ancr_test(sk)) {
		return ro->dupthresh;
	}

	return tp->reordering;
}

/* We received a SACK for a segment not previously SACK'ed */
static void tcp_ancr_new_sack(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct ancr *ro = inet_csk_ro(sk);

	// only init ELT, if we're not already in ELT and this is the first SACK'ed segment
	if (tcp_ancr_test(sk) && (!ro->elt_flag) && (tp->sacked_out == 0))
		tcp_ancr_elt_init(sk, 0);
}

/* A non-retransmitted SACK hole was filled */
static void tcp_ancr_sack_hole_filled(struct sock *sk, int flag)
{
	struct ancr *ro = inet_csk_ro(sk);

	if (ro->elt_flag)
		tcp_ancr_elt_end(sk, flag, 1);
}

/* the state machine will start right after this */
static void tcp_ancr_sm_starts(struct sock *sk, int flag)
{
	struct ancr *ro = inet_csk_ro(sk);

	if (ro->elt_flag && (flag & FLAG_DATA_SACKED))
		tcp_ancr_elt(sk);
}

/* recovery starts */
static void tcp_ancr_recovery_starts(struct sock *sk, int flag)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	struct ancr *ro = inet_csk_ro(sk);

	if (ro->elt_flag) {
		tcp_ancr_elt_end(sk, flag, 0);
	}
	else
		tp->snd_ssthresh = icsk->icsk_ca_ops->ssthresh(sk);

}

static void tcp_ancr_update_mode(struct sock *sk, int val) {
	struct ancr *ro = inet_csk_ro(sk);

	if (val == 2)
		ro->reorder_mode = val;
	else
		ro->reorder_mode = 1;
}

static void tcp_ancr_rto_happened(struct sock *sk)
{
	struct ancr *ro = inet_csk_ro(sk);
	ro->elt_flag = 0;
	ro->max_factor = 0;
}

static struct tcp_reorder_ops tcp_ancr = {
	.flags            = TCP_REORDER_NON_RESTRICTED,
	.name             = "ancr",
	.owner            = THIS_MODULE,
	.init             = tcp_ancr_init,
	.dupthresh        = tcp_ancr_dupthresh,
	.new_sack         = tcp_ancr_new_sack,
	.sack_hole_filled = tcp_ancr_sack_hole_filled,
	.sm_starts        = tcp_ancr_sm_starts,
	.recovery_starts  = tcp_ancr_recovery_starts,
	.reorder_detected_factor = tcp_ancr_reordering_detected_factor,

	.update_mode      = tcp_ancr_update_mode,
	.allow_moderation = 0,
	.allow_head_to    = 0,
	.moddupthresh     = tcp_ancr_dupthresh,
	.rto_happened	  = tcp_ancr_rto_happened,
};

static int __init tcp_ancr_register(void)
{
	BUILD_BUG_ON(sizeof(struct ancr) > ICSK_RO_PRIV_SIZE);
	tcp_register_reorder(&tcp_ancr);
	return 0;
}

static void __exit tcp_ancr_unregister(void)
{
	tcp_unregister_reorder(&tcp_ancr);
}

module_init(tcp_ancr_register);
module_exit(tcp_ancr_unregister);

MODULE_AUTHOR("Carsten Wolff, Lennart Schulte");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("TCP-ANCR");
MODULE_VERSION("2.0");
