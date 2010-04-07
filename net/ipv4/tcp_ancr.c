/*
 * TCP-aNCR reordering response
 *
 * Inspired by ideas from TCP-NCR and the paper
 * "Enhancing TCP Performance to Persistent Packet Reordering"
 * by Ka-Cheong Leung and Changming Ma
 */

#include <linux/mm.h>
#include <linux/module.h>
#include <linux/skbuff.h>

#include <net/tcp.h>

/* choose dupthresh calculation that should be compiled
 * 1: Leung-Ma
 * 2: max. tp->reordering throughout connection
 * 3: based on reordering/congestion ratio
 */
#define DUP_CALC 2

#define MIN_DUPTHRESH 2
#define FIXED_POINT_SHIFT 8

// copied from tcp_input.c
#define FLAG_DATA_SACKED    0x20 // New SACK.

/*static int mode = 1;
module_param(mode, int, 0644);
MODULE_PARM_DESC(mode, "mode: careful (1) or aggressive (2)");*/

/* ancr variables */
struct ancr {
	u8  reorder_mode;
	u8  elt_flag;
	u8  lt_f;
	u32 dupthresh;
	u32 dupthresh_bound;
	u32 prior_packets_out;
	u16 rodist_avg;
	u16 rodist_mdev;
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
	ro->dupthresh_bound = TCP_MAX_REORDERING;
	ro->prior_packets_out = 0;
	ro->rodist_avg = 0;
	ro->rodist_mdev = 0;
}

#if DUP_CALC == 3
/* calculates an EWMA of samples of two values:
 * - value 1 means that a reordering event happened 
 * - value 0 means that a congestion event happened */
static void tcp_ancr_update_ratio(struct sock *sk, int reorder)
{
	// abuse rodist_avg for the EWMA of the congestion/reordering ratio

}
#endif

/* New reordering event, recalculate avg and mdev (and dupthresh)
 */
static void tcp_ancr_reordering_detected(struct sock *sk, int length)
{
	struct ancr *ro = inet_csk_ro(sk);
	u32 dupthresh = ro->dupthresh;
#if DUP_CALC == 1
	u16 aerr = 0;
	u16 slength = length << FIXED_POINT_SHIFT;
#endif

// we want to play with this, use BSD-styled code ;)
// First, Leung-Ma variants
#if DUP_CALC == 1
	// on the first event, avg needs to be initialized properly
	if (unlikely(!ro->rodist_avg && !ro->rodist_mdev)) {
		ro->rodist_avg = slength;
	} else {
		// recalculate avg and mdev. order is important, here!
		aerr = abs(ro->rodist_avg - slength);
		//                |  about 0.3 * aerr |   |   about  0.7 * mdev       |
		ro->rodist_mdev = ((19 * aerr)    >> 6) + ((45 * ro->rodist_mdev) >> 6);
		ro->rodist_avg  = ((19 * slength) >> 6) + ((45 * ro->rodist_avg)  >> 6);
	}

	// TODO: Try higher factors than 0.3 * mdev
	//                            |    about 0.3 * mdev        |
	//dupthresh = (ro->rodist_avg + ((19 * ro->rodist_mdev) >> 6)) >> FIXED_POINT_SHIFT;
	dupthresh = (ro->rodist_avg + ro->rodist_mdev) >> FIXED_POINT_SHIFT;
#endif

// second, maximum always
#if DUP_CALC == 2
	// we can't use tp->reordering, because it is reset to the sysctl value on RTOs.
	// so, remember the largest measured reordering event ourselves.
	if (length > dupthresh)
		dupthresh = length;
#endif

// third, depending on congestion/reordering ratio estimate
#if DUP_CALC == 3
	// abuse rodist_mdev for the maximum observed reordering length
	// abuse rodist_avg  for the EWMA of the congestion/reordering ratio
	if (length > ro->rodist_mdev)
		ro->rodist_mdev = length;
	tcp_ancr_update_ratio(sk, 1);
	ro->dupthresh = (ro->rodist_mdev * ro->rodist_avg) >> FIXED_POINT_SHIFT;
#endif

	// apply lower bound
	ro->dupthresh = max_t(u32, dupthresh, MIN_DUPTHRESH);
}

/* An RTO happened. We probably waited too long, reduce dupthresh by dumping components.
 * Only call on the first RTO for the same segment, because there's no way we could have
 * avoided a backed-off RTO by fast-retransmitting more quickly.
 *//*
// Do nothing for now. RTO avoidance should be guaranteed by TCP-NCR's upper bound
static void tcp_ancr_rto_happened(struct sock *sk)
{
	struct ancr *ro = inet_csk_ro(sk);

	if (inet_csk(sk)->icsk_retransmits == 0) {
		ro->rodist_avg  = ro->rodist_avg >> 1;
		ro->rodist_mdev = ro->rodist_mdev >> 2;

		tcp_ancr_recalc_dupthresh(sk);
	}
} */

/* Test if TCP-ancr may be used
 */
static int tcp_ancr_test(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);

	return tcp_is_sack(tp) && !(tp->nonagle & TCP_NAGLE_OFF);
}

/* Initiate Extended Limited Transmit
 */
static void tcp_ancr_elt_init(struct sock *sk, int how)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct ancr *ro = inet_csk_ro(sk);

	if (!how)
		ro->prior_packets_out = tp->packets_out;
	ro->elt_flag = 1;
	ro->dupthresh_bound = max_t(u32, ((2 * tp->packets_out)/ro->lt_f), MIN_DUPTHRESH);
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
	u32 room = ro->prior_packets_out > tcp_packets_in_flight(tp) ?
		ro->prior_packets_out - tcp_packets_in_flight(tp) :
		0;

	if (ro->reorder_mode == 1) {
		sent = tp->packets_out > ro->prior_packets_out ?
			tp->packets_out - ro->prior_packets_out :
			0;
		room = room > sent ?
			room - sent :
			0;
	}

	tp->snd_cwnd = tcp_packets_in_flight(tp) + min_t(u32, room, 3); // burst protection
	tp->snd_cwnd_stamp = tcp_time_stamp;

	ro->dupthresh_bound = max_t(u32, ((2 * tp->packets_out)/ro->lt_f), MIN_DUPTHRESH);
}

/* Terminate Extended Limited Transmit
 */
static void tcp_ancr_elt_end(struct sock *sk, int flag , int cumack)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	struct ancr *ro = inet_csk_ro(sk);


	tp->snd_cwnd = min(tcp_packets_in_flight(tp) + 1, ro->prior_packets_out);
	tp->snd_cwnd_stamp = tcp_time_stamp;
	if (cumack) {
		/* New cumulative ACK during ELT, it is reordering.
		   The following condition will only be true, if we were previously in
		   congestion avoidance. In that case, set ssthresh to allow slow
		   starting quickly back to the previous operating point. Otherwise,
		   don't touch ssthresh to allow slow start to continue to the point
		   it was previously supposed to. */
		if (tp->snd_ssthresh < ro->prior_packets_out)
			tp->snd_ssthresh = ro->prior_packets_out;
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

	if (tcp_ancr_test(sk))
		return min_t(u32, ro->dupthresh, ro->dupthresh_bound);

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

	if (ro->elt_flag)
		tcp_ancr_elt_end(sk, flag, 0);
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
	.reorder_detected = tcp_ancr_reordering_detected,
	//.rto_happened     = tcp_ancr_rto_happened, // disabled, see above
	.update_mode      = tcp_ancr_update_mode,
	.allow_moderation = 0,
	.allow_head_to    = 0,
	.moddupthresh     = tcp_ancr_dupthresh,
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

MODULE_AUTHOR("Carsten Wolff");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("TCP-ANCR");
MODULE_VERSION("1.0");
