/*
 * TCP-leungma reordering response
 *
 * Inspired by the paper
 * "Enhancing TCP Performance to Persistent Packet Reordering"
 * by Ka-Cheong Leung and Changming Ma
 */

#include <linux/mm.h>
#include <linux/module.h>
#include <linux/skbuff.h>

#include <net/tcp.h>

#define MIN_DUPTHRESH 3
#define FIXED_POINT_SHIFT 8

// copied from tcp_input.c
#define FLAG_DATA_SACKED    0x20 // New SACK.

/*static int mode = 1;
module_param(mode, int, 0644);
MODULE_PARM_DESC(mode, "mode: careful (1) or aggressive (2)");*/

/* leungma variables */
struct leungma {
	u8  reorder_mode;
	u8  elt_flag;
	u32 dupthresh;
	u32 prior_packets_out;
	u32 rodist_avg;
	u32 rodist_mdev;
};

static inline void tcp_leungma_init(struct sock *sk)
{
	struct leungma *ro = inet_csk_ro(sk);

	if (ro->reorder_mode != 2)
		ro->reorder_mode = 1;
	ro->elt_flag = 0;
	ro->dupthresh = MIN_DUPTHRESH;
	ro->prior_packets_out = 0;
	ro->rodist_avg = 0;
	ro->rodist_mdev = 0;
}

/* recalculate dupthresh
 */
static void tcp_leungma_recalc_dupthresh(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct leungma *ro = inet_csk_ro(sk);

	//                                |    about 0.3 * mdev         |
	u32 dupthresh   = (ro->rodist_avg + ((19 * ro->rodist_mdev) >> 6)) >> FIXED_POINT_SHIFT;

	// FIXME: Who says rto/rtt is really >2 ???
	// upper bound. srtt is the RTT-Value left-shifted by 3. So left-shift rto for a correct RTO/RTT ratio
	//                                |      about 0.7 * rto / rtt                   |
	u32 upper_bound = tp->snd_cwnd * (((45 * ((icsk->icsk_rto << 3) / tp->srtt)) >> 6) - 2);

	// FIXME: see above
	upper_bound = 256;

	// apply bounds
	ro->dupthresh = clamp_t(u32, dupthresh, MIN_DUPTHRESH, upper_bound);
}

/* New reordering event, recalculate avg and mdev
 */
static void tcp_leungma_reordering_detected(struct sock *sk, int length)
{
	struct leungma *ro = inet_csk_ro(sk);
	u32 aerr = 0;
	u32 slength = length << FIXED_POINT_SHIFT;

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

	tcp_leungma_recalc_dupthresh(sk);
}

/* An RTO happened. We probably waited too long, reduce dupthresh by dumping components.
 * Only call on the first RTO for the same segment, because there's no way we could have
 * avoided a backed-off RTO by fast-retransmitting more quickly.
 */
static void tcp_leungma_rto_happened(struct sock *sk)
{
	struct leungma *ro = inet_csk_ro(sk);

	if (inet_csk(sk)->icsk_retransmits == 0) {
		ro->rodist_avg  = ro->rodist_avg >> 1;
		ro->rodist_mdev = ro->rodist_mdev >> 2;

		tcp_leungma_recalc_dupthresh(sk);
	}
}

/* Test if TCP-leungma may be used
 */
static int tcp_leungma_test(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);

	return tcp_is_sack(tp) && !(tp->nonagle & TCP_NAGLE_OFF);
}

/* Initiate Extended Limited Transmit
 */
static void tcp_leungma_elt_init(struct sock *sk, int how)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct leungma *ro = inet_csk_ro(sk);

	if (!how)
		ro->prior_packets_out = tp->packets_out;
	ro->elt_flag = 1;
}

/* TCP-leungma Extended Limited Transmit
 */
static void tcp_leungma_elt_end(struct sock *sk, int flag , int cumack)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	struct leungma *ro = inet_csk_ro(sk);

	if (cumack) {
		/* New cumulative ACK during ELT, it is reordering. */
		tp->snd_ssthresh = ro->prior_packets_out;
		tp->snd_cwnd = min(tcp_packets_in_flight(tp) + 1, ro->prior_packets_out);
		tp->snd_cwnd_stamp = tcp_time_stamp;
		if (flag & FLAG_DATA_SACKED)
			tcp_leungma_elt_init(sk, 1);
		else
			ro->elt_flag = 0;
	} else {
		/* Dupthresh is reached, start recovery */
		// Don't force the RFC
		//tp->snd_ssthresh = (ro->prior_packets_out/2);
		//tp->snd_cwnd = tp->snd_ssthresh;
		//tp->snd_cwnd_stamp = tcp_time_stamp;
		// Instead, let the usual Linux recovery happen (with ratehalving)
		tp->snd_cwnd = min(tcp_packets_in_flight(tp) + 1, ro->prior_packets_out);
		tp->snd_cwnd_stamp = tcp_time_stamp;
		tp->snd_ssthresh = icsk->icsk_ca_ops->ssthresh(sk);
		ro->elt_flag = 0;
	}
}

/* Extended Limited Transmit
 *
 * tcp_cwnd_down() is not meant to be used in the disorder phase. It is
 * implemented under assumptions only valid in the recovery phase.
 * So, we need our own version for ELT, similar to the "E"-steps in RFC 4653
 */
static void tcp_leungma_elt(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct leungma *ro = inet_csk_ro(sk);
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
}

/* Return the dupthresh.
 * If everything is right, return leungma's dupthresh.
 * Else, fall back to native
 */
static u32 tcp_leungma_dupthresh(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct leungma *ro = inet_csk_ro(sk);

//	if (ro->elt_flag && tcp_leungma_test(sk))
	if (tcp_leungma_test(sk))
		return ro->dupthresh;

	return tp->reordering;
}

/* We received a SACK for a segment not previously SACK'ed */
static void tcp_leungma_new_sack(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct leungma *ro = inet_csk_ro(sk);

	// only init ELT, if we're not already in ELT and this is the first SACK'ed segment
	if (tcp_leungma_test(sk) && (!ro->elt_flag) && (tp->sacked_out == 0))
		tcp_leungma_elt_init(sk, 0);
}

/* A non-retransmitted SACK hole was filled */
static void tcp_leungma_sack_hole_filled(struct sock *sk, int flag)
{
	struct leungma *ro = inet_csk_ro(sk);

	if (ro->elt_flag)
		tcp_leungma_elt_end(sk, flag, 1);
}

/* the state machine will start right after this */
static void tcp_leungma_sm_starts(struct sock *sk, int flag)
{
	struct leungma *ro = inet_csk_ro(sk);

	if (ro->elt_flag && (flag & FLAG_DATA_SACKED))
		tcp_leungma_elt(sk);
}

/* recovery starts */
static void tcp_leungma_recovery_starts(struct sock *sk, int flag)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	struct leungma *ro = inet_csk_ro(sk);

	if (ro->elt_flag)
		tcp_leungma_elt_end(sk, flag, 0);
	else
		tp->snd_ssthresh = icsk->icsk_ca_ops->ssthresh(sk);
}

static void tcp_leungma_update_mode(struct sock *sk, int val) {
	struct leungma *ro = inet_csk_ro(sk);

	if (val == 2)
		ro->reorder_mode = val;
	else
		ro->reorder_mode = 1;
}

static struct tcp_reorder_ops tcp_leungma = {
	.flags            = TCP_REORDER_NON_RESTRICTED,
	.name             = "leungma",
	.owner            = THIS_MODULE,
	.init             = tcp_leungma_init,
	.dupthresh        = tcp_leungma_dupthresh,
	.new_sack         = tcp_leungma_new_sack,
	.sack_hole_filled = tcp_leungma_sack_hole_filled,
	.sm_starts        = tcp_leungma_sm_starts,
	.recovery_starts  = tcp_leungma_recovery_starts,
	.reorder_detected = tcp_leungma_reordering_detected,
	.rto_happened     = tcp_leungma_rto_happened,
	.update_mode      = tcp_leungma_update_mode,
	.allow_moderation = 0,
	.allow_head_to    = 0,
	.moddupthresh     = tcp_leungma_dupthresh,
};

static int __init tcp_leungma_register(void)
{
	BUILD_BUG_ON(sizeof(struct leungma) > ICSK_RO_PRIV_SIZE);
	tcp_register_reorder(&tcp_leungma);
	return 0;
}

static void __exit tcp_leungma_unregister(void)
{
	tcp_unregister_reorder(&tcp_leungma);
}

module_init(tcp_leungma_register);
module_exit(tcp_leungma_unregister);

MODULE_AUTHOR("Carsten Wolff");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("TCP-LEUNGMA");
MODULE_VERSION("1.0");
