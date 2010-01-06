/*
 * TCP-NCR reordering response
 *
 * Implements RFC4653
 * http://www.ietf.org/rfc/rfc4653.txt
 */

#include <linux/mm.h>
#include <linux/module.h>
#include <linux/skbuff.h>

#include <net/tcp.h>

// copied from tcp_input.c
#define FLAG_DATA_SACKED    0x20 /* New SACK.               */

static int mode = 1;
module_param(mode, int, 0644);
MODULE_PARM_DESC(mode, "mode: careful (1) or aggressive (2)");

/* NCR variables */
struct ncr {
	u8  elt_flag;
	u8  dupthresh;
	u8  lt_f;
	u32 prior_flight_size;
};

static inline void tcp_ncr_reset(struct ncr *ro)
{
	ro->elt_flag = 0;
	ro->dupthresh = TCP_FASTRETRANS_THRESH;
	if (mode == 2)
		ro->lt_f = 4;
	else
		ro->lt_f = 3;
	ro->prior_flight_size = 0;
}

static void tcp_ncr_init(struct sock *sk)
{
	tcp_ncr_reset(inet_csk_ro(sk));
}

/* TCP-NCR: Test if TCP-NCR may be used
 * (Following RFC 4653 recommendations)
 */
static int tcp_ncr_test(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);

	return tcp_is_sack(tp) && !(tp->nonagle & TCP_NAGLE_OFF);
}

/* TCP-NCR: Initiate Extended Limited Transmit
 * (RFC 4653 Initialization)
 */
static void tcp_ncr_elt_init(struct sock *sk, int how)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct ncr *ro = inet_csk_ro(sk);

	if (!how)
		ro->prior_flight_size = tp->packets_out;
	ro->elt_flag = 1;
	// TODO: use shift
	ro->dupthresh = max_t(u32, ((2 * tp->packets_out)/ro->lt_f), 3);
}

/* TCP-NCR Extended Limited Transmit
 * (RFC 4653 Termination)
 */
static void tcp_ncr_elt_end(struct sock *sk, int flag , int how)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct ncr *ro = inet_csk_ro(sk);

	if (how) {
		/* New cumulative ACK during ELT, it is reordering. */
		tp->snd_ssthresh = ro->prior_flight_size;
		tp->snd_cwnd = min(tp->packets_out + 1, ro->prior_flight_size);
		tp->snd_cwnd_stamp = tcp_time_stamp;
		if (flag & FLAG_DATA_SACKED)
			tcp_ncr_elt_init(sk, 1);
		else
			ro->elt_flag = 0;
	} else {
		/* Dupthresh is reached, start recovery */
		tp->snd_ssthresh = (ro->prior_flight_size/2);
		tp->snd_cwnd = tp->snd_ssthresh;
		tp->snd_cwnd_stamp = tcp_time_stamp;
		ro->elt_flag = 0;
	}
}

/* TCP-NCR: Extended Limited Transmit
 * (RFC 4653 Main Part)
 */
static void tcp_ncr_elt(struct sock *sk, int flag)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct ncr *ro = inet_csk_ro(sk);

	if (ro->lt_f == 3)
		tcp_cwnd_down(sk, flag);
	// TODO: use shift
	ro->dupthresh = max_t(u32, ((2 * tp->packets_out)/ro->lt_f), 3);
}

/* Return the dupthresh.
 * If everything is right, return NCR's dupthresh.
 * Else, fall back to native
 */
static u32 tcp_ncr_dupthresh(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct ncr *ro = inet_csk_ro(sk);

	if (ro->elt_flag && tcp_ncr_test(sk))
		return ro->dupthresh;

	return tp->reordering;
}

/* We received a SACK for a segment not previously SACK'ed */
static void tcp_ncr_new_sack(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct ncr *ro = inet_csk_ro(sk);

	// only init ELT, if we're not already in ELT and this is the first SACK'ed segment
	if (tcp_ncr_test(sk) && (!ro->elt_flag) && (tp->sacked_out == 0))
		tcp_ncr_elt_init(sk, 0);
}

/* A non-retransmitted SACK hole was filled */
static void tcp_ncr_sack_hole_filled(struct sock *sk, int flag)
{
	struct ncr *ro = inet_csk_ro(sk);

	if (ro->elt_flag)
		tcp_ncr_elt_end(sk, flag, 1);
}

/* the state machine will start right after this */
static void tcp_ncr_sm_starts(struct sock *sk, int flag)
{
	struct ncr *ro = inet_csk_ro(sk);

	if (ro->elt_flag && (flag & FLAG_DATA_SACKED))
		tcp_ncr_elt(sk, flag);
}

/* ssthresh needs to be set */
static void tcp_ncr_set_ssthresh(struct sock *sk, int flag)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	struct ncr *ro = inet_csk_ro(sk);

	if (ro->elt_flag)
		tcp_ncr_elt_end(sk, flag, 0);
	else
		tp->snd_ssthresh = icsk->icsk_ca_ops->ssthresh(sk);
}

/* cwnd is to be reduced */
static void tcp_ncr_cwnd_down(struct sock *sk, int flag)
{
	if (!tcp_ncr_test(sk))
		tcp_cwnd_down(sk, flag);
}

static struct tcp_reorder_ops tcp_ncr = {
	.flags      = TCP_REORDER_NON_RESTRICTED,
	.name       = "ncr",
	.owner      = THIS_MODULE,
	.dupthresh  = tcp_ncr_dupthresh,
	.new_sack   = tcp_ncr_new_sack,
	.sm_starts  = tcp_ncr_sm_starts,
	.set_ssthresh = tcp_ncr_set_ssthresh,
	.cwnd_down  = tcp_ncr_cwnd_down,
	.allow_moderation = 0,
};

static int __init tcp_ncr_register(void)
{
	BUILD_BUG_ON(sizeof(struct ncr) > ICSK_RO_PRIV_SIZE);
	tcp_register_reorder(&tcp_ncr);
	return 0;
}

static void __exit tcp_ncr_unregister(void)
{
	tcp_unregister_reorder(&tcp_ncr);
}

module_init(tcp_ncr_register);
module_exit(tcp_ncr_unregister);

MODULE_AUTHOR("Daniel Slot, Carsten Wolff");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("TCP-NCR");
MODULE_VERSION("1.0");
