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
printk(KERN_NOTICE "tcp_ncr_reset(): mode=%i\n", mode);
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
printk(KERN_NOTICE "tcp_ncr_init()\n");
	tcp_ncr_reset(inet_csk_ro(sk));
}

/* TCP-NCR: Test if TCP-NCR may be used
 * (Following RFC 4653 recommendations)
 */
static int tcp_ncr_test(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
printk(KERN_NOTICE "tcp_ncr_test()\n");

	return tcp_is_sack(tp) && !(tp->nonagle & TCP_NAGLE_OFF);
}

/* tcp_cwnd_down() is not meant to be used in the disorder phase. It is
 * implemented under assumptions only valid in the recovery phase.
 *
 * So, we need our own version for ELT, similar to the "E"-steps in RFC 4653
 */
void tcp_ncr_cwnd_down(struct sock *sk, int flag)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct ncr *ro = inet_csk_ro(sk);
	u32 room = ro->prior_flight_size > tcp_packets_in_flight(tp) ? ro->prior_flight_size - tcp_packets_in_flight(tp) : 0;
	u32 sent = tp->packets_out > ro->prior_flight_size ? tp->packets_out - ro->prior_flight_size : 0;
		
	if (mode == 1) {
		if (room > sent) {
			tp->snd_cwnd = tcp_packets_in_flight(tp) + room - sent;
			tp->snd_cwnd_stamp = tcp_time_stamp;
printk(KERN_NOTICE "tcp_ncr_cwnd_down(): found room: %i\n", room - sent);
		} else {
			tp->snd_cwnd = tcp_packets_in_flight(tp);
			tp->snd_cwnd_stamp = tcp_time_stamp;
printk(KERN_NOTICE "tcp_ncr_cwnd_down(): not enough room\n");
		}
	} else {
		if (room) {
			tp->snd_cwnd = tcp_packets_in_flight(tp) + max_t(u32, room, 3);   // burst protection
			tp->snd_cwnd_stamp = tcp_time_stamp;
		}
	}
}

/* TCP-NCR: Initiate Extended Limited Transmit
 * (RFC 4653 Initialization)
 */
static void tcp_ncr_elt_init(struct sock *sk, int how)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct ncr *ro = inet_csk_ro(sk);
printk(KERN_NOTICE "tcp_ncr_elt_init(): how (re-init because of partial ACK): %i\n", how);
printk(KERN_NOTICE "tcp_ncr_elt_init(): cwnd: %i ssthresh: %i in_flight: %i sacked_out: %i packets_out: %i dupthresh: %i retrans_out: %i elt_flag: %i snd_una: %u\n",
		tp->snd_cwnd,
		tp->snd_ssthresh,
		tcp_packets_in_flight(tp),
		tp->sacked_out,
		tp->packets_out,
		ro->dupthresh,
		tp->retrans_out,
		ro->elt_flag,
		tp->snd_una);
	if (!how)
		ro->prior_flight_size = tp->packets_out;
	ro->elt_flag = 1;
	ro->dupthresh = max_t(u32, ((2 * tp->packets_out)/ro->lt_f), 3);
}

/* TCP-NCR Extended Limited Transmit
 * (RFC 4653 Termination)
 */
static void tcp_ncr_elt_end(struct sock *sk, int flag , int how)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct ncr *ro = inet_csk_ro(sk);
printk(KERN_NOTICE "tcp_ncr_elt_end(): cwnd: %i in_flight: %i packets_out: %i dupthresh: %i retrans_out: %i snd_una: %u how: %i\n",
		tp->snd_cwnd,
		tcp_packets_in_flight(tp),
		tp->packets_out,
		ro->dupthresh,
		tp->retrans_out,
		tp->snd_una,
		how);
	if (how) {
		/* New cumulative ACK during ELT, it is reordering. */
		tp->snd_ssthresh = ro->prior_flight_size;
		tp->snd_cwnd = min(tcp_packets_in_flight(tp) + 1, ro->prior_flight_size);
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
printk(KERN_NOTICE "tcp_ncr_elt(): cwnd: %i ssthresh: %i in_flight: %i sacked_out: %i packets_out: %i dupthresh: %i retrans_out: %i elt_flag: %i snd_una: %u\n",
		tp->snd_cwnd,
		tp->snd_ssthresh,
		tcp_packets_in_flight(tp),
		tp->sacked_out,
		tp->packets_out,
		ro->dupthresh,
		tp->retrans_out,
		ro->elt_flag,
		tp->snd_una);
	if (mode == 1)
		tcp_ncr_cwnd_down(sk, flag);
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
{printk(KERN_NOTICE "tcp_ncr_dupthresh(): NCR\n");
		return ro->dupthresh;
}printk(KERN_NOTICE "tcp_ncr_dupthresh(): Native\n");
	return tp->reordering;
}

/* We received a SACK for a segment not previously SACK'ed */
static void tcp_ncr_new_sack(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct ncr *ro = inet_csk_ro(sk);
printk(KERN_NOTICE "-------------------------------------------- NEW SACK --------------------------------------------\n");
printk(KERN_NOTICE "tcp_ncr_new_sack(): cwnd: %i ssthresh: %i in_flight: %i sacked_out: %i packets_out: %i dupthresh: %i retrans_out: %i elt_flag: %i snd_una: %u\n",
		tp->snd_cwnd,
		tp->snd_ssthresh,
		tcp_packets_in_flight(tp),
		tp->sacked_out,
		tp->packets_out,
		ro->dupthresh,
		tp->retrans_out,
		ro->elt_flag,
		tp->snd_una);
	// only init ELT, if we're not already in ELT and this is the first SACK'ed segment
	if (tcp_ncr_test(sk) && (!ro->elt_flag) && (tp->sacked_out == 0))
		tcp_ncr_elt_init(sk, 0);
}

/* A non-retransmitted SACK hole was filled */
static void tcp_ncr_sack_hole_filled(struct sock *sk, int flag)
{
	struct ncr *ro = inet_csk_ro(sk);
printk(KERN_NOTICE "tcp_ncr_sack_hole_filled()\n");
	if (ro->elt_flag)
		tcp_ncr_elt_end(sk, flag, 1);
}

/* the state machine will start right after this */
static void tcp_ncr_sm_starts(struct sock *sk, int flag)
{
	struct ncr *ro = inet_csk_ro(sk);
printk(KERN_NOTICE "tcp_ncr_sm_starts()\n");
	if (ro->elt_flag && (flag & FLAG_DATA_SACKED))
		tcp_ncr_elt(sk, flag);
}

/* recovery starts */
static void tcp_ncr_recovery_starts(struct sock *sk, int flag)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	struct ncr *ro = inet_csk_ro(sk);
printk(KERN_NOTICE "tcp_ncr_recovery_starts()\n");
	if (ro->elt_flag)
		tcp_ncr_elt_end(sk, flag, 0);
	else
		tp->snd_ssthresh = icsk->icsk_ca_ops->ssthresh(sk);
}

static struct tcp_reorder_ops tcp_ncr = {
	.flags      = TCP_REORDER_NON_RESTRICTED,
	.name       = "ncr",
	.owner      = THIS_MODULE,
	.init       = tcp_ncr_init,
	.dupthresh  = tcp_ncr_dupthresh,
	.new_sack   = tcp_ncr_new_sack,
	.sack_hole_filled = tcp_ncr_sack_hole_filled,
	.sm_starts  = tcp_ncr_sm_starts,
	.recovery_starts = tcp_ncr_recovery_starts,
	.allow_moderation = 0,
	.allow_head_to = 0,
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
