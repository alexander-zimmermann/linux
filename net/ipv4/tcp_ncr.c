/*
 * TCP-NCR reordering response
 *
 * Implements RFC4653
 * http://www.ietf.org/rfc/rfc4653.txt
 *
 * While reading this code, remember:
 *      Linux                  IETF
 *   packets_out            FLIGHT_SIZE
 * tcp_flight_size()          pipe()
 */

#include <linux/mm.h>
#include <linux/module.h>
#include <linux/skbuff.h>

#include <net/tcp.h>

// copied from tcp_input.c
#define FLAG_DATA_SACKED    0x20 /* New SACK.               */

/*static int mode = 1;
module_param(mode, int, 0644);
MODULE_PARM_DESC(mode, "mode: careful (1) or aggressive (2)"); */

/* NCR variables */
struct ncr {
	u8  reorder_mode;
	u8  elt_flag;
	u32 dupthresh;
	u8  lt_f;
	u32 prior_packets_out;
	u32 acked;
};

static void tcp_ncr_update_mode(struct sock *sk, int val)
{
	struct ncr *ro = inet_csk_ro(sk);

	if (val == 2) {
		ro->lt_f = 4;
		ro->reorder_mode = val;
	} else {
		ro->lt_f = 3;
		ro->reorder_mode = 1;
	}
}

static inline void tcp_ncr_init(struct sock *sk)
{
	struct ncr *ro = inet_csk_ro(sk);

	ro->elt_flag = 0;
	ro->dupthresh = TCP_FASTRETRANS_THRESH;

	tcp_ncr_update_mode(sk, ro->reorder_mode);

	ro->prior_packets_out = 0;

	ro->acked = 0;
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

	//printk(KERN_INFO "elt init: how=%u", how);
	if (!how) { //execute in I.1 but not in T.4
		ro->prior_packets_out = tp->packets_out;
		ro->acked = 0;
	}
	ro->elt_flag = 1;
	ro->dupthresh = max_t(u32, ((2 * tp->packets_out)/ro->lt_f), 3);
}

/* TCP-NCR Extended Limited Transmit
 * (RFC 4653 Termination)
 */
static void tcp_ncr_elt_end(struct sock *sk, int flag , int cumack)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	struct ncr *ro = inet_csk_ro(sk);

	//printk(KERN_INFO "elt end: cumack=%u", cumack);
	if (cumack) {
		/* New cumulative ACK during ELT, it is reordering. */
		if (tp->snd_ssthresh < ro->prior_packets_out)  //fix: slowstart bug
			tp->snd_ssthresh = ro->prior_packets_out;
		tp->snd_cwnd = min(tcp_packets_in_flight(tp) + 1, ro->prior_packets_out);
		tp->snd_cwnd_stamp = tcp_time_stamp;
		if (tp->sacked_out)
		//if (flag & FLAG_DATA_SACKED) it seems as if this doesnt work 
			tcp_ncr_elt_init(sk, 1); //T.4
		else {
			//printk(KERN_INFO "elt_flag 0");
			ro->elt_flag = 0;
		}
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

/* TCP-NCR: Extended Limited Transmit
 * (RFC 4653 Main Part)
 *
 * tcp_cwnd_down() is not meant to be used in the disorder phase. It is
 * implemented under assumptions only valid in the recovery phase.
 * So, we need our own version for ELT, similar to the "E"-steps in RFC 4653
 */
static void tcp_ncr_elt(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct ncr *ro = inet_csk_ro(sk);
	u32 sent;
	u32 room = ro->prior_packets_out > tcp_packets_in_flight(tp) ?
		ro->prior_packets_out - tcp_packets_in_flight(tp) :
		0;

	if (ro->reorder_mode == 1) {
		/* acked: when receiving an ACK, that acknowledges new data, but also
		 * carries SACK information (partial ACK in ELT), careful ELT would
		 * send a burst of data which resembles the number of packets not sent
		 * compared to aggressive ELT. With this variable all acknowledged
		 * segments during ELT can be taken into account.
		 * */
		sent = (tp->packets_out/* + ro->acked*/) > ro->prior_packets_out ?
			(tp->packets_out/* + ro->acked*/) - ro->prior_packets_out :
			0;
		room = room > sent ?
			room - sent :
			0;
	}

	tp->snd_cwnd = tcp_packets_in_flight(tp) + room;
	tp->snd_cwnd_stamp = tcp_time_stamp;

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

	if (ro->elt_flag && tcp_ncr_test(sk)) {
		return ro->dupthresh;
	}
	return tp->reordering;
}

/* Return the dupthresh calculated by this module
 * to show differences between calculated dupthresh
 * and native dupthresh in flowgrind logs.
 */
static u32 tcp_ncr_moddupthresh(struct sock *sk)
{
	struct ncr *ro = inet_csk_ro(sk);
	return ro->dupthresh;
}

/* We received a SACK for a segment not previously SACK'ed */
static void tcp_ncr_new_sack(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct ncr *ro = inet_csk_ro(sk);
	const struct inet_connection_sock *icsk = inet_csk(sk);

	// only init ELT, if we're not already in ELT and this is the first SACK'ed segment
	if (tcp_ncr_test(sk) && (!ro->elt_flag) && (tp->sacked_out == 0) && (icsk->icsk_ca_state < TCP_CA_CWR))
		tcp_ncr_elt_init(sk, 0); //I.1
}

/* A non-retransmitted SACK hole was filled */
static void tcp_ncr_sack_hole_filled(struct sock *sk, int flag)
{
	struct ncr *ro = inet_csk_ro(sk);

	if (ro->elt_flag)
		tcp_ncr_elt_end(sk, flag, 1);
}

/* the state machine will start right after this */
static void tcp_ncr_sm_starts(struct sock *sk, int flag, int acked)
{
	struct ncr *ro = inet_csk_ro(sk);
	struct tcp_sock *tp = tcp_sk(sk);

	ro->acked += acked;

	if (ro->elt_flag && (tp->sacked_out)) //(flag & FLAG_DATA_SACKED)) this one works only for new sack info?
		tcp_ncr_elt(sk);
}

/* recovery starts */
static void tcp_ncr_recovery_starts(struct sock *sk, int flag)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	struct ncr *ro = inet_csk_ro(sk);

	if (ro->elt_flag)
		tcp_ncr_elt_end(sk, flag, 0);
	else
		tp->snd_ssthresh = icsk->icsk_ca_ops->ssthresh(sk);
}

static void tcp_ncr_rto_happened(struct sock *sk)
{
	struct ncr *ro = inet_csk_ro(sk);
	ro->elt_flag = 0;
}

static struct tcp_reorder_ops tcp_ncr = {
	.flags            = TCP_REORDER_NON_RESTRICTED,
	.name             = "ncr",
	.owner            = THIS_MODULE,
	.init             = tcp_ncr_init,
	.dupthresh        = tcp_ncr_dupthresh,
	.new_sack         = tcp_ncr_new_sack,
	.sack_hole_filled = tcp_ncr_sack_hole_filled,
	.sm_starts        = tcp_ncr_sm_starts,
	.recovery_starts  = tcp_ncr_recovery_starts,
	.update_mode      = tcp_ncr_update_mode,
	.allow_moderation = 0,
	.allow_head_to    = 0,
	.moddupthresh     = tcp_ncr_moddupthresh,
	.rto_happened	  = tcp_ncr_rto_happened,
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

MODULE_AUTHOR("Daniel Slot, Carsten Wolff, Lennart Schulte");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("TCP-NCR");
MODULE_VERSION("1.0");
