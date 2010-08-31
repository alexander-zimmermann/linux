/*
 * No reordering detection/response
 * dupthresh is always 3
 */

#include <linux/module.h>
#include <linux/mm.h>
#include <net/tcp.h>

/*
 * TCP Linux noreor DupAck threshold
 */

struct noreor {
    u8  reorder_mode;
};

u32 tcp_noreor_dupthresh(struct sock *sk)
{
	return 3;
}
//EXPORT_SYMBOL_GPL(tcp_noreor_dupthresh);

static void tcp_noreor_update_mode(struct sock *sk, int val) {
	struct noreor *ro_priv = inet_csk_ro(sk);

	ro_priv->reorder_mode = val;
}

struct tcp_reorder_ops tcp_noreor = {
	.flags		= TCP_REORDER_NON_RESTRICTED,
	.name		= "noreor",
	.owner		= THIS_MODULE,
	.dupthresh	= tcp_noreor_dupthresh,
	.update_mode= tcp_noreor_update_mode,
	.allow_moderation = 1,
	.allow_head_to = 1,
	.moddupthresh = tcp_noreor_dupthresh,
};

static int __init tcp_noreor_register(void)
{
	    BUILD_BUG_ON(sizeof(struct noreor) > ICSK_RO_PRIV_SIZE);
		    tcp_register_reorder(&tcp_noreor);
			    return 0;
}

static void __exit tcp_noreor_unregister(void)
{
	    tcp_unregister_reorder(&tcp_noreor);
}

module_init(tcp_noreor_register);
module_exit(tcp_noreor_unregister);

MODULE_AUTHOR("Lennart Schulte");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("TCP-NOREOR");
MODULE_VERSION("1.0");

