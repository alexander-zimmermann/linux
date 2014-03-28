/*
 * Plugable segment reordering modules
 * Based on plugable congestion control
 *
 * Copyright (C) 2009 Carsten Wolff <carsten@wolffcarsten.de>
 */

#include <linux/module.h>
#include <linux/mm.h>
#include <linux/types.h>
#include <linux/list.h>
#include <net/tcp.h>

int sysctl_tcp_reordering __read_mostly = TCP_FASTRETRANS_THRESH;

struct native {
	u8 reorder_mode;
};

static DEFINE_SPINLOCK(tcp_reorder_list_lock);
static LIST_HEAD(tcp_reorder_list);

/* Simple linear search, don't expect many entries! */
static struct tcp_reorder_ops *tcp_ro_find(const char *name)
{
	struct tcp_reorder_ops *e;

	list_for_each_entry_rcu(e, &tcp_reorder_list, list) {
		if (strcmp(e->name, name) == 0)
			return e;
	}

	return NULL;
}

/*
 * Attach new reordering algorithm to the list
 * of available options.
 */
int tcp_register_reorder(struct tcp_reorder_ops *ro)
{
	int ret = 0;

	/* all algorithms must implement certain ops */
	if (!ro->dupthresh || !ro->update_mode) {
		printk(KERN_ERR "TCP %s does not implement required ops\n",
		       ro->name);
		return -EINVAL;
	}

	spin_lock(&tcp_reorder_list_lock);
	if (tcp_ro_find(ro->name)) {
		printk(KERN_NOTICE "TCP %s already registered\n", ro->name);
		ret = -EEXIST;
	} else {
		list_add_tail_rcu(&ro->list, &tcp_reorder_list);
		printk(KERN_INFO "TCP %s registered\n", ro->name);
	}
	spin_unlock(&tcp_reorder_list_lock);

	return ret;
}
EXPORT_SYMBOL_GPL(tcp_register_reorder);

/*
 * Remove reordering algorithm, called from
 * the module's remove function.  Module ref counts are used
 * to ensure that this can't be done till all sockets using
 * that method are closed.
 */
void tcp_unregister_reorder(struct tcp_reorder_ops *ro)
{
	spin_lock(&tcp_reorder_list_lock);
	list_del_rcu(&ro->list);
	spin_unlock(&tcp_reorder_list_lock);
}
EXPORT_SYMBOL_GPL(tcp_unregister_reorder);

/* Assign choice of reordering algorithm. */
void tcp_init_reorder(struct sock *sk)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct tcp_reorder_ops *ro;

	/* if no choice made yet assign the current value set as default */
	if (icsk->icsk_ro_ops == &tcp_init_reorder_ops) {
		rcu_read_lock();
		list_for_each_entry_rcu(ro, &tcp_reorder_list, list) {
			if (try_module_get(ro->owner)) {
				icsk->icsk_ro_ops = ro;
				break;
			}

			/* fallback to next available */
		}
		rcu_read_unlock();
	}

	if (icsk->icsk_ro_ops->init)
		icsk->icsk_ro_ops->init(sk);
}

/* Manage refcounts on socket close. */
void tcp_cleanup_reorder(struct sock *sk)
{
	struct inet_connection_sock *icsk = inet_csk(sk);

	if (icsk->icsk_ro_ops->release)
		icsk->icsk_ro_ops->release(sk);
	module_put(icsk->icsk_ro_ops->owner);
}

/* Used by sysctl to change default congestion control */
int tcp_set_default_reorder(const char *name)
{
	struct tcp_reorder_ops *ro;
	int ret = -ENOENT;

	spin_lock(&tcp_reorder_list_lock);
	ro = tcp_ro_find(name);
#ifdef CONFIG_MODULES
	if (!ro && capable(CAP_SYS_MODULE)) {
		spin_unlock(&tcp_reorder_list_lock);

		request_module("tcp_%s", name);
		spin_lock(&tcp_reorder_list_lock);
		ro = tcp_ro_find(name);
	}
#endif

	if (ro) {
		ro->flags |= TCP_REORDER_NON_RESTRICTED;	/* default is always allowed */
		list_move(&ro->list, &tcp_reorder_list);
		ret = 0;
	}
	spin_unlock(&tcp_reorder_list_lock);

	return ret;
}

/* Set default value from kernel configuration at bootup */
static int __init tcp_reorder_default(void)
{
	return tcp_set_default_reorder(CONFIG_DEFAULT_TCP_REORDER);
}
late_initcall(tcp_reorder_default);


/* Build string with list of available reordering algorithms */
void tcp_get_available_reorder(char *buf, size_t maxlen)
{
	struct tcp_reorder_ops *ro;
	size_t offs = 0;

	rcu_read_lock();
	list_for_each_entry_rcu(ro, &tcp_reorder_list, list) {
		offs += snprintf(buf + offs, maxlen - offs,
				 "%s%s",
				 offs == 0 ? "" : " ", ro->name);

	}
	rcu_read_unlock();
}

/* Get current default reordering algorithm */
void tcp_get_default_reorder(char *name)
{
	struct tcp_reorder_ops *ro;
	/* We will always have linux native... */
	BUG_ON(list_empty(&tcp_reorder_list));

	rcu_read_lock();
	ro = list_entry(tcp_reorder_list.next, struct tcp_reorder_ops, list);
	strncpy(name, ro->name, TCP_REORDER_NAME_MAX);
	rcu_read_unlock();
}

/* Built list of non-restricted reordering values */
void tcp_get_allowed_reorder(char *buf, size_t maxlen)
{
	struct tcp_reorder_ops *ro;
	size_t offs = 0;

	*buf = '\0';
	rcu_read_lock();
	list_for_each_entry_rcu(ro, &tcp_reorder_list, list) {
		if (!(ro->flags & TCP_REORDER_NON_RESTRICTED))
			continue;
		offs += snprintf(buf + offs, maxlen - offs,
				 "%s%s",
				 offs == 0 ? "" : " ", ro->name);

	}
	rcu_read_unlock();
}

/* Change list of non-restricted reordering algorithms */
int tcp_set_allowed_reorder(char *val)
{
	struct tcp_reorder_ops *ro;
	char *clone, *name;
	int ret = 0;

	clone = kstrdup(val, GFP_USER);
	if (!clone)
		return -ENOMEM;

	spin_lock(&tcp_reorder_list_lock);
	/* pass 1 check for bad entries */
	while ((name = strsep(&clone, " ")) && *name) {
		ro = tcp_ro_find(name);
		if (!ro) {
			ret = -ENOENT;
			goto out;
		}
	}

	/* pass 2 clear old values */
	list_for_each_entry_rcu(ro, &tcp_reorder_list, list)
		ro->flags &= ~TCP_REORDER_NON_RESTRICTED;

	/* pass 3 mark as allowed */
	while ((name = strsep(&val, " ")) && *name) {
		ro = tcp_ro_find(name);
		WARN_ON(!ro);
		if (ro)
			ro->flags |= TCP_REORDER_NON_RESTRICTED;
	}
out:
	spin_unlock(&tcp_reorder_list_lock);

	return ret;
}


/* Change reordering algorithm for socket */
int tcp_set_reorder(struct sock *sk, const char *name)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct tcp_reorder_ops *ro;
	struct native *ro_priv = inet_csk_ro(sk);
	int err = 0;

	rcu_read_lock();
	ro = tcp_ro_find(name);

	/* no change asking for existing value */
	if (ro == icsk->icsk_ro_ops)
		goto out;

#ifdef CONFIG_MODULES
	/* not found attempt to autoload module */
	if (!ro && capable(CAP_SYS_MODULE)) {
		rcu_read_unlock();
		request_module("tcp_%s", name);
		rcu_read_lock();
		ro = tcp_ro_find(name);
	}
#endif
	if (!ro)
		err = -ENOENT;

	else if (!((ro->flags & TCP_REORDER_NON_RESTRICTED) || capable(CAP_NET_ADMIN)))
		err = -EPERM;

	else if (!try_module_get(ro->owner))
		err = -EBUSY;

	else {
		tcp_cleanup_reorder(sk);
		icsk->icsk_ro_ops = ro;

		if (sk->sk_state != TCP_CLOSE) {
			if (icsk->icsk_ro_ops->init)
				icsk->icsk_ro_ops->init(sk);
			if (icsk->icsk_ro_ops->update_mode)
				icsk->icsk_ro_ops->update_mode(sk, ro_priv->reorder_mode);
		}
	}
 out:
	rcu_read_unlock();
	return err;
}

/*
 * TCP Linux native DupAck threshold
 */
u32 tcp_native_dupthresh(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	return tp->reordering;
}
EXPORT_SYMBOL_GPL(tcp_native_dupthresh);

static void tcp_native_update_mode(struct sock *sk, int val) {
	struct native *ro_priv = inet_csk_ro(sk);

	ro_priv->reorder_mode = val;
}

struct tcp_reorder_ops tcp_native = {
	.flags		= TCP_REORDER_NON_RESTRICTED,
	.name		= "native",
	.owner		= THIS_MODULE,
	.dupthresh	= tcp_native_dupthresh,
	.update_mode= tcp_native_update_mode,
	.allow_moderation = 1,
	.allow_head_to = 1,
	.moddupthresh = tcp_native_dupthresh,
};

/* Initial reordering algorithm used (until SYN)
 * really native under another name so we can tell difference
 * during tcp_set_default_reorder
 */
struct tcp_reorder_ops tcp_init_reorder_ops  = {
	.name		= "",
	.owner		= THIS_MODULE,
	.dupthresh	= tcp_native_dupthresh,
	.update_mode= tcp_native_update_mode,
	.allow_moderation = 1,
	.moddupthresh = tcp_native_dupthresh,
};
EXPORT_SYMBOL_GPL(tcp_init_reorder_ops);
