#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/sched.h>
#include <linux/inet.h>
#include <linux/hashtable.h>
#include <linux/spinlock.h>
#include "ppnpc.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("OpenAI + User");
MODULE_DESCRIPTION("Per-Process Packet Counting Kernel Module");
MODULE_VERSION("1.0");

DEFINE_HASHTABLE(process_table, 10);
DEFINE_SPINLOCK(ppnpc_lock);

static struct nf_hook_ops nfho_out, nfho_in;

struct process_net_stat *find_or_create_stat(pid_t pid) {
    struct process_net_stat *entry;
    hash_for_each_possible(process_table, entry, hnode, pid) {
        if (entry->pid == pid)
            return entry;
    }

    entry = kmalloc(sizeof(*entry), GFP_ATOMIC);
    if (!entry) return NULL;

    entry->pid = pid;
    entry->packets_sent = 0;
    entry->packets_received = 0;

    hash_add(process_table, &entry->hnode, pid);
    return entry;
}

unsigned int hook_out(void *priv,
                      struct sk_buff *skb,
                      const struct nf_hook_state *state) {
    pid_t pid = current->pid;
    struct process_net_stat *entry;

    spin_lock(&ppnpc_lock);
    entry = find_or_create_stat(pid);
    if (entry)
        entry->packets_sent++;
    spin_unlock(&ppnpc_lock);

    return NF_ACCEPT;
}

unsigned int hook_in(void *priv,
                     struct sk_buff *skb,
                     const struct nf_hook_state *state) {
    pid_t pid = current->pid;
    struct process_net_stat *entry;

    spin_lock(&ppnpc_lock);
    entry = find_or_create_stat(pid);
    if (entry)
        entry->packets_received++;
    spin_unlock(&ppnpc_lock);

    return NF_ACCEPT;
}

static int __init ppnpc_init(void) {
    hash_init(process_table);

    nfho_out.hook = hook_out;
    nfho_out.hooknum = NF_INET_LOCAL_OUT;
    nfho_out.pf = PF_INET;
    nfho_out.priority = NF_IP_PRI_FIRST;

    nfho_in.hook = hook_in;
    nfho_in.hooknum = NF_INET_LOCAL_IN;
    nfho_in.pf = PF_INET;
    nfho_in.priority = NF_IP_PRI_FIRST;

    nf_register_net_hook(&init_net, &nfho_out);
    nf_register_net_hook(&init_net, &nfho_in);

    printk(KERN_INFO "ppnpc: Per-process network accounting initialized.\n");
    return 0;
}

static void __exit ppnpc_exit(void) {
    int bkt;
    struct process_net_stat *entry;
    struct hlist_node *tmp;

    nf_unregister_net_hook(&init_net, &nfho_out);
    nf_unregister_net_hook(&init_net, &nfho_in);

    hash_for_each_safe(process_table, bkt, tmp, entry, hnode) {
        printk(KERN_INFO "ppnpc: PID=%d Sent=%lu Recv=%lu\n",
               entry->pid, entry->packets_sent, entry->packets_received);
        hash_del(&entry->hnode);
        kfree(entry);
    }

    printk(KERN_INFO "ppnpc: Unloaded.\n");
}

module_init(ppnpc_init);
module_exit(ppnpc_exit);
