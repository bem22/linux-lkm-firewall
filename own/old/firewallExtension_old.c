#include <linux/module.h> /* Needed by all modules */
#include <linux/kernel.h> /* Needed for KERN_ALERT */
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/compiler.h>
#include <net/tcp.h>
#include <linux/namei.h>
#include <linux/version.h>

MODULE_AUTHOR("Mihai-Emilian Buduroi <meb648@student.bham.ac.uk>");
MODULE_DESCRIPTION("Extensions to the firewall");
MODULE_LICENSE("GPL");

/* make IP4-addresses readable */

#define NIPQUAD(addr)                \
    ((unsigned char *)&addr)[0],     \
        ((unsigned char *)&addr)[1], \
        ((unsigned char *)&addr)[2], \
        ((unsigned char *)&addr)[3]

struct nf_hook_ops *reg;

// the firewall hook - called for each outgoing packet
#if LINUX_VERSION_CODE <= KERNEL_VERSION(4, 3, 0)
#error "Kernel version < 4.4 not supported!"
//kernels < 4.4 need another firewallhook!
#endif

unsigned int FirewallExtensionHook(void *priv,
                                   struct sk_buff *skb,
                                   const struct nf_hook_state *state)
{

    struct tcphdr *tcp;
    struct tcphdr _tcph;
    struct sock *sk;
    struct mm_struct *mm;

    sk = skb->sk;
    if (!sk)
    {
        printk(KERN_INFO "firewall: netfilter called with empty socket!\n");
        return NF_ACCEPT;
    }

    if (sk->sk_protocol != IPPROTO_TCP)
    {
        printk(KERN_INFO "firewall: netfilter called with non-TCP-packet.\n");
        return NF_ACCEPT;
    }

    /* get the tcp-header for the packet */
    tcp = skb_header_pointer(skb, ip_hdrlen(skb), sizeof(struct tcphdr), &_tcph);
    if (!tcp)
    {
        printk(KERN_INFO "Could not get tcp-header!\n");
        return NF_ACCEPT;
    }
    if (tcp->syn)
    {
        struct iphdr *ip;

        printk(KERN_INFO "firewall: Starting connection \n");
        ip = ip_hdr(skb);
        if (!ip)
        {
            printk(KERN_INFO "firewall: Cannot get IP header!\n!");
        }
        else
        {
            printk(KERN_INFO "firewall: Destination address = %u.%u.%u.%u\n", NIPQUAD(ip->daddr));
        }
        printk(KERN_INFO "firewall: destination port = %d\n", ntohs(tcp->dest));

        if (in_irq() || in_softirq() || !(mm = get_task_mm(current)))
        {
            printk(KERN_INFO "Not in user context - retry packet\n");
            return NF_ACCEPT;
        }
        mmput(mm);

        if (ntohs(tcp->dest) == 80)
        {
            tcp_done(sk); /* terminate connection immediately */
            printk(KERN_INFO "Connection shut down\n");
            return NF_DROP;
        }
    }
    return NF_ACCEPT;
}

static struct nf_hook_ops firewallExtension_ops = {
    .hook = FirewallExtensionHook,
    .pf = PF_INET,
    .priority = NF_IP_PRI_FIRST,
    .hooknum = NF_INET_LOCAL_OUT
};

int init_module(void)
{

    int errno;

    errno = nf_register_hook(&firewallExtension_ops); /* register the hook */
    if (errno)
    {
        printk(KERN_INFO "Firewall extension could not be registered!\n");
    }
    else
    {
        printk(KERN_INFO "Firewall extensions module loaded\n");
    }

    // A non 0 return means init_module failed; module can't be loaded.
    return errno;
}

void cleanup_module(void)
{

    nf_unregister_hook(&firewallExtension_ops); /* restore everything to normal */
    printk(KERN_INFO "Firewall extensions module unloaded\n");
}
