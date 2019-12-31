#include <linux/module.h> /* Needed by all modules */
#include <linux/kernel.h> /* Needed for KERN_ALERT */
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/compiler.h>
#include <net/tcp.h>
#include <linux/namei.h>
#include <linux/version.h>
#include <linux/semaphore.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/fs.h>
#include <linux/version.h>
#include <linux/compiler.h>
#include <net/tcp.h>
#include <linux/proc_fs.h>
#include <linux/namei.h>
#include "firewallExtension.h"

MODULE_AUTHOR("Mihai-Emilian Buduroi <meb648@student.bham.ac.uk>");
MODULE_DESCRIPTION("Extension of the firewall");
MODULE_LICENSE("GPL");

#define NIPQUAD(addr)                \
    ((unsigned char *)&addr)[0],     \
        ((unsigned char *)&addr)[1], \
        ((unsigned char *)&addr)[2], \
        ((unsigned char *)&addr)[3]

// the firewall hook - called for each outgoing packet
#if LINUX_VERSION_CODE <= KERNEL_VERSION(4, 3, 0)
#error "Kernel version < 4.4 not supported!"
//kernels < 4.4 need another firewallhook!
#endif

static void list_init(list *list)
{
    list->node = NULL;
}

static void kfreen(void *pointer)
{
    kfree(pointer);
    pointer = NULL;
}

static int list_insert(list *list, int port, char *exec)
{
    Node *candidate;

    // Create fresh node
    candidate = (Node *)kmalloc(sizeof(Node), GFP_KERNEL);
    if (!candidate)
    {
        printk(KERN_WARNING "%s", "Kernel memory error: No memory left for allocation\n");
        return -1;
    }

    candidate->exec = exec;
    if (!candidate->exec)
    {
        printk(KERN_WARNING "%s", "Kernel memory error: No memory left for allocation\n");
        kfreen(candidate);
        return -1;
    }

    // populate members
    candidate->port_no = port;
    candidate->exec = exec;

    if (list->node)
    {                                 // we have a node in the list
        candidate->next = list->node; // head:tail
    }
    else
    {
        candidate->next = NULL; // head:null
    }

    list->node = candidate;

    return 0;
}

static void list_print(list *list)
{
    Node *current_node = list->node;
    down_read(&sem_rules);
    while (current_node)
    {
        printk(KERN_INFO "Firewall rule: %d %s\n", current_node->port_no, current_node->exec);
        current_node = current_node->next;
    }
    up_read(&sem_rules);
}

static int list_find(list *list, int port, char *exec)
{
    Node *cursor = list->node;
    int result = 1; // In absence of a rule, we return 1
    down_read(&sem_rules);
    while (cursor)
    {
        if (cursor->port_no == port)
        {
            if (!exec)
            {
                up_read(&sem_rules);
                return 0;
            }
            result = 0;
            // We found a rule, so now only return 1 if a rule for the exec exists
            if (strcmp(cursor->exec, exec) == 0)
            {
                up_read(&sem_rules);
                return 1;
            }
        }
        cursor = cursor->next;
    }
    up_read(&sem_rules);
    return result;
}

// This deallocator is itterative
static void list_destroy(list *list)
{
    Node *head = list->node;
    Node *tail;
    while (head)
    {
        tail = head->next;
        kfreen(head->exec);
        kfreen(head);
        head = tail;
    }
}

char *find_exec_path(char *exec_filename, size_t count)
{
    struct path path;
    struct dentry *file_link;

    pid_t pid;
    size_t remaining = count;

    char path_string[PATH_SIZE];
    int result;
    int size;

    pid = current->pid;
    snprintf(path_string, PATH_SIZE, "/proc/%d/exe", pid);
    result = kern_path(path_string, LOOKUP_FOLLOW, &path);

    if (result)
    {
        return NULL;
    }

    exec_filename[0] = '\0';
    file_link = path.dentry;
    size = 0;

    while ((strcmp(file_link->d_name.name, "/") != 0) && (remaining > 0))
    {
        const char *entry;

        entry = file_link->d_name.name;

        if (remaining < (strlen(entry) + 1))
        {
            kfreen(exec_filename);
            path_put(&path);
            return NULL;
        }

        memmove(exec_filename + strlen(entry) + 1, exec_filename, size + 1);
        exec_filename[strlen(entry)] = '/';
        memcpy(exec_filename, entry, strlen(entry));
        remaining = remaining - strlen(entry) - 1;
        file_link = file_link->d_parent;
        size = size + strlen(entry) + 1;
    }

    path_put(&path);

    size = strlen(exec_filename);
    memmove(exec_filename + 1, exec_filename, strlen(exec_filename));
    exec_filename[size] = '\0';
    exec_filename[0] = '/';

    printk(KERN_INFO "%s\n", exec_filename);
    return exec_filename;
}

int allowConnection(int port)
{
    int ret = 1;
    char *buffer;
    char *exec_filename;

    buffer = kmalloc(EXEC_SIZE, GFP_KERNEL);
    if (!buffer)
    {
        return -ENOMEM;
    }

    exec_filename = find_exec_path(buffer, EXEC_SIZE);

    if (!exec_filename)
    {
        kfreen(buffer);
    } // Couldn't get executable name

    ret = list_find(&rules, port, exec_filename);

    if (exec_filename)
    {
        kfreen(exec_filename);
    }
    return ret;
}

unsigned int firewallExtension(void *priv,
                               struct sk_buff *skb,
                               const struct nf_hook_state *state)
{
    struct tcphdr *tcp;
    struct tcphdr _tcph;
    struct mm_struct *mm;
    struct sock *socket;

    socket = skb->sk;
    if (!socket)
    {
        return NF_ACCEPT;
    } // No socket information

    if (socket->sk_protocol != IPPROTO_TCP)
    {
        return NF_ACCEPT;
    } // Not TCP packet

    tcp = skb_header_pointer(skb, ip_hdrlen(skb), sizeof(struct tcphdr), &_tcph);
    if (!tcp)
    {
        return NF_ACCEPT;
    } // tcp header missing
    if (tcp->syn)
    {
        struct iphdr *ip;

        ip = ip_hdr(skb);
        if (!ip)
        {
            printk(KERN_INFO "\nIP header not found\n!");
        }
        else
        {
            printk(KERN_INFO "\nOutgoing address = %u.%u.%u.%u\n", NIPQUAD(ip->daddr));
        }
        printk(KERN_INFO "From port= %d\n", htons(tcp->dest));

        if (in_irq() || in_softirq() || !(mm = get_task_mm(current)))
        {
            return NF_ACCEPT; // kernel context
        }
        mmput(mm);

        if (!allowConnection(htons(tcp->dest)))
        {
            tcp_done(socket); // ultimately drop syn packet and kill the connection
            return NF_DROP;
        }
    }
    return NF_ACCEPT;
}

static struct nf_hook_ops firewallExtension_ops = {
    .hook = firewallExtension,
    .pf = PF_INET,
    .priority = NF_IP_PRI_FIRST,
    .hooknum = NF_INET_LOCAL_OUT};

static char *extract_path(char *src, size_t length)
{
    char *cursor;
    char *path;

    src++; // jump one space

    cursor = src;

    while (*cursor != ' ')
    {
        cursor++;
    }

    path = (char *)kmalloc(cursor - src + 1, GFP_KERNEL);

    if (!path)
    {
        return NULL;
    }

    memset(path, 0, cursor - src + 1);
    memcpy(path, src, cursor - src);

    return path;
}

static int extract_port(char *src)
{
    int port, i;
    char port_string[6] = {'\0'};
    src++;
    memcpy(port_string, src, 5);

    for (i = 0; i < 6; i++)
    {
        if (port_string[i] == ' ')
        {
            port_string[i] = '\0';
        }
    }
    kstrtoint(port_string, 10, &port);
    return port;
}

static int load_rules(char *rules_string, size_t length)
{
    int port;
    list new_list;
    char *path, *cursor;

    list_init(&new_list);

    cursor = rules_string + 1; // Jump ACTION
    length -= 1;

    while (length >= 5)
    {
        port = extract_port(cursor);
        cursor += 6;
        length -= 6;

        if (port == 0)
        {
            down_write(&sem_rules);
            list_destroy(&rules);
            rules = new_list;
            up_write(&sem_rules);
            return 0;
        }

        path = extract_path(cursor, length);

        cursor += (strlen(path) + 1); // + 1 for space
        length -= (strlen(path) + 1);

        if (list_insert(&new_list, port, path) != 0)
        {
            list_destroy(&new_list);
            return -ENOMEM;
        }

        if (DEBUG)
        {
            printk(KERN_INFO "%d %s\n", port, path);
        }
    }

    return -EINVAL;
}

ssize_t kernelWrite(struct file *filep, const char __user *buffer, size_t len, loff_t *offset)
{
    char *payload;

    payload = (char *)kmalloc(len, GFP_KERNEL);

    if (!payload)
    {
        return -ENOMEM;
    }

    if (copy_from_user(payload, buffer, len))
    {
        kfreen(payload);
        return -EFAULT;
    }

    if (payload[0] == 'L')
    {
        list_print(&rules);
    }

    if (payload[0] == 'W')
    {
        load_rules(payload, len);
    }

    kfreen(payload);

    return len;
}

int procfs_open(struct inode *inode, struct file *file)
{
    int response = 0;

    down(&sem_proc);

    if (lock_flag)
    {
        response = -EAGAIN; // process busy with another query
    }
    else
    {
        lock_flag = 1;
        if (DEBUG)
        {
            printk(KERN_INFO "kernelWrite opened\n");
        }
    }

    up(&sem_proc);

    return response;
}

int procfs_close(struct inode *inode, struct file *file)
{
    down(&sem_proc);
    lock_flag = 0;

    if (DEBUG)
    {
        printk(KERN_INFO "kernelWrite closed\n");
    }

    up(&sem_proc);

    return 0;
}

const struct file_operations proc_file_ops = {
    .owner = THIS_MODULE,
    .write = kernelWrite,
    .open = procfs_open,
    .release = procfs_close,
};

int init_module(void)
{
    int errno;
    proc_file = proc_create_data(PROC_FD, 0644, NULL, &proc_file_ops, NULL);

    if (proc_file == NULL)
    {
        printk(KERN_ALERT "Error: Could not initialize /proc/%s\n", PROC_FD);
        return -ENOMEM;
    }

    printk(KERN_INFO "/proc/%s created\n", PROC_FD);

    errno = nf_register_hook(&firewallExtension_ops); /* register the hook */
    if (errno)
    {
        printk(KERN_INFO "Firewall extension could not be registered!\n");
    }
    else
    {
        printk(KERN_INFO "Firewall extension module loaded\n");
    }

    list_init(&rules);

    return errno;
}

void cleanup_module(void)
{
    down_write(&sem_rules);
    list_destroy(&rules);
    up_write(&sem_rules);

    nf_unregister_hook(&firewallExtension_ops); /* restore everything to normal */

    remove_proc_entry(PROC_FD, NULL);
    printk(KERN_INFO "/proc/%s removed\n", PROC_FD);

    printk(KERN_INFO "Firewall extension module unloaded\n");
}