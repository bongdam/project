#include <linux/module.h>
#include <linux/types.h>
#include <linux/timer.h>
#include <linux/skbuff.h>
#include <linux/gfp.h>
#include <net/xfrm.h>
#include <linux/jhash.h>
#include <linux/in.h>
#include <linux/inetdevice.h>
#include <linux/inet.h>
#include <os_util.h>

#ifdef CONFIG_RTL_HARDWARE_MULTICAST
extern int test_and_mcast_trap(__be32 group, int cpu);
#endif

static LIST_HEAD(grp_snoop_list);

struct group_snoop_entry {
	struct in_addr_entry addr;
	atomic_t usage;
	unsigned long jiffy;
};

struct ipt_work_struct {
	struct work_struct work;
	char rule[128];
};

static int ipt_rule_eval(struct ipt_work_struct *work)
{
	char *argv[24];
	int status = -1;
	char *envp[3] = { "HOME=/", "PATH=/sbin:/usr/sbin:/bin:/usr/bin", NULL };

	if (strargs(work->rule, argv, ARRAY_SIZE(argv), " \t\r\n") > 0)
		status = call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC);
	kfree(work);
	return status;
}

static int ipt_rule_command(__be32 ip, int add)
{
	struct ipt_work_struct *iw;
#ifdef CONFIG_RTL_HARDWARE_MULTICAST
	test_and_mcast_trap(ip, add);
#endif
	iw = kmalloc(sizeof(*iw), GFP_ATOMIC);
	if (iw == NULL)
		return -1;
	snprintf(iw->rule, sizeof(iw->rule),
		"/bin/iptables -%c INPUT -p udp -d %pI4 -j ACCEPT",
		add ? 'I' : 'D', &ip);
	INIT_WORK(&iw->work, (void *)ipt_rule_eval);
	schedule_work(&iw->work);
	return 0;
}

static int group_compr(struct group_snoop_entry *grp, __be32 addr)
{
	return (grp->addr.addr.s_addr == addr) ? 0 : -1;
}

static int group_snoop_add(__be32 group)
{
	struct group_snoop_entry *gse;

	if (!IN_MULTICAST(ntohl(group)))
		return -1;
	gse = (struct group_snoop_entry *)ip_addr_entry_get(&grp_snoop_list,
						(void *)group_compr, (void *)group);
	if (gse == NULL) {
		gse = kmalloc(sizeof(*gse), GFP_ATOMIC);
		if (gse == NULL)
			return -1;
		gse->addr.addr.s_addr = group;
		atomic_set(&gse->usage, 1);
		gse->jiffy = jiffies;
		in_addr_entry_add(&gse->addr, &grp_snoop_list);
		ipt_rule_command(group, 1);
		return 0;
	}

	gse->jiffy = jiffies;
	atomic_inc_not_zero(&gse->usage);
	ip_addr_entry_put(&gse->addr);
	return 0;
}

static void group_snoop_del(__be32 group)
{
	struct group_snoop_entry *gse;

	gse = (struct group_snoop_entry *)ip_addr_entry_get(&grp_snoop_list,
						(void *)group_compr, (void *)group);
	if (gse && ip_addr_entry_put(&gse->addr)) {
		if (atomic_dec_and_test(&gse->usage)) {
			ipt_rule_command(group, 0);
			ip_addr_entry_put(&gse->addr);
		}
	}
}

int group_snoop_test(__be32 group)
{
	struct group_snoop_entry *gse;

	gse = (struct group_snoop_entry *)ip_addr_entry_get(&grp_snoop_list,
						(void *)group_compr, (void *)group);
	if (gse)
		ip_addr_entry_put(&gse->addr);
	return (gse) ? 0 : -1;
}
EXPORT_SYMBOL(group_snoop_test);

static int group_strcat(struct in_addr_entry *addr, struct seq_file *s)
{
	return seq_printf(s, "%pI4\n", &addr->addr);
}

static int group_snoop_show(struct seq_file *s, void *v)
{
	ip_addr_entry_iterate(&grp_snoop_list, (void *)group_strcat, (void *)s);
	return 0;
}

static ssize_t group_snoop_write(struct file *filp, const char __user *buffer,
				size_t count, loff_t *off)
{
	char buf[80], cmd[16], addr[24];
	__be32 ip;
	if (strtrim_from_user(buf, sizeof(buf), buffer, count) > 0) {
		if (sscanf(buf, "%15s %23s", cmd, addr) >= 2) {
			if (in4_pton(addr, -1, (u8 *)&ip, -1, NULL) != 1)
				return count;
			if (!strcasecmp(cmd, "add"))
				group_snoop_add(ip);
			else if (!strcasecmp(cmd, "del"))
				group_snoop_del(ip);
		}
	}
	return count;
}

static int group_snoop_single_open(struct inode *inode, struct file *file)
{
        return single_open(file, group_snoop_show, NULL);
}

struct file_operations group_snoop_proc_fops = {
        .open = group_snoop_single_open,
        .read = seq_read,
        .llseek = seq_lseek,
        .release = single_release,
        .write = group_snoop_write,
};

static int __init group_snoop_init(void)
{
	proc_create_data("mgsnoop", 0, NULL, &group_snoop_proc_fops, NULL);
	return 0;
}

static void __exit group_snoop_exit(void)
{
	remove_proc_entry("mgsnoop", NULL);
}

module_init(group_snoop_init);
module_exit(group_snoop_exit);
