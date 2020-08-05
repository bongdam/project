#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/spinlock.h>
#include <linux/sysctl.h>

unsigned int debug_msg_mask;

#if defined(CONFIG_SYSCTL)
static struct ctl_table private_childs[] = {
	{
		.procname	= "debug_msg_mask",
		.data		= &debug_msg_mask,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
	{}
};

static struct ctl_table private_root[] = {
	{
		.procname	= "private",
		.mode		= 0555,
		.child		= private_childs,
	},
	{}
};

static struct ctl_table_header *private_sysctls;

static int __init netpriv_sysctl_register(void)
{
	private_sysctls = register_sysctl_table(private_root);
	return 0;
}

static void __exit netpriv_sysctl_unregister(void)
{
	if (private_sysctls)
		unregister_sysctl_table(private_sysctls);
}

module_init(netpriv_sysctl_register);
module_exit(netpriv_sysctl_unregister);
#endif
