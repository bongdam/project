/*
 * Shared library add-on to iptables to add TCPOPTADD target support.
 * Copyright (c) 2018 hf_shi <hf_shi@realsil.com.cn>
 * Copyright (c) Realsil 2018
 */
#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <xtables.h>
#include <netinet/tcp.h>
#include <linux/netfilter/x_tables.h>
#include <linux/netfilter/xt_TCPOPTADD.h>

enum {
    FLAG_ADD = 1 << 0,		
    FLAG_MOD = 1 << 1,
};

static const struct option tcpoptadd_tg_opts[] = {
	{.name = "add-options", .has_arg = true, .val = 'a'},	
	{.name = "mod-options", .has_arg = true, .val = 'm'},
	{ .name = NULL }
};

static void tcpoptadd_tg_help(void)
{
	const struct tcp_optionmap *w;

	printf(
"TCPOPTADD target options:\n"
"  --add-options ID,value     add specified TCP options denoted by ID,value\n"
"                            (separated by comma) to TCP header\n"
"							 where value is a hex string 	   \n"
"  --mod-options ID,value	  add specified TCP options denoted by ID,value\n"
"							 (separated by comma) to TCP header\n"
"							 where value is a hex string	   \n"
	);

}

static void tcpoptadd_tg_init(struct xt_entry_target *t)
{
	struct xt_tcpoptadd_target_info *info = (void *)t->data;

	/* strictly necessary? play safe for now. */
	memset(info, 0, sizeof(info));
}


static int _is_hex(char c)
{
    return (((c >= '0') && (c <= '9')) ||
            ((c >= 'A') && (c <= 'F')) ||
            ((c >= 'a') && (c <= 'f')));
}

static int string_to_hex(char *string, unsigned char *key, int len)
{
	char tmpBuf[4];
	int idx, ii=0;
	for (idx=0; idx<len; idx+=2) {
		tmpBuf[0] = string[idx];
		tmpBuf[1] = string[idx+1];
		tmpBuf[2] = 0;
		if ( !_is_hex(tmpBuf[0]) || !_is_hex(tmpBuf[1]))
			return 0;

		key[ii++] = (unsigned char) strtol(tmpBuf, NULL, 16);
	}
	return 1;
}

static void parse_list(struct xt_tcpoptadd_target_info *info, char *arg)
{
	unsigned int option;
	char *p;
	int i,len;

	option = 0;
	while (true) {
		p = strchr(arg, ',');
		if (p != NULL)
			*p = '\0';

		/*ID*/
		if (option == 0 &&
		    !xtables_strtoui(arg, NULL, &info->id, 0, UINT8_MAX))
			xtables_error(PARAMETER_PROBLEM,
			           "Bad TCP option value \"%s\"", arg);

		
		/*Value*/
		if (option == 1) {
			if((strlen(arg)%2 !=0) && ((strlen(arg)/2) > MAX_TCP_OPTION_LEN))
				xtables_error(PARAMETER_PROBLEM,
				"Value length is odd");
			string_to_hex(arg,info->value,strlen(arg));
			info->len = strlen(arg)/2+2;
		}

		if (option >= 2)
			xtables_error(PARAMETER_PROBLEM,
			           "more than 2 argument");
		option++;
		if (p == NULL)
			break;
		arg = p + 1;
	}
}

static int tcpoptadd_tg_parse(int c, char **argv, int invert,
                                unsigned int *flags, const void *entry,
                                struct xt_entry_target **target)
{
	struct xt_tcpoptadd_target_info *info = (void *)(*target)->data;

	switch (c) {
	case 'a':
		if (*flags & FLAG_ADD)
			xtables_error(PARAMETER_PROBLEM,
			           "You can specify --add-options only once");
		parse_list(info, optarg);
		info->op |= FLAG_ADD;
		*flags |= FLAG_ADD;
		return true;
	case 'm':
		if (*flags & FLAG_MOD)
			xtables_error(PARAMETER_PROBLEM,
			           "You can specify --mod-options only once");
		parse_list(info, optarg);		
		info->op |= FLAG_MOD;
		*flags |= FLAG_MOD;
		return true;	
	}

	return false;
}

static void tcpoptadd_tg_check(unsigned int flags)
{
	if (flags == 0)
		xtables_error(PARAMETER_PROBLEM,
		           "TCPOPTADD: --add-options parameter required");
}

static void
tcpoptadd_print_list(const struct xt_tcpoptadd_target_info *info,
                       bool numeric)
{
	unsigned int i;

	printf("0x%02x,",info->id);	
	for(i=0;i<(info->len-2);i++)
		printf("%02x",info->value[i]);
}

static void
tcpoptadd_tg_print(const void *ip, const struct xt_entry_target *target,
                     int numeric)
{
	const struct xt_tcpoptadd_target_info *info =
		(const void *)target->data;

	printf("TCPOPTADD options ");
	tcpoptadd_print_list(info, numeric);
}

static void
tcpoptadd_tg_save(const void *ip, const struct xt_entry_target *target)
{
	const struct xt_tcpoptadd_target_info *info =
		(const void *)target->data;

	if(info->op & FLAG_ADD)
		printf("--add-options ");
	else if(info->op & FLAG_MOD)
		printf("--mod-options ");
	tcpoptadd_print_list(info, true);
}

static struct xtables_target tcpoptadd_tg_reg = {
	.version       = XTABLES_VERSION,
	.name          = "TCPOPTADD",
	.family        = NFPROTO_IPV4,
	.size          = XT_ALIGN(sizeof(struct xt_tcpoptadd_target_info)),
	.userspacesize = XT_ALIGN(sizeof(struct xt_tcpoptadd_target_info)),
	.help          = tcpoptadd_tg_help,
	.init          = tcpoptadd_tg_init,
	.parse         = tcpoptadd_tg_parse,
	.final_check   = tcpoptadd_tg_check,
	.print         = tcpoptadd_tg_print,
	.save          = tcpoptadd_tg_save,
	.extra_opts    = tcpoptadd_tg_opts,
};

static struct xtables_target tcpoptadd_tg6_reg = {
	.version       = XTABLES_VERSION,
	.name          = "TCPOPTADD",
	.family        = NFPROTO_IPV6,
	.size          = XT_ALIGN(sizeof(struct xt_tcpoptadd_target_info)),
	.userspacesize = XT_ALIGN(sizeof(struct xt_tcpoptadd_target_info)),
	.help          = tcpoptadd_tg_help,
	.init          = tcpoptadd_tg_init,
	.parse         = tcpoptadd_tg_parse,
	.final_check   = tcpoptadd_tg_check,
	.print         = tcpoptadd_tg_print,
	.save          = tcpoptadd_tg_save,
	.extra_opts    = tcpoptadd_tg_opts,
};

void _init(void)
{
	xtables_register_target(&tcpoptadd_tg_reg);
	xtables_register_target(&tcpoptadd_tg6_reg);
}
