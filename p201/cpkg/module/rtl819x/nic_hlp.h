#ifndef __NIC_HLP_H
#define __NIC_HLP_H

extern void (*os_link_notifier)(void);

void setup_probe_link(void);
void del_probe_link(void);

void accumulate_stats22(int port);
void reset_stats22(int port);
u64 get_stats22(int port, int out, int token);

int mib_procfs_init(void);
void mib_procfs_exit(void);

#endif
