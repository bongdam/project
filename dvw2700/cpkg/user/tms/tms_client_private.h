#ifndef __TMS_CLIENT_PRIVATE_H__
#define __TMS_CLIENT_PRIVATE_H__

#define MAX_DOWN_DATA	2048
#define MAX_TIMEO		10000
#define FORCE_SETUP_LETTER '#'
#define TMS_TX 1
#define TMS_RX 2

void initenv(struct tms_t *p);
void dump_fwinfo(char *where, struct tms_t *p);
void make_build_msg(struct tms_t *p);
void init_random_number(void);
int check_ntp_client(void);
int check_service_idle(struct tms_t *p);
int tms_setvar(struct variable_s *v, char *name, char *value, int group_idx);
int tms_nvram_setvar(struct variable_s *v, char *name, char *value, int group_idx);
int do_wget(struct fwstat *fbuf, char *fbuf_buf, int *exp, int timeo, struct tms_t *p, int req_type, int *psys_flag, int *status);
int letsgo_download_davo_config(struct tms_t *p);
int letsgo_need_download_firmware(struct tms_t *p);
int tms_check_cfg(struct variable_s *v, char *name, char *value, int group_idx);
int tms_cfg_setvar(struct variable_s *v, char *name, char *value, int group_idx);
void restart_web(void);
int check_dvflag(int flag);
#endif
