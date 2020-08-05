#ifndef __public_func_h
#define __public_func_h

int percent_encode(char *str, char *encoded, int encodedsz);
int get_diag_log(char *path, int http_encoding);
int get_diag_log_tr069(char *path, int http_encoding);
int port_reset(int port, char *config);

int CONV_TO_RSSI(int percent);
#define LGU_DEF_WEB_PASS    0
char *lgu_default_val(int type, char *s, int slen);

int get_mcast_join_count(void);

#endif
