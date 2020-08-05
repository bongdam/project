#ifndef __CONF_H_
#define __CONF_H_

extern int conf_opmode(void);
extern int conf_autoconf_method(void);
extern const char *conf_ifwan(void);
#define conf_sdmz_test() ({ 0; })

#endif
