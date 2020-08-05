#ifndef __bcmutils_h_
#define __bcmutils_h_

struct url_info {
	char domain[256];
	char port[8];
	char suburl[256];
};

#define hchk_pchk(arg...) do {} while (0)
int port_reset(int port, char *cfg);
int extract_info_from_url(char *url, struct url_info *info, unsigned short def_port);

#endif
