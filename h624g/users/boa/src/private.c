#include "boa.h"
#ifdef SERVER_SSL
# include <openssl/ssl.h>
# include <openssl/err.h>
#endif

#include <stddef.h>		/* for offsetof */
#ifdef SUPPORT_ASP
# include "asp_page.h"
#endif

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "apform.h"
#include <furl.h>
#include <bcmnvram.h>
#include <syslog.h>

#define MB * 1024 * 1024

extern int isUpgrade_OK;
extern int isFWUPGRADE;
extern int Reboot_Wait;
extern int isCFG_ONLY;
extern int need_reboot;
extern int dv_reboot_system;

int lock_upload(void)
{
	return 0;
}

void unlock_upload(void)
{
}

static int parse_header(const char *str, size_t str_len,
			const char *var_name,
			char *buf, size_t buf_size)
{
	int ch = ' ', ch1 = ',', len = 0;
	size_t n = strlen(var_name);
	const char *p, *end = str + str_len, *s = NULL;

	if (buf != NULL && buf_size > 0)
		buf[0] = '\0';

	// Find where variable starts
	for (s = str; s != NULL && s + n < end; s++) {
		if ((s == str || s[-1] == ch || s[-1] == ch1) &&
		    s[n] == '=' && !memcmp(s, var_name, n))
			break;
	}

	if (s != NULL && &s[n + 1] < end) {
		s += n + 1;
		if (*s == '"' || *s == '\'')
			ch = ch1 = *s++;
		p = s;
		while (p < end && p[0] != ch && p[0] != ch1 && len < (int)buf_size) {
			if (ch == ch1 && p[0] == '\\' && p[1] == ch)
				p++;
			buf[len++] = *p++;
		}
		if (len >= (int)buf_size || (ch != ' ' && *p != ch)) {
			len = 0;
		} else {
			if (len > 0 && s[len - 1] == ',')
				len--;
			if (len > 0 && s[len - 1] == ';')
				len--;
			buf[len] = '\0';
		}
	}

	return len;
}

// Check whether full request is buffered. Return:
//   -1  if request is malformed
//    0  if request is not yet fully buffered
//   >0  actual request length, including last \r\n\r\n
static int get_request_len(const char *s, size_t buf_len)
{
	const unsigned char *buf = (unsigned char *)s;
	size_t i;

	for (i = 0; i < buf_len; i++) {
		// Control characters are not allowed but >=128 are.
		// Abort scan as soon as one malformed character is found.
		if (!isprint(buf[i]) && buf[i] != '\r' && buf[i] != '\n' && buf[i] < 128) {
			return -1;
		} else if (buf[i] == '\n' && i + 1 < buf_len && buf[i + 1] == '\n') {
			return i + 2;
		} else if (buf[i] == '\n' && i + 2 < buf_len && buf[i + 1] == '\r' &&
			   buf[i + 2] == '\n') {
			return i + 3;
		}
	}

	return 0;
}

static int get_line_len(const char *buf, int buf_len)
{
	int len = 0;
	while (len < buf_len && buf[len] != '\n')
		len++;
	return buf[len] == '\n' ? len + 1 : -1;
}

static int mg_parse_multipart(const char *buf, int buf_len,
			      char *var_name, int var_name_len,
			      char *file_name, int file_name_len,
			      const char **data, int *data_len)
{
	static const char cd[] = "Content-Disposition: ";
	//struct mg_connection c;
	int hl, bl, n, ll, pos, cdl = sizeof(cd) - 1;
	//char *p;

	if (buf == NULL || buf_len <= 0)
		return 0;
	if ((hl = get_request_len(buf, buf_len)) <= 0)
		return 0;
	if (buf[0] != '-' || buf[1] != '-' || buf[2] == '\n')
		return 0;

	// Get boundary length
	bl = get_line_len(buf, buf_len);

	// Loop through headers, fetch variable name and file name
	var_name[0] = file_name[0] = '\0';
	for (n = bl; (ll = get_line_len(buf + n, hl - n)) > 0; n += ll) {
		if (strncasecmp(cd, buf + n, cdl) == 0) {
			parse_header(buf + n + cdl, ll - (cdl + 2),
				"name", var_name, var_name_len);
			parse_header(buf + n + cdl, ll - (cdl + 2),
				"filename", file_name, file_name_len);
		}
	}

	// Scan body, search for terminating boundary
	for (pos = hl; pos + (bl - 2) < buf_len; pos++) {
		if (buf[pos] == '-' && !memcmp(buf, &buf[pos], bl - 2)) {
			if (data_len != NULL)
				*data_len = (pos - 2) - hl;
			if (data != NULL)
				*data = buf + hl;
			return pos;
		}
	}

	return 0;
}

#define safe_free(p)	do { \
				if ((p)) { \
					free((p)); \
					(p) = NULL; \
				} \
			} while (0)

#define FIRM_FILE   "/var/tmp/firm.bin"
#define URL_DELIM       " \r\n\t:"
int FW_Data_Size=0;
int isFWUpgrade=0;
unsigned char *FW_Data=NULL;
void formTftpUpload(request *wp, char *path, char *query)
{
	FILE *fp;
	char tmpBuf[200];
	char *r_server, *r_url, *r_file, *submitUrl;
	char cmd[256];
	char urlbuf[128];
	char name[32], filename[NAME_MAX];
	struct stat f_stat;
	struct fwstat *fbuf;
	int status, numWrite;
	struct in_addr ip;
	int pid;
	char *saveptr;

	r_url = req_get_cstream_var(wp, "server", "");
	r_file = req_get_cstream_var(wp, "file", "");

	if (r_url && r_url[0] != 0) {
		ydespaces(r_url);
		r_server = strtok_r(r_url, URL_DELIM, &saveptr);
	}

	if (!r_server || !r_server[0] || !r_file || !r_file[0]) {
		sprintf(tmpBuf, "<b>server: %s, file name: %s</b><br>",
			(r_server) ? r_server : "empty!", (r_file) ? r_file : "empty!");
		goto fail_upload;
	}

	if (!res_gethostbyname(r_server, &ip, 1)) {
		sprintf(tmpBuf, "<b> %s :invalid address</b><br>", r_server);
		goto fail_upload;
	}
	sprintf(cmd, "tftp -g -r %s -l %s %s", r_file, FIRM_FILE, inet_ntoa(ip));
	if (system(cmd) != 0) {
		sprintf(tmpBuf, "<p><b> 펌웨어 다운로드 실패!</b><br>");
		goto fail_upload;
	}

	if (access(FIRM_FILE, F_OK) != 0 || stat(FIRM_FILE, &f_stat) < 0) {
		sprintf(tmpBuf, "<p><b> 펌웨어 다운로드 실패-!</b><br>");
		goto fail_upload;
	}

	if (FW_Data == NULL) {
		if ((FW_Data = (unsigned char *)malloc(f_stat.st_size + sizeof(fbuf) + 4)) == NULL) {
			sprintf(tmpBuf, "<p><b> 펌웨어 다운로드 실패--!</b><br>");
			goto fail_upload;
		}
	}
	memset(FW_Data, 0, sizeof(FW_Data));
	if ((fp = fopen(FIRM_FILE, "rb")) == NULL)
		goto fail_upload;

	if ( (numWrite = fread(FW_Data, 1, f_stat.st_size, fp)) < f_stat.st_size ) {
		sprintf(tmpBuf, "<p><b> 펌웨어 다운로드 실패--!(W:%d, R:%d)</b><br>", f_stat.st_size, numWrite);
		goto fail_upload;
	}
	fclose(fp);
	unlink(FIRM_FILE);

	submitUrl = req_get_cstream_var(wp, "submit-url", "");

	//support multiple image
	fbuf = (struct fwstat *)&FW_Data[(numWrite + 3) & ~3];
	memset(fbuf, 0, sizeof(struct fwstat));
	fbuf->fmem = FW_Data;
	fbuf->caplen = 8 MB;
	fbuf->rcvlen = numWrite;
	status = fw_validate(fbuf);

	if (status) {
		sprintf(tmpBuf, "<b>%s!</b><br>", fw_strerror(status));
		goto fail_upload;
	} else {
		sprintf(tmpBuf, "펌웨어 업로드 성공!<br><br>단말 업그레이드 진행중.");
	}
	FW_Data_Size = numWrite;

	sprintf(tmpBuf, "<b>업데이트 성공!");
	Reboot_Wait = (FW_Data_Size / 43840) + 30;
	isFWUPGRADE = 1;
	isFWUpgrade = 1;
	isCFG_ONLY = 1;

	if (Reboot_Wait < 50)
		Reboot_Wait = 50;

#if defined(CONFIG_RTL8196_SPI)
	Reboot_Wait = Reboot_Wait + 40;
#endif

#ifdef REBOOT_CHECK
	sprintf(lastUrl, "%s", "/skb_status.htm");
	sprintf(okMsg, "%s", tmpBuf);
	countDownTime = Reboot_Wait;
	send_redirect_perm(wp, COUNTDOWN_PAGE);
#else
	OK_MSG_FW(tmpBuf, submitUrl, Reboot_Wait, lan_ip);
#endif

	return;

fail_upload:
	safe_free(FW_Data);
	if (isFileExist(FIRM_FILE))
		unlink(FIRM_FILE);
	Reboot_Wait = 0;
	ERR_MSG(tmpBuf);
}

void formUpload(request *wp, char *path, char *query)
{
	char msg[128];
	char name[32], filename[NAME_MAX];
	struct fwstat *fbuf;
	int status;
	int n;
#ifndef REBOOT_CHECK
	char ipstr[24];
	struct in_addr ip;
	char *submitUrl;

	submitUrl = req_get_cstream_var(wp, "submit-url", "");
	apmib_get(MIB_IP_ADDR,  (void *)&ip);
	sprintf(ipstr, "%s", inet_ntoa(ip));
#endif
	fbuf = (struct fwstat *)&wp->upload_data[(wp->upload_len + 3) & ~3];
	memset(fbuf, 0, sizeof(struct fwstat));
	fbuf->fmem = wp->upload_data;
	fbuf->caplen = 8 MB;
	fbuf->rcvlen = wp->upload_len;

	mg_parse_multipart(wp->upload_data, wp->upload_len,
			   name, sizeof(name),
			   filename, sizeof(filename),
			   (const char **)&fbuf->fmem,
			   (int *)&fbuf->rcvlen);

	status = fw_validate(fbuf);
	if (status) {
		sprintf(msg, "<b>%s!</b><br>", fw_strerror(status));
		Reboot_Wait = 0;
		ERR_MSG(msg);
		return;
	}

#ifdef __DAVO__
	n = sprintf(msg, "<br><br><b>업로드 성공!!</b><br><br>펌웨어 업그레이드 진행중...");
	sprintf(&msg[n], "<br><b><font color=\"red\" size=\"2\">(주의!) 단말의 전원및 인터넷(랜) 케이블 연결을 분리하지 마세요.</font></b><br>");
#else
	sprintf(msg, "Upload successfully! (filename=\"%s\"; size=%d)<br><br>Firmware update in progress.",
		filename, fbuf->rcvlen);
#endif

	isFWUPGRADE = 1;
	Reboot_Wait = 120;
	if ((fbuf->fincmask & FW_ALL_MASK) == (1 << FW_CONFIG)) {
		strcpy(msg, "<b>Update successfully!");
		Reboot_Wait = 10;
		isCFG_ONLY = 1;
	}
#ifdef REBOOT_CHECK
	sprintf(lastUrl, "%s", "/skb_status.htm");
	strcpy(okMsg, msg);
	countDownTime = Reboot_Wait;
	send_redirect_perm(wp, COUNTDOWN_PAGE);
#else
	OK_MSG_FW(msg, submitUrl, Reboot_Wait, ipstr);
#endif
}

void formUploadConfig(request *wp, char *path, char *query)
{
	char msg[80];
	sprintf(msg, "<b>Uploading Configuration Not Permitted.</b><br>");
	ERR_MSG(msg);
}

static int FirmwarePreWrite(struct fwblk *fb, void *arg, FW_WR * flags)
{
	switch (fb->sig_id) {
	case FW_ROOTFS:
		break;

	case FW_CONFIG:
		*flags = FW_WR_SKIP;
		break;
	}

	return 0;
}

int FirmwareUpgrade(char *upload_data, int upload_len, int is_root, char *unused)
{
	struct fwstat *fbuf;
	int status = -1;
	int major, minor, conf;

	(void)unused;
	fbuf = (struct fwstat *)&upload_data[(upload_len + 3) & ~3];
	fw_parse_bootline(&fbuf->blnfo);
	if (!(status = fw_dualize(fbuf)))
		status = fw_write(fbuf, FirmwarePreWrite, NULL);

	if (status) {
		fprintf(stderr, "furl: %s\n", fw_strerror(status));
		return 0;
	}

	major = (fbuf->version >> 14) & 3;
	minor = (fbuf->version >> 7) & 0x7f;
	conf = fbuf->version & 0x7f;
	LOG(LOG_INFO, "웹에서 버전 %d.%02d.%02d 펌웨어 업그레이드 수행됨", major, minor, conf);
#ifndef NO_ACTION
	isUpgrade_OK = 1;
	REBOOT_WAIT_COMMAND(2);
	while (1)
		;
#endif
	return 1;
}

#ifdef __DAVO__
void Default_init_status()
{
	char buffer[52], param[52];
	int i, var, j;
	int	entryNum;

	nvram_get_r_def("x_STATICMAP_TBL_NUM", buffer, sizeof(buffer), "0");
	var = atoi(buffer);
	for(i=0; i<var; i++) {
		sprintf(buffer, "x_STATICMAP_TBL%d", i);
		nvram_unset(buffer);
	}

	nvram_get_r_def("PORTFW_TBL_NUM", buffer, sizeof(buffer), "0");
	var = atoi(buffer);
	for(i=0; i<var; i++) {
		sprintf(buffer, "PORTFW_TBL%d", i+1);
		nvram_unset(buffer);
	}

	nvram_get_r_def("x_Q_R_NUM", buffer, sizeof(buffer), "8");
	var = atoi(buffer);
	for(i=0; i<var; i++) {
		sprintf(buffer, "x_Q_R_%d", i);
		nvram_unset(buffer);
	}

	apmib_get(MIB_DHCPRSVDIP_TBL_NUM, (void *)&entryNum);
	for(i=0; i<entryNum; i++) {
		sprintf(buffer, "DHCPRSVDIP_TBL%d", i+1);
		nvram_unset(buffer);
	}

	nvram_get_r_def("x_MACFILTER_TBL_NUM", buffer, sizeof(buffer), "0");
	var = atoi(buffer);
	for(i=0; i<var; i++) {
		sprintf(buffer, "x_MACFILTER_TBL%d", i+1);
		nvram_unset(buffer);
	}

	for (j = 0; j < 2; j++) {
		snprintf(param, sizeof(param), "WLAN%d_MACAC_NUM", j);
		nvram_get_r_def(param, buffer, sizeof(buffer), "0");
		var = atoi(buffer);
		for (i = 0; i < var; i++) {
			snprintf(buffer, sizeof(buffer), "WLAN%d_MACAC_ADDR%d", j, i + 1);
			nvram_unset(buffer);
		}

		snprintf(param, sizeof(param), "WLAN%d_VAP0_MACAC_NUM", j);
		nvram_get_r_def(param, buffer, sizeof(buffer), "0");
		var = atoi(buffer);
		for (i = 0; i < var; i++) {
			snprintf(buffer, sizeof(buffer), "WLAN%d_VAP0_MACAC_ADDR%d", j, i + 1);
			nvram_unset(buffer);
		}

		snprintf(param, sizeof(param), "WLAN%d_VAP1_MACAC_NUM", j);
		nvram_get_r_def(param, buffer, sizeof(buffer), "0");
		var = atoi(buffer);
		for (i = 0; i < var; i++) {
			snprintf(buffer, sizeof(buffer), "WLAN%d_VAP1_MACAC_ADDR%d", j, i + 1);
			nvram_unset(buffer);
		}

		snprintf(param, sizeof(param), "WLAN%d_VAP2_MACAC_NUM", j);
		nvram_get_r_def(param, buffer, sizeof(buffer), "0");
		var = atoi(buffer);
		for (i = 0; i < var; i++) {
			snprintf(buffer, sizeof(buffer), "WLAN%d_VAP2_MACAC_ADDR%d", j, i + 1);
			nvram_unset(buffer);
		}

		snprintf(param, sizeof(param), "WLAN%d_VAP3_MACAC_NUM", j);
		nvram_get_r_def(param, buffer, sizeof(buffer), "0");
		var = atoi(buffer);
		for (i = 0; i < var; i++) {
			snprintf(buffer, sizeof(buffer), "WLAN%d_VAP3_MACAC_ADDR%d", j, i + 1);
			nvram_unset(buffer);
		}
	}

	nvram_get_r_def("sta_protection_num", buffer, sizeof(buffer), "0");
	var = atoi(buffer);
	for (i = 0; i < var; i++) {
		sprintf(buffer, "sta_protection_list%d", i + 1);
		nvram_unset(buffer);
	}
	nvram_unset("sta_protection_num");

	nvram_unset("continue_traffic_report");
	nvram_unset("continue_traffic_interval");

	yexecl(NULL, "/bin/mirror clear");
}
#endif

void formSaveConfig(request *wp, char *path, char *query)
{
	char tmpBuf[200];
	char *p;
	struct in_addr ip;
	char ipbuf[30];

	p = req_get_cstream_var(wp, ("save-cs"), "");
	if (!p[0]) {
		p = req_get_cstream_var(wp, ("save"), "");
		if (!p[0]) {
			p = req_get_cstream_var(wp, ("save-hs"), "");
			if (!p[0]) {
				p = req_get_cstream_var(wp, ("save-ds"), "");
				if (!p[0])
					p = req_get_cstream_var(wp, ("save-all"), "");
			}
		}
	}

	if (p[0]) {
		send_redirect_perm(wp, "/config.dat");
		return;
	}

	p = req_get_cstream_var(wp, ("reset_val"), "");
	if (!strcmp(p, "Reset")) {
		LOG(LOG_INFO, "공장 기본값으로 초기화를 수행함");
		Default_init_status();
#ifdef RTL_DEF_SETTING_IN_FW
		system("flash reset");
#else
		apmib_updateDef();
#endif
#ifdef CONFIG_RTL_802_1X_CLIENT_SUPPORT
		//To clear 802.1x certs
		//RunSystemCmd(NULL_FILE, "rsCert","-rst", NULL_STR);
		system("rsCert -rst");
#endif
#ifdef CONFIG_RTL_WAPI_SUPPORT
		//To clear CA files
		system("storeWapiFiles -reset");
#endif
		Reboot_Wait = 40;
#ifdef HOME_GATEWAY
		sprintf(tmpBuf, "%s", "<br><br><b>초기화 설정 성공!<br>");
#else
		sprintf(tmpBuf, "%s", "Reload setting successfully!<br><br>The AP is booting.<br>");
#endif
#ifdef __DAVO__
		need_reboot = 1;
		REBOOT_WAIT("/skb_saveconf.htm");
		sleep(1);
		dv_reboot_system = 1;
		//isUpgrade_OK = 1;
	} else if (!strcmp(p, "Reboot")) {
		need_reboot = 1;
		REBOOT_WAIT("/skb_saveconf.htm");
		sleep(1);
		dv_reboot_system = 1;
		return;
	} else
		send_redirect_perm(wp, "/skb_saveconf.htm");
#endif
}
