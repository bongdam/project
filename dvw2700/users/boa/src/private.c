#include "boa.h"
#ifdef SERVER_SSL
# include <openssl/ssl.h>
# include <openssl/err.h>
#endif

#include <stddef.h>		/* for offsetof */
#ifdef SUPPORT_ASP
# include "asp_page.h"
#endif

#include <signal.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "apform.h"
#include "utility.h"
#include "captcha.h"
#ifdef __CONFIG_LIB_FURL__
# include <furl.h>
#endif
#include <bcmnvram.h>
#include <syslog.h>
#include <libytool.h>
#include <glob.h>
#include <brdio.h>
#include <sys/ioctl.h>
#ifdef __CONFIG_APP_LABORER__
#include <nmpipe.h>
#endif
#include <custom.h>
#include <net/if.h>
#include "nvram_mib/nvram_mib.h"

#define MB * 1024 * 1024

#ifndef EJH_TABLE_BEGIN
#define EJH_TABLE_BEGIN(_label) \
__asm__( \
	".section \"" EJSECTNAM ".1\",\"a\"\n" \
	".globl " __xstring(EJH_LABEL_DEFN(_label)) "\n" \
	".type    " __xstring(EJH_LABEL_DEFN(_label)) ",object\n" \
	".p2align " __xstring(EJARC_P2ALIGNMENT) "\n" \
	__xstring(EJH_LABEL_DEFN(_label)) ":\n" \
	".previous\n" \
       )
#endif

extern struct ej_handler ej_handlers[];
extern struct ej_handler ej_handlers_end;
extern int need_reboot;
extern int dv_reboot_system;

EJH_TABLE_BEGIN(ej_handlers);

#ifndef EJH_TABLE_END
#define EJH_TABLE_END(_label) \
__asm__( \
	".section \"" EJSECTNAM ".3\",\"a\"\n" \
	".globl " __xstring(EJH_LABEL_DEFN(_label)) "\n" \
	".type    " __xstring(EJH_LABEL_DEFN(_label)) ",object\n" \
	".p2align " __xstring(EJARC_P2ALIGNMENT) "\n" \
	__xstring(EJH_LABEL_DEFN(_label)) ":\n" \
	".previous\n" \
       )
#endif

EJH_TABLE_END(ej_handlers_end);

static int cmpr(const struct ej_handler *m1, const struct ej_handler *m2)
{
	return strcmp(m1->pattern, m2->pattern);
}

struct ej_handler *ej_find_handler(char *func)
{
	struct ej_handler key = { .pattern = func };
	return bsearch(&key, ej_handlers,
	               (size_t)(&ej_handlers_end - ej_handlers),
	               sizeof(struct ej_handler), (void *)cmpr);
}

#ifndef EJX_TABLE_BEGIN
#define EJX_TABLE_BEGIN(_label) \
__asm__( \
	".section \"" EJXSECTNAM ".1\",\"a\"\n" \
	".globl " __xstring(EJH_LABEL_DEFN(_label)) "\n" \
	".type    " __xstring(EJH_LABEL_DEFN(_label)) ",object\n" \
	".p2align " __xstring(EJARC_P2ALIGNMENT) "\n" \
	__xstring(EJH_LABEL_DEFN(_label)) ":\n" \
	".previous\n" \
       )
#endif

extern struct ej_handler ej_indices[];
extern struct ej_handler ej_indices_end;

EJX_TABLE_BEGIN(ej_indices);

#ifndef EJX_TABLE_END
#define EJX_TABLE_END(_label) \
__asm__( \
	".section \"" EJXSECTNAM ".3\",\"a\"\n" \
	".globl " __xstring(EJH_LABEL_DEFN(_label)) "\n" \
	".type    " __xstring(EJH_LABEL_DEFN(_label)) ",object\n" \
	".p2align " __xstring(EJARC_P2ALIGNMENT) "\n" \
	__xstring(EJH_LABEL_DEFN(_label)) ":\n" \
	".previous\n" \
       )
#endif

EJX_TABLE_END(ej_indices_end);

struct ej_handler *ej_find_index(char *func)
{
	struct ej_handler key = { .pattern = func };
	return bsearch(&key, ej_indices,
	               (size_t)(&ej_indices_end - ej_indices),
	               sizeof(struct ej_handler), (void *)cmpr);
}

void formUploadConfig(request *wp, char *path, char *query)
{
}

void formPortMirror(request *wp, char *path, char *query)
{
	char *submitUrl;
	int from, to;
	char *strVal;
	int is_on;

	if (wp->superUser != 1)
		return;

	strVal = req_get_cstream_var(wp, "save", (""));
	if (strVal[0]) {
		strVal = req_get_cstream_var(wp, "portMirrorMode", ("OFF"));
		is_on = (strcmp(strVal, "ON") == 0) ? 1 : 0;

		strVal = req_get_cstream_var(wp, "port_from", (""));
		from = atoi(strVal);

		strVal = req_get_cstream_var(wp, "port_to", (""));
		to = atoi(strVal);

		if (is_on)
			yexecl(NULL, "/bin/mirror set %d %d", from, to);
		else
			yexecl(NULL, "/bin/mirror clear");
	}

	submitUrl = req_get_cstream_var(wp, ("submit-url"), ("")); // hidden page
	if (submitUrl[0])
		send_redirect_perm(wp, submitUrl);

	return;
}

void formSNMP(request *wp, char *path, char *query)
{
	char *submitUrl, *tmpStr;
	int enabled = 0;

#if 0
	if (wp->superUser == 0)
		return;
#endif
	submitUrl = req_get_cstream_var(wp, ("submit-url"), ("/snmp.htm"));   // hidden page

	tmpStr = req_get_cstream_var(wp, ("snmpEnable"), (""));
	if (!strcmp(tmpStr, "ON"))
		enabled = 1;
	else
		enabled = 0;

	if (enabled) {
		nvram_set("snmp_enable", "1");
		if ((tmpStr = req_get_cstream_var(wp, ("getCommunity"), ("CJHV-ap-Read"))) && strcmp("******", tmpStr))
			nvram_set("snmp_get_community", tmpStr);

		if ((tmpStr = req_get_cstream_var(wp, ("setCommunity"), ("CJHV-ap-Write"))) && strcmp("******", tmpStr))
			nvram_set("snmp_set_community", tmpStr);

		if ((tmpStr = req_get_cstream_var(wp, ("DummyTTL"), "")))
			nvram_set("dummy_ttl", tmpStr);

		if ((tmpStr = req_get_cstream_var(wp, ("NormalTTL"), "")))
			nvram_set("normal_ttl", tmpStr);

		tmpStr = req_get_cstream_var(wp, ("snmpTrapEnable"), (""));
		if (tmpStr[0] && !strcasecmp(tmpStr, "ON")) {
			nvram_set("snmp_trap_enable", "1");
			if ((tmpStr = req_get_cstream_var(wp, ("trapCommunity"), ("iptvshrw^_"))) && strcmp("******", tmpStr))
				nvram_set("snmp_trp_community", tmpStr);
			if ((tmpStr = req_get_cstream_var(wp, ("trapServer"), ("iptvsh-trap.skbroadband.com"))) && strcmp("******", tmpStr))
				nvram_set("snmp_trap_server", tmpStr);
			if ((tmpStr = req_get_cstream_var(wp, ("trapServer2"), ("iptvap-trap.skbroadband.com"))) && strcmp("******", tmpStr))
				nvram_set("snmp_trap_server2", tmpStr);
		} else
			nvram_set("snmp_trap_enable", "0");
	} else
		nvram_set("snmp_enable", "0");

	OK_MSG(submitUrl);

	return;
}

#ifdef __CONFIG_LIB_FURL__
extern int isUpgrade_OK;
extern int isFWUPGRADE;
extern int Reboot_Wait;
extern int isCFG_ONLY;

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

#define FIRM_FILE "/var/tmp/firm.bin"
#define URL_DELIM " \r\n\t:"
int FW_Data_Size;
int isFWUpgrade;
unsigned char *FW_Data;

#if !defined(__DAVO__)
void formTftpUpload(request *wp, char *path, char *query)
{
	FILE *fp;
	char tmpBuf[200];
	char *r_server =  NULL, *r_url, *r_file, *submitUrl;
	char buf[256];
	struct stat f_stat;
	struct fwstat *fbuf;
	int status, numWrite;
	char *saveptr;
	struct addrinfo *rp, hints;

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
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_INET;
	status = getaddrinfo(r_server, NULL, &hints, &rp);
	if (status != 0 || (rp == NULL)) {
		sprintf(tmpBuf, "<b> %s: %s</b><br>", r_server, status ? gai_strerror(status) : "Can't resolve address");
		goto fail_upload;
	}
	inet_ntop(rp->ai_family, ((struct sockaddr_in *)rp->ai_addr)->sin_addr.s_addr,
	          buf, sizeof(buf));
	freeaddrinfo(rp);

	sprintf(buf, "tftp -g -r %s -l %s %s", r_file, FIRM_FILE, buf);
	if (system(buf) != 0) {
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

	if ((numWrite = fread(FW_Data, 1, f_stat.st_size, fp)) < f_stat.st_size) {
		sprintf(tmpBuf, "<p><b> 펌웨어 다운로드 실패--!(W:%ld, R:%d)</b><br>", f_stat.st_size, numWrite);
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
	sprintf(lastUrl, "%s", "/status.htm");
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
#endif

void formFtpUpload(request *wp, char *path, char *query)
{
	FILE *fp;
	char tmpBuf[200];
	char *r_server = NULL, *r_url, *r_port = NULL, *r_file, *r_id, *r_passwd, *submitUrl;
	char buf[256];
	char ip[16];
	char passopt[32];
	struct stat f_stat;
	struct fwstat *fbuf;
	int status, numWrite;
	char *saveptr;
	struct addrinfo *rp, hints;
	struct sockaddr_in *sin;

	r_url = req_get_cstream_var(wp, ("ftp_server"), "");
	r_file = req_get_cstream_var(wp, ("ftp_file"), "");
	r_id = req_get_cstream_var(wp, ("ftp_id"), "");
	r_passwd = req_get_cstream_var(wp, ("ftp_passwd"), "");

	if (r_url && r_url[0] != 0) {
		ydespaces(r_url);
		nvram_set("ftp_server", r_url);

		r_server = strtok_r(r_url, URL_DELIM, &saveptr);
		r_port = strtok_r(NULL, URL_DELIM, &saveptr);
	}

	if (r_file && r_file[0] != 0)
		nvram_set("ftp_file", r_file);

	if (r_id && r_id[0] != 0)
		nvram_set("ftp_id", r_id);

	if (r_passwd) {
		nvram_set("ftp_passwd", r_passwd);
		snprintf(passopt, sizeof(passopt), "%s", (r_passwd[0]) ? r_passwd : "\"\"");
	}

	if (!r_server || !r_server[0] || !r_file || !r_file[0] || !r_id || !r_id[0]) {
		snprintf(tmpBuf, sizeof(tmpBuf), "<b>server: %s, file name: %s,id: %s, passwd: %s</b><br>",
		         (r_server) ? r_server : "empty!",
		         (r_file) ? r_file : "empty!", (r_id) ? "ok" : "empty!", (r_passwd) ? "ok" : "empty!");
		goto fail_upload;
	}

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_INET;
	status = getaddrinfo(r_server, NULL, &hints, &rp);
	if (status != 0 || (rp == NULL)) {
		sprintf(tmpBuf, "<b> %s: %s</b><br>", r_server, status ? gai_strerror(status) : "Can't resolve address");
		goto fail_upload;
	}
	sin = (void *)rp->ai_addr;
	inet_ntop(rp->ai_family, &sin->sin_addr, ip, sizeof(ip));
	freeaddrinfo(rp);

	snprintf(buf, sizeof(buf), "wget -O %s ftp://%s:%s@%s:%d/%s", FIRM_FILE, r_id,
	         passopt, ip, r_port == NULL ? 21 : atoi(r_port), r_file);

	if (system(buf) != 0) {
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

	if ((numWrite = fread(FW_Data, 1, f_stat.st_size, fp)) < f_stat.st_size) {
		sprintf(tmpBuf, "<p><b> 펌웨어 다운로드 실패--!(W:%ld, R:%d)</b><br>", f_stat.st_size, numWrite);
		goto fail_upload;
	}
	fclose(fp);
	unlink(FIRM_FILE);

	submitUrl = req_get_cstream_var(wp, "submit-url", "");

	//support multiple image
	fbuf = (struct fwstat *)&FW_Data[(numWrite + 3) & ~3];
	memset(fbuf, 0, sizeof(struct fwstat));
	fbuf->fmem = (char *)FW_Data;
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
	sprintf(lastUrl, "%s", "/status.htm");
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
	int autoup_upgrade = 0;
#ifndef REBOOT_CHECK
	char ipstr[24];
	struct in_addr ip;
	char *submitUrl;

	submitUrl = req_get_cstream_var(wp, "submit-url", "");
	apmib_get(MIB_IP_ADDR, (void *)&ip);
	sprintf(ipstr, "%s", inet_ntoa(ip));
#endif
	if (yfcat("/tmp/autoup_upgrade", "%d", &autoup_upgrade)) {
		if (autoup_upgrade > 0) {
			n = sprintf(msg, "<br><br><b>업로드 실패!!");
			sprintf(&msg[n], "<br><font color=\"red\" size=\"2\">(알람!)자동업그레이드를 통해 펌웨어가 이미 업로드 된 상태입니다.</font>");
			Reboot_Wait = 0;
			ERR_MSG(msg);
			return;
		}
	}

	fbuf = (struct fwstat *)&wp->upload_data[(wp->upload_len + 3) & ~3];
	memset(fbuf, 0, sizeof(struct fwstat));
	fbuf->fmem = (char *)wp->upload_data;
	fbuf->caplen = 8 MB;
	fbuf->rcvlen = wp->upload_len;

	mg_parse_multipart((char *)wp->upload_data, wp->upload_len,
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

	n = sprintf(msg, "<br><br><b>업로드 성공!!</b><br><br>펌웨어 업그레이드 진행중...");
	sprintf(&msg[n], "<br><b><font color=\"red\" size=\"2\">(주의!) 단말의 전원및 인터넷(랜) 케이블 연결을 분리하지 마세요.</font></b><br>");

	isFWUPGRADE = 1;
	Reboot_Wait = 120;
	if ((fbuf->fincmask & FW_ALL_MASK) == (1 << FW_CONFIG)) {
		strcpy(msg, "<b>Update successfully!");
		Reboot_Wait = 10;
		isCFG_ONLY = 1;
	}
#ifdef REBOOT_CHECK
	sprintf(lastUrl, "%s", "/status.htm");
	strcpy(okMsg, msg);
	countDownTime = Reboot_Wait;
	send_redirect_perm(wp, COUNTDOWN_PAGE);
#else
	OK_MSG_FW(msg, submitUrl, Reboot_Wait, ipstr);
#endif
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
#ifndef NO_ACTION
	isUpgrade_OK = 1;
	REBOOT_WAIT_COMMAND(2);
	while (1)
		;
#endif
	return 1;
}
#endif /* __CONFIG_LIB_FURL__ */

void formSaveConfig(request *wp, char *path, char *query)
{
	char *p;

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
		yexecl(NULL, "flash reset /bin/preclean");
		sleep(1);
		FACTORY_WAIT("Reset");
		dv_reboot_system = 1;
	} else if (!strcmp(p, "Reboot")) {
		FACTORY_WAIT("Reboot");
		dv_reboot_system = 1;
		return;
	} else {
		send_redirect_perm(wp, "saveconf.htm");
	}
}

#define TMS_PID_FILE "/var/run/tms.pid"
void formautoupgrade(request *wp, char *path, char *query)
{
	char *p;
	char *sp;
	char *strUrl;
	char *pSubUrl;
#if 0
	int pid;
#endif
	char buf[16];
	int changed = 0;

#if 0
	if (wp->superUser == 0)
		return;
#endif

	if (!(strUrl = req_get_cstream_var(wp, ("server_url"), "")) || !strUrl[0])
		goto setErr;

	if (strUrl) {
		nvram_get_r("prov_ip", buf, sizeof(buf));

		if (strcmp(buf, strUrl)) {
			p = strUrl;
			if ((p = strtok_r(p, " \r\n\t:", &sp)))
				nvram_set("prov_ip", p);

			if ((p = strtok_r(NULL, " \r\n\t:", &sp)))
				nvram_set("prov_port", p);
			changed = 1;
		}
	}
	if ((pSubUrl = req_get_cstream_var(wp, ("submit-url"), ("/apms_upgrade.htm"))))
		send_redirect_perm(wp, pSubUrl);

	if (changed) {
#if 0
		if ((pid = getPid(TMS_PID_FILE)) >  0)
			kill(pid, SIGTERM);
		system("tms &");
#endif
	}

	return;
setErr:
	ERR_MSG("서버 Url 또는 데이터 파일명을 확인해주시기 바랍니다.");
}

int showAutoUpState(request *wp, int argc, char **argv)
{
	int nBytesSent = 0;

	nBytesSent += req_format_write(wp, ("<tr>" \
	                                    "	<td width=\"50%%\">진행상태:</td>" \
	                                    "   <td width=\"50%%\"><font color='blue'><b>%s</b></font></td>" \
	                                    "   </tr>\n"), showApmsState());

	return nBytesSent;
}

unsigned int switch_port_status(int portno)
{
	struct phreq phr;
	int fd;

	if (portno < PH_MINPORT || portno > PH_MAXPORT)
		return 0;

	memset(&phr, 0, sizeof(phr));
	fd = open("/proc/brdio", O_RDWR);
	if (fd < 0)
		return 0;
	phr.phr_port = portno;
	if (ioctl(fd, PHGIO, &phr))
		perror("PHGIO");
	close(fd);
	return phr.phr_optmask;
}

static int ej_nvram_get(request *wp, int argc, char **argv, void *data)
{
	char *p = nvram_get(argv[0]);
	char translate_code[500];

	if (p) {
		snprintf(translate_code, sizeof(translate_code), "%s", p);
		translate_control_code(translate_code);
	}

	return req_format_write(wp, "%s", p ? translate_code : ((data) ? : ""));
}

/* 0:wan, 1:LAN1, 2:LAN2 3:LAN3 4:LAN4 */
int g_port_info[PRTNR_MAX] = {PRTNR_WAN0, PRTNR_LAN1, PRTNR_LAN2, PRTNR_LAN3, PRTNR_LAN4};

static int ej_link_status(request *wp, int argc, char **argv, void *unused)
{
	char var[32], *p;
	unsigned int phy_status;
	int mask = 0, portno;

	if (!strncmp(argv[0], "wan", 3))
		portno = PRTNR_WAN0;
	else if (!strncmp(argv[0], "lan1", 4))
		portno = PRTNR_LAN1;
	else if (!strncmp(argv[0], "lan2", 4))
		portno = PRTNR_LAN2;
	else if (!strncmp(argv[0], "lan3", 4))
		portno = PRTNR_LAN3;
	else
		portno = PRTNR_LAN4;

	phy_status = switch_port_status(portno);
	snprintf(var, sizeof(var), "x_port_%d_config", portno);
	p = nvram_get(var) ? : "up_auto_-rxpause_-txpause";

	if ((phy_status & PHF_LINKUP))
		mask |= 1;
	if ((phy_status & PHF_100M))
		mask |= 2;
	else if ((phy_status & PHF_500M))
		mask |= 4;
	else if ((phy_status & PHF_1000M))
		mask |= 6;
	if ((phy_status & PHF_FDX))
		mask |= 8;

	mask |= 0x20;
	mask |= 0x10;
	if (strstr(p, "down"))
		mask &= ~0x10;
	if (strstr(p, "half"))
		mask |= 0x40;
	if (strstr(p, "1000")) {
		mask |= 0x100;
	} else if (!strstr(p, "100"))
		mask |= 0x80;
	if (strstr(p, "auto"))
		mask &= ~0x20;

	return req_format_write(wp, "%d", (strstr(argv[0], "linkUp")) ? (mask & 1) : mask);
}
EJH_ENTRY(wan_link_status, ej_link_status);
EJH_ENTRY(lan1_link_status, ej_link_status);
EJH_ENTRY(lan2_link_status, ej_link_status);
EJH_ENTRY(lan3_link_status, ej_link_status);
EJH_ENTRY(lan4_link_status, ej_link_status);
EJH_ENTRY(wan_linkUp, ej_link_status);
EJH_ENTRY(lan1_linkUp, ej_link_status);
EJH_ENTRY(lan2_linkUp, ej_link_status);
EJH_ENTRY(lan3_linkUp, ej_link_status);
EJH_ENTRY(lan4_linkUp, ej_link_status);

EJH_ENTRY(HW_SERIAL_NO, ej_nvram_get);
EJH_ENTRY(ntp_server_ip1, ej_nvram_get);
EJH_ENTRY(ntp_server_ip2, ej_nvram_get);
EJH_ENTRY(ftp_server, ej_nvram_get);
EJH_ENTRY(ftp_file, ej_nvram_get);
EJH_ENTRY(ftp_id, ej_nvram_get);
EJH_ENTRY(ftp_passwd, ej_nvram_get);
EJH_ENTRY(dummy_ttl, ej_nvram_get);
EJH_ENTRY(normal_ttl, ej_nvram_get);

#ifdef __CONFIG_APP_LABORER__
static int ej_cpuusage(request *wp, int argc, char **argv, void *unused)
{
	char buf[32];
	double idle = 100;
	struct nmpipe *np;

	np = prequest("cpu_stat");
	if (np) {
		if (presponse(np, buf, sizeof(buf)) > 0)
			sscanf(buf, "%lf", &idle);
		prelease(np);
	}
	return req_format_write(wp, "%ld", (long)(100.00 - idle));
}
EJH_ENTRY(cpu_usage, ej_cpuusage);
#endif

static int ej_memusage(request *wp, int argc, char **argv, void *unused)
{
	FILE *f;
	char buf[64];
	long i, kilos[4];

	f = fopen("/proc/meminfo", "r");
	if (f == NULL)
		return -1;
	for (i = 0; fgets(buf, sizeof(buf), f) && i < 4;) {
		if (sscanf(buf, "MemTotal: %ld", kilos + 0) > 0 ||
		    sscanf(buf, "MemFree: %ld", kilos + 1) > 0 ||
		    sscanf(buf, "Buffers: %ld", kilos + 2) > 0 ||
		    sscanf(buf, "Cached: %ld", kilos + 3) > 0)
			i += 1;
	}
	fclose(f);

	if (kilos[0] == 0)
		return 0;
	return req_format_write(wp, "%ld",
	                        100L - (((kilos[1] + kilos[2] + kilos[3]) * 100) / kilos[0]));
}
EJH_ENTRY(ram_usage, ej_memusage);

static int ej_wlan_max_conn(request *wp, int argc, char **argv, void *data)
{
	char name[20]; // wlan0_vap3_max_conn
	char val[4];
	int vidx = 0;

	if (argc > 1) {
		vidx = strtoul(argv[1], NULL, 10);
		snprintf(name, sizeof(name), "wlan%d_vap%d_max_conn", wlan_idx, vidx);
	} else
		snprintf(name, sizeof(name), "wlan%d_max_conn", wlan_idx);

	nvram_get_r_def(name, val, sizeof(val), "10");
	return req_format_write(wp, "%s", val);
}
EJH_ENTRY(wlan_max_conn, ej_wlan_max_conn);

static int ej_apms_server(request *wp, int argc, char **argv, void *data)
{
	char apms_ip[16], apms_port[8];

	nvram_get_r("prov_ip", apms_ip, sizeof(apms_ip));
	nvram_get_r("prov_port", apms_port, sizeof(apms_port));

	return req_format_write(wp, "%s:%s", apms_ip, apms_port);
}
EJH_ENTRY(apms_server, ej_apms_server);

static int ej_isAdmin(request *wp, int argc, char **argv, void *data)
{
	int common_user = 0;

	if (wp->superUser == 1)
		common_user = 0;
	else
		common_user = 1;

	return req_format_write(wp, "%d", common_user);
}
EJX_ENTRY(isAdmin, ej_isAdmin);

static int ej_dv_port_mirror(request *wp, int argc, char **argv, void *data)
{
	FILE *pp = NULL;
	char buf[8];

	pp = popen("/bin/mirror print", "r");
	if (pp) {
		fgets(buf, sizeof(buf), pp);
		pclose(pp);

		return req_format_write(wp, buf);
	}

	return req_format_write(wp, "0,0,0");
}
EJH_ENTRY(dv_port_mirror, ej_dv_port_mirror);
EJX_ENTRY(snmp_enable, ej_nvram_get);
EJX_ENTRY(snmp_trap_enable, ej_nvram_get);


#ifdef __DAVO__
static int ej_account_get(request *wp, int argc, char **argv, void *data)
{
	char account[32];

	if (wp->superUser == 1) {	/* SuperUser account */
		nvram_get_r_def("touch_superUser", account, sizeof(account), "cjroot");
	} else {					/* User account */
		nvram_get_r_def("touch_User", account, sizeof(account), "cjadmin");
	}

	return req_format_write(wp, "%s", account);
}

EJH_ENTRY_DATA(dhcpc_discover_retry, ej_nvram_get, "0");
EJH_ENTRY_DATA(dhcpc_decline_time, ej_nvram_get, "10");
EJH_ENTRY_DATA(dhcpc_watching_time, ej_nvram_get, "60");
EJH_ENTRY_DATA(dhcpc_watching_probe, ej_nvram_get, "1");
EJH_ENTRY_DATA(telnet_enable, ej_nvram_get, "0");
EJH_ENTRY_DATA(mac_clone_enable, ej_nvram_get, "0");
EJH_ENTRY(ping_test_result, ej_nvram_get);
EJH_ENTRY(account_info, ej_account_get);

static int ej_local_connection(request *wp, int argc, char **argv, void *data)
{
	unsigned long lanip = 0, lanmask = 0, peer_ip = 0;
	int local_connect = 0;
	unsigned long WanIP_long = 0;
	char wan_ip[32];

	apmib_get(MIB_IP_ADDR, (void *)&lanip);
	apmib_get(MIB_SUBNET_MASK, (void *)&lanmask);
	//check local_connect
	if (inet_aton(wp->remote_ip_addr, (struct in_addr *)&peer_ip)) {
		if ((lanip & lanmask) == (peer_ip & lanmask)) {
			local_connect = 1;
		} else if (sdmz_enable()) {
			if (get_ipaddr_file("/var/wan_ip", &WanIP_long, wan_ip) == 0) {
				WanIP_long = 0;
			}
			if (WanIP_long == peer_ip) {
				local_connect = 1;
			}
		}
	}
	return req_format_write(wp, "%d", local_connect);
}
EJH_ENTRY(local_connection, ej_local_connection);

static int ej_login_hwaddr(request *wp, int argc, char **argv, void *data)
{
	char login_mac[64];
	char buffer[32];

	apmib_get(MIB_HW_NIC1_ADDR, (void *)buffer);

	snprintf(login_mac, sizeof(login_mac), "%02X%02X%02X%02X<font color='red'><b>%02X%02X</b></font>",
	         (unsigned char)buffer[0], (unsigned char)buffer[1], (unsigned char)buffer[2], (unsigned char)buffer[3], (unsigned char)buffer[4], (unsigned char)buffer[5]);

	return req_format_write(wp, "%s", login_mac);
}
EJH_ENTRY(login_hwaddr, ej_login_hwaddr);

static int ej_wan_dns(request *wp, int argc, char **argv, void *data)
{
	unsigned int dns1, dns2;
	int dns_mode;

	dns1 = dns2 = 0;

	if (!apmib_get(MIB_DNS_MODE, (void *)&dns_mode))
		return -1;

	if (dns_mode == 1) {
		/*inet_aton("180.182.54.1", (struct in_addr *)dns1);*/
		apmib_get(MIB_DNS1, &dns1);
		apmib_get(MIB_DNS2, &dns2);
	} else {
		FILE *fp;
		char *option = "nameserver";
		int len = strlen(option);
		char buf[128], *p;
		int  ii = 0;

		fp = fopen("/etc/resolv.conf", "r");
		if (!fp)
			return req_format_write(wp, "0.0.0.0");

		while (fgets(buf, sizeof(buf), fp) != NULL && ii < 2) {
			if (strncmp(buf, option, len) || !isspace((unsigned char)buf[len]))
				continue;
			p = &buf[len];
			while (isspace((unsigned char)*p))
				p++;
			if (ii == 0)
				dns1 = inet_addr(p);
			else if (ii == 1)
				dns2 = inet_addr(p);
			ii++;
		}
		fclose(fp);
	}

	req_format_write(wp, "%s / ", inet_ntoa(to_in_addr((u_char *)&dns1)));
	return req_format_write(wp, "%s", inet_ntoa(to_in_addr((u_char *)&dns2)));
}
EJH_ENTRY(wan_dns, ej_wan_dns);

static int ej_login_page_ssid(request *wp, int argc, char **argv, void *data)
{
	char buffer[64];

	if (argc < 2)
		return -1;

	if (strcmp(argv[1], "24g") == 0) {
		nvram_get_r_def("WLAN1_SSID",  buffer, sizeof(buffer), "");
	} else if (strcmp(argv[1], "5g") == 0) {
		nvram_get_r_def("WLAN0_SSID",  buffer, sizeof(buffer), "");
	} else {
		return -1;
	}

	translate_control_code(buffer);
	return req_format_write(wp, "%s", buffer);
}
EJH_ENTRY(login_page_ssid, ej_login_page_ssid);

static int ej_get_bandwidth(request *wp, int argc, char **argv, void *data)
{
	int bandwidth;

	bandwidth = autochan_get_bandwidth();

	return req_format_write(wp, "%d", bandwidth);
}
EJX_ENTRY(get_bandwidth, ej_get_bandwidth);

static void gen_captcha_name(char *captcha)
{
	int i;
	char capt_str[8];
	static int rand_seed_gen = 0;
	int len = CAPTCHA_STR_POOL_LEN;

	if (!rand_seed_gen) {
		int fd;
		fd = open("/dev/urandom", O_RDONLY);
		if (fd >= 0) {
			read(fd, (unsigned char *)&i, 4);
			close(fd);
		} else {
			i = (time_t)time(NULL);
		}
		srand((unsigned int)i);
		rand_seed_gen = 1;
	}

	for (i = 0; i < 7; i ++) {
		capt_str[i] = CAPTCHA_STR_POOL[(rand() % len)];
	}
	capt_str[i] = 0;

	strncpy(captcha, capt_str, CAPTCHA_STR_LEN - 1);
	captcha[CAPTCHA_STR_LEN - 1] = 0;
}

static int unlink_slow(const char *pattern, int ceiling)
{
	glob_t gb;
	struct stat sb;
	time_t current;
	unsigned long elapsed;
	int i, left;

	if (glob(pattern, GLOB_NOSORT, NULL, &gb))
		return -1;
	time(&current);
	left = gb.gl_pathc;
	for (i = 0; i < gb.gl_pathc; i++) {
		if (!stat(gb.gl_pathv[i], &sb)) {
			elapsed = (unsigned long)(current - sb.st_atime);
			if (elapsed < 3UL)
				continue;
		}
		unlink(gb.gl_pathv[i]);
		/* hack for marking deletion */
		gb.gl_pathv[i][0] = '\0';
		left--;
	}

	for (i = 0; (left > ceiling) && (i < gb.gl_pathc); i++) {
		if (gb.gl_pathv[i][0]) {
			/* force deletion */
			unlink(gb.gl_pathv[i]);
			left--;
		}
	}
	globfree(&gb);
	return left;
}

int captcha_img(request *wp, int argc, char **argv)
{
	int	nBytesSent = 0;
	char hash_captcha[80];
	char captcha_str[6];
	char captcha_fname[128];
	int ret = 0;

	unlink_slow("/tmp/img/*", 3);

	gen_captcha_name(captcha_str);
	hash_sha256_captcha((unsigned char *)captcha_str, (unsigned char *)hash_captcha);

	mkdir("/tmp/img", 0755);
	snprintf(captcha_fname, sizeof(captcha_fname), "/tmp/img/%s.gif", hash_captcha);

	ret = gencaptcha(captcha_str, captcha_fname);

	if (ret != 0)
		return -1;

	snprintf(captcha_fname, sizeof(captcha_fname), "img/%s.gif", hash_captcha);
	nBytesSent += req_format_write(wp, ("%s"), captcha_fname);

	return nBytesSent;
}

void formDiagnostic_ping(request *wp, char *path, char *query)
{
	char *input_ip;
	char result[64];

	input_ip = req_get_cstream_var(wp, "input_ip", "");

	if (input_ip[0]) {
		if (send_ping_test(input_ip) == 1) {
			snprintf(result, sizeof(result), "%s success ", input_ip);
		} else {
			snprintf(result, sizeof(result), "%s lose ", input_ip);
		}
	} else {
		snprintf(result, sizeof(result), "error");
	}

	nvram_set("ping_test_result", result);
	nvram_commit();

	send_redirect_perm(wp, "diagnostic_ping.htm");
}

static int ej_get_wlan_traffic(request *wp, int argc, char **argv, void *data)
{
	FILE *f;
	char buf[80], *args[4];
	char *p = "0";
	unsigned long long bytes = 0;
	char tmp[80];


	if (argc != 3) {
		return 0;
	}

	snprintf(buf, sizeof(buf), "/proc/%s/stats", argv[1] ? : "");
	f = fopen(buf, "r");
	if (f != NULL) {
		while (fgets(buf, sizeof(buf), f)) {
			snprintf(tmp, 80, "%s", buf);
			if (ystrargs(buf, args, _countof(args), ":", 0) &&
			    strcmp(args[0], argv[2]) == 0) {
				p = args[1] ? : "0";
				bytes = strtoull(p, NULL, 10);
				break;
			}
		}
		fclose(f);
	}
	return req_format_write(wp, "%u, %u", (unsigned int)(bytes >> 32), (unsigned int)(bytes));

}
EJH_ENTRY(get_wlan_traffic, ej_get_wlan_traffic);

static void formPhyConfig(request *wp, int portid)
{
	char buf[32], cmd[64];
	int n = 0, len, up, nego, duplex, speed;
	char *p = NULL;

	len = sizeof(cmd);

	snprintf(buf, sizeof(buf), "power%d", portid);
	p = req_get_cstream_var(wp, buf, "0");
	up = strtol(p, NULL, 10);

	snprintf(buf, sizeof(buf), "nego%d", portid);
	p = req_get_cstream_var(wp, buf, "1");
	nego = strtol(p, NULL, 10);

	up = !up;
	if (!nego) {
		snprintf(buf, sizeof(buf), "speed%d", portid);
		p = req_get_cstream_var(wp, buf, "1");
		speed = strtol(p, NULL, 10);

		snprintf(buf, sizeof(buf), "duplex%d", portid);
		p = req_get_cstream_var(wp, buf, "0");
		duplex = strtol(p, NULL, 10);
	} else {
		duplex = 0;
		speed = 0;
	}
	//up_auto_-rxpause_txpause
	//down_duplex_half_speed_100_-rxpause_txpause
	//up_duplex_full_speed_10_-rxpause_txpause
	snprintf(buf, sizeof(buf), "x_port_%d_config", portid);
	n += snprintf(&cmd[n], len - n, "%s_", (up) ? "up" : "down");
	if (nego) {
		n += snprintf(&cmd[n], len - n, "auto_");
	} else {
		n += snprintf(&cmd[n], len - n, "duplex_%s_speed_%s_", (duplex) ? "full" : "half", (speed) ? "100" : "10");
	}

	n += snprintf(&cmd[n], len - n, "%s", (portid == PRTNR_WAN0) ? "rxpause_txpause" : "-rxpause_txpause");

	nvram_set(buf, cmd);
}

void formPortSetup(request *wp, char *path, char *query)
{
	int i;
	char *p = NULL;
	char buf[64];
	int mode, changed = 0;
	DHCP_T dhcp;
	int intVal = 0;

	for (i = 0; i < 5; i++) {
		snprintf(buf, sizeof(buf), "port_reset_%d", i);
		p = req_get_cstream_var(wp, buf, "");
		if (p[0]) {
			yexecl(NULL, "phyconfig %d up auto %s txpause", i, (i == PRTNR_WAN0) ? "rxpause" : "-rxpause");
			ynvram_put("x_port_%d_config=%s", i, (i == PRTNR_WAN0) ? "up_auto_rxpause_txpause" : "up_auto_-rxpause_txpause");
			nvram_commit();
			send_redirect_perm(wp, "/tcpipport.htm");
			return;
		}
	}

	p = req_get_cstream_var(wp, "opMode", "");
	if (p[0]) {
		mode = strtol(p, NULL, 10);
		switch (mode) {
		case 0:
			dhcp = DHCP_SERVER;
			changed = 1;
			break;
		case 1:
			dhcp = DHCP_DISABLED;
			changed = 1;
			break;
		default:
			break;
		}

		if (changed) {
			if (!apmib_set(MIB_DHCP, (void *)&dhcp)) {
				strcpy(buf, "네트워크 모드 설정 오류!");
				goto setErr;
			}
			if (!apmib_set(MIB_OP_MODE, (void *)&mode)) {
				strcpy(buf, "네트워크 모드 설정 오류!");
				goto setErr;
			}
			if (dhcp != DHCP_SERVER) {
				apmib_set(MIB_CUSTOM_PASSTHRU_ENABLED, (void *)&intVal);
			}
		}
	}

	for (i = 0; i < 5; i++) {
		formPhyConfig(wp, i);
	}

	nvram_commit();
	OK_MSG("/tcpipport.htm");

	return;
setErr:
	ERR_MSG(buf);
}

#endif

EJH_ENTRY_DATA(x_sdmz_enable, ej_nvram_get, "0");
EJH_ENTRY_DATA(x_sdmz_host, ej_nvram_get, "");

static int ej_check_duple_sdmzconf(request *wp, int argc, char **argv, void *data)
{
	int len = 0;
	int entryNum, i;
	DHCPRSVDIP_T entry;
	char macaddr[30];

	apmib_get(MIB_DHCPRSVDIP_TBL_NUM, (void *)&entryNum);
	len += req_format_write(wp, ("var static_mac = new Array(%d);\n"), entryNum);
	for (i = 1; i <= entryNum; i++) {
		*((char *)&entry) = (char)i;
		apmib_get(MIB_DHCPRSVDIP_TBL, (void *)&entry);
		if (memcmp(entry.macAddr, "\x0\x0\x0\x0\x0\x0", 6)) {
			sprintf(macaddr, "%02x%02x%02x%02x%02x%02x",
			        entry.macAddr[0], entry.macAddr[1],
			        entry.macAddr[2], entry.macAddr[3],
			        entry.macAddr[4], entry.macAddr[5]);
			len += req_format_write(wp, ("static_mac[%d] = \"%s\";\n"), i - 1, macaddr);
		} else {
			len += req_format_write(wp, ("static_mac[%d] = 0;\n"), i - 1);
		}
	}
	len += req_format_write(wp, ("var static_mac_cnt = %d;\n"), entryNum);

	return len;
}
EJH_ENTRY(check_duple_sdmzconf, ej_check_duple_sdmzconf);

void formBroadcastStormCtrl(request *wp, char *path, char *query)
{
	char *submitUrl, *strEnable, *strVal;
	char info[32];
	int rate;
	int i;
	char strBuf[64];

	strEnable = req_get_cstream_var(wp, ("broadcast_storm_ctrl_enable"), (""));
	if (!strcmp(strEnable, ("ON"))) {
		nvram_set("BROADCASTSTORM_CTRL_ENABLE", "1");
		strVal = req_get_cstream_var(wp, ("rate"), (""));
		rate = atoi(strVal);
		if (rate < 1 || rate > 500) {
			ERR_MSG("오류!!! BPS는 1 ~ 500 퍼센트 사이로 설정해야 합니다");
			return;
		}
		nvram_set("BROADCASTSTORM_CTRL_PERCENT", strVal);

#if 1
		//cpercent -> permillage(by skb)
		sprintf(strBuf, "%d", (int)(float)(rate * 30.6));
#else
		sprintf(strBuf, "%d", (int)(float)(rate * 303.6));
#endif

		nvram_set("BROADCASTSTORM_BPS", strBuf);

		for (i = 0; i < PRTNR_MAX; i++) {
			sprintf(strBuf, "port%d_enable", i);
			strVal = req_get_cstream_var(wp, (strBuf), (""));
			if (!strcmp(strVal, ("ON"))) {
				sprintf(info, "1");
			} else {
				sprintf(info, "0");
			}
			sprintf(strBuf, "BROADCASTSTORM_PORT%d_ENABLE ", g_port_info[i]);
			nvram_set(strBuf, info);
		}
	} else {
		nvram_set("BROADCASTSTORM_CTRL_ENABLE", "0");
	}

	nvram_commit();
	yexecl(NULL, "/bin/broadcast_storm.sh");

	submitUrl = req_get_cstream_var(wp, ("submit-url"), ("bstorm.htm"));
#ifdef __DAVO__
	need_reboot = 1;
	OK_MSG(submitUrl);
#else
	if (submitUrl[0])
		send_redirect_perm(wp, submitUrl);
#endif

	return;
}

static int ej_bcast_port_status(request *wp, int argc, char **argv, void *unused)
{
	int portno = 0;
	char name[32], val[32];

	if (argc < 2) {
		return req_format_write(wp, "%s", "");
	}

	if (!strcmp(argv[1], "lan1")) {
		portno = PRTNR_LAN1;
	} else if (!strcmp(argv[1], "lan2")) {
		portno = PRTNR_LAN2;
	} else if (!strcmp(argv[1], "lan3")) {
		portno = PRTNR_LAN3;
	} else if (!strcmp(argv[1], "lan4")) {
		portno = PRTNR_LAN4;
	} else {
		portno = PRTNR_WAN0;
	}

	snprintf(name, sizeof(name), "BROADCASTSTORM_PORT%d_ENABLE", portno);
	nvram_get_r_def(name, val, sizeof(val), "0");

	return req_format_write(wp, "%s", val);
}
EJH_ENTRY(BSTORM_CTRL_PORT_STATUS, ej_bcast_port_status);
EJH_ENTRY(BROADCASTSTORM_CTRL_ENABLE, ej_nvram_get);
EJH_ENTRY(BROADCASTSTORM_CTRL_PERCENT, ej_nvram_get);

static int ej_wlweb_permit(request *wp, int argc, char **argv, void *data)
{
	char name[20]; // wlan0_vap3_max_conn
	char val[4];

	snprintf(name, sizeof(name), "wlan%d_wlweb_permit", wlan_idx);

	nvram_get_r_def(name, val, sizeof(val), "0");
	return req_format_write(wp, "%s", val);
}
EJX_ENTRY(wlweb_permit, ej_wlweb_permit);

#define WEB_MAX_ACL_ENTRY 10

int check_ip_duplication(int acl_num, char *acl_ip)
{
	int i;
	char cmd[40], buf[40];

	for (i = 1; i < acl_num; i++) {
		sprintf(cmd, "webacl_addr%d", i);
		nvram_get_r_def(cmd, buf, sizeof(buf), "0.0.0.0");
		if (!strcmp(buf, acl_ip))
			return 1;
	}

	return 0;
}

void rearrange_acllist()
{
	int i, j = 0;
	char cmd[40], num[12], buf[40];
	char tmp[40];
	char *p = NULL;

	for (i = 0; i < WEB_MAX_ACL_ENTRY; i++) {
		sprintf(cmd, "webacl_addr%d", (i + 1));
		p = nvram_get(cmd);
		if (p) {
			snprintf(tmp, sizeof(tmp), "%s", p);
			nvram_unset(cmd);
			sprintf(buf, "webacl_addr%d", (j + 1));
			nvram_set(buf, tmp);
			j++;
		}
	}

	sprintf(num, "%d", j);
	nvram_set("webacl_num", num);
}


EJX_ENTRY_DATA(webaclNum, ej_nvram_get, "0");
EJX_ENTRY_DATA(webacl_mode, ej_nvram_get, "0");
EJX_ENTRY_DATA(webman_enable, ej_nvram_get, "0");

static int ej_web_aclList(request *wp, int argc, char **argv, void *unused)
{
	int len = 0;
	char cmd[40], buf[40], num[12];
	int acl_num, i;

	len += req_format_write(wp, ("<tr class='tbl_head'>"
	                             "<td align=center width=\"25%%\"><font size=\"2\"><b>리스트</b></font></td>\n"
	                             "<td align=center width=\"50%%\"><font size=\"2\"><b>허용주소</b></font></td>\n"
	                             "<td align=center width=\"25%%\"><font size=\"2\"><b>삭제</b></font></td></tr>\n"));

	nvram_get_r_def("webacl_num", num, sizeof(num), "0");
	acl_num = atoi(num);
	for (i = 1; i <= acl_num; i++) {
		snprintf(cmd, sizeof(cmd), "webacl_addr%d", i);
		nvram_get_r_def(cmd, buf, sizeof(buf), "0.0.0.0");
		len += req_format_write(wp, ("<tr>"
		                             "<td align=center width=\"25%%\" bgcolor=\"#C0C0C0\"><font size=\"2\">%d</td>\n"
		                             "<td align=center width=\"50%%\" bgcolor=\"#C0C0C0\"><font size=\"2\">%s</td>\n"
		                             "<td align=center width=\"25%%\" bgcolor=\"#C0C0C0\">"
		                             "<input type=\"submit\" value=\"삭제\" id=\"deleteSelAcl%d\" name=\"deleteSelAcl\" onClick=\"return deleteClick(%d)\"></td></tr>\n"),
		                        	i, buf, i, i);
	}

	return len;
}
EJH_ENTRY(web_aclList, ej_web_aclList);

static int ej_web_man_status(request *wp, int argc, char **argv, void *unused)
{
	int len = 0;
	int webman_en, is_user_setup = 0;

	is_user_setup = nvram_atoi("webacl_mode", 0);
	webman_en = nvram_atoi("webman_enable", 0);
	len += req_format_write(wp, ("<tr><td>REMOTE WEB 접근상태: %s</td></tr>"),
	                        (((webman_en) ? ((is_user_setup) ? "ACL LIST" : "ALL IP") : "OFF")));

	return len;
}
EJH_ENTRY(web_man_status, ej_web_man_status);

static int ej_web_acl_list(request *wp, int argc, char **argv, void *unused)
{
	int len = 0;
	int i;
	int wwwPort, webman_enable, webacl_active;
	int acl_num;
	int is_user_setup = 0, all_accept = 0;
	char cmd[80], buf[80];

	wwwPort = nvram_atoi("httpd_port", 80);
	webman_enable = nvram_atoi("webman_enable", 0);
	webacl_active = (webman_enable) ? wwwPort : 0;

	is_user_setup = nvram_atoi("webacl_mode", wwwPort);

	len += req_format_write(wp, ("<tr><td>WEB 활성화: %s(WEBMAN: %s| ACL: %s)</td></tr>"),
	                        ((webacl_active) ? "ON" : "OFF"), ((webacl_active) ? "O" : "X"), ((is_user_setup) ? "O" : "X"));

	acl_num = nvram_atoi("webacl_num", 0);
	for (i = 1; i <= acl_num; i++) {
		sprintf(cmd, "webacl_addr%d", i);
		nvram_get_r_def(cmd, buf, sizeof(buf), "0.0.0.0");
		if (!strcmp(buf, "0.0.0.0")) {
			all_accept = 1;
		}
	}

	if (webacl_active) {
		if (is_user_setup) {
			if (all_accept) {
				len += req_format_write(wp, ("<tr><td>[1] %s</td></tr>"), "ALL IP ACCEESS");
			} else {
				int white_list_num = 0;
				char *p = NULL;
				for (i = 1; i <= acl_num; i++) {
					sprintf(cmd, "webacl_addr%d", i);
					nvram_get_r_def(cmd, buf, sizeof(buf), "0.0.0.0");
					len += req_format_write(wp, ("<tr><td>[%d] %s</td></tr>"), i, buf);
				}
				white_list_num = nvram_atoi("acl_white_list_num", 0);
				for (i = 1; i <= white_list_num; i++) {
					sprintf(cmd, "acl_white_list%d", i);

					p = nvram_get(cmd);
					if (p) {
						sprintf(cmd, "%s", p);
						len += req_format_write(wp, ("<tr><td>[%d] %s</td></tr>"), ++acl_num, cmd);
					}
				}
			}
		} else {
			len += req_format_write(wp, ("<tr><td>[1] %s</td></tr>"), "ALL IP ACCEESS");
		}
	}

	return len;
}
EJH_ENTRY(web_acl_list, ej_web_acl_list);
EJH_ENTRY_DATA(webacl_addr, ej_nvram_get, "0.0.0.0");
EJH_ENTRY_DATA(webacl_port, ej_nvram_get, "8787");

void formWebAcl(request *wp, char *path, char *query)
{
	char *submitUrl, *strSave, *strVal, *strDelacl;
	char tmpBuf[100], buffer[100];
	int i, acl_num;
	char buf[80], cmd[80], num[12];

	strSave = req_get_cstream_var(wp, ("save"), (""));
	strDelacl = req_get_cstream_var(wp, ("deleteSelAcl"), (""));

	nvram_get_r_def("webacl_num", num, sizeof(num), "0");
	acl_num = atoi(num);

	if (strSave[0]) {
		strVal = req_get_cstream_var(wp, ("web_management"), (""));
		if (!strcmp(strVal, ("ON"))) {
			strVal = req_get_cstream_var(wp, ("webacl_mode"), (""));
			if (!strcmp(strVal, ("ON"))) {
				strVal = req_get_cstream_var(wp, ("webacl_ip"), (""));
				if (!strcmp(strVal, ("ON"))) {
					sprintf(tmpBuf, "%s.%s.%s.%s",
					        req_get_cstream_var(wp, ("ip1"), ("0")),
					        req_get_cstream_var(wp, ("ip2"), ("0")),
					        req_get_cstream_var(wp, ("ip3"), ("0")),
					        req_get_cstream_var(wp, ("ip4"), ("0")));

					if ((acl_num + 1) > WEB_MAX_ACL_ENTRY) {
						snprintf(buffer, sizeof(buffer), "최대 %d개의 ACL리스트만 추가할 수 있습니다!", WEB_MAX_ACL_ENTRY);
						goto setErr_webacl;
					}

					if (check_ip_duplication((acl_num + 1), tmpBuf)) {
						snprintf(buffer, sizeof(buffer), "%s", ("ACL IP가 이미 사용 중 입니다!"));
						goto setErr_webacl;
					}

					snprintf(cmd, sizeof(cmd), "webacl_addr%d", (acl_num + 1));
					nvram_set(cmd, tmpBuf);
					num[0] = 0;
					snprintf(num, sizeof(num), "%d", (acl_num + 1));
					nvram_set("webacl_num", num);

					strVal = req_get_cstream_var(wp, ("rcs_port"), ("8787"));
					buf[0] = 0;
					nvram_get_r_def("webacl_port", buf, sizeof(buf), "8787");
					if (strcmp(buf, strVal))
						nvram_set("webacl_port", strVal);
				}
				buf[0] = 0;
				nvram_get_r_def("webacl_mode", buf, sizeof(buf), "0");
				if (buf[0] != strVal[0])
					nvram_set("webacl_mode", "1");
			} else {
				nvram_set("webacl_mode", "0");
			}
			nvram_set("webman_enable", "1");
		} else {
			nvram_set("webacl_mode", "0");
			nvram_set("webman_enable", "0");
		}
	}

	/* Delete entry */
	if (strDelacl[0]) {
		for (i = acl_num; i > 0; i--) {
			snprintf(tmpBuf, sizeof(tmpBuf), "select%d", i);

			strVal = req_get_cstream_var(wp, tmpBuf, (""));
			if (!strcmp(strVal, ("ON"))) {
				snprintf(cmd, sizeof(cmd), "webacl_addr%d", i);
				nvram_unset(cmd);
				rearrange_acllist();
			}
		}
	}

#ifndef NO_ACTION
	{
		int pid;
		pid = fork();
		if (pid) {
			waitpid(pid, NULL, 0);
		} else if (pid == 0) {
			yexecl(NULL, "%s/%s", _CONFIG_SCRIPT_PATH, _FIREWALL_SCRIPT_PROG);
			exit(1);
		}
	}
#endif

	submitUrl = req_get_cstream_var(wp, ("submit-url"), (""));   // hidden page
	need_reboot = 1;

#ifdef REBOOT_CHECK
	if (needReboot == 1) {
		OK_MSG(submitUrl);
		return;
	}
#endif

	nvram_commit();
	if (submitUrl[0])
		send_redirect_perm(wp, submitUrl);
	return;

setErr_webacl:
	ERR_MSG(buffer);
}

static int ej_lanstats(request *wp, int argc, char **argv, void *data)
{
	int ports[] = { PRTNR_LAN1, PRTNR_LAN2, PRTNR_LAN3, PRTNR_LAN4 };
	char buf[128];
	struct user_net_device_stats stats;
	int i;

	switch (argv[0][3]) {
	case 'T':
	case 'R':
		stats.rx_bytes = stats.tx_bytes = 0LL;
		for (i = 0; i < _countof(ports); i++) {
			if (getPortStats(ports[i], buf)) {
				sscanf(buf, (char *)data, &stats.rx_bytes);
				stats.tx_bytes += stats.rx_bytes;
			}
		}
		return req_format_write(wp, "%u, %u", (unsigned int)(stats.tx_bytes >> 32), (unsigned int)stats.tx_bytes);
	case '2':
	case '3':
	case '4':
#if defined(VLAN_CONFIG_SUPPORTED)
		if (*((char **)data) == NULL || getStats(*((char **)data), &stats) < 0)
			memset(&stats, 0, sizeof(stats));
		if (argv[0][4] == 'T')
			return req_format_write(wp, "%u, %u",
			                        (unsigned int)(stats.tx_bytes >> 32), (unsigned int)stats.tx_bytes);
		else
			return req_format_write(wp, "%u, %u",
			                        (unsigned int)(stats.rx_bytes >> 32), (unsigned int)stats.rx_bytes);
#else
		return req_format_write(wp, "0, 0");
#endif
	default:
		break;
	}
	return 0;
}
EJH_ENTRY_DATA(lanTxDataBytes, ej_lanstats, "%*s %*s %llu %*s");
EJH_ENTRY_DATA(lanRxDataBytes, ej_lanstats, "%*s %*s %*s %llu");
EJH_ENTRY_DATA(lan2TxDataBytes, ej_lanstats, &ELAN2_IF);
EJH_ENTRY_DATA(lan2RxDataBytes, ej_lanstats, &ELAN2_IF);
EJH_ENTRY_DATA(lan3TxDataBytes, ej_lanstats, &ELAN3_IF);
EJH_ENTRY_DATA(lan3RxDataBytes, ej_lanstats, &ELAN3_IF);
EJH_ENTRY_DATA(lan4TxDataBytes, ej_lanstats, &ELAN4_IF);
EJH_ENTRY_DATA(lan4RxDataBytes, ej_lanstats, &ELAN4_IF);

static int ej_wanstats(request *wp, int argc, char **argv, void *data)
{
	char buf[128];
	unsigned long long count = 0;

	if (getPortStats(PRTNR_WAN0, buf))
		sscanf(buf, (char *)data, &count);
	if (argv[0][5] == 'D')
		return req_format_write(wp, "%u, %u", (unsigned int)(count >> 32), (unsigned int)count);
	else
		return req_format_write(wp, "%u", (unsigned int)count);
}
EJH_ENTRY_DATA(wanTxDataBytes, ej_wanstats, "%*s %*s %llu %*s");
EJH_ENTRY_DATA(wanRxDataBytes, ej_wanstats, "%*s %*s %*s %llu");
EJH_ENTRY_DATA(wanTxPacketNum, ej_wanstats, "%llu %*s");
EJH_ENTRY_DATA(wanRxPacketNum, ej_wanstats, "%*s %llu");

// port forward to wifi phone
struct _WiFi_phone_entry {
	char mac[20];
	char ip[20];
	int wireless;
};

struct _WiFi_phone_info {
	int count;
	struct _WiFi_phone_entry phone_entry[32];
};

void add_WiFi_phone_info(struct _WiFi_phone_info* WiFi_phone_info, struct _WiFi_phone_entry *phone)
{
	int i;
	int mac_len, ip_len;
	struct _WiFi_phone_entry *phone_entry;

	mac_len = strlen(phone->mac);
	ip_len = strlen(phone->ip);
	for (i = 0; i < WiFi_phone_info->count; i++) {
		phone_entry = &WiFi_phone_info->phone_entry[i];
		if ((mac_len > 5) && (strcasecmp(phone_entry->mac, phone->mac) == 0)) {
			if (strlen(phone_entry->ip) < 5) {
				strcpy(phone_entry->ip, phone->ip);
			}
			if (phone->wireless == 1) {
				phone_entry->wireless = phone->wireless;
			}
			return;
		} else if ((ip_len > 5) && (strcasecmp(phone_entry->ip, phone->ip) == 0)) {
			if (strlen(phone_entry->mac) < 5) {
				strcpy(phone_entry->mac, phone->mac);
			}
			if (phone->wireless == 1) {
				phone_entry->wireless = phone->wireless;
			}
			return;
		}
	}

	phone_entry = &WiFi_phone_info->phone_entry[WiFi_phone_info->count];
	memcpy(phone_entry, phone, sizeof(struct _WiFi_phone_entry));
	WiFi_phone_info->count++;
}

void get_dhcpd_voip_lease(struct _WiFi_phone_info* WiFi_phone_info)
{
	char tmpBuf[100], buf[256];
	int pid;
	FILE *fp = NULL;
	char ip[20], mac[20];
	long lease_time;
	struct _WiFi_phone_entry phone;

	snprintf(tmpBuf, 100, "%s/%s.pid", _DHCPD_PID_PATH, _DHCPD_PROG_NAME);
	pid = fget_and_test_pid(tmpBuf);

	if (pid > 0) {
		yexecl(NULL, "kill -SIGUSR1 %d", pid);
	} else {
		return ;
	}
	usleep(1000);

#define _PATH_DHCPS_VOIP_LEASES "/var/lib/misc/udhcpd_voip.lease"
	fp = fopen(_PATH_DHCPS_VOIP_LEASES, "r");

	if (fp == NULL) {
		return;
	}
	while (fgets(buf, sizeof(buf), fp) != NULL) {
		memset(&phone, 0, sizeof(struct _WiFi_phone_entry));
		if (sscanf(buf, "%s %s %ld", mac, ip, &lease_time) != 3) {
			continue;
		}
		if (strcmp(mac, "00:00:00:00:00:00") == 0)
			continue;
		strcpy(phone.mac, mac);
		strcpy(phone.ip, ip);
		add_WiFi_phone_info(WiFi_phone_info, &phone);
	}
	fclose(fp);
}

void get_5060_used_ip(struct _WiFi_phone_info *WiFi_phone_info)
{
	char buf[256], *p;
	FILE *f;
	struct _WiFi_phone_entry phone;

	if ((f = fopen("/proc/net/ip_conntrack", "r"))) {
		while (fgets(buf, sizeof(buf), f)) {
			if (strstr(buf, "sport=5060 ") == NULL)
				continue;
			p = strstr(buf, "src=");
			if (p) {
				memset(&phone, 0, sizeof(phone));
				sscanf(p + sizeof("src=") - 1, "%19s", phone.ip);
				add_WiFi_phone_info(WiFi_phone_info, &phone);
			}
		}
		fclose(f);
	}
}

void fill_ipaddr_mac(struct _WiFi_phone_info *phone, int mode)
{
	struct arpent *t, *p;
	int i;

	p = arpent_dump();
	if (p == NULL)
		return;

	for (i = 0; i < phone->count; i++) {
		if (strlen(phone->phone_entry[i].ip) > 5 &&
		    strlen(phone->phone_entry[i].mac) > 5)
			continue;
		if (mode == 0) {
			unsigned char mac[6];
			ether_atoe(phone->phone_entry[i].mac, mac);
			for (t = p; t->netdev[0]; t++) {
				if (!memcmp(t->mac, mac, 6)) {
					strcpy(phone->phone_entry[i].ip, inet_ntoa(t->ip));
					break;
				}
			}
		} else {
			in_addr_t ip = inet_addr(phone->phone_entry[i].ip);
			for (t = p; t->netdev[0]; t++) {
				if (t->ip.s_addr == ip) {
					sprintf(phone->phone_entry[i].mac,
					        "%02x:%02x:%02x:%02x:%02x:%02x",
					        t->mac[0], t->mac[1], t->mac[2],
					        t->mac[3], t->mac[4], t->mac[5]);
					break;
				}
			}
		}
	}
	free(p);
}

void wireless_check(struct _WiFi_phone_info* WiFi_phone_info)
{
	int i, j;
	WLAN_STA_INFO_Tp pInfo;
	char *buff = NULL;
	char Root_WLAN_IF[20];
	char wifi_mac[20];
	int ssid_vid = 0;
	struct _WiFi_phone_entry *phone_entry;
	buff = calloc(1, sizeof(WLAN_STA_INFO_T) * (MAX_STA_NUM + 1));
	if (buff == 0) {
		printf("Allocate buffer failed!\n");
		return;
	}

	for (ssid_vid = 0; ssid_vid < 5; ssid_vid++) {
		if (ssid_vid != 0) {
			int virtual_index;
			char virtual_name[20];
			strcpy(Root_WLAN_IF, WLAN_IF);
			virtual_index = ssid_vid - 1;

			sprintf(virtual_name, "-va%d", virtual_index);
			strcat(WLAN_IF, virtual_name);
		}

		if (getWlStaInfo(WLAN_IF, (WLAN_STA_INFO_Tp)buff) < 0) {
			printf("Read %s sta info failed!\n", WLAN_IF);

			if (ssid_vid != 0)
				strcpy(WLAN_IF, Root_WLAN_IF);
			continue;
		}

		if (ssid_vid != 0)
			strcpy(WLAN_IF, Root_WLAN_IF);

		for (i = 1; i <= MAX_STA_NUM; i++) {
			pInfo = (WLAN_STA_INFO_Tp)&buff[i * sizeof(WLAN_STA_INFO_T)];
			if (pInfo->aid && (pInfo->flags & STA_INFO_FLAG_ASOC)) {
				sprintf(wifi_mac, "%02x:%02x:%02x:%02x:%02x:%02x",
				        pInfo->addr[0], pInfo->addr[1], pInfo->addr[2],
				        pInfo->addr[3], pInfo->addr[4], pInfo->addr[5]);
				for (j = 0; j < WiFi_phone_info->count; j++) {
					phone_entry = &WiFi_phone_info->phone_entry[j];
					if (strlen(phone_entry->mac) < 5) {
						continue;
					}

					if (strcasecmp(wifi_mac, phone_entry->mac) == 0) {
						phone_entry->wireless = 1;
						break;
					}
				}
			}
		}
	}

	free(buff);
}


// cmd -  0:get, 1:set
void wifi_phone_control_config_cmd(int cmd, int *forward, char *internal_ip, char *internal_port, char *external_port)
{
	static char wifi_phone_internal_ip[32] = "0.0.0.0", wifi_phone_internal_port[10] = "8080", wifi_phone_external_port[10] = "0";
	static int Wifi_phone_forward = 0;

	if (cmd == 0) { // get
		if (forward != NULL) {
			*forward = Wifi_phone_forward;
		}
		if (internal_ip != NULL) {
			strcpy(internal_ip, wifi_phone_internal_ip);
		}
		if (internal_port != NULL) {
			strcpy(internal_port, wifi_phone_internal_port);
		}
		if (external_port != NULL) {
			if (strlen(wifi_phone_external_port) < 2)
				nvram_get_r_def("VOIP_DEVICE_EXTERNAL_PORT", wifi_phone_external_port, sizeof(wifi_phone_external_port), "18080");
			strcpy(external_port, wifi_phone_external_port);
		}
	} else { // set
		if (forward != NULL) {
			Wifi_phone_forward = *forward;
		}
		if (internal_ip != NULL) {
			strcpy(wifi_phone_internal_ip, internal_ip);
		}
		if (internal_port != NULL) {
			strcpy(wifi_phone_internal_port, internal_port);
		}
		if (external_port != NULL) {
			strcpy(wifi_phone_external_port, external_port);
		}
	}
}

void get_stamac(int ssid_vid, struct _WiFi_phone_info* WiFi_phone_info)
{
	int i;
	WLAN_STA_INFO_Tp pInfo;
	char *buff;
	char Root_WLAN_IF[20];
	struct _WiFi_phone_entry phone;

	buff = calloc(1, sizeof(WLAN_STA_INFO_T) * (MAX_STA_NUM + 1));
	if (buff == 0) {
		printf("Allocate buffer failed!\n");
		return;
	}

	if (ssid_vid != 0) {
		int virtual_index;
		char virtual_name[20];
		strcpy(Root_WLAN_IF, WLAN_IF);
		virtual_index = ssid_vid - 1;

		sprintf(virtual_name, "-va%d", virtual_index);
		strcat(WLAN_IF, virtual_name);
	}

	if (getWlStaInfo(WLAN_IF, (WLAN_STA_INFO_Tp)buff) < 0) {
		printf("Read wlan sta info failed!\n");

		if (ssid_vid != 0)
			strcpy(WLAN_IF, Root_WLAN_IF);
		free(buff);
		return;
	}

	if (ssid_vid != 0)
		strcpy(WLAN_IF, Root_WLAN_IF);

	for (i = 1; i <= MAX_STA_NUM; i++) {
		pInfo = (WLAN_STA_INFO_Tp)&buff[i * sizeof(WLAN_STA_INFO_T)];
		if (pInfo->aid && (pInfo->flags & STA_INFO_FLAG_ASOC)) {
			memset(&phone, 0, sizeof(struct _WiFi_phone_entry));
			sprintf(phone.mac, "%02x:%02x:%02x:%02x:%02x:%02x",
			        pInfo->addr[0], pInfo->addr[1], pInfo->addr[2],
			        pInfo->addr[3], pInfo->addr[4], pInfo->addr[5]);
			phone.wireless = 1;
			add_WiFi_phone_info(WiFi_phone_info, &phone);
		}
	}

	free(buff);

}

int showConnectVoIPtbl(request *wp, int argc, char **argv)
{
	int i = 0, Wifi_phone_forward = 0;
	int voip_ssid;
	int nBytesSent = 0;
	struct _WiFi_phone_info wifi_phone_info;
	char wan_ip[32];
	char wifi_phone_internal_ip[32] = {}, wifi_phone_internal_port[10] = {}, wifi_phone_external_port[10] = {};
	char buf[64];
	int str_argc;
	char *str_args[10], *p;
	int radio_idx = 0;
	char Root_WLAN_IF[20];

	wifi_phone_control_config_cmd(0, &Wifi_phone_forward, wifi_phone_internal_ip, wifi_phone_internal_port, wifi_phone_external_port);
	memset(&wifi_phone_info, 0, sizeof(struct _WiFi_phone_info));

//@NOTE: CJHV used 2 voice ssid
	nvram_get_r_def("VOIP_SSID_VID", buf, sizeof(buf), "2 3");
	p = buf;
	str_argc = ystrargs(p, str_args, 10, " \t\n\t", 0);

	get_dhcpd_voip_lease(&wifi_phone_info);

	snprintf(Root_WLAN_IF, sizeof(Root_WLAN_IF), "%s", WLAN_IF);
	for (radio_idx = 0; radio_idx < 2; radio_idx++) {
		snprintf(WLAN_IF, 16, "wlan%d", radio_idx);
		for (i = 0; i < str_argc; i++) {
			voip_ssid = atoi(str_args[i]);
			get_stamac(voip_ssid, &wifi_phone_info);
		}
		wireless_check(&wifi_phone_info);
	}
	snprintf(WLAN_IF, 16, "%s", Root_WLAN_IF);
	fill_ipaddr_mac(&wifi_phone_info, 0);

	get_5060_used_ip(&wifi_phone_info);
	fill_ipaddr_mac(&wifi_phone_info, 1);

	if (!get_network_info("wan_ip", wan_ip)) {
		strcpy(wan_ip, "0.0.0.0");
	}
	ydespaces(wan_ip);

	nBytesSent += req_format_write(wp, ("<input type='hidden' name='externalPort' value='%s'>"), wifi_phone_external_port);

	for (i = 0; i < wifi_phone_info.count; i++) {
		if (strlen(wifi_phone_info.phone_entry[i].ip) < 5)
			continue;
		if ((Wifi_phone_forward == 1) && (strcmp(wifi_phone_info.phone_entry[i].ip, wifi_phone_internal_ip) == 0)) {
			nBytesSent += req_format_write(wp, ("  <tr>\n" \
			                                    "    <td align=center style=\"font-size:9pt\">%s</td>\n" \
			                                    "    <td align=center style=\"font-size:9pt\">%s</td>\n" \
			                                    "    <td align=center style=\"font-size:9pt\"><input type='text' style='text-align: center; font-size:9pt' maxLength='6' size='6' name='internalPort%d' value='%s'></td>\n" \
			                                    "    <td align=center style=\"font-size:9pt\">%s</td>\n" \
			                                    "    <td align=center style=\"font-size:9pt\">%s</td>\n" \
			                                    "    <td align=center style=\"font-size:9pt\">%s</td>\n" \
			                                    "    <td align=center style=\"font-size:9pt\">%s</td>\n" \
			                                    "    <td align=center style=\"font-size:9pt\"><input type=button style=\"font-size:9pt\" name='connect' value='해제' onClick='submit_check(%d)'></td>\n" \
			                                    "    <td style='text-align: center; font-size:9pt'><b>&nbsp&nbspDN:</b>&nbsp<input type='text'style=\"font-size:9pt\"  size='20' maxlength='20' name='dn%d'>" \
			                                    "                     <input type=button style=\"font-size:9pt\" name='reboot' value='재시작' onClick='submit_reboot_check(%d)'></td>\n" \
			                                    "    </tr>\n"), wifi_phone_info.phone_entry[i].ip, wifi_phone_info.phone_entry[i].mac, i, wifi_phone_internal_port, \
			                               wifi_phone_info.phone_entry[i].wireless ? "무선" : "유선", \
			                               "Forwarding", wan_ip, wifi_phone_external_port, i, i, i);
			nBytesSent += req_format_write(wp, ("<input type='hidden' name='internal_ip_%d' value='%s'>" \
			                                    "   <input type='hidden' name='action_type_%d' value='1'> "), i, wifi_phone_info.phone_entry[i].ip, i);
		} else {
			nBytesSent += req_format_write(wp, ("  <tr>\n" \
			                                    "    <td align=center style=\"font-size:9pt\">%s</td>\n" \
			                                    "    <td align=center style=\"font-size:9pt\">%s</td>\n" \
			                                    "    <td align=center style=\"font-size:9pt\"><input type='text' style='text-align: center; font-size:9pt' maxLength='6' size='6' name='internalPort%d' value='8080'></td>\n" \
			                                    "    <td align=center style=\"font-size:9pt\">%s</td>\n" \
			                                    "    <td align=center style=\"font-size:9pt\">%s</td>\n" \
			                                    "    <td align=center style=\"font-size:9pt\">%s</td>\n" \
			                                    "    <td align=center style=\"font-size:9pt\">%s</td>\n" \
			                                    "    <td align=center style=\"font-size:9pt\"><input type=button style=\"font-size:9pt\" name='connect' value='연결' onClick='submit_check(%d)'></td>\n" \
			                                    "    <td style='text-align: center; font-size:9pt'><b>&nbsp&nbspDN:</b>&nbsp<input type='text' style=\"font-size:9pt\" size='20' maxlength='20' name='dn%d'>" \
			                                    "                     <input type=button style=\"font-size:9pt\" name='reboot' value='재시작' onClick='submit_reboot_check(%d)'></td>\n" \
			                                    "    </tr>\n"), wifi_phone_info.phone_entry[i].ip, wifi_phone_info.phone_entry[i].mac, i, \
			                               wifi_phone_info.phone_entry[i].wireless ? "무선" : "유선", \
			                               "-", "-", "-", i, i, i);
			nBytesSent += req_format_write(wp, ("<input type='hidden' name='internal_ip_%d' value='%s'>" \
			                                    "   <input type='hidden' name='action_type_%d' value='0'> "), i, wifi_phone_info.phone_entry[i].ip, i);
		}
	}
	return nBytesSent;
}

#define _eval(timeout, cmd, args...) ({ \
	char *argv[] = { cmd , ## args, NULL }; \
	yexecv(argv, NULL, timeout, NULL); \
})
void formConnectVoIP(request *wp, char *path, char *query)
{
	char *submitUrl, *internalIp, *internalPort, *connect_Action, *preset;
	char wan_ip[32];
	char wifi_phone_internal_ip[32] = {}, wifi_phone_internal_port[10] = {}, wifi_phone_external_port[10] = {};
	int Wifi_phone_forward;
	char cmd[256];

	/*if (wp->superUser == 0)
		return;*/

	if (!get_network_info("wan_ip", wan_ip)) {
		strcpy(wan_ip, "0.0.0.0");
	}
	ydespaces(wan_ip);

	wifi_phone_control_config_cmd(0, &Wifi_phone_forward, wifi_phone_internal_ip, wifi_phone_internal_port, wifi_phone_external_port);

	internalIp = req_get_cstream_var(wp, ("internalIp"), (""));
	internalPort = req_get_cstream_var(wp, ("internalPort"), (""));
	connect_Action = req_get_cstream_var(wp, ("connect_Action"), (""));
	submitUrl = req_get_cstream_var(wp, ("submit-url"), (""));   // hidden page
	preset = req_get_cstream_var(wp, ("reboot_flag"), (""));   // hidden page

	if (!strcmp(preset, "1")) { // reboot
		snprintf(cmd, sizeof(cmd), "http://%s:%s/reboot%s",
		         internalIp, internalPort,
		         req_get_cstream_var(wp, ("dn"), ("")));
		_eval(2, "wget", cmd, "-s");

		snprintf(cmd, sizeof(cmd), "http://%s:%s/goform/cgi_form_reboot?", internalIp, internalPort);
		_eval(2, "wget", cmd);
	} else {
		char wan_interface[32];
		if (!yfcat("/var/wan_info", "%s", wan_interface)) {
			snprintf(wan_interface, sizeof(wan_interface), "%s", "eth1");
		}

		if (strcmp(connect_Action, "0") == 0) { // connect
			if (Wifi_phone_forward == 1) { //first disconnect
				yexecl(NULL, "iptables -D PREROUTING -t nat -p tcp --dport %s -d %s -j DNAT --to %s:%s",
				       wifi_phone_external_port, wan_ip, wifi_phone_internal_ip, wifi_phone_internal_port);
				yexecl(NULL, "iptables -D FORWARD -i %s -d %s -p tcp --dport %s -j ACCEPT",
				       wan_interface, wifi_phone_internal_ip, wifi_phone_internal_port);
			}

			yexecl(NULL, "iptables -A PREROUTING -t nat -p tcp --dport %s -d %s -j DNAT --to %s:%s",
			       wifi_phone_external_port, wan_ip, internalIp, internalPort);
			yexecl(NULL, "iptables -A FORWARD -i %s -d %s -p tcp --dport %s -j ACCEPT",
			       wan_interface, internalIp, internalPort);
			Wifi_phone_forward = 1;
			wifi_phone_control_config_cmd(1, &Wifi_phone_forward, internalIp, internalPort, wifi_phone_external_port);
		} else {    // disconnect
			if (Wifi_phone_forward == 1) {
				yexecl(NULL, "iptables -D PREROUTING -t nat -p tcp --dport %s:%s -d %s -j DNAT --to %s:%s",
				       wifi_phone_external_port, wifi_phone_external_port, wan_ip, wifi_phone_internal_ip, wifi_phone_internal_port);
				yexecl(NULL, "iptables -D FORWARD -i eth1 -d %s -p tcp --dport %s -j ACCEPT",
				       wifi_phone_internal_ip, wifi_phone_internal_port);
				Wifi_phone_forward = 0;
				wifi_phone_control_config_cmd(1, &Wifi_phone_forward, "", "", NULL);
			}
		}
	}
	if (submitUrl[0]) {
		send_redirect_perm(wp, submitUrl);
	}
	return;
}

/*** Mac Filter ****/
void DvAlignMacFilterEntry(int entryNum)
{
	int i, j;
	char tmpBuf[512], queury[32];

	i = j = 1;
	while (i <= entryNum) {
		sprintf(queury, "x_MACFILTER_TBL%d", i++);
		if (nvram_get_r(queury, tmpBuf, sizeof(tmpBuf)) == NULL)
			continue;
		nvram_unset(queury);

		sprintf(queury, "x_MACFILTER_TBL%d", j++);
		nvram_set(queury, tmpBuf);
	}
}

void DvDeleteMacFilterEntry(int entryNum, int index)
{
	char tmp[16];
	char *mac, *port, opmode[16];
	char queury[32];
	char tmpBuf[512];
	int portlist;
	int i;

	snprintf(queury, sizeof(queury), "x_MACFILTER_TBL%d", index);
	if (nvram_get_r(queury, tmpBuf, sizeof(tmpBuf)) == NULL)
		return;

	nvram_unset(queury);

	mac = strtok(tmpBuf, ",");
	port = strtok(NULL, ",");
	if (!mac || !port)
		return;

	portlist = atoi(port);
	for (i = 1; i <= 4; i++)
		if (portlist == (0x1 << g_port_info[i]))
			break;

	if (i > 4)
		return;

	sprintf(queury, "x_MACFILTER_OPMODE%d", i);
	if (nvram_get_r(queury, opmode, sizeof(opmode))) {
		yexecl(NULL, "aclwrite del br0 -a %s -r sfilter -o 7 "
		       "-m %s -P %d -3 -4",
		       opmode, mac, atoi(port));
	}

	snprintf(tmp, sizeof(tmp), "%d", entryNum - 1);
	if (nvram_set("MACFILTER_TBL_NUM", tmp) < 0) {
		return ;
	}
}

void DvDeleteAllMacFilterEntry(void)
{
	int entryNum, i;
	char tmpBuf[32];
	char old_mode[16];

	if (!apmib_get(MIB_MACFILTER_TBL_NUM, (void *)&entryNum)) {
		entryNum = 0;
	}

	for (i = 1; i <= entryNum; i++) {
		DvDeleteMacFilterEntry(entryNum, i);
	}

	entryNum = 0;
	apmib_set(MIB_MACFILTER_TBL_NUM, (void *)&entryNum);

	// set to the default 'drop'
	for (i = 1; i <= 4; i++) {
		sprintf(tmpBuf, "x_MACFILTER_OPMODE%d", i);
		if (nvram_get_r(tmpBuf, old_mode, sizeof(old_mode)) == NULL) {
			continue;
		}
		if (!strcasecmp(old_mode, "permit")) {
			yexecl(NULL, "aclwrite del br0 -a drop -r sfilter -o 7 -3 -4 -P %d",
			       1 << g_port_info[i]);
			nvram_set(tmpBuf, "drop");
		}
	}
}

int DvAddMacFilterEntry(MACFILTER_T *macEntry, int port)
{
	char strPort[32], tmpBuf[128];
	int entryNum;
	char tmp[512];
	char opmode[16];
	char mac[32];
	int i;

	if (!apmib_get(MIB_MACFILTER_TBL_NUM, (void *)&entryNum)) {
		entryNum = 0;
		apmib_set(MIB_MACFILTER_TBL_NUM, (void *)&entryNum);
	}

	snprintf(mac, sizeof(mac), "%02x:%02x:%02x:%02x:%02x:%02x",
	         macEntry->macAddr[0], macEntry->macAddr[1],
	         macEntry->macAddr[2], macEntry->macAddr[3],
	         macEntry->macAddr[4], macEntry->macAddr[5]);

	snprintf(tmp, sizeof(tmp), "%s,%02d,%s",
	         mac, (1 << g_port_info[port]), macEntry->comment);

	// check duplicated entry
	for (i = 1; i <= entryNum; i++) {
		snprintf(strPort, sizeof(strPort), "x_MACFILTER_TBL%d", i);
		if (nvram_get_r(strPort, tmpBuf, sizeof(tmpBuf)) &&
		    !strncmp(tmp, tmpBuf, 20)) {
			return -2;
		}
	}

	snprintf(strPort, sizeof(strPort), "x_MACFILTER_TBL%d", entryNum + 1);
	if (nvram_set(strPort, tmp) < 0) {
		return -1;
	}

	entryNum++;

	if (!apmib_set(MIB_MACFILTER_TBL_NUM, (void *)&entryNum)) {
		return -1;
	}

	memset(opmode, 0, sizeof(opmode));
	sprintf(tmp, "x_MACFILTER_OPMODE%d", port);
	nvram_get_r(tmp, opmode, sizeof(opmode));
	if (strcmp(opmode, "drop") && strcmp(opmode, "permit")) {
		snprintf(opmode, sizeof(opmode), "%s", "drop");
	}

	yexecl(NULL, "aclwrite add br0 -a %s -r sfilter -o 7 "
	       "-m %s -P %d -3 -4",
	       opmode, mac, (1 << g_port_info[port]));	// add acl entry from acl list

	if (strcmp(opmode, "permit") == 0) {
		yexecl(NULL, "aclwrite del br0 -a drop -r sfilter -o 7 -3 -4 -P %d", (0x1 << g_port_info[port]));
		yexecl(NULL, "aclwrite add br0 -a drop -r sfilter -o 7 -3 -4 -P %d", (0x1 << g_port_info[port]));
	}

	return 0;
}

void DvChangePortMode(int port, char *mode)
{
	char queury[32];
	char old_mode[16];
	char tmpBuf[512];
	int i, j, entryNum;
	char *mac, *cur_port, *p;
	int portlist;

	snprintf(queury, sizeof(queury), "x_MACFILTER_OPMODE%d", port);
	if ((p = nvram_get_r(queury, old_mode, sizeof(old_mode))) == NULL) {
		nvram_set(queury, mode);
		snprintf(old_mode, sizeof(old_mode), "%s", mode);
	}
	if (!strcasecmp(old_mode, "permit") && strcasecmp(old_mode, mode)) {
		yexecl(NULL, "aclwrite del br0 -a drop -r sfilter -o 7 -3 -4 -P %d",
		       1 << g_port_info[port]);
	}
	if (!strcasecmp(old_mode, mode))
		return;

	if (strcmp(mode, "drop") && strcmp(mode, "permit")) {
		nvram_set(queury, "drop");
	} else {
		nvram_set(queury, mode);
	}

	if (!nvram_get_r("MACFILTER_TBL_NUM", tmpBuf, sizeof(tmpBuf))) {
		nvram_set("MACFILTER_TBL_NUM", "0");
		entryNum = 0;
	} else {
		entryNum = atoi(tmpBuf);
	}

	for (i = 1; i <= entryNum; i++) {
		sprintf(queury, "x_MACFILTER_TBL%d", i);
		if (!nvram_get_r(queury, tmpBuf, sizeof(tmpBuf))) {
			continue;
		}
		mac = strtok(tmpBuf, ",");
		cur_port = strtok(NULL, ",");
		if (!mac || !cur_port)
			continue;
		portlist = atoi(cur_port);
		for (j = 1; j <= 4; j++)
			if ((portlist >> g_port_info[j]) & 0x1)
				break;
		if (j > 4)
			continue;
		if (port != j)
			continue;
		yexecl(NULL, "aclwrite del br0 -a %s -r sfilter -o 7 "
		       "-m %s -P %d -3 -4",
		       old_mode, mac, 1 << g_port_info[port]);	// delete acl entry from alc list
	}

	for (i = 1; i <= entryNum; i++) {
		sprintf(queury, "x_MACFILTER_TBL%d", i);
		if (!nvram_get_r(queury, tmpBuf, sizeof(tmpBuf))) {
			continue;
		}
		mac = strtok(tmpBuf, ",");
		cur_port = strtok(NULL, ",");
		if (!mac || !cur_port)
			continue;
		portlist = atoi(cur_port);
		for (j = 1; j <= 4; j++)
			if ((portlist >> g_port_info[j]) & 0x1)
				break;
		if (j > 4)
			continue;
		if (port != j)
			continue;
		yexecl(NULL, "aclwrite add br0 -a %s -r sfilter -o 7 "
		       "-m %s -P %d -3 -4",
		       mode, mac, 1 << g_port_info[port]);	// delete acl entry from alc list
	}

	if (strcasecmp(mode, "permit") == 0) {
		yexecl(NULL, "aclwrite add br0 -a drop -r sfilter -o 7 -3 -4 -P %d", 1 << g_port_info[port]);
	}
}


void formMacFilter(request *wp, char *path, char *query)
{
	char *strAddMac, *strDelMac;
	char *strVal, *strComment = NULL;
	char *strModeMac;

	char tmpBuf[100];
	int entryNum, i;

	MACFILTER_T macEntry;
	void *pEntry;

	strAddMac = req_get_cstream_var(wp, ("addFilterMac"), "");
	strDelMac = req_get_cstream_var(wp, ("deleteSelFilterMac"), "");
	strModeMac = req_get_cstream_var(wp, ("changeModeFilterMac"), (""));

	memset(&macEntry, 0, sizeof(macEntry));
	pEntry = (void *)&macEntry;

	i = 1;
	apmib_set(MIB_MACFILTER_ENABLED, (void *)&i);

	if (strAddMac[0]) {
		int ret;
		int lan_port;

		strVal = req_get_cstream_var(wp, ("mac"), (""));

		if (!strVal[0])
			goto setOk_filter;

		if (!strVal[0]) {
			snprintf(tmpBuf, sizeof(tmpBuf), "%s", "오류! mac 주소를 설정해야 합니다.");
			goto setErr_filter;
		}

		if (strlen(strVal) != 12 || !ether_atoe(strVal, macEntry.macAddr)) {
			snprintf(tmpBuf, sizeof(tmpBuf), "%s", "오류! MAC 주소가 올바르지 않습니다.");
			goto setErr_filter;
		}

		strComment = req_get_cstream_var(wp, ("comment"), "");
		if (strComment[0]) {
			if (strlen(strComment) > COMMENT_LEN - 1) {
				snprintf(tmpBuf, sizeof(tmpBuf), "%s", "오류! 설명이 너무 깁니다.");
				goto setErr_filter;
			}
			snprintf((char *)macEntry.comment, sizeof(macEntry.comment), "%s", strComment);
		}

		strVal = req_get_cstream_var(wp, ("port"), (""));
		if (!strVal[0]) {
			snprintf(tmpBuf, sizeof(tmpBuf), "%s", "오류! 포트를 설정해야 합니다.");
			goto setErr_filter;
		}
		lan_port = atoi(strVal);

		if ((ret = DvAddMacFilterEntry(pEntry, lan_port)) < 0) {
			if (ret == -2)
				snprintf(tmpBuf, sizeof(tmpBuf), "%s", "오류! 중복되었습니다.");
			else
				snprintf(tmpBuf, sizeof(tmpBuf), "%s", "오류! mac 필터 설정 실패.");
			goto setErr_filter;
		}
	}

	if (strAddMac[0]) {
		if (strComment && strComment[0]) {
			if (strlen(strComment) > COMMENT_LEN - 1) {
				strcpy(tmpBuf, ("오류! 설명이 너무 깁니다."));
				goto setErr_filter;
			}
			strcpy((char *)macEntry.comment, strComment);
		}

		if (!apmib_get(MIB_MACFILTER_TBL_NUM, (void *)&entryNum)) {
			strcpy(tmpBuf, ("읽기 실패!"));
			goto setErr_filter;
		}

		if ((entryNum + 1) > MAX_FILTER_NUM) {
			strcpy(tmpBuf, ("테이블이 모두 차서 더이상 추가할 수 없습니다!"));
			goto setErr_filter;
		}
	}

	if (!strAddMac[0] && (strDelMac[0] || strModeMac[0])) {
		int entrynum;
		int cnt_del;

		if (!nvram_get_r("MACFILTER_TBL_NUM", tmpBuf, sizeof(tmpBuf))) {
			nvram_set("MACFILTER_TBL_NUM", "0");
			entrynum = 0;
		} else {
			entrynum = atoi(tmpBuf);
		}

		for (cnt_del = 0, i = entrynum; i > 0; i--) {
			snprintf(tmpBuf, sizeof(tmpBuf), "select%d", i);

			strVal = req_get_cstream_var(wp, tmpBuf, (""));
			if (!strcmp(strVal, "ON")) {
				DvDeleteMacFilterEntry(entrynum - cnt_del, i);
				cnt_del++;
			}
		}
		if (cnt_del > 0)
			DvAlignMacFilterEntry(entrynum);

		for (i = 1; i <= 4; i++) {
			snprintf(tmpBuf, 20, "opmode%d", i);
			strVal = req_get_cstream_var(wp, tmpBuf, (""));
			if (strVal[0]) {
				DvChangePortMode(i, strVal);
			}
		}
	}

setOk_filter:
	nvram_commit();
	DO_APPLY_WAIT("/macfilter.htm");
	return;
setErr_filter:
	ERR_MSG(tmpBuf);
}

int macFilterList(request *wp, int argc, char **argv)
{
	int nBytesSent = 0, entryNum, i;
	char tmpBuf[512];
	char *mac, *port, *comment, *setColor;
	char *p;
	char queury[32];
	int cnt_lan[4];
	int lan_port;
	char tmp[16];
	int mac_count;
	char opmode[16];

	if (!nvram_get_r("MACFILTER_TBL_NUM", tmpBuf, sizeof(tmpBuf))) {
		nvram_set("MACFILTER_TBL_NUM", "0");
		entryNum = 0;
	} else {
		entryNum = atoi(tmpBuf);
	}

	cnt_lan[0] = cnt_lan[1] = cnt_lan[2] = cnt_lan[3] = 0;
	for (i = 1; i <= entryNum; i++) {
		sprintf(queury, "x_MACFILTER_TBL%d", i);
		if ((p = nvram_get_r(queury, tmpBuf, sizeof(tmpBuf))) == NULL) {
			continue;
		}
		mac 	= strtok(tmpBuf, ",");
		port 	= strtok(NULL, ",");
		if (!mac || !port)
			continue;

		lan_port = atoi(port);

		if (lan_port == (0x1 << PRTNR_LAN1)) {
			cnt_lan[0]++;
		} else if (lan_port == (0x1 << PRTNR_LAN2)) {
			cnt_lan[1]++;
		} else if (lan_port == (0x1 << PRTNR_LAN3)) {
			cnt_lan[2]++;
		} else if (lan_port == (0x1 << PRTNR_LAN4)) {
			cnt_lan[3]++;
		}
	}

	nBytesSent += req_format_write(wp, ("<tr class='tbl_head'>"
	                                    "<td align=center width=\"20%%\" ><font size=\"2\"><b>포트</b></font></td>\n"
	                                    "<td align=center width=\"30%%\" ><font size=\"2\"><b>MAC 주소</b></font></td>\n"
	                                    "<td align=center width=\"30%%\" ><font size=\"2\"><b>설명</b></font></td>\n"
	                                    "<td align=center width=\"20%%\" ><font size=\"2\"><b>삭제</b></font></td></tr>\n"));

	for (lan_port = 1; lan_port <= 4; lan_port++) {
		mac_count = 0;

		if (lan_port % 2 == 0)
			setColor = "d5d5d5";
		else
			setColor = "f0f0f0";

		sprintf(queury, "x_MACFILTER_OPMODE%d", lan_port);
		if ((p = nvram_get_r(queury, opmode, sizeof(opmode))) == NULL) {
			snprintf(opmode, sizeof(opmode), "%s", "drop");
			nvram_set(queury, opmode);
		}
		nBytesSent += req_format_write(wp, ("<tr>\n"
		                                    "<td rowspan='%d' align=center width=\"20%%\" bgcolor=\"#%s\"><font size=\"2\">LAN%d"
		                                    "<br><select name='ftmode%d' onChange=\"modeChange(%d, this);\"><option value=\"drop\" %s>차단<option value=\"permit\" %s>허용</select></td>\n"),
		                               (cnt_lan[lan_port - 1]) ? : 1, setColor, lan_port, lan_port, lan_port, !strcasecmp(opmode, "drop") ? "selected" : "", !strcasecmp(opmode, "permit") ? "selected" : "");

		for (i = 1; i <= entryNum; i++) {
			sprintf(queury, "x_MACFILTER_TBL%d", i);
			if ((p = nvram_get_r(queury, tmpBuf, sizeof(tmpBuf))) == NULL) {
				continue;
			}
			mac 	= strtok(tmpBuf, ",");
			port 	= strtok(NULL, ",");
			comment = strtok(NULL, ",");

			if (!mac || !port)
				continue;

			snprintf(tmp, sizeof(tmp), "%02d", (0x1 << g_port_info[lan_port]));
			if (strcasecmp(port, tmp))
				continue;

			snprintf(tmpBuf, sizeof(tmpBuf), "%s", mac);

			if (comment)
				translate_control_code(comment);

			nBytesSent += req_format_write(wp, (
			                                       "<td align=center width=\"30%%\" bgcolor=\"#%s\"><font size=\"2\">%s</td>\n"
			                                       "<td align=center width=\"30%%\" bgcolor=\"#%s\"><font size=\"2\">%s</td>\n"
			                                       "<td align=center width=\"20%%\" bgcolor=\"#%s\">"
			                                       "<input type=\"submit\" value=\" 삭제 \" id=\"deleteSelFilterMac%d\" name=\"deleteSelFilterMac\" onClick=\"return deleteClick(%d)\">"
			                                       "</td></tr>\n"),
			                               setColor, tmpBuf, setColor, comment ? comment : "", setColor, i, i);
			mac_count++;
		}
		if (mac_count == 0) {
			nBytesSent += req_format_write(wp, (
			                                       "<td bgcolor=\"#%s\"></td><td bgcolor=\"#%s\"></td>"
			                                       "<td bgcolor=\"#%s\"></td></tr>\n"), setColor, setColor, setColor);
		}
	}
	return nBytesSent;
}

static int ej_macfil_active_port(request *wp, int argc, char **argv, void *unused)
{
	int lan_port, port = 0;
	int i, entryNum;
	char queury[32], tmpBuf[512];
	char *mac, *cur_port;

	if (!nvram_get_r("MACFILTER_TBL_NUM", tmpBuf, sizeof(tmpBuf))) {
		nvram_set("MACFILTER_TBL_NUM", "0");
		entryNum = 0;
	} else {
		entryNum = atoi(tmpBuf);
	}
	for (i = 1; i <= entryNum; i++) {
		sprintf(queury, "x_MACFILTER_TBL%d", i);
		if (!nvram_get_r(queury, tmpBuf, sizeof(tmpBuf))) {
			continue;
		}
		mac = strtok(tmpBuf, ",");
		cur_port = strtok(NULL, ",");
		if (!mac || !cur_port)
			continue;

		lan_port = atoi(cur_port);
		if (lan_port == (0x1 << PRTNR_LAN1)) {
			port |= 1;
		} else if (lan_port == (0x1 << PRTNR_LAN2)) {
			port |= 2;
		} else if (lan_port == (0x1 << PRTNR_LAN3)) {
			port |= 4;
		} else if (lan_port == (0x1 << PRTNR_LAN4)) {
			port |= 8;
		}
		if (port == 0xf) {
			break;
		}
	}

	return req_format_write(wp, "%d", port);
}

EJH_ENTRY(macfil_active_port, ej_macfil_active_port);

static int ej_wlan_sel_auto_ch(request *wp, int argc, char **argv, void *data)
{
	char name[64];
	char val[128];

	snprintf(name, sizeof(name), "wlan%d_sel_auto_ch", wlan_idx);
	if (wlan_idx == 1) {
		nvram_get_r_def(name, val, sizeof(val), "1 2 3 4 5 6 7 8 9 10 11");
	}

	return req_format_write(wp, "%s", val);
}
EJH_ENTRY(wlan_sel_auto_ch, ej_wlan_sel_auto_ch);

#define EMIT_DELIM ((n > 0) ? "," : "")
static inline int emit_str(char *buf, int len, int n, char *name, char *p)
{
	return snprintf(&buf[n], len - n, "%s%s%s", EMIT_DELIM, name, p);
}

static char *hex2ip(char *h)
{
	struct in_addr ip;
	struct in6_addr addr;

	if (inet_pton(AF_INET6, h, &addr) <= 0) {
		ip.s_addr = htonl(strtoul(h, NULL, 16));
		return inet_ntoa(ip);
	}

	return h;
}

static char *ruleString(int ruleType, char *rule, char *buf, int len)
{
	int n;
	char *p;
	char *s = rule;

	n = 0;
	switch (ruleType) {
	case 0:
		p = strsep(&s, "_");
		if (p && p[0])
			n += emit_str(buf, len, n, "P:", p);
		p = strsep(&s, "_");
		if (p && p[0])
			n += emit_str(buf, len, n, "Vi:", p);
		p = strsep(&s, "_");
		if (p && p[0])
			n += emit_str(buf, len, n, "Vp:", p);
		p = strsep(&s, "_");
		if (p && p[0])
			n += emit_str(buf, len, n, "SI:", hex2ip(p));
		p = strsep(&s, "_");
		if (p && p[0])
			n += emit_str(buf, len, n, "SIm:", p);
		p = strsep(&s, "_");
		if (p && p[0])
			n += emit_str(buf, len, n, "SPb:", p);
		p = strsep(&s, "_");
		if (p && p[0])
			n += emit_str(buf, len, n, "SPe:", p);
		p = strsep(&s, "_");
		if (p && p[0])
			n += emit_str(buf, len, n, "Act:", p);
		break;

	case 1:
		p = strsep(&s, "_");
		if (p && p[0])
			n += emit_str(buf, len, n, "Vi:", p);
		p = strsep(&s, "_");
		if (p && p[0])
			n += emit_str(buf, len, n, "Vp:", p);
		p = strsep(&s, "_");
		if (p && p[0])
			n += emit_str(buf, len, n, "DI:", hex2ip(p));
		p = strsep(&s, "_");
		if (p && p[0])
			n += emit_str(buf, len, n, "DIm:", p);
		p = strsep(&s, "_");
		if (p && p[0])
			n += emit_str(buf, len, n, "DPb:", p);
		p = strsep(&s, "_");
		if (p && p[0])
			n += emit_str(buf, len, n, "DPe:", p);
		p = strsep(&s, "_");
		if (p && p[0])
			n += emit_str(buf, len, n, "Act:", p);
		break;

	case 2:
		p = strsep(&s, "_");
		if (p && p[0])
			n += emit_str(buf, len, n, "SI:", hex2ip(p));
		p = strsep(&s, "_");
		if (p && p[0])
			n += emit_str(buf, len, n, "SIm:", p);
		p = strsep(&s, "_");
		if (p && p[0])
			n += emit_str(buf, len, n, "DI:", hex2ip(p));
		p = strsep(&s, "_");
		if (p && p[0])
			n += emit_str(buf, len, n, "DIm:", p);
		p = strsep(&s, "_");
		if (p && p[0])
			n += emit_str(buf, len, n, "T:0x", p);
		p = strsep(&s, "_");
		if (p && p[0])
			n += emit_str(buf, len, n, "TM:0x", p);
		p = strsep(&s, "_");
		if (p && p[0])
			n += emit_str(buf, len, n, "Pt:", p);
		p = strsep(&s, "_");
		if (p && p[0])
			n += emit_str(buf, len, n, "Act:", p);
		break;

	case 3:
		p = strsep(&s, "_");
		if (p && p[0])
			n += emit_str(buf, len, n, "SI:", hex2ip(p));
		p = strsep(&s, "_");
		if (p && p[0])
			n += emit_str(buf, len, n, "SIm:", p);
		p = strsep(&s, "_");
		if (p && p[0])
			n += emit_str(buf, len, n, "DI:", hex2ip(p));
		p = strsep(&s, "_");
		if (p && p[0])
			n += emit_str(buf, len, n, "DIm:", p);
		p = strsep(&s, "_");
		if (p && p[0])
			n += emit_str(buf, len, n, "T:0x", p);
		p = strsep(&s, "_");
		if (p && p[0])
			n += emit_str(buf, len, n, "TM:0x", p);
		p = strsep(&s, "_");
		if (p && p[0])
			n += emit_str(buf, len, n, "", toupper(p[0]) == 'T' ? "TCP" : "UDP");
		p = strsep(&s, "_");
		if (p && p[0])
			n += emit_str(buf, len, n, "SPb:", p);
		p = strsep(&s, "_");
		if (p && p[0])
			n += emit_str(buf, len, n, "SPe:", p);
		p = strsep(&s, "_");
		if (p && p[0])
			n += emit_str(buf, len, n, "DPb:", p);
		p = strsep(&s, "_");
		if (p && p[0])
			n += emit_str(buf, len, n, "DPe:", p);
		p = strsep(&s, "_");
		if (p && p[0])
			n += emit_str(buf, len, n, "Act:", p);
		break;

	case 4:
		p = strsep(&s, "_");
		if (p && p[0])
			n += emit_str(buf, len, n, "Vp:", p);
		p = strsep(&s, "_");
		if (p && p[0])
			n += emit_str(buf, len, n, "Act:", p);
		break;

	case 5:
		p = strsep(&s, "_");
		if (p && p[0])
			n += emit_str(buf, len, n, "SI6:", hex2ip(p));
		p = strsep(&s, "_");
		if (p && p[0])
			n += emit_str(buf, len, n, "SIm6:", p);
		p = strsep(&s, "_");
		if (p && p[0])
			n += emit_str(buf, len, n, "DI6:", hex2ip(p));
		p = strsep(&s, "_");
		if (p && p[0])
			n += emit_str(buf, len, n, "DIm6:", p);
		p = strsep(&s, "_");
		if (p && p[0])
			n += emit_str(buf, len, n, "T:0x", p);
		p = strsep(&s, "_");
		if (p && p[0])
			n += emit_str(buf, len, n, "TM:0x", p);
		p = strsep(&s, "_");
		if (p && p[0])
			n += emit_str(buf, len, n, "Pt:", p);
		p = strsep(&s, "_");
		if (p && p[0])
			n += emit_str(buf, len, n, "Act:", p);
		break;

	default:
		strcpy(buf, "알 수 없는 rule\n");
		break;
	}

	return buf;
}

int show_acltbl(request *wp, int argc, char **argv)
{
	int entryNum = 0, i, nCount;
	int nBytesSent = 0, ruleType;
	char buffer[32], value[128], comment[128];
	char *Inf = "", *rule = "", *strTmp;

	nvram_get_r_def("x_Q_R_NUM", value, sizeof(value), "0");
	entryNum = strtol(value, NULL, 10);

	for (i = 0, nCount = 1; nCount <= entryNum; i++) {
		snprintf(buffer, sizeof(buffer), "x_Q_R_%d", i);
		if (!nvram_get_r(buffer, value, sizeof(value))) {
			continue;
		} else {
			nCount++;
		}

		ruleType = atoi(value);
		strTmp = strchr(value, '_');
		if (strTmp && strlen(strTmp) > 1)
			Inf = strTmp + 1;
		strTmp = strchr(Inf, '_');
		if (strTmp && strlen(strTmp) > 1) {
			Inf[strTmp - Inf] = 0;
			rule = strTmp + 1;
		} else {
			rule = "";
		}

		nBytesSent += req_format_write(wp, "<tr bgcolor=#DDDDDD>\n" \
		                               "	<td align=center>%d</td>\n" \
		                               "	<td align=center>%d</td>\n", i + 1, ruleType);
		if (ruleType == 4)
			nBytesSent += req_format_write(wp, "<td align=center>---</td>\n", "");
		else
			nBytesSent += req_format_write(wp, "<td align=center>%s</td>\n", strcasecmp(Inf, "br0") == 0 ? "LAN" : "WAN");

		nBytesSent += req_format_write(wp, "<td>%s</td>\n", ruleString(ruleType, rule, comment, sizeof(comment)));
		nBytesSent += req_format_write(wp, "<td align=center><input type='checkbox' name='Q_R_%d' value='1'></td></tr>\n", i);
	}

	return nBytesSent;
}

static void formDelete_acl(request *wp, char *path, char *query)
{
	int i, j, entryNum = 0;
	char request[32], value[80];
	char buf[32];
	char *str;

	if (nvram_get_r("x_Q_R_NUM", value, sizeof(value))) {
		entryNum = strtol(value, NULL, 10);
	}

	if (entryNum <= 0) {
		printf("error entryNum\n");
		send_redirect_perm(wp, "/qosacl.htm");
		return;
	}

	for (i = 0; i < entryNum; i++) {
		snprintf(request, sizeof(request), "Q_R_%d", i);
		str = req_get_cstream_var(wp, request, "");
		if (!str[0])
			continue;
		printf("formDelete_acl(): delete %s\n", request);
		snprintf(value, sizeof(value), "x_%s", request);
		nvram_unset(value);
	}

	for (i = 0, j = 0; i < entryNum; i++) {
		snprintf(request, sizeof(request), "x_Q_R_%d", i);
		if (nvram_get_r(request, value, sizeof(value))) {
			if (i != j) {
				snprintf(buf, sizeof(buf), "x_Q_R_%d", j);
				nvram_set(buf, value);
				nvram_unset(request);
			}
			j++;
		}
	}

	if (j != entryNum) {
		snprintf(value, sizeof(value), "%d", j);
		nvram_set("x_Q_R_NUM", value);
	}

	send_redirect_perm(wp, "/qosacl.htm");
	nvram_commit();
	yexecl(NULL, "dvqos --apply");
}

void formAclSetup(request *wp, char *path, char *query)
{
	char *postValue, *strUseSrcIp;
	char value[80], errMsg[128], rule[128];
	int ToSValue, ruleType;
	char *strUsePhyPort, *strPhyPort, *strUseSrcPort;
	char *strUseVlan, *strVLANID = NULL;
	char *strSIP0, *strSIP1, *strSIP2, *strSIP3;
	char *strDIP0, *strDIP1, *strDIP2, *strDIP3;
	char *SourceIPv6, *DestIPv6;
	unsigned int SourceIP, DestIP;
	struct in6_addr addr;
	char *strSrcIpMask, *strDstIpMask, *strSrcIpv6Mask, *strDstIpv6Mask;
	char *strSrcPortFrom, *strSrcPortTo, *strDstPortFrom, *strDstPortTo;
	char *strUsePriority, *strLevel2Priority;
	char *strAction, *strIntPriority;
	char *strUseToS, *strToSValue, *strProtocol;
	int proto, entryNum = 0;

	if (wp->superUser != 1)
		return;

	postValue = req_get_cstream_var(wp, "delete", "");
	if (postValue[0]) {
		formDelete_acl(wp, path, query);
		return;
	}

	if (nvram_get_r("x_Q_R_NUM", value, sizeof(value)))
		entryNum = strtol(value, NULL, 10);

	if (entryNum >= 200) {
		snprintf(errMsg, sizeof(errMsg), "Rule이 너무 많습니다. 최대 200까지만 가능합니다.");
		goto setErr;
	}

	entryNum += 1;

	printf("ACL Tabled Add Query:%s\n", query);
	postValue = req_get_cstream_var(wp, "ruleType", "");
	if (postValue[0] == 0) {
		snprintf(errMsg, sizeof(errMsg), "Rule 형식을 얻을 수 없습니다.");
		goto setErr;
	}

	ruleType = (strtol(postValue, NULL, 10) - 1);
	postValue = req_get_cstream_var(wp, "side", "");
	printf("ACL Table From: %s, rule Type:%d\n", postValue, ruleType);

	if (postValue[0] == '0' || ruleType == 4)
		snprintf(rule, sizeof(rule), "%d_br0_", ruleType);
	else if (postValue[0] == '1')
		snprintf(rule, sizeof(rule), "%d_eth1_", ruleType);
	else
		snprintf(errMsg, sizeof(errMsg), "포트를 알 수 없습니다...\n");

	switch (ruleType) {
	case 0:
		strUsePhyPort = req_get_cstream_var(wp, "physical_use", "");
		if (!strUsePhyPort[0] || strUsePhyPort[0] == '0') {
			snprintf(errMsg, sizeof(errMsg), "Physical 포트 사용을 알 수 없습니다..");
			goto setErr;
		}

		strPhyPort = req_get_cstream_var(wp, "physical_port", "");
		if (strPhyPort[0])
			snprintf(rule, sizeof(rule), "%s%c_", rule, strPhyPort[0]);
		else
			snprintf(rule, sizeof(rule), "%s_", rule);

		strUseVlan = req_get_cstream_var(wp, "vlan_use", "");
		if (strUseVlan[0] == '1')
			strVLANID = req_get_cstream_var(wp, "vlan_value", "");

		if (strVLANID && strVLANID[0])
			strcat(rule, strVLANID);
		strcat(rule, "_");
		strcat(rule, "_");

		strUseSrcIp = req_get_cstream_var(wp, "srcip_use", "");
		strSIP0 = req_get_cstream_var(wp, "srcip0", "");
		strSIP1 = req_get_cstream_var(wp, "srcip1", "");
		strSIP2 = req_get_cstream_var(wp, "srcip2", "");
		strSIP3 = req_get_cstream_var(wp, "srcip3", "");

		SourceIPv6 = req_get_cstream_var(wp, "srcipv6", "");

		SourceIP = atoi(strSIP0) * 0x1000000 + atoi(strSIP1) * 0x10000
		           + atoi(strSIP2) * 0x100 + atoi(strSIP3);

		if (SourceIP) {
			snprintf(value, sizeof(value), "%08x_", SourceIP);
			strcat(rule, value);
		} else if (SourceIPv6[0]) {
			if ((inet_pton(AF_INET6, SourceIPv6, &addr) <= 0)) {
				snprintf(errMsg, sizeof(errMsg), "입력하신 출발지 주소가 IPv6 형식이 아닙니다.");
				goto setErr;
			}
			snprintf(value, sizeof(value), "%s_", SourceIPv6);
			strcat(rule, value);
		} else {
			strcat(rule, "_");
		}

		strSrcIpMask = req_get_cstream_var(wp, "srcip_mask", "");
		strSrcIpv6Mask = req_get_cstream_var(wp, "srcipv6_mask", "");

		if (*strSrcIpMask && atoi(strSrcIpMask) > 0) {
			snprintf(value, sizeof(value), "%d", atoi(strSrcIpMask));
			strcat(rule, value);
		} else if (*strSrcIpv6Mask && atoi(strSrcIpv6Mask) > 0) {
			snprintf(value, sizeof(value), "%d", atoi(strSrcIpv6Mask));
			strcat(rule, value);
		}
		strcat(rule, "_");

		strUseSrcPort = req_get_cstream_var(wp, "srcport_use", "");
		strSrcPortFrom = req_get_cstream_var(wp, "srcport0", "");
		if (*strSrcPortFrom)
			strcat(rule, strSrcPortFrom);
		strcat(rule, "_");

		strSrcPortTo = req_get_cstream_var(wp, "srcport1", "");

		if (strSrcPortTo[0])
			strcat(rule, strSrcPortTo);
		strcat(rule, "_");

		break;
	case 1:
		strVLANID = req_get_cstream_var(wp, "vlan_value", "");
		if (strVLANID)
			strcat(rule, strVLANID);
		strcat(rule, "_");
		strcat(rule, "_");

		strDIP0 = req_get_cstream_var(wp, "dstip0", "");
		strDIP1 = req_get_cstream_var(wp, "dstip1", "");
		strDIP2 = req_get_cstream_var(wp, "dstip2", "");
		strDIP3 = req_get_cstream_var(wp, "dstip3", "");

		DestIPv6 = req_get_cstream_var(wp, "dstipv6", "");

		DestIP = atoi(strDIP0) * 0x1000000 + atoi(strDIP1) * 0x10000
		         + atoi(strDIP2) * 0x100 + atoi(strDIP3);

		if (DestIP) {
			snprintf(value, sizeof(value), "%08x_", DestIP);
			strcat(rule, value);
		} else if (DestIPv6[0]) {
			if ((inet_pton(AF_INET6, DestIPv6, &addr) <= 0)) {
				snprintf(errMsg, sizeof(errMsg), "입력하신 목적지 주소가 IPv6 형식이 아닙니다.");
				goto setErr;
			}
			snprintf(value, sizeof(value), "%s_", DestIPv6);
			strcat(rule, value);
		} else {
			strcat(rule, "_");
		}

		strDstIpMask = req_get_cstream_var(wp, "dstip_mask", "");
		strDstIpv6Mask = req_get_cstream_var(wp, "dstipv6_mask", "");

		if (strDstIpMask[0] && atoi(strDstIpMask) > 0) {
			snprintf(value, sizeof(value), "%d", atoi(strDstIpMask));
			strcat(rule, value);
		} else if (strDstIpv6Mask[0] && atoi(strDstIpv6Mask) > 0) {
			snprintf(value, sizeof(value), "%d", atoi(strDstIpv6Mask));
			strcat(rule, value);
		}
		strcat(rule, "_");

		strDstPortFrom = req_get_cstream_var(wp, "dstport0", "");
		if (strDstPortFrom[0])
			strcat(rule, strDstPortFrom);
		strcat(rule, "_");

		strDstPortTo = req_get_cstream_var(wp, "dstport1", "");

		if (strDstPortTo[0])
			strcat(rule, strDstPortTo);
		strcat(rule, "_");
		break;
	case 2:
		strSIP0 = req_get_cstream_var(wp, "srcip0", "");
		strSIP1 = req_get_cstream_var(wp, "srcip1", "");
		strSIP2 = req_get_cstream_var(wp, "srcip2", "");
		strSIP3 = req_get_cstream_var(wp, "srcip3", "");

		SourceIPv6 = req_get_cstream_var(wp, "srcipv6", "");

		SourceIP = atoi(strSIP0) * 0x1000000 + atoi(strSIP1) * 0x10000
		           + atoi(strSIP2) * 0x100 + atoi(strSIP3);

		if (SourceIP) {
			snprintf(value, sizeof(value), "%08x_", SourceIP);
			strcat(rule, value);
		} else if (SourceIPv6[0]) {
			if ((inet_pton(AF_INET6, SourceIPv6, &addr) <= 0)) {
				snprintf(errMsg, sizeof(errMsg), "입력하신 출발지 주소가 IPv6 형식이 아닙니다.");
				goto setErr;
			}
			snprintf(value, sizeof(value), "%s_", SourceIPv6);
			strcat(rule, value);
		} else {
			strcat(rule, "_");
		}

		strSrcIpMask = req_get_cstream_var(wp, "srcip_mask", "");
		strSrcIpv6Mask = req_get_cstream_var(wp, "srcipv6_mask", "");

		if (strSrcIpMask[0] && atoi(strSrcIpMask) > 0) {
			snprintf(value, sizeof(value), "%d", atoi(strSrcIpMask));
			strcat(rule, value);
		} else if (*strSrcIpv6Mask && atoi(strSrcIpv6Mask) > 0) {
			snprintf(value, sizeof(value), "%d", atoi(strSrcIpv6Mask));
			strcat(rule, value);
		}
		strcat(rule, "_");

		strDIP0 = req_get_cstream_var(wp, "dstip0", "");
		strDIP1 = req_get_cstream_var(wp, "dstip1", "");
		strDIP2 = req_get_cstream_var(wp, "dstip2", "");
		strDIP3 = req_get_cstream_var(wp, "dstip3", "");

		DestIPv6 = req_get_cstream_var(wp, "dstipv6", "");

		DestIP = atoi(strDIP0) * 0x1000000 + atoi(strDIP1) * 0x10000
		         + atoi(strDIP2) * 0x100 + atoi(strDIP3);

		if (DestIP) {
			snprintf(value, sizeof(value), "%08x_", DestIP);
			strcat(rule, value);
		} else if (DestIPv6[0]) {
			if ((inet_pton(AF_INET6, DestIPv6, &addr) <= 0)) {
				snprintf(errMsg, sizeof(errMsg), "입력하신 목적지 주소가 IPv6 형식이 아닙니다.");
				goto setErr;
			}
			snprintf(value, sizeof(value), "%s_", DestIPv6);
			strcat(rule, value);
		} else {
			strcat(rule, "_");
		}

		strDstIpMask = req_get_cstream_var(wp, "dstip_mask", "");
		strDstIpv6Mask = req_get_cstream_var(wp, "dstipv6_mask", "");

		if (strDstIpMask[0] && atoi(strDstIpMask) > 0) {
			snprintf(value, sizeof(value), "%d", atoi(strDstIpMask));
			strcat(rule, value);
		} else if (strDstIpv6Mask[0] && atoi(strDstIpv6Mask) > 0) {
			snprintf(value, sizeof(value), "%d", atoi(strDstIpv6Mask));
			strcat(rule, value);
		}
		strcat(rule, "_");

		strUseToS = req_get_cstream_var(wp, "tos_use", "0");
		if (strUseToS[0] == '1') { // Check Using TOS
			strToSValue = req_get_cstream_var(wp, "tos_value", "0");
			ToSValue = strtol(strToSValue, NULL, 16);
			snprintf(value, sizeof(value), "%02x_ff_", ToSValue);
		} else {
			strUseToS = req_get_cstream_var(wp, "dscp_use", "0");
			if (strUseToS[0] == '1') {	// Checck Using DSCP
				strToSValue = req_get_cstream_var(wp, "dscp_value", "0");
				ToSValue = atoi(strToSValue) << 2;
				snprintf(value, sizeof(value), "%02x_fc_", ToSValue);
			} else {
				strcpy(value, "__");
			}
		}
		strcat(rule, value);

		strProtocol = req_get_cstream_var(wp, "protocol_val", "");
		if (strProtocol[0]) {
			if (atoi(strProtocol) == 99) {
				char *etc_proto;
				etc_proto = req_get_cstream_var(wp, "etc_proto_val", "");
				if (etc_proto[0])
					strcat(rule, etc_proto);
			} else {
				strcat(rule, strProtocol);
			}
		}
		strcat(rule, "_");
		break;
	case 3:
		strSIP0 = req_get_cstream_var(wp, "srcip0", "");
		strSIP1 = req_get_cstream_var(wp, "srcip1", "");
		strSIP2 = req_get_cstream_var(wp, "srcip2", "");
		strSIP3 = req_get_cstream_var(wp, "srcip3", "");

		SourceIPv6 = req_get_cstream_var(wp, "srcipv6", "");

		SourceIP = atoi(strSIP0) * 0x1000000 + atoi(strSIP1) * 0x10000
		           + atoi(strSIP2) * 0x100 + atoi(strSIP3);

		if (SourceIP) {
			snprintf(value, sizeof(value), "%08x_", SourceIP);
			strcat(rule, value);
		} else if (SourceIPv6[0]) {
			if ((inet_pton(AF_INET6, SourceIPv6, &addr) <= 0)) {
				snprintf(errMsg, sizeof(errMsg), "입력하신 출발지 주소가 IPv6 형식이 아닙니다.");
				goto setErr;
			}
			snprintf(value, sizeof(value), "%s_", SourceIPv6);
			strcat(rule, value);
		} else {
			strcat(rule, "_");
		}

		strSrcIpMask = req_get_cstream_var(wp, "srcip_mask", "");
		strSrcIpv6Mask = req_get_cstream_var(wp, "srcipv6_mask", "");

		if (strSrcIpMask[0] && atoi(strSrcIpMask) > 0) {
			snprintf(value, sizeof(value), "%d", atoi(strSrcIpMask));
			strcat(rule, value);
		} else if (*strSrcIpv6Mask && atoi(strSrcIpv6Mask) > 0) {
			snprintf(value, sizeof(value), "%d", atoi(strSrcIpv6Mask));
			strcat(rule, value);
		}
		strcat(rule, "_");

		strDIP0 = req_get_cstream_var(wp, "dstip0", "");
		strDIP1 = req_get_cstream_var(wp, "dstip1", "");
		strDIP2 = req_get_cstream_var(wp, "dstip2", "");
		strDIP3 = req_get_cstream_var(wp, "dstip3", "");

		DestIPv6 = req_get_cstream_var(wp, "dstipv6", "");

		DestIP = atoi(strDIP0) * 0x1000000 + atoi(strDIP1) * 0x10000
		         + atoi(strDIP2) * 0x100 + atoi(strDIP3);

		if (DestIP) {
			snprintf(value, sizeof(value), "%08x_", DestIP);
			strcat(rule, value);
		} else if (DestIPv6[0]) {
			if ((inet_pton(AF_INET6, DestIPv6, &addr) <= 0)) {
				snprintf(errMsg, sizeof(errMsg), "입력하신 목적지 주소가 IPv6 형식이 아닙니다.");
				goto setErr;
			}
			snprintf(value, sizeof(value), "%s_", DestIPv6);
			strcat(rule, value);
		} else {
			strcat(rule, "_");
		}

		strDstIpMask = req_get_cstream_var(wp, "dstip_mask", "");
		strDstIpv6Mask = req_get_cstream_var(wp, "dstipv6_mask", "");

		if (strDstIpMask[0] && atoi(strDstIpMask) > 0) {
			snprintf(value, sizeof(value), "%d", atoi(strDstIpMask));
			strcat(rule, value);
		} else if (strDstIpv6Mask[0] && atoi(strDstIpv6Mask) > 0) {
			snprintf(value, sizeof(value), "%d", atoi(strDstIpv6Mask));
			strcat(rule, value);
		}
		strcat(rule, "_");

		strUseToS = req_get_cstream_var(wp, "tos_use", "0");
		if (strUseToS[0] == '1') { // Check Using TOS
			strToSValue = req_get_cstream_var(wp, "tos_value", "0");
			ToSValue = strtol(strToSValue, NULL, 16);
			snprintf(value, sizeof(value), "%02x_ff_", ToSValue);
		} else {
			strUseToS = req_get_cstream_var(wp, "dscp_use", "0");
			if (strUseToS[0] == '1') {	// Checck Using DSCP
				strToSValue = req_get_cstream_var(wp, "dscp_value", "0");
				ToSValue = atoi(strToSValue) << 2;
				snprintf(value, sizeof(value), "%02x_fc_", ToSValue);
			} else {
				strcpy(value, "__");
			}
		}
		strcat(rule, value);

		strProtocol = req_get_cstream_var(wp, "protocol_val", "");
		if (strProtocol[0] && (atoi(strProtocol) == 6 || atoi(strProtocol) == 17)) {
			if (atoi(strProtocol) == 6)
				strcat(rule, "t_");
			else
				strcat(rule, "u_");
		} else {
			snprintf(errMsg, sizeof(errMsg), "프로토콜이 올바르지 않습니다(%s). TCP 또는 UDP를 선택해하여 주십시오.", strProtocol);
			goto setErr;
		}

		strSrcPortFrom = req_get_cstream_var(wp, "srcport0", "");
		if (strSrcPortFrom[0])
			strcat(rule, strSrcPortFrom);
		strcat(rule, "_");

		strSrcPortTo = req_get_cstream_var(wp, "srcport1", "");
		if (strSrcPortTo[0])
			strcat(rule, strSrcPortTo);
		strcat(rule, "_");


		strDstPortFrom = req_get_cstream_var(wp, "dstport0", "");
		if (strDstPortFrom[0])
			strcat(rule, strDstPortFrom);
		strcat(rule, "_");

		strDstPortTo = req_get_cstream_var(wp, "dstport1", "");
		if (strDstPortTo[0])
			strcat(rule, strDstPortTo);
		strcat(rule, "_");

		break;
	case 4:
		strUsePriority = req_get_cstream_var(wp, "l2priority", "");
		strLevel2Priority = req_get_cstream_var(wp, "l2priority_val", "");
		if (*strLevel2Priority)
			strcat(rule, strLevel2Priority);
		strcat(rule, "_");
		break;
	case 5:
		if ((SourceIPv6 = req_get_cstream_var(wp, "srcipv6", "")) && SourceIPv6[0]) {
			if ((inet_pton(AF_INET6, SourceIPv6, &addr) <= 0)) {
				snprintf(errMsg, sizeof(errMsg), "입력하신 출발지 주소가 IPv6 형식이 아닙니다.");
				goto setErr;
			}
			snprintf(value, sizeof(value), "%s_", SourceIPv6);
			strcat(rule, value);
		} else {
			strcat(rule, "_");
		}

		strSrcIpv6Mask = req_get_cstream_var(wp, "srcipv6_mask", "");
		if (*strSrcIpv6Mask && atoi(strSrcIpv6Mask) > 0) {
			snprintf(value, sizeof(value), "%d", atoi(strSrcIpv6Mask));
			strcat(rule, value);
		}

		strcat(rule, "_");
		if ((DestIPv6 = req_get_cstream_var(wp, "dstipv6", "")) && DestIPv6[0]) {
			if ((inet_pton(AF_INET6, DestIPv6, &addr) <= 0)) {
				snprintf(errMsg, sizeof(errMsg), "입력하신 목적지 주소가 IPv6 형식이 아닙니다.");
				goto setErr;
			}
			snprintf(value, sizeof(value), "%s_", DestIPv6);
			strcat(rule, value);
		} else {
			strcat(rule, "_");
		}
		strDstIpv6Mask = req_get_cstream_var(wp, "dstipv6_mask", "");

		if (strDstIpv6Mask[0] && atoi(strDstIpv6Mask) > 0) {
			snprintf(value, sizeof(value), "%d", atoi(strDstIpv6Mask));
			strcat(rule, value);
		}
		strcat(rule, "_");

		strUseToS = req_get_cstream_var(wp, "tos_use", "0");
		if (strUseToS[0] == '1') { // Check Using TOS
			strToSValue = req_get_cstream_var(wp, "tos_value", "0");
			ToSValue = strtol(strToSValue, NULL, 16);
			snprintf(value, sizeof(value), "%02x_ff_", ToSValue);
		} else {
			strcpy(value, "__");
		}
		strcat(rule, value);

		strProtocol = req_get_cstream_var(wp, "protocol_val", "");
		if (strProtocol[0]) {
			if ((proto = atoi(strProtocol)) == 99) {
				char *etc_proto;
				etc_proto = req_get_cstream_var(wp, "etc_proto_val", "");
				if (etc_proto[0])
					strcat(rule, etc_proto);
			} else {
				strcat(rule, strProtocol);
			}
		}
		strcat(rule, "_");
		break;
	default:
		strcpy(errMsg, "Rule 형식을 알 수 없습니다.");
		goto setErr;
		break;
	}
	strAction = req_get_cstream_var(wp, "qos_action", "");

	if (strAction[0]) {
		if (strAction[0] == '0') {
			strcat(rule, "d");
		} else {
			int IntPrior = -1;

			strIntPriority = req_get_cstream_var(wp, "int_pri", "");
			if (strIntPriority[0])
				IntPrior = atoi(strIntPriority);
			if (IntPrior >= 0 && IntPrior <= 7) {
				strcat(rule, strIntPriority);
			} else {
				strcpy(errMsg, "int.priority ACTION이 정의되지 않았습니다.");
				goto setErr;
			}
		}
	} else {
		strcpy(errMsg, "ACTION이 정의되지 않았습니다.");
		goto setErr;
	}
	{
		char Field[12];
		char *ipv6;

		snprintf(Field, sizeof(Field), "x_Q_R_%d", entryNum - 1);
		ipv6 = req_get_cstream_var(wp, "ipmode", "");
		if (ipv6[0] == '1') // ipv6 mode
			strcat(rule, "_v6");
		printf("RULE: %s=%s\n", Field, rule);
		nvram_set(Field, rule);
	}

	snprintf(value, sizeof(value), "%d", entryNum);
	nvram_set("x_Q_R_NUM", value);

	send_redirect_perm(wp, "/qosacl.htm");

	nvram_commit();

	yexecl(NULL, "dvqos --apply");

	return;
setErr:
	ERR_MSG(errMsg);
	return;
}

static int ej_qos_init_js(request *wp, int argc, char **argv, void *data)
{
	int i, j;
	char name[32], value[32];
	char *p;
	int len = 0;

	for (i = 0; i < 5; i++) {
		snprintf(name, sizeof(name), "x_QOS_ENABLE_%d", i);
		nvram_get_r_def(name, value, sizeof(value), "0");
		len += req_format_write(wp, "q_enable[%d]=%s;\n", i, value);

		snprintf(name, sizeof(name), "x_QOS_RATE_ENABLE_%d", i);
		nvram_get_r_def(name, value, sizeof(value), "0");
		len += req_format_write(wp, "r_enable[%d]=%s;\n", i, value);

		snprintf(name, sizeof(name), "x_QOS_RATE_I_%d", i);
		nvram_get_r_def(name, value, sizeof(value), "0");
		len += req_format_write(wp, "q_inrate[%d]=%s;\n", i, value);

		snprintf(name, sizeof(name), "x_QOS_RATE_O_%d", i);
		nvram_get_r_def(name, value, sizeof(value), "0");
		len += req_format_write(wp, "q_outrate[%d]=%s;\n", i, value);

		for (j = 0; j < 4; j++) {
			snprintf(name, sizeof(name), "x_QOS_Q_%d_%d", i, j);
			nvram_get_r_def(name, value, sizeof(value), "W_0_1");
			if ((p = strtok(value, "_")) == NULL)
				p = "W";
			len += req_format_write(wp, "q_qtype[%d][%d]=\"%s\";\n", i, j, toupper(p[0]) == 'W' ? "WFQ" : "SPQ");
			if ((p = strtok(NULL, "_")) == NULL)
				p = "0";
			len += req_format_write(wp, "q_qrate[%d][%d]=%s;\n", i, j, p);
			if ((p = strtok(NULL, "_")) == NULL)
				p = "1";
			len += req_format_write(wp, "q_qweight[%d][%d]=%s;\n", i, j, p);
		}
	}

	return len;
}

EJH_ENTRY(qosQ_init_js, ej_qos_init_js);

void formQosQue(request *wp, char * path, char * query)
{
	char *strPort, *str;
	int port = 0;
	char name[32], value[32], buffer[32];
	int i, n = 0;
	int qos_enable = 0, qos_rate_enable;

	if (wp->superUser != 1)
		return;

	if ((strPort = req_get_cstream_var(wp, "port_num", ""))) {
		port = strtoul(strPort, NULL, 10);
		snprintf(name, sizeof(name), "x_QOS_ENABLE_%d", port);
	}

	if ((str = req_get_cstream_var(wp, "que_enable", "off"))) {
		if (strcmp(str, "on") == 0) {
			qos_enable = 1;
			snprintf(value, sizeof(value), "1");
		} else {
			qos_enable = 0;
			snprintf(value, sizeof(value), "0");
		}

		nvram_set(name, value);
	}

	if (qos_enable) {
		for (i = 0; i < 4; i++) {
			snprintf(name, sizeof(name), "x_QOS_Q_%d_%d", port, i);
			snprintf(buffer, sizeof(buffer), "qtype%d", i);
			if ((str = req_get_cstream_var(wp, buffer, "WFQ"))) {
				n = snprintf(value, sizeof(value), "%c",  str[0]);
				snprintf(buffer, sizeof(buffer), "qrate%d", i);
				if ((str = req_get_cstream_var(wp, buffer, "0"))) {
					n += snprintf(&value[n], sizeof(value) - n, "_%s", str);
				}
			}

			snprintf(buffer, sizeof(buffer), "qweight%d", i);
			if ((str = req_get_cstream_var(wp, buffer, "1")))
				n += snprintf(&value[n], sizeof(value) - n, "_%s", str);

			nvram_set(name, value);
		}
	}

	if ((str = req_get_cstream_var(wp, "rate_enable", "off"))) {
		if (strcmp(str, "on") == 0)
			snprintf(value, sizeof(value), "1");
		else
			snprintf(value, sizeof(value), "0");

		snprintf(name, sizeof(name), "x_QOS_RATE_ENABLE_%d", port);
		nvram_set(name, value);

		qos_rate_enable = strtol(value, NULL, 10);
		if (qos_rate_enable) {
			if ((str = req_get_cstream_var(wp, "in_rate", "0"))) {
				snprintf(value, sizeof(value), "%s", str);
				snprintf(name, sizeof(name), "x_QOS_RATE_I_%d", port);
				nvram_set(name, value);
			}

			if ((str = req_get_cstream_var(wp, "out_rate", "0"))) {
				snprintf(value, sizeof(value), "%s", str);
				snprintf(name, sizeof(name), "x_QOS_RATE_O_%d", port);
				nvram_set(name, value);
			}
		}
	}

	send_redirect_perm(wp, "/qosque.htm");

	nvram_commit();
	yexecl(NULL, "dvqos --apply");
	return;
}

static int ej_qos_remark_js(request *wp, int argc, char **argv, void *data)
{
	char *p;
	int pbs, i;
	char buffer[32];
	int len = 0;

	nvram_get_r_def("x_QOS_RM_1Q", buffer, sizeof(buffer), "0_0_1_2_3_4_5_6_7");

	if ((p = strtok(buffer, "_")) == NULL)
		p = "0";

	pbs = strtoul(p, NULL, 16);
	len += req_format_write(wp, "q_use_tag=%s;\n", pbs ? "1" : "0");

	for (i = 0; i < 5; i++) {
		len += req_format_write(wp, "q_tag_p[%d]=%s;\n", i, (pbs & (0x01 << i)) ? "1" : "0");
	}

	for (i = 0; i < 8; i++) {
		if ((p = strtok(NULL, "_")) == NULL)
			p = "0";

		len += req_format_write(wp, "q_tag[%d]=%s;\n", i, p);
	}

	nvram_get_r_def("x_QOS_RM_DSCP", buffer, sizeof(buffer), "0_0_0_0_0_46_46_46_46");

	if ((p = strtok(buffer, "_")) == NULL)
		p = "0";

	pbs = strtoul(p, NULL, 16);
	len += req_format_write(wp, "q_use_dscp=%s;\n", pbs ? "1" : "0");

	for (i = 0; i < 5; i++) {
		len += req_format_write(wp, "q_dscp_p[%d]=%s;\n", i, (pbs & (0x01 << i)) ? "1" : "0");
	}

	for (i = 0; i < 8; i++) {
		if ((p = strtok(NULL, "_")) == NULL)
			p = "0";

		len += req_format_write(wp, "q_dscp[%d]=%s;\n", i, p);
	}

	return len;
}

EJH_ENTRY(qos_remark_js, ej_qos_remark_js);

void formRemark(request *wp, char * path, char * query)
{
	char tmpBuf[40], tmp[20];
	int i, portbits = 0, n = 0;
	char *str[5];

	if (wp->superUser == 0)
		return;

	str[0] = req_get_cstream_var(wp, ("use_tag"), "off");
	if (strcmp(str[0], "on") == 0) {
		str[PRTNR_WAN0] = req_get_cstream_var(wp, ("tag_wan"), "off");
		str[PRTNR_LAN1] = req_get_cstream_var(wp, ("tag_lan1"), "off");
		str[PRTNR_LAN2] = req_get_cstream_var(wp, ("tag_lan2"), "off");
		str[PRTNR_LAN3] = req_get_cstream_var(wp, ("tag_lan3"), "off");
		str[PRTNR_LAN4] = req_get_cstream_var(wp, ("tag_lan4"), "off");

		for (i = 0; i < 5; i++) {
			if (strcmp(str[i], "on") == 0) {
				portbits |= (0x01 << i);
			}
		}
	}

	if (portbits == 0) {
		nvram_set("x_QOS_RM_1Q", "0_0_1_2_3_4_5_6_7");
	} else {
		n = 0;
		n = snprintf(tmpBuf, sizeof(tmpBuf), "%02X", portbits);
		for (i = 0; i < 8; i++) {
			snprintf(tmp, sizeof(tmp), "tag_%d", i);
			str[0] = req_get_cstream_var(wp, tmp, "off");
			n += snprintf(&tmpBuf[n], sizeof(tmpBuf) - n, "_%s", str[0]);
		}
		nvram_set("x_QOS_RM_1Q", tmpBuf);
	}

	str[0] = req_get_cstream_var(wp, ("use_dscp"), "off");
	portbits = 0;

	if (strcmp(str[0], "on") == 0) {
		str[PRTNR_WAN0] = req_get_cstream_var(wp, ("dscp_wan"), "off");
		str[PRTNR_LAN1] = req_get_cstream_var(wp, ("dscp_lan1"), "off");
		str[PRTNR_LAN2] = req_get_cstream_var(wp, ("dscp_lan2"), "off");
		str[PRTNR_LAN3] = req_get_cstream_var(wp, ("dscp_lan3"), "off");
		str[PRTNR_LAN4] = req_get_cstream_var(wp, ("dscp_lan4"), "off");

		for (i = 0; i < 5; i++) {
			if (strcmp(str[i], "on") == 0) {
				portbits |= (0x01 << i);
			}
		}
	}

	if (portbits == 0) {
		nvram_set("x_QOS_RM_DSCP", "0_0_0_0_0_46_46_46_46");
	} else {
		n = 0;
		n = snprintf(tmpBuf, sizeof(tmpBuf), "%02X", portbits);
		for (i = 0; i < 8; i++) {
			snprintf(tmp, sizeof(tmp), "dscp_%d", i);
			str[0] = req_get_cstream_var(wp, tmp, "off");
			n += snprintf(&tmpBuf[n], sizeof(tmpBuf) - n, "_%s", str[0]);
		}
		nvram_set("x_QOS_RM_DSCP", tmpBuf);
	}

	send_redirect_perm(wp, "/qosremark.htm");

	nvram_commit();

	yexecl(NULL, "dvqos --apply");

	return;
}

static int ej_navi_js(request *wp, int argc, char **argv, void *unused)
{
	return req_format_write(wp, "%s", (wp->superUser) ? "navigation.js" : "navigation_user.js");
}

EJH_ENTRY(navi_js, ej_navi_js);

#define _DHCPC_PROG_NAME	"udhcpc"
#define _DHCPC_PID_PATH		"/etc/udhcpc"

static void send_renewal_dhcpc(void)
{
	char tmpBuf[128], ifmode[32];
	int pid, opmode = 0;

	if (!apmib_get(MIB_OP_MODE, (void *)&opmode))
		return;

	if (opmode == 1)
		snprintf(ifmode, sizeof(ifmode), "-br0");
	else
		snprintf(ifmode, sizeof(ifmode), "-eth1");

	snprintf(tmpBuf, sizeof(tmpBuf), "%s/%s%s.pid", _DHCPC_PID_PATH, _DHCPC_PROG_NAME, ifmode);

	pid = fget_and_test_pid(tmpBuf);
	if (pid > 0) {
		kill(pid, SIGUSR2);
		usleep(500000);
		kill(pid, SIGUSR1);
	}
}

void formWanIpRenewal(request *wp, char *path, char *query)
{
	char *submitUrl;

	submitUrl = req_get_cstream_var(wp, "submit-url", "/status.htm");
	if (submitUrl[0]) {
		send_renewal_dhcpc();
		DO_APPLY_WAIT("/status.htm");
		return;
	}
}

int ej_wlAcMACList(request *wp, int argc, char **argv, void *unused)
{
	int nBytesSent = 0, entryNum, i, old;
	MACFILTER_T entry;
	char tmpBuf[100];

	old = vwlan_idx;
	vwlan_idx = atoi(argv[1]);
	if (!apmib_get(MIB_WLAN_MACAC_NUM, (void *)&entryNum)) {
		nBytesSent += req_format_write(wp, "");
	} else {
		for (i = 1; i <= entryNum; i++) {
			*((char *)&entry) = (char)i;
			if (!apmib_get(MIB_WLAN_MACAC_ADDR, (void *)&entry))
				break;

			snprintf(tmpBuf, 100, "'%02x:%02x:%02x:%02x:%02x:%02x'",
			         entry.macAddr[0], entry.macAddr[1], entry.macAddr[2],
			         entry.macAddr[3], entry.macAddr[4], entry.macAddr[5]);

			if (i == 1) {
				nBytesSent += req_format_write(wp, "%s", tmpBuf);
			} else {
				nBytesSent += req_format_write(wp, ",%s", tmpBuf);
			}
		}
	}
	vwlan_idx = old;
	return nBytesSent;
}

int ej_wlAcCommentList(request *wp, int argc, char **argv, void *unused)
{
	int nBytesSent = 0, entryNum, i, old;
	MACFILTER_T entry;
	char tmpBuf[100];

	old = vwlan_idx;
	vwlan_idx = atoi(argv[1]);
	if (!apmib_get(MIB_WLAN_MACAC_NUM, (void *)&entryNum)) {
		nBytesSent += req_format_write(wp, "");
	} else {
		for (i = 1; i <= entryNum; i++) {
			*((char *)&entry) = (char)i;
			if (!apmib_get(MIB_WLAN_MACAC_ADDR, (void *)&entry))
				break;
			escape_special(tmpBuf, (char *)entry.comment, sizeof(tmpBuf));
			translate_control_code(tmpBuf);
			if (i == 1) {
				nBytesSent += req_format_write(wp, "'%s'", tmpBuf);
			} else {
				nBytesSent += req_format_write(wp, ",'%s'", tmpBuf);
			}
		}
	}
	vwlan_idx = old;
	return nBytesSent;
}

EJH_ENTRY(wlAcMACList, ej_wlAcMACList);
EJH_ENTRY(wlAcCommentList, ej_wlAcCommentList);

/*** WPS ****/
static int ej_wscDisable(request *wp, int argc, char **argv, void *unused)
{
	int len = 0;
	int wsc_disable = 0;
	if (nvram_atoi("WLAN0_WSC_DISABLE", 1)) {
		wsc_disable |= 0x1 ;
	}
	if (nvram_atoi("WLAN1_WSC_DISABLE", 1)) {
		wsc_disable |= 0x2 ;
	}
	len += req_format_write(wp, "%d", (wsc_disable == 0x3) ? 1 : 0);
	return len;
}

static int ej_wscPossible(request *wp, int argc, char **argv, void *unused)
{
	int i, len = 0;
	int wsc_possible = 0;
	char nv_name[32];
	int intVal;

	/* WPA2 + AES, not HIDDEN_SSID */
	for (i = 0; i < 2; i++) {
		snprintf(nv_name, sizeof(nv_name), "WLAN%d_WLAN_DISABLED", i);
		if (nvram_atoi(nv_name, 1)) {
			continue; /* wlan disabled */
		}

		snprintf(nv_name, sizeof(nv_name), "WLAN%d_WSC_DISABLE", i);
		if (nvram_atoi(nv_name, 1)) {
			continue; /* wsc disabled */
		}

		snprintf(nv_name, sizeof(nv_name), "WLAN%d_WPA_AUTH", i);
		intVal = nvram_atoi(nv_name, 0);
		if (intVal != WPA_AUTH_PSK) {
			continue; /* not psk */
		}

		snprintf(nv_name, sizeof(nv_name), "WLAN%d_ENCRYPT", i);
		intVal = nvram_atoi(nv_name, 0);
		if (intVal != ENCRYPT_WPA2 && intVal != ENCRYPT_WPA2_MIXED) {
			continue; /* not wpa2 */
		}
		snprintf(nv_name, sizeof(nv_name), "WLAN%d_WPA2_CIPHER_SUITE", i);
		intVal = nvram_atoi(nv_name, 0);
		if (intVal != WPA_CIPHER_AES && intVal != WPA_CIPHER_MIXED) {
			continue; /* not aes */
		}
		snprintf(nv_name, sizeof(nv_name), "WLAN%d_HIDDEN_SSID", i);
		if (nvram_atoi(nv_name, 0)) {
			continue; /* hidden ssid */
		}

		wsc_possible = 1;
	}

	len += req_format_write(wp, "%d", wsc_possible ? 1 : 0);
	return len;
}

void formWsc(request *wp, char *path, char *query)
{
	char *strVal, *submitUrl;
	char buf[128];

	submitUrl = req_get_cstream_var(wp, ("submit-url"), "");

	strVal = req_get_cstream_var(wp, ("triggerPBC"), "");
	if (strVal[0]) {
		snprintf(buf, sizeof(buf), "%s -sig_pbc wlan0", _WSC_DAEMON_PROG);
		system(buf);
		send_redirect_perm(wp, "/wlwps_connect.htm");
		return;
	}

	strVal = req_get_cstream_var(wp, ("disableWPS"), "");
	if (!strcmp(strVal, "ON")) {
		snprintf(buf, sizeof(buf), "%s", "1");
	} else {
		snprintf(buf, sizeof(buf), "%s", "0");
	}

	nvram_set("WLAN0_WSC_DISABLE", buf);
	nvram_set("WLAN1_WSC_DISABLE", buf);

	apmib_update_web(CURRENT_SETTING);	// update to flash

	OK_MSG(submitUrl);
}

EJX_ENTRY(wscPossible, ej_wscPossible);
EJX_ENTRY(wscDisable, ej_wscDisable);
EJX_ENTRY(x_noreply_tracert, ej_nvram_get);
EJX_ENTRY(x_pingSecEnabled, ej_nvram_get);
EJX_ENTRY(x_icmp_reply_rate, ej_nvram_get);

static int ej_wmm_mode(request *wp, int argc, char **argv, void *unused)
{
	char name[64];
	char val[32];

	snprintf(name, sizeof(name), "x_wlan%d_wme_mode", wlan_idx);

	nvram_get_r_def(name, val, sizeof(val), "2");

	return req_format_write(wp, "%s", val);

}
EJX_ENTRY(wmm_mode, ej_wmm_mode);

int print_wme_dscp(request *wp, int argc, char **argv)
{
	int	nBytesSent = 0;
	FILE *fp;
	int  i, j, dscpidx=0;
	char buf[128], *ptr;
	int  pri[8];
	char fpath[80];

	snprintf(fpath, sizeof(fpath), "/proc/dv_wlan%d/wme_dscp", wlan_idx);
	fp = fopen(fpath, "r");
	if (fp != NULL ) {
		j = 0;
		while (fgets(buf, sizeof(buf), fp)) {
			if (((j/8)%2) == 0)
				nBytesSent += req_format_write(wp, "<tr align=center class=\"content\" height=\"20\" bgcolor=#DDDDDD>\n");
			else
				nBytesSent += req_format_write(wp, "<tr align=center class=\"content\" height=\"20\" bgcolor=#EEEEEE>\n");
			nBytesSent += req_format_write(wp, "<td width=250>DSCP[%2d - %2d]</td>", j, j+7);
			ptr = strstr(buf, ": ");
			if (ptr != NULL && strlen(ptr) > 2) {
				ptr += 2;
				memset(pri, 0, sizeof(pri));
				sscanf(ptr, "%2d %2d %2d %2d %2d %2d %2d %2d",
								&pri[0], &pri[1], &pri[2], &pri[3],
								&pri[4], &pri[5], &pri[6], &pri[7]);

				//DAVOLINK 10:06:24
				//@NOTE: revision wmm mapping table-R/W
				for (i = 0 ; i < 8; i++) {
					nBytesSent += req_format_write(wp, "<td width=30><select name=\"pri_%d\">"
								"<option value=\"0\" %s>0"
								"<option value=\"1\" %s>1"
								"<option value=\"2\" %s>2"
								"<option value=\"3\" %s>3"
								"<option value=\"4\" %s>4"
								"<option value=\"5\" %s>5"
								"<option value=\"6\" %s>6"
								"<option value=\"7\" %s>7"
								"</select></td>\n",
							dscpidx++,
							pri[i]==0?"selected":"", pri[i]==1?"selected":"",
							pri[i]==2?"selected":"", pri[i]==3?"selected":"",
							pri[i]==4?"selected":"", pri[i]==5?"selected":"",
							pri[i]==6?"selected":"", pri[i]==7?"selected":"");
				}
			}
			nBytesSent += req_format_write(wp, "</tr>");
			j += 8;
		}
		fclose(fp);
	} else {
		nBytesSent += req_format_write(wp, "\n");
	}

	return nBytesSent;
}

//@NOTE: revision wmm mapping table-R/W
#define DAVO_WME_RULE_SIZE_DSCP     64

void formWlwmm(request *wp, char *path, char *query)
{
	int dscpIdx;
	char *p;
	char param[16], setup_path[80];
	FILE *fp;

	if ((p = req_get_cstream_var(wp, "saveApply", "")) && strlen(p) > 0) {
		sprintf(setup_path, "/var/web_wme_dscp%d", wlan_idx);
		if ((fp = fopen(setup_path, "w"))) {
			for (dscpIdx = 0; dscpIdx < DAVO_WME_RULE_SIZE_DSCP; dscpIdx++) {
				sprintf(param, "pri_%d", dscpIdx);
				p = req_get_cstream_var(wp, param, "");
				if (strlen(p) == 0) {
					fclose(fp);
					ERR_MSG("DSCP setting value is invalid");
					return;
				}
				fprintf(fp, "%d:%d\n", dscpIdx, atoi(p));
			}
			fclose(fp);
		}
		yexecl(NULL, "wmmmap -m 2 -d -i %d -o -c %s", wlan_idx, setup_path);
		OK_MSG("/wlwmm.htm");
	} else {
		send_redirect_perm(wp, "/wlwmm.htm");
	}
}

int show_ExceptionLog(request *wp, int argc, char **argv)
{
	FILE *f;
	int nbytes, i = 0;
	char *tstamp, *s, buf[256];
	struct user_info * pUser_info;
	struct in_addr LanIP, LanMask, inIP;
	const char *path = "/var/log/messages";
	char filenames[128];
	const int max_file=100;

	pUser_info = search_login_list(wp);

	//check login
	if (!wp->cookie || (!pUser_info) || (strcmp(pUser_info->uniq_cookie, wp->cookie))) {
		goto err_exception;
	}
	//check super user
	if (wp->userName && nvram_match("SUPER_NAME", wp->userName)) {
		if (!apmib_get(MIB_IP_ADDR, (void *)&LanIP)) {
			goto err_exception;
		}
		if (!apmib_get(MIB_SUBNET_MASK, (void *)&LanMask)) {
			goto err_exception;
		}
		//check remote web
		inIP.s_addr = inet_addr(wp->remote_ip_addr);
		if ( (LanIP.s_addr&LanMask.s_addr) == (inIP.s_addr&LanMask.s_addr) ) { // Lan side access.
			goto err_exception;
		}
	} else {
		goto err_exception;
	}

	for (i = max_file; i >= 0; i--) {

		memset(filenames, 0, sizeof(filenames));

		if (i > 0) {
			snprintf(filenames, sizeof(filenames), "%s.%d", path, i-1);
		} else {
			snprintf(filenames, sizeof(filenames), "%s", path);
		}

		f = fopen(filenames, "r");
		if (f == NULL)
			continue;
		while (fgets(buf, sizeof(buf), f)) {
			tstamp = buf;
			s = &buf[15];
			*s++ = '\0';
			while (*s && isspace(*s))
				++s;
			while (*s && !isspace(*s))
				++s;
			while (*s && isspace(*s))
				++s;
			translate_control_code(s);
			nbytes += req_format_write(wp, "[%s] %s<br>\n", tstamp, s);
		}
		fclose(f);
	}

	return nbytes;

err_exception:
	ERR_MSG("Page not found!");

}

int string_to_hex(const char *s, unsigned char *key, int len)
{
	int nm_errno_saved = nm_errno;
	nm_errno = 0;
	if (yxatoi(key, s, len) || nm_errno != ENM_INVAL)
		return ({ nm_errno = nm_errno_saved; 1; });
	return 0;
}

int string_to_dec(const char *s, int *ret)
{
	int i, len = strlen(s);

	for (i = 0; i < len; i++) {
		if (!_isdigit(s[i]))
			return 0;
	}
	*ret = strtol(s, NULL, 10);
	return 1;
}

int apmib_update_web(int type)
{
	int ret;

#if defined(CONFIG_RTL_ULINKER)
	/*
	   For auto mode, we need to keep two wlan mib settings for ap/client.
	   Currently, we use WLAN0_VAP5 for save AP value and WLAN0_VAP6 for Client
	   When user save value to root ap, we will copy it to corresponding mib.
	 */
	if (type == CURRENT_SETTING) {
		extern int set_domain_name_query_ready(int val);
		set_domain_name_query_ready(2);

		dbg_wlan_mib(1);
		if (pMib->ulinker_auto == 1)
			pMib->wlan[0][0].wlanDisabled = 0;

		if (pMib->wlan[0][0].wlanMode == ULINKER_WL_AP) {
			pMib->ulinker_cur_wl_mode = ULINKER_WL_AP;
			pMib->ulinker_lst_wl_mode = ULINKER_WL_CL;

# if defined(UNIVERSAL_REPEATER)
			if (pMib->repeaterEnabled1 == 1) {
				ulinker_wlan_mib_copy(&pMib->wlan[0][ULINKER_RPT_MIB], &pMib->wlan[0][0]);
			} else
# endif
			{
				ulinker_wlan_mib_copy(&pMib->wlan[0][ULINKER_AP_MIB], &pMib->wlan[0][0]);
			}
		} else if (pMib->wlan[0][0].wlanMode == ULINKER_WL_CL) {
			pMib->ulinker_cur_wl_mode = ULINKER_WL_CL;
			pMib->ulinker_lst_wl_mode = ULINKER_WL_AP;

			ulinker_wlan_mib_copy(&pMib->wlan[0][ULINKER_CL_MIB], &pMib->wlan[0][0]);
		}

		/*
		   backup repeater value, because auto mode need to keep repeater disable,
		   we backup this value and restore it when device switch to manual mode.
		 */
		if (pMib->ulinker_auto == 0) {
			pMib->ulinker_repeaterEnabled1 = pMib->repeaterEnabled1;
			pMib->ulinker_repeaterEnabled2 = pMib->repeaterEnabled2;
		}
		dbg_wlan_mib(2);
	}
#endif

	ret = apmib_update(type);

	if (ret == 0)
		return 0;

	if (type & CURRENT_SETTING) {
		save_cs_to_file();
	}
	return ret;
}

void update_form_hander_name(request * wp)
{
	char *last, *nextp;

	last = wp->request_uri;
	while (1) {
		nextp = strstr(last, "/boafrm/");
		if (nextp) {
			last = nextp + 8;
			nextp = last;
			while (*nextp && !isspace(*nextp))
				nextp++;
			*nextp = '\0';
#ifdef CSRF_SECURITY_PATCH
			log_boaform(last, wp);
#endif
		}
		break;
	}
}

void _OK_MSG(request *wp, const char *url)
{
	needReboot = 1;
	if (strlen(url) == 0)
		url = "/home.htm";
	req_format_write(wp, "<html><head>");
	req_format_write(wp, "<meta http-equiv=\"Content-Type\" content=\"text/html\" charset=\"utf-8\">");
	getIncludeCss(wp);
	req_format_write(wp, "<script>var a=false;function chk_btn(){if(a==false){ a=true;return true;}else return false;}</script>\n");
 	req_format_write(wp, "</head><body><blockquote>\n<b><font size=3 face=\"arial\" color=\"red\"><br>재시작이 필요합니다</font></b>");
 	req_format_write(wp, "<table border=0 width=\"540\" cellspacing=4 cellpadding=0><tr><td><font size=2><br>");
 	req_format_write(wp, "변경된 설정이 저장되었습니다. 설정을 적용하려면 재시작해야 합니다.<br>");
 	req_format_write(wp, "지금 장비를 재시작하거나 설정을 계속 한 후 나중에 재시작하셔도 됩니다.</font>\n");
 	req_format_write(wp, "<tr><td><hr size=1 noshade align=top></td></tr><tr><td> \n");
	req_format_write(wp, "<form action=/boafrm/formRebootCheck method=POST name='rebootForm'>");
	req_format_write(wp, "<input type='hidden' value='%s' name='submit-url'>", url);
	req_format_write(wp, "<input id='restartNow' type='submit' value='지금 재시작' onclick=\"return chk_btn();\" />&nbsp;&nbsp;");
	req_format_write(wp, "<input id='restartLater' type='button' value='나중에 재시작' OnClick=window.location.replace(\"%s\")>", url);
	req_format_write(wp, "</form></blockquote></body></html>");
	log_boaform("formRebootCheck", wp);
}

void _FAIL_TO_LOGIN(request *wp, const char *msg)
{
	update_form_hander_name(wp);
   	req_format_write(wp, "<html><head>");
   	req_format_write(wp, "<meta HTTP-EQUIV='Pragma' CONTENT='no-cache'>");
   	req_format_write(wp, "<meta HTTP-equiv=\"Cache-Control\" content=\"no-cache\">");
   	req_format_write(wp, "<meta http-equiv=\"Content-Type\" content=\"text/html\" charset=\"utf-8\">");
   	getIncludeCss(wp);
   	req_format_write(wp, "</head><body><blockquote><h4>%s</h4>\n", msg);
	req_format_write(wp, "<form><input type=\"button\" onclick=\"location.href='/skb_login.htm'\" value=\"&nbsp;&nbsp;OK&nbsp;&nbsp\" name=\"OK\"></form></blockquote></body></html>");
}

void _ERR_MSG(request *wp, const char *msg)
{
	update_form_hander_name(wp);
	req_format_write(wp, "<html><head>");
   	req_format_write(wp, "<meta HTTP-EQUIV='Pragma' CONTENT='no-cache'>");
   	req_format_write(wp, "<meta HTTP-equiv=\"Cache-Control\" content=\"no-cache\">");
   	req_format_write(wp, "<meta http-equiv=\"Content-Type\" content=\"text/html\" charset=\"utf-8\">");
	getIncludeCss(wp);
	req_format_write(wp, "</head><body><blockquote><h4>%s</h4>\n", msg);
	req_format_write(wp, "<form><input type=\"button\" onclick=\"history.go (-1)\" value=\"&nbsp;&nbsp;OK&nbsp;&nbsp\" name=\"OK\"></form></blockquote></body></html>");
}

#ifdef REBOOT_CHECK
void _REBOOT_WAIT(request *wp, const char *url)
{
	strlcpy(lastUrl, url, sizeof(lastUrl));
	strlcpy(okMsg, APPLY_OK_MSG, sizeof(okMsg));
	countDownTime = APPLY_REBOOT_COUNTDOWN_TIME;
	send_redirect_perm(wp, COUNTDOWN_PAGE);
}

void _FACTORY_WAIT(request *wp, const char *url)
{
	strlcpy(lastUrl, "/home.htm", sizeof(lastUrl));
	if (!strcmp(url, "Reset"))
		strlcpy(okMsg, APPLY_RESET_MSG, sizeof(okMsg));
	countDownTime = APPLY_REBOOT_COUNTDOWN_TIME;
	send_redirect_perm(wp, COUNTDOWN_PAGE);
}

void _DO_APPLY_WAIT(request *wp, const char *url)
{
	strlcpy(lastUrl, url, sizeof(lastUrl));
	strlcpy(okMsg, "<br><br><b>설정 항목을 적용하고 있습니다. 잠시 기다려주시기 바랍니다.</b>", sizeof(okMsg));
	countDownTime = 3;
	send_redirect_perm(wp, COUNTDOWN_PAGE);
}
#endif	/* REBOOT_CHECK */

static int ej_wlanStatus(request *wp, int argc, char **argv, void *data)
{
	int skfd = 0;
	struct ifreq ifr;
	char if_name[32] = {0,};
	int status = 0;

	if ( (skfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
		return 0;

	snprintf(if_name, sizeof(if_name), "wlan%d", wlan_idx);

	strncpy(ifr.ifr_name, if_name, IFNAMSIZ);

	if (ioctl(skfd, SIOCGIFFLAGS, &ifr) < 0) {
		close(skfd);
		return -1;
	}

	close(skfd);

	status = (ifr.ifr_flags & IFF_UP)? 1 : 0;
	return req_format_write(wp, "%d", status);
}

EJX_ENTRY(wlanStatus, ej_wlanStatus);
EJH_ENTRY_DATA(CUSTOM_PASSTHRU_ENABLED, ej_nvram_get, "0");
