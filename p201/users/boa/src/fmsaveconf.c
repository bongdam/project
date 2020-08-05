#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <signal.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <time.h>
#include <net/route.h>
#include <sys/ioctl.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <net/if.h>

#include <bcmnvram.h>
#include <libytool.h>
#include <dvflag.h>

#include "boa.h"
#include "globals.h"
#include "apmib.h"
#include "apform.h"
#include "utility.h"
#include "mibtbl.h"
#include "asp_page.h"
#include "sys_lib.h"

extern int dv_reboot_system;

char *qURLencode(char *str)
{
	char *encstr, buf[2+1];
	unsigned char c;
	int i, j;

	if (str == NULL)
		return NULL;

	if ((encstr = (char *)malloc((strlen(str) * 3) + 1)) == NULL)
		return NULL;

	for(i = j = 0; str[i]; i++)
	{
		c = (unsigned char)str[i];
		if ((c == '&') || (c == '%') || (c == '+') || (c == '=')) {
			sprintf(buf, "%02X", c);
			encstr[j++] = '%';
			encstr[j++] = buf[0];
			encstr[j++] = buf[1];
		} else
			encstr[j++] = c;
	}

	encstr[j] = '\0';

	return encstr;
}

static int generate_nvram_file(char *filename)
{
	FILE *fp;
	int i = 0, j;
	char buf[256] = {0,}, count[12] = {0,}, list[256] = {0,};

	fp = fopen(filename, "w");
	if (!fp)
		return 0;

	do {
		FILE *f = fopen("/etc/rconf.dfl", "r");

		while (fscanf(f, "%[^=]%*[^\n]\n", buf) != EOF) {
			nvram_get_r_def(buf, list, sizeof(list), "");
			fprintf(fp, "%s=%s\n", buf, qURLencode(list));
		}
		fclose(f);
	} while (0);

	/* VPN LIST*/
	nvram_get_r_def("ipsec_tbl_num", count, sizeof(count), "0");
	for (i = 0; i < atoi(count); i ++) {
		snprintf(buf, sizeof(buf), "vpn_ipsec%d_conn_name", i);
		nvram_get_r_def(buf, list, sizeof(list), "");
		fprintf(fp, "%s=%s\n", buf, qURLencode(list));

		snprintf(buf, sizeof(buf), "vpn_ipsec%d_local_id", i);
		nvram_get_r_def(buf, list, sizeof(list), "");
		fprintf(fp, "%s=%s\n", buf, qURLencode(list));

		snprintf(buf, sizeof(buf), "vpn_ipsec%d_remote_fqdn", i);
		nvram_get_r_def(buf, list, sizeof(list), "");
		fprintf(fp, "%s=%s\n", buf, qURLencode(list));

		snprintf(buf, sizeof(buf), "vpn_ipsec%d_ike", i);
		nvram_get_r_def(buf, list, sizeof(list), "");
		fprintf(fp, "%s=%s\n", buf, qURLencode(list));

		snprintf(buf, sizeof(buf), "vpn_ipsec%d_esp", i);
		nvram_get_r_def(buf, list, sizeof(list), "");
		fprintf(fp, "%s=%s\n", buf, qURLencode(list));

		snprintf(buf, sizeof(buf), "vpn_ipsec%d_remote_host", i);
		nvram_get_r_def(buf, list, sizeof(list), "");
		fprintf(fp, "%s=%s\n", buf, qURLencode(list));

		snprintf(buf, sizeof(buf), "vpn_ipsec%d_server_mode", i);
		nvram_get_r_def(buf, list, sizeof(list), "");
		fprintf(fp, "%s=%s\n", buf, qURLencode(list));

		snprintf(buf, sizeof(buf), "vpn_ipsec%d_active", i);
		nvram_get_r_def(buf, list, sizeof(list), "");
		fprintf(fp, "%s=%s\n", buf, qURLencode(list));

		snprintf(buf, sizeof(buf), "vpn_ipsec%d_remote_subnet", i);
		nvram_get_r_def(buf, list, sizeof(list), "");
		fprintf(fp, "%s=%s\n", buf, qURLencode(list));

		snprintf(buf, sizeof(buf), "vpn_ipsec%d_psk", i);
		nvram_get_r_def(buf, list, sizeof(list), "");
		fprintf(fp, "%s=%s\n", buf, qURLencode(list));

		snprintf(buf, sizeof(buf), "vpn_ipsec%d_local_fqdn", i);
		nvram_get_r_def(buf, list, sizeof(list), "");
		fprintf(fp, "%s=%s\n", buf, qURLencode(list));

		snprintf(buf, sizeof(buf), "vpn_ipsec%d_remote_id", i);
		nvram_get_r_def(buf, list, sizeof(list), "");
		fprintf(fp, "%s=%s\n", buf, qURLencode(list));

		snprintf(buf, sizeof(buf), "vpn_ipsec%d_local_subnet", i);
		nvram_get_r_def(buf, list, sizeof(list), "");
		fprintf(fp, "%s=%s\n", buf, qURLencode(list));

		snprintf(buf, sizeof(buf), "vpn_ipsec%d_protocol", i);
		nvram_get_r_def(buf, list, sizeof(list), "");
		fprintf(fp, "%s=%s\n", buf, qURLencode(list));
	}

	/* MACFILTER LIST */
	snprintf(buf, sizeof(buf), "%s", "MACFILTER_TBL_NUM");
	nvram_get_r_def(buf, count, sizeof(count), "0");
	for (i = 0; i < atoi(count); i++) {
		snprintf(buf, sizeof(buf), "MACFILTER_TBL%d", i + 1);
		nvram_get_r_def(buf, list, sizeof(list), "");
		fprintf(fp, "%s=%s\n", buf, qURLencode(list));
	}

	/* WLAN MACFILTER LIST */
	for (i = 0; i < 2; i++) {
		snprintf(buf, sizeof(buf), "WLAN%d_MACAC_NUM", i);
		nvram_get_r_def(buf, count, sizeof(count), "0");
		for (j = 0; j < atoi(count); j++) {
			snprintf(buf, sizeof(buf), "WLAN%d_MACAC_ADDR%d", i, (j + 1));
			nvram_get_r_def(buf, list, sizeof(list), "");
			fprintf(fp, "%s=%s\n", buf, qURLencode(list));
		}
	}

	/* PORTFORWARDING LIST */
	snprintf(buf, sizeof(buf), "%s", "PORTFW_TBL_NUM");
	nvram_get_r_def(buf, count, sizeof(count), "0");
	for (i = 0; i < atoi(count); i++) {
		snprintf(buf, sizeof(buf), "PORTFW_TBL%d", i + 1);
		nvram_get_r_def(buf, list, sizeof(list), "");
		fprintf(fp, "%s=%s\n", buf, qURLencode(list));
	}

	/* IPPORTFILTERING LIST */
	snprintf(buf, sizeof(buf), "%s", "IPFILTER_TBL_NUM");
	nvram_get_r_def(buf, count, sizeof(count), "0");
	for (i = 0; i < atoi(count); i++) {
		snprintf(buf, sizeof(buf), "IPFILTER_TBL%d", i + 1);
		nvram_get_r_def(buf, list, sizeof(list), "");
		fprintf(fp, "%s=%s\n", buf, qURLencode(list));
	}

	fprintf(fp, "P201_Encrypt_Complete");

	fclose(fp);
	return 1;
}

unsigned char *encode_file(char *filename, int *plen)
{
	int buffersize = 0;
	struct stat encode;
	int fd = -1;
	char *buffer = NULL;
	int len;

	*plen = 0;

	if ((fd = open(filename, O_RDONLY)) < 0)
		return NULL;

	if (fstat(fd, &encode) < 0) {
		close(fd);
		return NULL;
	}

	buffersize = encode.st_size + 32;

	buffer = (char *)malloc(buffersize);
	if (!buffer) {
		close(fd);
		return NULL;
	}

	len = read(fd, buffer, encode.st_size);
	if (len != encode.st_size) {
		close(fd);
		free(buffer);
		return NULL;
	}

	close(fd);

	buffersize = sys_encrypt((unsigned char *)buffer, encode.st_size, buffersize);
	*plen = buffersize;

	return (unsigned char *)buffer;
}

void formNvramSave(request *wp, char *path, char *query)
{
	char *act;
	int plen;
	unsigned char *p;

	act = req_get_cstream_var(wp, "act", "");
	if (strcmp(act, "act_download_nvram") == 0) {
		send_r_request_nvram_ok(wp);

		if (generate_nvram_file("/tmp/restore") == 0)
			return;

		yexecl(NULL, "gzip /tmp/restore");

		p = encode_file("/tmp/restore.gz", &plen);
		if (p) {
			req_write_binary(wp, p, plen);
			free(p);
		} else
			printf("error encode\n");
	}
}

int get_upload_data(char *data, int data_len)
{
	char *boundary, *p, *end;
	int len;

	boundary = data;
	p = memchr(boundary, 0x0D, data_len);
	if (!p)
		return -1;

	*p++ = 0;
	if ((end = memstr(p, boundary, data_len-(p-data))) == NULL)
		return -2;

	end -= 2;
	if ((end[0] != 0x0d) || (end[1] != 0x0a))
		return -3;

	p = memstr(p, "\x0d\x0a\x0d\x0a", end-p);
	if (!p)
		return -4;
	p += 4;

	len = end - p;
	memmove(data, p, len);

	return len;
}

int decode_mem(unsigned char * buf, int buflen)
{
	int len;

	len = sys_decrypt(buf, buflen, buflen);
	return len;
}

int do_file_unzip(request *wp, int len)
{
	FILE *pp = NULL, *fp = NULL;
	char *valid_check = "P201_Encrypt_Complete";
	int i, block, valid_len, size;
	int p201_cgi = 0;
	char buffer[32] = {0,};

	valid_len = strlen(valid_check);

	pp = popen("gzip -d -c >/tmp/restore2", "w");
	for (i = 0; i < len; i += block) {
		block = ((len - i) >= 1024) ? 1024 : len - i;
		if (fwrite(wp->post_data + i, 1, block, pp) != block)
			break;
	}
	pclose(pp);

	if (i < len) {
		yecho("/tmp/nvram_restore_fail", "1\n");
		return -1;
	}

	fp = fopen("/tmp/restore2", "r");
	if (fp) {
		fseek(fp, 0, SEEK_END);
		size = ftell(fp);
		fseek(fp, (size - valid_len), SEEK_SET);
		fread(buffer, sizeof(buffer), 1, fp);
		if (!strcmp(buffer, valid_check))
			p201_cgi = 1;
		fclose(fp);
	}

	if (!p201_cgi) {
		yecho("/tmp/nvram_restore_fail", "1\n");
		return -1;
	}

	return 0;
}

void formNvramRestore(request *wp, char *path, char *query)
{
	int len;

	if ((len = get_upload_data(wp->post_data, wp->post_data_len)) < 0) {
		yecho("/tmp/nvram_restore_fail", "1\n");
		goto err_nvram;
	}

	len = decode_mem(wp->post_data, len);
	if (len <= 0) {
		yecho("/tmp/nvram_restore_fail", "1\n");
		goto err_nvram;
	}

	wp->post_data_len = len;
	// file generate
	if (do_file_unzip(wp, len) < 0)
		goto err_nvram;

	yexecl(NULL, "nvram fset /tmp/restore2");
	nvram_commit();
	snprintf(lastUrl, 100, "%s","/home.htm");
	countDownTime = 60;
	dv_reboot_system = 1;
	send_redirect_perm(wp, COUNTDOWN_PAGE);
	return;

err_nvram :
	send_redirect_perm(wp, "/saveconf.htm");
}

void formSaveConfigReset(request *wp, char *path, char *query)
{
	char *status;
	char msg[128] = {0,};
	int is_factory = 0;

	status = req_get_cstream_var(wp, "device_status", "");
	snprintf(lastUrl, 100, "%s","/home.htm");
	countDownTime = 60;
	dv_reboot_system = 1;
	if (status[0]) {
		if (strcmp(status, "factory") == 0) {
			snprintf(msg, sizeof(msg), "%s", "<font color=\"red\"><script>dw(progress_factory)</script></font><br><br>");
			is_factory = 1;
		} else
			snprintf(msg, sizeof(msg), "%s", "<font color=\"red\"><script>dw(progress_reboot)</script></font><br><br>");

		if (is_factory) {
			printf("Going to Reload Default\n");
			yexecl(NULL, "flash reset /bin/preclean");
		}

		snprintf(okMsg, 300, "%s", msg);
		send_redirect_perm(wp, "/progress_setting.htm");
	} else
        send_redirect_perm(wp, COUNTDOWN_PAGE);
}
