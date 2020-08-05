#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <time.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <sys/poll.h>
#include <dirent.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <mtd/mtd-user.h>
#include "goods.h"
#include "apmib_defs.h"
#include "apmib.h"
#include <dvflag.h>
#include <bcmnvram.h>
#include "furl.h"
#include "display.h"

#ifndef bool
#define bool    int
#endif

#ifndef true
#define true    1
#define false   0
#endif

#define MAX_TESTPID		16
#define fw_commit_lock()	fw_commit_stat(true)
#define fw_commit_unlock()	fw_commit_stat(false)

typedef void (*sighandler_t)(int);

static uint8_t crc8(uint8_t *pdata, int len, uint8_t crc);

static int pdir(const struct dirent *entry)
{
	if (strspn(entry->d_name, "1234567890") != strlen(entry->d_name) ||
	    strtoul(entry->d_name, NULL, 10) <= 1)
		return 0;
	return 1;
}

static int sort_pid(const struct dirent **e1, const struct dirent **e2)
{
	pid_t pid1, pid2;
	pid1 = strtoul(e1[0]->d_name, NULL, 10);
	pid2 = strtoul(e2[0]->d_name, NULL, 10);
	return (int)(pid2 - pid1);
}

static int read_to_buf(const char *filename, void *buf, int len)
{
	int fd;
	/* open_read_close() would do two reads, checking for EOF.
	 * When you have 10000 /proc/$NUM/stat to read, it isn't desirable */
	ssize_t ret = -1;
	fd = open(filename, O_RDONLY);
	if (fd >= 0) {
		ret = TEMP_FAILURE_RETRY(read(fd, buf, len - 1));
		close(fd);
	}
	((char *)buf)[ret > 0 ? ret : 0] = '\0';
	return ret;
}

static pid_t kill_child(pid_t pid)
{
	struct dirent **namelist;
	char buf[1024];
	char filename[sizeof("/proc//stat") + sizeof(int) * 3];
	int n, len;
	char *cp;
	char state[4];
	pid_t ppid, child_pid = 0;

	n = scandir("/proc", &namelist, pdir, (void *)sort_pid);
	if (n > -1) {
		for (; n-- > 0; free(namelist[n])) {
			if (child_pid > 0)
				continue;
			sprintf(filename, "/proc/%s/stat", namelist[n]->d_name);
			len = read_to_buf(filename, buf, sizeof(buf));
			if (len < 0)
				continue;
			cp = strrchr(buf, ')');	/* split into "PID (cmd" and "<rest>" */
			sscanf(cp + 2, "%c %u", state, &ppid);
			if (ppid == pid) {
				child_pid =
				    strtoul(namelist[n]->d_name, NULL, 10);
				kill(child_pid, SIGKILL);
			}
		}
		free(namelist);
	}

	if (!child_pid)
		fprintf(stderr, "Not found child of %d ppid\n", pid);

	return child_pid;
}

static int p_read(int fd, int (*__read) (char *, int, void *), void *parm)
{
	char buf[8192];
	int n;

	n = TEMP_FAILURE_RETRY(read(fd, buf, sizeof(buf)));
	if (n < 0)
		return -1;

	if (__read && __read(buf, n, parm))
		return -2;

	return n;
}

struct p_creat_item *p_creat(const char *command, const char *modes)
{
	FILE *fp;
	struct p_creat_item *pi;
	int pipe_fd[2];
	int parent_fd;
	int child_fd;
	int child_writing;	/* Doubles as the desired child fildes. */
	pid_t pid;

	child_writing = 0;	/* Assume child is writing. */
	if (modes[0] != 'w') {	/* Parent not writing... */
		++child_writing;	/* so child must be writing. */
		if (modes[0] != 'r') {	/* Oops!  Parent not reading either! */
			errno = EINVAL;
			goto RET_NULL;
		}
	}

	if (!(pi = malloc(sizeof(struct p_creat_item))))
		goto RET_NULL;

	if (pipe(pipe_fd))
		goto FREE_PI;

	child_fd = pipe_fd[child_writing];
	parent_fd = pipe_fd[1 - child_writing];

	if (!(fp = fdopen(parent_fd, modes))) {
		close(parent_fd);
		close(child_fd);
		goto FREE_PI;
	}

	if ((pid = vfork()) == 0) {	/* Child of vfork... */
		close(parent_fd);
		if (child_fd != child_writing) {
			dup2(child_fd, child_writing);
			close(child_fd);
		}

		execl("/bin/sh", "sh", "-c", command, (char *)0);

		/* SUSv3 mandates an exit code of 127 for the child if the
		 * command interpreter can not be invoked. */
		_exit(127);
	}

	/* We need to close the child filedes whether vfork failed or
	 * it succeeded and we're in the parent. */
	close(child_fd);

	if (pid > 0) {		/* Parent of vfork... */
		pi->pid = pid;
		pi->f = fp;
		return pi;
	}

	/* If we get here, vfork failed. */
	fclose(fp);		/* Will close parent_fd. */

 FREE_PI:
	free(pi);

 RET_NULL:
	return NULL;
}

int p_close(struct p_creat_item *p)
{
	int stat;
	pid_t pid;

	/* First, find the list entry corresponding to stream and remove it
	 * from the list.  Set p to the list item (NULL if not found). */
	if (p) {
		pid = p->pid;	/* Save the pid we need */
		fclose(p->f);	/* The SUSv3 example code ignores the return. */
		free(p);	/* and free the list item. */
		/* SUSv3 specificly requires that p_close not return before the child
		 * terminates, in order to disallow p_close from returning on EINTR. */
		do {
			if (waitpid(pid, &stat, 0) >= 0)
				return stat;
			if (errno != EINTR)
				break;
		} while (1);
	}

	return -1;
}

int furl(char *command, int rcvtimeo, p_read_f __read, void *parm)
{
	struct pollfd pfd;
	struct p_creat_item *pi;
	int nret, status = 0;
	sighandler_t save_quit, save_int, save_chld;

	if (!command || !command[0])
		return -1;

	save_quit = signal(SIGQUIT, SIG_DFL);
	save_int = signal(SIGINT, SIG_DFL);
	save_chld = signal(SIGCHLD, SIG_DFL);

	pi = p_creat(command, "r");
	if (!pi) {
		signal(SIGQUIT, save_quit);
		signal(SIGINT, save_int);
		signal(SIGCHLD, save_chld);
		return -1;
	}

	pfd.fd = fileno(pi->f);
	pfd.events = POLLIN;

	while (1) {
		if ((nret = poll(&pfd, 1, rcvtimeo)) <= 0) {
			if (nret == 0) {
				status = -ETIMEDOUT;
				kill_child(pi->pid);
			}
			break;
		}

		if (pfd.revents && (nret = p_read(pfd.fd, __read, parm)) <= 0) {
			if (nret == -2) {
				status = -EBADMSG;
				kill_child(pi->pid);
			}
			break;
		}

		if (rcvtimeo < 10000)
			rcvtimeo = 10000;
	}

	nret = p_close(pi);
	if (status == 0)
		status = nret;

	signal(SIGQUIT, save_quit);
	signal(SIGINT, save_int);
	signal(SIGCHLD, save_chld);
	return status;
}

/* ---------------- firmware validation and commit API --------------------- */

#define bntohs(p)   ((((unsigned short)(unsigned char)(p)[0]) <<  8) | \
                     (((unsigned short)(unsigned char)(p)[1])))

const int fw_hlen = sizeof(IMG_HEADER_T);

static unsigned short cksum16(const char *p, int len)
{
	int nleft;
	unsigned short tmp, sum = 0;

	for (nleft = len; nleft > 1; nleft -= 2) {
		tmp = bntohs(p);
		sum += tmp;
		p += 2;
	}

	if (nleft > 0) {
		tmp = (((unsigned short)(unsigned char)p[0]) << 8);
		sum += tmp;
	}

	return ~sum + 1;
}

static unsigned char cksum8(const char *p, int len)
{
	unsigned char sum = 0;

	while (len-- > 0)
		sum += (unsigned char)*p++;
	return ~sum + 1;
}

/* x^8 + x^2 + x + 1 polynomial */
static uint8_t crc8(uint8_t *pdata, int len, uint8_t crc)
{
	int i;

	while (len > 0) {
		crc = crc ^ *pdata++;
		for (i = 0; i < 8; i++) {
			if ((crc & 0x80)) {
				crc <<= 1;
				crc ^= 0x07;
			} else
				crc <<= 1;
		}
		len--;
	}
	return crc;
}

static bool fw_commit_stat(bool f_set)
{
	int fd;
	unsigned int cmd[2];
	bool status = true;

	fd = open("/proc/dvflag", O_RDWR);
	if (fd != -1) {
		do {
			if (f_set) {
				read(fd, (void *)&cmd[0], sizeof(int));
				if ((cmd[0] & DF_UPLOADING)) {
					status = false;
					break;
				}
			}
			cmd[0] = (f_set) ? DF_UPLOADING : 0;
			cmd[1] = DF_UPLOADING;
			write(fd, cmd, sizeof(cmd));
		} while (0);
		close(fd);
	}

	return status;
}

int fw_read_callback(char *buf, int n, struct fwstat *state)
{
	if (n > 0) {
		if ((state->rcvlen + n) > state->caplen)
			state->lasterror = -EFBIG;
		else {
			memcpy(&state->fmem[state->rcvlen], buf, n);
			state->rcvlen += n;
		}
	}
	return (state->lasterror) ? -1 : 0;
}

#define KB * 1024

int fw_parse_bootline(struct bootline_mtd_info *bl)
{
	char *q, *p = nvram_get("x_sys_bootm");

	if (p != NULL) {
		u_int kernel = strtoul(p, &q, 16);
		if (*q) {
			u_int rootfs = strtoul(++q, NULL, 16);
			if (kernel < rootfs && rootfs < CONFIG_FLASH_SIZE) {
				bl->kernel_offset = kernel;
				bl->rootfs_offset = rootfs;
				return 0;
			}
		}
	}

	bl->kernel_offset = CONFIG_RTL_CODE_IMAGE_OFFSET;
	bl->rootfs_offset = CONFIG_RTL_ROOT_IMAGE_OFFSET;
	return 0;
}

int fw_dualize(struct fwstat *fbuf)
{
	int i, mask;
	unsigned int aligned;
	struct fwblk *kern_blk, *fs_blk;
	struct bootline_mtd_info *bl = &fbuf->blnfo;

	mask = fbuf->fincmask & FW_KERNFS_MASK;
	if (mask && mask != FW_KERNFS_MASK)
		return -EDUAL;

	kern_blk = NULL;
	fs_blk = NULL;
	for (i = 0; i < fbuf->fblkcount; i++) {
		if (fbuf->fblks[i].sig_id == FW_KERNEL)
			kern_blk = &fbuf->fblks[i];
		else if (fbuf->fblks[i].sig_id == FW_ROOTFS)
			fs_blk = &fbuf->fblks[i];
	}

	if (mask) {
		if (!kern_blk || !fs_blk)
			return -EDUAL;

		if (bl->rootfs_offset
		    && (bl->rootfs_offset < (CONFIG_FLASH_SIZE / 2)))
			kern_blk->rom_dst = (CONFIG_FLASH_SIZE / 2);
		else
			kern_blk->rom_dst = CONFIG_RTL_CODE_IMAGE_OFFSET;
		/* make alignment with 4KB erase block */
		aligned = (kern_blk->rom_dst + kern_blk->length + 0xfff) & ~0xfff;
		fs_blk->rom_dst = aligned;
	}
	return 0;
}

int fw_validate(struct fwstat *fbuf)
{
	IMG_HEADER_T fhdr;
	int head_offset = 0;
	int len;
	int status = 0;
	struct fwblk *pblk;
	int rootfs_sig, hw_sig, dft_sig, curr_sig;
#ifdef COMPRESS_MIB_SETTING
	COMPRESS_MIB_HEADER_Tp compchdr;
#else
	PARAM_HEADER_Tp chdr;
#endif
	IMG_HEADER_T K, R;
	unsigned short kern_csum, rootfs_csum;
	struct goods_tag *gt;
	unsigned int tmp;
	unsigned char crc;

	if (!fbuf->fmem || fbuf->rcvlen <= fw_hlen)
		return -1;

	fbuf->fblkcount = 0;
	fbuf->fincmask = 0;
	pblk = &fbuf->fblks[0];

	while (!status && (head_offset < fbuf->rcvlen)) {
		rootfs_sig = 0;
		hw_sig = 0;
		dft_sig = 0;
		curr_sig = 0;

		memcpy(&fhdr, &fbuf->fmem[head_offset], fw_hlen);
		len = ntohl(fhdr.len);
		if (!memcmp(fhdr.signature, FW_HEADER, SIGNATURE_LEN) ||
		    !memcmp(fhdr.signature, FW_HEADER_WITH_ROOT, SIGNATURE_LEN) ||
		    (rootfs_sig = !memcmp(fhdr.signature, ROOT_HEADER, SIGNATURE_LEN))) {
			if (cksum16(&fbuf->fmem[head_offset + fw_hlen], len))
				status = -ECKSUM;
			else {
				if (rootfs_sig) {
					memcpy(&R, &fhdr, sizeof(IMG_HEADER_T));
					memcpy(&rootfs_csum, &fbuf->fmem[head_offset + fw_hlen + len - sizeof(short)], sizeof(short));
				} else {
					memcpy(&K, &fhdr, sizeof(IMG_HEADER_T));
					memcpy(&kern_csum, &fbuf->fmem[head_offset + fw_hlen + len - sizeof(short)], sizeof(short));
				}
				pblk->length = len + fw_hlen;
				pblk->rom_dst = ntohl(fhdr.burnAddr);
				pblk->ram_src = &fbuf->fmem[head_offset];
				if (rootfs_sig) {
					pblk->length -= fw_hlen;
					pblk->ram_src += fw_hlen;
					pblk->sig_id = FW_ROOTFS;
				} else
					pblk->sig_id = FW_KERNEL;
				head_offset += (len + fw_hlen);
			}
		} else if (!memcmp(fhdr.signature, WEB_HEADER, SIGNATURE_LEN)) {
			if (cksum8(&fbuf->fmem[head_offset + fw_hlen], len))
				status = -ECKSUM;
			else {

				pblk->length = len + fw_hlen;
				pblk->rom_dst = ntohl(fhdr.burnAddr);
				pblk->ram_src = &fbuf->fmem[head_offset];
				pblk->sig_id = FW_WEBS;
				head_offset += (len + fw_hlen);
			}
		} else if (
#ifdef COMPRESS_MIB_SETTING
				  (hw_sig = !memcmp(fhdr.signature, COMP_HS_SIGNATURE, COMP_SIGNATURE_LEN))
				  || (dft_sig = !memcmp(fhdr.signature, COMP_DS_SIGNATURE, COMP_SIGNATURE_LEN))
				  || (curr_sig = !memcmp(fhdr.signature, COMP_CS_SIGNATURE, COMP_SIGNATURE_LEN))
#else
				  (curr_sig = !memcmp(fhdr.signature, CURRENT_SETTING_HEADER_TAG, TAG_LEN))
				  || (curr_sig = !memcmp(fhdr.signature, CURRENT_SETTING_HEADER_FORCE_TAG, TAG_LEN))
				  || (curr_sig = !memcmp(fhdr.signature, CURRENT_SETTING_HEADER_UPGRADE_TAG, TAG_LEN))
				  || (dft_sig = !memcmp(fhdr.signature, DEFAULT_SETTING_HEADER_TAG, TAG_LEN))
				  || (dft_sig = !memcmp(fhdr.signature, DEFAULT_SETTING_HEADER_FORCE_TAG, TAG_LEN))
				  || (dft_sig = !memcmp(fhdr.signature, DEFAULT_SETTING_HEADER_UPGRADE_TAG, TAG_LEN))
				  || (hw_sig = !memcmp(fhdr.signature, HW_SETTING_HEADER_TAG, TAG_LEN))
				  || (hw_sig = !memcmp(fhdr.signature, HW_SETTING_HEADER_FORCE_TAG, TAG_LEN))
				  || (hw_sig = !memcmp(fhdr.signature, HW_SETTING_HEADER_UPGRADE_TAG, TAG_LEN))
#endif
		    ) {

			if (hw_sig)
				pblk->rom_dst = CONFIG_RTL_HW_SETTING_OFFSET;
			else if (dft_sig)
				pblk->rom_dst = CONFIG_RTL_DEFAULT_SETTING_OFFSET;
			else
				pblk->rom_dst = CONFIG_RTL_CURRENT_SETTING_OFFSET;
			pblk->ram_src = &fbuf->fmem[head_offset];
			pblk->sig_id = FW_CONFIG;
#ifdef COMPRESS_MIB_SETTING
			compchdr = (COMPRESS_MIB_HEADER_Tp)&fhdr;
			len = (compchdr->compLen + sizeof(COMPRESS_MIB_HEADER_T));
#else
			chdr = (PARAM_HEADER_Tp)&fhdr;
			len = (ntohs(chdr->len) + sizeof(PARAM_HEADER_T));
#endif
			pblk->length = len;
			head_offset += len;
		} else if (!memcmp(fhdr.signature, BOOT_HEADER, SIGNATURE_LEN)) {
			if (cksum16(&fbuf->fmem[head_offset + fw_hlen], len))
				status = -ECKSUM;
			else {
				pblk->length = len;
				pblk->rom_dst = ntohl(fhdr.burnAddr);
				pblk->ram_src = &fbuf->fmem[head_offset + fw_hlen];
				pblk->sig_id = FW_BOOT;
				head_offset += (len + fw_hlen);
			}
		} else
			status = -ESIGN;

		fbuf->fincmask |= (1 << pblk->sig_id);
		pblk = &fbuf->fblks[++fbuf->fblkcount];
		if (fbuf->fblkcount >= MAX_FBLKS)
			break;
	}

	if (status)
		return status;
	else if (fbuf->fincmask == (1 << FW_BOOT))
		goto its_boot;

	/* Both kernel and rootfs should exit */
	if ((fbuf->fincmask & FW_KERNFS_MASK) != FW_KERNFS_MASK)
		return -EPARTIAL;

	/* Check identity and forgery - young 2015-04-27 21:17 */
	tmp = R.startAddr;
	R.startAddr = R.len;
	R.len = tmp;
	gt = (struct goods_tag *)&R.len;
	if (gt->id != GOODS_ID)
		return -EIDENTITY;
/*
          linux                      linux IMG_HEADER_T (2 + 16 octets)
	+---+---+    +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
	| cksum | +  |               |               |               |               | +
	+---+---+    +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+ |
	                                                                               /
	                                                                              /
	   ---------------------------<-----------------------<----------------------+
	  /
         L
         rootfs       rootfs IMG_HEADER_T (2 + 15 octest excluding last significant byte when encoding)
	+---+---+    +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
	| cksum | +  |               |   startAddr   |               |     len   |///|
	+---+---+    +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
                                            ^                                ^
                                            |                                |
                                            +---------  swapping ------------+
 */
	crc = crc8((uint8_t *)&kern_csum, sizeof(uint16_t), 0);
	crc = crc8((uint8_t *)&K, sizeof(IMG_HEADER_T), crc);
	crc = crc8((uint8_t *)&rootfs_csum, sizeof(uint16_t), crc);
	if (crc8((uint8_t *)&R, sizeof(IMG_HEADER_T), crc))
		return -ECKSUM;

	fbuf->version = ntohs(gt->ver);

its_boot:
	if (fbuf->rcvlen != head_offset)
		return -ELENGTH;

	return 0;
}

static int __fw_verify(const char *mtddev, unsigned int mtd_base, struct fwblk *fb)
{
	int f, status = 0;
	char *buffer;
	char *ram;
	unsigned int len;
	int pagesize;

	pagesize = getpagesize();
	buffer = (char *)malloc(pagesize);
	if (buffer == NULL)
		return -errno;

	f = open(mtddev, O_RDONLY);
	if (f == -1) {
		free(buffer);
		perror(__func__);
		return -errno;
	}

	lseek(f, fb->rom_dst - mtd_base, SEEK_SET);

	ram = fb->ram_src;
	for (len = fb->length; len >= pagesize; len -= pagesize) {
		if (TEMP_FAILURE_RETRY(read(f, buffer, pagesize)) != pagesize ||
		    memcmp(buffer, ram, pagesize))
			goto quit;
		ram += pagesize;
	}

	if (len > 0 && (TEMP_FAILURE_RETRY(read(f, buffer, len)) != len ||
			memcmp(buffer, ram, len)))
		goto quit;

 out:
	close(f);
	free(buffer);
	return status;

 quit:
	printf("-> stop verifying for error from 0x%x to 0x%x\n",
	       (unsigned int)(ram - fb->ram_src), (unsigned int)(ram - fb->ram_src) + pagesize);
	status = EVERIFY;
	goto out;
}

static int __fw_write(struct fwblk *fb, struct bootline_mtd_info *bl)
{
	const char *fnames[] = { "", "linux", "web", "rootfs", "config", "boot" };
	u_int mtd_base, len, unit;
	const char *mtddev;
	struct mtd_info_user mtd;
	erase_info_t erase;
	int f, status = -1;
	unsigned int magic;
	off_t pos;

	if (bl->rootfs_offset && bl->rootfs_offset < fb->rom_dst) {
		mtd_base = bl->rootfs_offset;
		mtddev = "/dev/mtd1";
	} else {
		mtd_base = 0;
		mtddev = "/dev/mtd0";
	}

	printf("-> mtd%c: %s to 0x%x(0x%x) from 0x%x with 0x%x length\n",
	       mtddev[strlen(mtddev) - 1], fnames[fb->sig_id], fb->rom_dst, mtd_base,
	       (unsigned int)fb->ram_src, fb->length);

	displayInit();
	displayBegin();
	d.total_write = 0;
	d.total_size = fb->length;
	d.total_size_known = 1;

	f = open(mtddev, O_RDWR);
	if (f == -1) {
		perror(mtddev);
		return -errno;
	}

	(void)ioctl(f, MEMGETINFO, &mtd);
	magic = *((unsigned int *)&fb->ram_src[0]);
	*((unsigned int *)&fb->ram_src[0]) = 0xffffffff;
	pos = lseek(f, fb->rom_dst - mtd_base, SEEK_SET);
	for (len = 0; len < fb->length; len += unit) {
		erase.start = fb->rom_dst - mtd_base + len;
		erase.length = ((fb->rom_dst + len) & (64 KB - 1)) ? mtd.erasesize : 64 KB;
		(void)ioctl(f, MEMUNLOCK, &erase);
		if (ioctl(f, MEMERASE, &erase)) {
			perror("MEMERASE");
			break;
		}
		unit = ((len + erase.length) < fb->length) ? erase.length : (fb->length - len);
		if (TEMP_FAILURE_RETRY(write(f, &fb->ram_src[len], unit)) != unit)
			break;
		d.total_write += unit;
		displayUpdate();
	}

	if (len == fb->length) {
		lseek(f, pos, SEEK_SET);
		if (TEMP_FAILURE_RETRY(write(f, &magic, sizeof(int))) != sizeof(int))
			len -= sizeof(int);	// force failure in test statement below
		else
			*((unsigned int *)&fb->ram_src[0]) = magic;
	}

	close(f);
	displayEnd();

	if (len == fb->length)
		status = __fw_verify(mtddev, mtd_base, fb);

	return status;
}

static int __fw_write_back(struct fwstat *fbuf,
			   int (*preprocess) (struct fwblk *, void *, FW_WR *),
			   void *parm, unsigned int *kern, unsigned int *fs)
{
	int i, status = -1;
	struct fwblk *fb;
	unsigned int __kern = 0, __fs = 0;
	FW_WR flags;

	for (i = 0; i < fbuf->fblkcount; i++) {
		fb = &fbuf->fblks[i];
		flags = FW_WR_DO;
		if (preprocess && (status = preprocess(fb, parm, &flags)))
			break;

		if (flags != FW_WR_DO)
			continue;

		if ((status = __fw_write(fb, &fbuf->blnfo)))
			break;

		if (fb->sig_id == FW_KERNEL)
			__kern = fb->rom_dst;
		else if (fb->sig_id == FW_ROOTFS)
			__fs = fb->rom_dst;
	}

	if (i == fbuf->fblkcount) {
		if ((fbuf->fincmask & FW_KERNFS_MASK) == FW_KERNFS_MASK) {
			if (__kern && __fs) {
				if (kern)
					*kern = __kern;
				if (fs)
					*fs = __fs;
				status = 0;
			}
		} else
			status = 0;
	}

	return status;
}

static int __fw_commit_bootline(struct bootline_mtd_info *bl,
				unsigned int kern, unsigned int fs)
{
	char bootline[64];

	if (kern && fs) {
		sprintf(bootline, "0x%x,0x%x", kern, fs);
		nvram_set("x_sys_bootm", bootline);
		return nvram_commit();
	}

	return -1;
}

int fw_commit_bootline(unsigned int kern, unsigned int fs)
{
	struct bootline_mtd_info bl;
	int status;

	if (!fw_commit_lock())
		return -EINBURNING;

	if (fw_parse_bootline(&bl)) {
		fw_commit_unlock();
		return -1;
	}

	status = __fw_commit_bootline(&bl, kern, fs);
	fw_commit_unlock();
	return status;
}

int fw_write_back(struct fwstat *fbuf,
		  int (*preprocess)(struct fwblk *, void *, FW_WR *),
		  void *parm, unsigned int *kern, unsigned int *fs)
{
	int status;

	if (!fw_commit_lock())
		return -EINBURNING;

	status = __fw_write_back(fbuf, preprocess, parm, kern, fs);

	fw_commit_unlock();
	return status;
}

int fw_write(struct fwstat *fbuf,
	     int (*preprocess)(struct fwblk *, void *, FW_WR *), void *parm)
{
	int status;
	unsigned int kern = 0, fs = 0;

	if (!fw_commit_lock())
		return -EINBURNING;

	status = __fw_write_back(fbuf, preprocess, parm, &kern, &fs);
	if (!status)
		status = __fw_commit_bootline(&fbuf->blnfo, kern, fs);
	fw_commit_unlock();
	return status;
}

const char *fw_strerror(int errnum)
{
	if (errnum < 0)
		errnum = -errnum;

	if (errnum == 0) {
		return "No Error";
	} else if (errnum >= ESIGN) {
		switch (errnum) {
		case ESIGN:
			return "Invalid Signature";
		case EIDENTITY:
			return "Invalid Identity";
		case ELENGTH:
			return "Too Big Length";
		case ECKSUM:
			return "Incorrect Checksum";
		case EPARTIAL:
			return "Need both Kernel and Root file system";
		case EGETCONF:
			return "Failed To Get Configuration";
		case EINVALCONF:
			return "Invalid Configuration";
		case ESAMEVERS:
			return "Same or lower Version";
		case EGETFW:
			return "Failed To Get Firmware";
		case EINBURNING:
			return "Writing In Progress";
		case EDUAL:
			return "Dualize Error";
		case EVERIFY:
			return "Failed to Verify Write";
		default:
			return "Unknown Error";
		}
	}
	return strerror(errnum);
}
