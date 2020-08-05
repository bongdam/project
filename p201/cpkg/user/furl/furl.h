#ifndef __FURL_H
#define __FURL_H

#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

typedef int (*p_read_f)(char *, int, void *);

enum {
	FW_KERNEL = 1,
	FW_WEBS,
	FW_ROOTFS,
	FW_CONFIG,
	FW_BOOT
};

#define FW_KERNFS_MASK  ((1 << FW_KERNEL) | (1 << FW_ROOTFS))
#define FW_ALL_MASK     ((1 << FW_KERNEL) | (1 << FW_WEBS) | (1 << FW_ROOTFS) | (1 << FW_CONFIG) | (1 << FW_BOOT))

struct p_creat_item {
	FILE *f;
	pid_t pid;
};

struct bootline_mtd_info {
	char name[16];
	unsigned int kernel_offset;     /* bootline kernel */
	unsigned int rootfs_offset;     /* bootline roofs */
};

struct fwblk {
	int sig_id;
	char *ram_src;
	unsigned int rom_dst;
	size_t length;
};

typedef enum {
	FW_WR_DO = 0,
	FW_WR_SKIP
} FW_WR;

#define MAX_FBLKS 4

struct fwstat {
	char *fmem;
	int lasterror;
	int rcvlen;
	int caplen;
	unsigned int version;
	unsigned fincmask;
	int fblkcount;
	struct fwblk fblks[MAX_FBLKS];
	struct bootline_mtd_info blnfo;
};

#define MAX_FWSIZE   0x600000

enum {
	ESIGN = 400,
	EIDENTITY,
	ELENGTH,
	ECKSUM,
	EPARTIAL,
	EGETCONF,
	EINVALCONF,
	ESAMEVERS,
	EGETFW,
	EINBURNING,
	EDUAL,
	EVERIFY
};

struct goods_tag {
	unsigned short ver;	/* [14:15] MAJOR, [7:13] MINOR, [0:6] BUILD */
	unsigned char id;
	unsigned char crc;
};

#ifdef __cplusplus
extern "C" {
#endif
extern const int fw_hlen;

struct p_creat_item *p_creat(const char *command, const char *modes);
int p_close(struct p_creat_item *p);
int furl(char *command, int rcvtimeo, p_read_f __read, void *parm);

int fw_read_callback(char *, int, struct fwstat *);
int fw_validate(struct fwstat *fbuf);
int fw_write(struct fwstat *fbuf,
            int (*preprocess)(struct fwblk *, void *, FW_WR *),
            void *parm);

int fw_write_back(struct fwstat *fbuf,
            int (*preprocess)(struct fwblk *, void *, FW_WR *),
            void *parm,
            unsigned int *kern,
            unsigned int *fs);

int fw_commit_bootline(unsigned int kern, unsigned int fs);

const char *fw_strerror(int);
int fw_parse_bootline(struct bootline_mtd_info *);
int fw_dualize(struct fwstat *);

#ifdef __cplusplus
}
#endif
#endif
