#ifndef __FILE_UTILS_H__
#define __FILE_UTILS_H__

#ifndef __hidden
#define __hidden __attribute__((visibility("hidden")))
#endif

__hidden int z_safe_read(int fd, void *buf, int count);
__hidden int z_safe_write(int fd, void *buf, int count);
__hidden int z_file_read(char *fname, unsigned char *buf, int buf_sz);
__hidden int z_file_write(char *fname, unsigned char *buf, int buf_sz);
__hidden int z_file_compare(char *fname1, char *fname2);
__hidden int z_file_copy(char *src, char *dst);
__hidden int z_file_touch(char *fname);

#define Z_FILE_OP_CMP_COPY 0
#define Z_FILE_OP_COPY 1
#define Z_FILE_EXEC_OP_BG 0
#define Z_FILE_EXEC_OP_FG 1

#define KTKST_BACKUP 1

/* !!!  set 0  key file single */
/* !!!  set 1  key file separate */
#define KT_SECURITY_FEATURE 		0

#define KTKST_KEY_FILE "/userdata/config/ktkstoa"
#define KTKST_KEY2_FILE "/userdata/config/ktkstoc"

#if KTKST_BACKUP
#define KTKST_KEY_FILE2 "/userdata/config/ktkstob"
#define KTKST_KEY2_FILE2 "/userdata/config/ktkstod"
#define KTKST_INIT_FILE "/tmp/.ktkst_init"
#endif

__hidden int z_file_cmp_copy(char *src, char *dst, int op, int exec_op);
#endif
