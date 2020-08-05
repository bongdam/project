#ifndef _GIO_H
#define _GIO_H 1

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>

/* Function codes. */
#define GIO_F_ACPT_STATE				 100
#define GIO_F_GIO_ACCEPT				 101
#define GIO_F_GIO_BER_GET_HEADER			 102
#define GIO_F_GIO_CALLBACK_CTRL				 131
#define GIO_F_GIO_CTRL					 103
#define GIO_F_GIO_GETHOSTBYNAME				 120
#define GIO_F_GIO_GETS					 104
#define GIO_F_GIO_GET_ACCEPT_SOCKET			 105
#define GIO_F_GIO_GET_HOST_IP				 106
#define GIO_F_GIO_GET_PORT				 107
#define GIO_F_GIO_MAKE_PAIR				 121
#define GIO_F_GIO_NEW					 108
#define GIO_F_GIO_NEW_FILE				 109
#define GIO_F_GIO_NEW_MEM_BUF				 126
#define GIO_F_GIO_NREAD					 123
#define GIO_F_GIO_NREAD0				 124
#define GIO_F_GIO_NWRITE				 125
#define GIO_F_GIO_NWRITE0				 122
#define GIO_F_GIO_PUTS					 110
#define GIO_F_GIO_READ					 111
#define GIO_F_GIO_SOCK_INIT				 112
#define GIO_F_GIO_WRITE					 113
#define GIO_F_BUFFER_CTRL				 114
#define GIO_F_CONN_CTRL					 127
#define GIO_F_CONN_STATE				 115
#define GIO_F_FILE_CTRL					 116
#define GIO_F_FILE_READ					 130
#define GIO_F_LINEBUFFER_CTRL				 129
#define GIO_F_MEM_READ					 128
#define GIO_F_MEM_WRITE					 117
#define GIO_F_SSL_NEW					 118
#define GIO_F_WSASTARTUP				 119

/* Reason codes. */
#define GIO_R_ACCEPT_ERROR				 100
#define GIO_R_BAD_FOPEN_MODE				 101
#define GIO_R_BAD_HOSTNAME_LOOKUP			 102
#define GIO_R_BROKEN_PIPE				 124
#define GIO_R_CONNECT_ERROR				 103
#define GIO_R_EOF_ON_MEMORY_GIO				 127
#define GIO_R_ERROR_SETTING_NGIO			 104
#define GIO_R_ERROR_SETTING_NGIO_ON_ACCEPTED_SOCKET	 105
#define GIO_R_ERROR_SETTING_NGIO_ON_ACCEPT_SOCKET	 106
#define GIO_R_GETHOSTBYNAME_ADDR_IS_NOT_AF_INET		 107
#define GIO_R_INVALID_ARGUMENT				 125
#define GIO_R_INVALID_IP_ADDRESS			 108
#define GIO_R_IN_USE					 123
#define GIO_R_KEEPALIVE					 109
#define GIO_R_NGIO_CONNECT_ERROR			 110
#define GIO_R_NO_ACCEPT_PORT_SPECIFIED			 111
#define GIO_R_NO_HOSTNAME_SPECIFIED			 112
#define GIO_R_NO_PORT_DEFINED				 113
#define GIO_R_NO_PORT_SPECIFIED				 114
#define GIO_R_NO_SUCH_FILE				 128
#define GIO_R_NULL_PARAMETER				 115
#define GIO_R_TAG_MISMATCH				 116
#define GIO_R_UNABLE_TO_BIND_SOCKET			 117
#define GIO_R_UNABLE_TO_CREATE_SOCKET			 118
#define GIO_R_UNABLE_TO_LISTEN_SOCKET			 119
#define GIO_R_UNINITIALIZED				 120
#define GIO_R_UNSUPPORTED_OPER			 121
#define GIO_R_WRITE_TO_READ_ONLY_GIO			 126
#define GIO_R_WSASTARTUP				 122

#define BUF_F_BUFF_MEMDUP				 103
#define BUF_F_BUFF_MEM_GROW				 100
#define BUF_F_BUFF_MEM_GROW_CLEAN			 105
#define BUF_F_BUFF_MEM_NEW				 101
#define BUF_F_BUF_STRDUP				 102
#define BUF_F_BUF_STRNDUP				 104

#define ERR_R_FATAL				64
#define	ERR_R_MALLOC_FAILURE			(1|ERR_R_FATAL)
#define	ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED	(2|ERR_R_FATAL)
#define	ERR_R_PASSED_NULL_PARAMETER		(3|ERR_R_FATAL)
#define	ERR_R_INTERNAL_ERROR			(4|ERR_R_FATAL)
#define	ERR_R_DISABLED				(5|ERR_R_FATAL)

#define GIO_TYPE_NONE		0
#define GIO_TYPE_MEM		(1|0x0400)
#define GIO_TYPE_FILE		(2|0x0400)
#define GIO_TYPE_FD		(4|0x0400|0x0100)

#define GIO_NOCLOSE		0x00
#define GIO_CLOSE		0x01

#define GIO_CTRL_RESET		1	/* opt - rewind/zero etc */
#define GIO_CTRL_EOF		2	/* opt - are we at the eof */
#define GIO_CTRL_INFO		3	/* opt - extra tit-bits */
#define GIO_CTRL_SET		4	/* man - set the 'IO' type */
#define GIO_CTRL_GET		5	/* man - get the 'IO' type */
#define GIO_CTRL_PUSH		6	/* opt - internal, used to signify change */
#define GIO_CTRL_POP		7	/* opt - internal, used to signify change */
#define GIO_CTRL_GET_CLOSE	8	/* man - set the 'close' on free */
#define GIO_CTRL_SET_CLOSE	9	/* man - set the 'close' on free */
#define GIO_CTRL_PENDING	10	/* opt - is their more data buffered */
#define GIO_CTRL_FLUSH		11	/* opt - 'flush' buffered output */
#define GIO_CTRL_DUP		12	/* man - extra stuff for 'duped' GIO */
#define GIO_CTRL_WPENDING	13	/* opt - number of bytes still to write */

#define GIO_FLAGS_READ		0x01
#define GIO_FLAGS_WRITE		0x02
#define GIO_FLAGS_IO_SPECIAL	0x04
#define GIO_FLAGS_RWS (GIO_FLAGS_READ|GIO_FLAGS_WRITE|GIO_FLAGS_IO_SPECIAL)
#define GIO_FLAGS_SHOULD_RETRY	0x08
#ifndef	GIO_FLAGS_UPLINK
/* "UPLINK" flag denotes file descriptors provided by application.
   It defaults to 0, as most platforms don't require UPLINK interface. */
#define	GIO_FLAGS_UPLINK	0
#endif

#define GIO_FLAGS_MEM_RDONLY	0x200

#define GIO_clear_retry_flags(b) \
		gio_clear_flags(b, (GIO_FLAGS_RWS|GIO_FLAGS_SHOULD_RETRY))
#define GIO_set_retry_read(b) \
		gio_set_flags(b, (GIO_FLAGS_READ|GIO_FLAGS_SHOULD_RETRY))
#define GIO_set_retry_write(b) \
		gio_set_flags(b, (GIO_FLAGS_WRITE|GIO_FLAGS_SHOULD_RETRY))
#define GIO_should_retry(a) gio_test_flags(a, GIO_FLAGS_SHOULD_RETRY)

typedef struct gio_st GIO;
typedef struct gio_operation_st GIO_OPER;

extern int gio_set(GIO *bio, GIO_OPER *op);
extern GIO *gio_new(GIO_OPER *op);
extern int gio_free(GIO *a);
extern void gio_clear_flags(GIO *b, int flags);
extern int gio_test_flags(const GIO *b, int flags);
extern void gio_set_flags(GIO *b, int flags);
extern const char *gio_oper_name(const GIO *b);
extern int gio_oper_type(const GIO *b);
extern long gio_ctrl(GIO *b, int cmd, long larg, void *parg);
extern int gio_read(GIO *b, void *out, int outl);
extern int gio_write(GIO *b, const void *in, int inl);

extern GIO *gio_new_fd(int fd, int close_flag);
extern GIO_OPER *gio_s_mem(void);
extern GIO *gio_new_mem_buf(void *buf, int len);

extern ssize_t gio_safe_read(GIO *g, void *buf, size_t count);
extern ssize_t gio_full_read(GIO *g, void *buf, size_t count);

extern ssize_t gio_full_write(GIO *g, const void *buf, ssize_t len);

#endif
