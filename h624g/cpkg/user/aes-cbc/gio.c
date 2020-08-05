
#include "gio.h"

/* Generic IO being copied from openssl and tailored */

static void GIOerr_say(int c, int r, const char *f, int l)
{
	fprintf(stderr, "%s(%d) function: %d, reason: %d\n", f, l, c, r);
}

#define GIOerr(a, b) GIOerr_say(a, b, __func__, __LINE__);
#define BUFerr GIOerr

struct gio_operation_st {
	int type;
	const char *name;
	int (*bwrite)(GIO *, const char *, int);
	int (*bread)(GIO *, char *, int);
	long (*ctrl)(GIO *, int, long, void *);
	int (*create)(GIO *);
	int (*destroy)(GIO *);
};

struct gio_st {
	GIO_OPER *op;
	int init;
	int shutdown;
	int flags;		/* extra storage */
	int num;
	void *ptr;
	unsigned long num_read;
	unsigned long num_write;
};

int gio_set(GIO *bio, GIO_OPER *op)
{
	bio->op = op;
	bio->init = 0;
	bio->shutdown = 1;
	bio->flags = 0;
	bio->num = 0;
	bio->ptr = NULL;
	bio->num_read = 0L;
	bio->num_write = 0L;
	if (op->create != NULL)
		if (!op->create(bio)) {
			return (0);
		}
	return (1);
}

GIO *gio_new(GIO_OPER *op)
{
	GIO *ret = NULL;

	ret = (GIO *)malloc(sizeof(GIO));
	if (ret == NULL) {
		GIOerr(GIO_F_GIO_NEW, ERR_R_MALLOC_FAILURE);
		return (NULL);
	}
	if (!gio_set(ret, op)) {
		free(ret);
		ret = NULL;
	}
	return (ret);
}

int gio_free(GIO *a)
{
	int ret;

	if (a == NULL)
		return (0);

	if ((a->op == NULL) || (a->op->destroy == NULL))
		return (1);
	ret = a->op->destroy(a);
	free(a);
	return ret;
}

void gio_clear_flags(GIO *b, int flags)
{
	b->flags &= ~flags;
}

int gio_test_flags(const GIO *b, int flags)
{
	return (b->flags & flags);
}

void gio_set_flags(GIO *b, int flags)
{
	b->flags |= flags;
}

const char *gio_oper_name(const GIO *b)
{
	return b->op->name;
}

int gio_oper_type(const GIO *b)
{
	return b->op->type;
}

long gio_ctrl(GIO *b, int cmd, long larg, void *parg)
{
	if (b == NULL)
		return (0);

	if ((b->op == NULL) || (b->op->ctrl == NULL)) {
		GIOerr(GIO_F_GIO_CTRL, GIO_R_UNSUPPORTED_OPER);
		return (-2);
	}

	return b->op->ctrl(b, cmd, larg, parg);
}

int gio_read(GIO *b, void *out, int outl)
{
	int i;

	if ((b == NULL) || (b->op == NULL) || (b->op->bread == NULL)) {
		GIOerr(GIO_F_GIO_READ, GIO_R_UNSUPPORTED_OPER);
		return (-2);
	}

	if (!b->init) {
		GIOerr(GIO_F_GIO_READ, GIO_R_UNINITIALIZED);
		return (-2);
	}

	i = b->op->bread(b, out, outl);

	if (i > 0)
		b->num_read += (unsigned long)i;

	return (i);
}

int gio_write(GIO *b, const void *in, int inl)
{
	int i;

	if (b == NULL)
		return (0);

	if ((b->op == NULL) || (b->op->bwrite == NULL)) {
		GIOerr(GIO_F_GIO_WRITE, GIO_R_UNSUPPORTED_OPER);
		return (-2);
	}

	if (!b->init) {
		GIOerr(GIO_F_GIO_WRITE, GIO_R_UNINITIALIZED);
		return (-2);
	}

	i = b->op->bwrite(b, in, inl);

	if (i > 0)
		b->num_write += (unsigned long)i;

	return (i);
}

// memory
typedef struct buf_mem_st BUFF_MEM;

struct buf_mem_st {
	int length;		/* current number of bytes */
	char *data;
	int max;		/* size of buffer */
};

static BUFF_MEM *BUFF_MEM_new(void)
{
	BUFF_MEM *ret;

	ret = malloc(sizeof(BUFF_MEM));
	if (ret == NULL) {
		BUFerr(BUF_F_BUFF_MEM_NEW, ERR_R_MALLOC_FAILURE);
		return (NULL);
	}
	ret->length = 0;
	ret->max = 0;
	ret->data = NULL;
	return (ret);
}

static void BUFF_MEM_free(BUFF_MEM *a)
{
	if (a == NULL)
		return;

	if (a->data != NULL) {
		memset(a->data, 0, (unsigned int)a->max);
		free(a->data);
	}
	free(a);
}

static int BUFF_MEM_grow(BUFF_MEM *str, int len)
{
	char *ret;
	unsigned int n;

	if (str->length >= len) {
		str->length = len;
		return (len);
	}
	if (str->max >= len) {
		memset(&str->data[str->length], 0, len - str->length);
		str->length = len;
		return (len);
	}
	n = (len + 3) / 3 * 4;
	if (str->data == NULL)
		ret = malloc(n);
	else
		ret = realloc(str->data, n);
	if (ret == NULL) {
		BUFerr(BUF_F_BUFF_MEM_GROW, ERR_R_MALLOC_FAILURE);
		len = 0;
	} else {
		str->data = ret;
		str->max = n;
		memset(&str->data[str->length], 0, len - str->length);
		str->length = len;
	}
	return (len);
}

static int mem_new(GIO *bi);
static int mem_free(GIO *a);
static long mem_ctrl(GIO * b, int cmd, long num, void *ptr);
static int mem_read(GIO *b, char *out, int outl);
static int mem_write(GIO *b, const char *in, int inl);

static GIO_OPER mem_method = {
	.type = GIO_TYPE_MEM,
	.name = "memory buffer",
	.bwrite = mem_write,
	.bread = mem_read,
	.ctrl = mem_ctrl,
	.create = mem_new,
	.destroy = mem_free,
};

GIO_OPER *gio_s_mem(void)
{
	return (&mem_method);
}

GIO *gio_new_mem_buf(void *buf, int len)
{
	GIO *ret;
	BUFF_MEM *b;
	if (!buf) {
		GIOerr(GIO_F_GIO_NEW_MEM_BUF, GIO_R_NULL_PARAMETER);
		return NULL;
	}
	if (len == -1)
		len = strlen(buf);
	if (!(ret = gio_new(gio_s_mem())))
		return NULL;
	b = (BUFF_MEM *)ret->ptr;
	b->data = buf;
	b->length = len;
	b->max = len;
	ret->flags |= GIO_FLAGS_MEM_RDONLY;
	/* Since this is static data retrying wont help */
	ret->num = 0;
	return ret;
}

static int mem_new(GIO *bi)
{
	BUFF_MEM *b;

	if ((b = BUFF_MEM_new()) == NULL)
		return (0);
	bi->shutdown = 1;
	bi->init = 1;
	bi->num = -1;
	bi->ptr = (char *)b;
	return (1);
}

static int mem_free(GIO *a)
{
	if (a == NULL)
		return (0);
	if (a->shutdown) {
		if ((a->init) && (a->ptr != NULL)) {
			BUFF_MEM *b;
			b = (BUFF_MEM *)a->ptr;
			if (a->flags & GIO_FLAGS_MEM_RDONLY)
				b->data = NULL;
			BUFF_MEM_free(b);
			a->ptr = NULL;
		}
	}
	return (1);
}

static long mem_ctrl(GIO * b, int cmd, long num, void *ptr)
{
	long ret = 1;
	char **pptr;

	BUFF_MEM *bm = (BUFF_MEM *) b->ptr;

	switch (cmd) {
	case GIO_CTRL_INFO:
		ret = (long)bm->length;
		if (ptr != NULL) {
			pptr = (char **)ptr;
			*pptr = (char *)&(bm->data[0]);
		}
		break;
	default:
		ret = 0;
		break;
	}
	return (ret);
}

static int mem_read(GIO *b, char *out, int outl)
{
	int ret = -1;
	BUFF_MEM *bm;
	int i;
	char *from, *to;

	bm = (BUFF_MEM *)b->ptr;
	GIO_clear_retry_flags(b);
	ret = (outl > bm->length) ? bm->length : outl;
	if ((out != NULL) && (ret > 0)) {
		memcpy(out, bm->data, ret);
		bm->length -= ret;
		/* memmove(&(bm->data[0]),&(bm->data[ret]), bm->length); */
		if (b->flags & GIO_FLAGS_MEM_RDONLY)
			bm->data += ret;
		else {
			from = (char *)&(bm->data[ret]);
			to = (char *)&(bm->data[0]);
			for (i = 0; i < bm->length; i++)
				to[i] = from[i];
		}
	} else if (bm->length == 0) {
		ret = b->num;
		if (ret != 0)
			GIO_set_retry_read(b);
	}
	return (ret);
}

static int mem_write(GIO *b, const char *in, int inl)
{
	int ret = -1;
	int blen;
	BUFF_MEM *bm;

	bm = (BUFF_MEM *)b->ptr;
	if (in == NULL) {
		GIOerr(GIO_F_MEM_WRITE, GIO_R_NULL_PARAMETER);
		goto end;
	}

	if (b->flags & GIO_FLAGS_MEM_RDONLY) {
		GIOerr(GIO_F_MEM_WRITE, GIO_R_WRITE_TO_READ_ONLY_GIO);
		goto end;
	}

	GIO_clear_retry_flags(b);
	blen = bm->length;
	if (BUFF_MEM_grow(bm, blen + inl) != (blen + inl))
		goto end;
	memcpy(&(bm->data[blen]), in, inl);
	ret = inl;
end:
	return (ret);
}

// fd
static int GIO_fd_non_fatal_error(int err)
{
	switch (err) {

#ifdef EWOULDBLOCK
#ifdef WSAEWOULDBLOCK
#if WSAEWOULDBLOCK != EWOULDBLOCK
	case EWOULDBLOCK:
#endif
#else
	case EWOULDBLOCK:
#endif
#endif

#if defined(ENOTCONN)
	case ENOTCONN:
#endif

#ifdef EINTR
	case EINTR:
#endif

#ifdef EAGAIN
#if EWOULDBLOCK != EAGAIN
	case EAGAIN:
#endif
#endif

#ifdef EPROTO
	case EPROTO:
#endif

#ifdef EINPROGRESS
	case EINPROGRESS:
#endif

#ifdef EALREADY
	case EALREADY:
#endif
		return (1);
	/* break; */
	default:
		break;
	}
	return (0);
}

static int GIO_fd_should_retry(int i)
{
	int err;

	if ((i == 0) || (i == -1)) {
		err = errno;

		return (GIO_fd_non_fatal_error(err));
	}
	return (0);
}

static int fd_write(GIO *h, const char *buf, int num);
static int fd_read(GIO *h, char *buf, int size);
static int fd_new(GIO *h);
static int fd_free(GIO *data);

static GIO_OPER methods_fdp = {
	.type = GIO_TYPE_FD,
	.name = "file descriptor",
	.bwrite = fd_write,
	.bread = fd_read,
	.create = fd_new,
	.destroy = fd_free,
};

GIO_OPER *GIO_s_fd(void)
{
	return (&methods_fdp);
}

GIO *gio_new_fd(int fd, int close_flag)
{
	GIO *ret;
	ret = gio_new(GIO_s_fd());
	if (ret == NULL)
		return (NULL);
	fd_free(ret);
	ret->num = fd;
	ret->shutdown = close_flag;
	ret->init = 1;
	return (ret);
}

static int fd_new(GIO *bi)
{
	bi->init = 0;
	bi->num = -1;
	bi->ptr = NULL;
	bi->flags = GIO_FLAGS_UPLINK;	/* essentially redundant */
	return (1);
}

static int fd_free(GIO *a)
{
	if (a == NULL)
		return (0);
	if (a->shutdown) {
		if (a->init) {
			close(a->num);
		}
		a->init = 0;
		a->flags = GIO_FLAGS_UPLINK;
	}
	return (1);
}

static int fd_read(GIO *b, char *out, int outl)
{
	int ret = 0;

	if (out != NULL) {
		errno = 0;
		ret = read(b->num, out, outl);
		GIO_clear_retry_flags(b);
		if (ret <= 0) {
			if (GIO_fd_should_retry(ret))
				GIO_set_retry_read(b);
		}
	}
	return (ret);
}

static int fd_write(GIO *b, const char *in, int inl)
{
	int ret;
	errno = 0;
	ret = write(b->num, in, inl);
	GIO_clear_retry_flags(b);
	if (ret <= 0) {
		if (GIO_fd_should_retry(ret))
			GIO_set_retry_write(b);
	}
	return (ret);
}

ssize_t gio_full_write(GIO *g, const void *buf, ssize_t len)
{
	ssize_t cc;
	ssize_t total;

	total = 0;

	while (len > 0) {
		do {
			cc = gio_write(g, buf, len);
		} while (cc < 0 && GIO_should_retry(g));
		if (cc < 0) {
			if (total) {
				/* we already wrote some! */
				/* user can do another write to know the error code */
				return total;
			}
			return cc;	/* write() returns -1 on failure. */
		}

		total += cc;
		buf = ((const char *)buf) + cc;
		len -= cc;
	}

	return total;
}

ssize_t gio_safe_read(GIO *g, void *buf, size_t count)
{
	ssize_t n;

	do {
		n = gio_read(g, buf, count);
	} while (n < 0 && GIO_should_retry(g));
	return n;
}
