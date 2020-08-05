/*
 * NVRAM variable manipulation (Linux user mode half)
 *
 * Copyright (C) 2012, Broadcom Corporation. All Rights Reserved.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 * $Id: nvram_linux.c 365067 2012-10-26 15:51:28Z $
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <error.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ipc.h>
#include <sys/sem.h>
#include <fcntl.h>
#include <sys/mman.h>

#include <typedefs.h>
#include <bcmnvram.h>
#include <signal.h>

#define PATH_DEV_NVRAM "/dev/nvram"

/* Globals */
static int nvram_fd = -1;
static char *nvram_buf = NULL;

static const long KEY_ID = 0x4E564D58;
static struct sembuf sb_lock[2] = { {0, 0, 0}, {0, 1, SEM_UNDO} };
static struct sembuf sb_unlock[1] = { {0, -1, IPC_NOWAIT | SEM_UNDO} };

static int nvram_semid = -1;

char *nvram_user_get(const char *name, char *value);

static inline void nvram_lock(void)
{
	if (nvram_semid > -1 && semop(nvram_semid, &sb_lock[0], 2) < 0)
		perror("nvram_lock");
}

static inline void nvram_unlock(void)
{
	if (nvram_semid > -1 && semop(nvram_semid, &sb_unlock[0], 1) < 0)
		perror("nvram_unlock");
}

static int nvram_init_MUTEX(void)
{
	int semid = nvram_semid;

	if (semid < 0 && (semid = semget(KEY_ID, 0, 0)) < 0) {
		if (((semid = semget(KEY_ID, 1, IPC_CREAT | 0666)) < 0) ||
		    (semctl(semid, 0, SETVAL, 0) < 0)) {
			perror("nvram_init_MUTEX");
			return -1;
		}
	}

	return semid;
}

int
nvram_init(void *unused)
{
	if (nvram_fd >= 0)
		return 0;

	if ((nvram_fd = open(PATH_DEV_NVRAM, O_RDWR)) < 0)
		goto err;

	/* Map kernel string buffer into user space */
	nvram_buf = mmap(NULL, MAX_NVRAM_SPACE, PROT_READ, MAP_SHARED, nvram_fd, 0);
	if (nvram_buf == MAP_FAILED) {
		close(nvram_fd);
		nvram_fd = -1;
		goto err;
	}

	fcntl(nvram_fd, F_SETFD, FD_CLOEXEC);
	nvram_semid = nvram_init_MUTEX();
	return 0;

err:
	perror(PATH_DEV_NVRAM);
	return errno;
}

char *
nvram_get(const char *name)
{
	size_t count = strlen(name) + 1;
	char tmp[100], *value;
	unsigned long *off = (unsigned long *) tmp;

#if defined(__DAVO__)
	sigset_t sigset, oldset;
#endif
	if (nvram_init(NULL))
		return NULL;

	if (count > sizeof(tmp)) {
		if (!(off = malloc(count)))
			return NULL;
	}

	/* Get offset into mmap() space */
	strcpy((char *) off, name);

#if defined(__DAVO__)
	sigfillset(&sigset);
	sigprocmask(SIG_BLOCK, &sigset, &oldset);
#endif

	nvram_lock();

	count = read(nvram_fd, off, count);

	if (count == sizeof(unsigned long))
		value = &nvram_buf[*off];
	else
		value = NULL;

	value = nvram_user_get(name, value);

	nvram_unlock();
#if defined(__DAVO__)
	sigprocmask(SIG_SETMASK, &oldset, NULL);
#endif

	if (count < 0)
		perror(PATH_DEV_NVRAM);

	if (off != (unsigned long *) tmp)
		free(off);

	return value;
}

int
nvram_getall(char *buf, int count)
{
	int ret;

	if (nvram_fd < 0)
		if ((ret = nvram_init(NULL)))
			return ret;

	if (count == 0)
		return 0;

	/* Get all variables */
	*buf = '\0';

	ret = read(nvram_fd, buf, count);

	if (ret < 0)
		perror(PATH_DEV_NVRAM);

	return (ret == count) ? 0 : ret;
}

typedef struct {
	const char *s;
	int len;
} str;

#define TRIM_SWITCH(c) \
	switch(c) { \
	case ' ': \
	case '\t': \
	case '\r': \
	case '\n': \
		break; \
	default: \
		return; \
	}

static inline void trim_leading(str * _s)
{
	for (; _s->len > 0; _s->len--, _s->s++) {
		TRIM_SWITCH(*(_s->s));
	}
}

static inline void trim_trailing(str * _s)
{
	for (; _s->len > 0; _s->len--) {
		TRIM_SWITCH(_s->s[_s->len - 1]);
	}
}

static inline void trim_whites(str * _s)
{
	trim_leading(_s);
	trim_trailing(_s);
}

static int
_nvram_set(const char *name, const char *value)
{
	str name_s = {.s = name };
	str value_s = {.s = value };
	size_t count;
	char tmp[100], *buf = tmp;
	int ret;
#if defined(__DAVO__)
	sigset_t sigset, oldset;
#endif

	name_s.len = strlen(name);
	count = (size_t)name_s.len + 1;
	if ((ret = nvram_init(NULL)))
		return ret;

	/* Unset if value is NULL */
	if (value) {
		value_s.len = strlen(value);
		count += ((size_t)(value_s.len) + 1);
	}

	if (count > sizeof(tmp)) {
		if (!(buf = malloc(count)))
			return -ENOMEM;
	}

	trim_whites(&name_s);
	if (value) {
		trim_whites(&value_s);
		sprintf(buf, "%.*s=%.*s", name_s.len, name_s.s, value_s.len, value_s.s);
	} else
		sprintf(buf, "%.*s", name_s.len, name_s.s);

#if defined(__DAVO__)
	sigfillset(&sigset);
	sigprocmask(SIG_BLOCK, &sigset, &oldset);
#endif
	nvram_lock();

	ret = write(nvram_fd, buf, count);

	if (value == NULL)
		nvram_user_get(name, NULL);

	nvram_unlock();
#if defined(__DAVO__)
	sigprocmask(SIG_SETMASK, &oldset, NULL);
#endif

	if (ret < 0)
		perror(PATH_DEV_NVRAM);

	if (buf != tmp)
		free(buf);

	return (ret == count) ? 0 : ret;
}

int
nvram_set(const char *name, const char *value)
{
	return _nvram_set(name, value);
}

int
nvram_unset(const char *name)
{
	return _nvram_set(name, NULL);
}

int
nvram_commit(void)
{
	int ret;

	if ((ret = nvram_init(NULL)))
		return ret;

	ret = ioctl(nvram_fd, NVRAM_MAGIC, NULL);

	if (ret < 0)
		perror(PATH_DEV_NVRAM);

	return ret;
}

char *_nvram_get_r(char *name, char *buf, int bufsize, char *dfl)
{
	if (buf != NULL && bufsize > 0) {
		char *value = nvram_get(name) ? : dfl;
		if (value) {
			strncpy(buf, value, bufsize--);
			buf[bufsize] = '\0';
			return buf;
		}
	}
	return NULL;
}
