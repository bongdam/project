
#define GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>

__attribute__((weak)) int pthread_create(pthread_t *, const pthread_attr_t *, void *(*)(void *), void *);

static inline int lock(pthread_mutex_t *mutex)
{
	return (pthread_create) ? pthread_mutex_lock(mutex) : 0;
}

static inline int unlock(pthread_mutex_t *mutex)
{
	return (pthread_create) ? pthread_mutex_unlock(mutex) : 0;
}

char *inet_n2a(unsigned int addr)
{
	static pthread_mutex_t lock_buf = PTHREAD_MUTEX_INITIALIZER;
	static char buf[16][16];
	static int pos;

	lock(&lock_buf);
	pos = (pos + 1) & 0xf;
	unlock(&lock_buf);
	return (char *)inet_ntop(AF_INET, &addr, buf[pos], sizeof(buf[0]));
}
