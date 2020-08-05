#include "lk.h"
#if defined(CONFIG_RTL8192CD) || defined(CONFIG_RTL8192CD_MODULE)
#include "../8192cd.h"
#include "../8192cd_headers.h"
#else
#include "../rtl8190/8190n.h"
#include "../rtl8190/8190n_headers.h"
#endif

void *calloc(size_t n, size_t size)
{
	return kzalloc(n * size, GFP_ATOMIC);
}

void free(void *ptr)
{
	kfree(ptr);
}

#if defined(MBEDTLS_SELF_TEST) && defined(MBEDTLS_PKCS1_V15)
int rand(void)
{
	return get_random_int();
}
#endif
