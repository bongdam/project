#ifndef __KTKST_H__
#define __KTKST_H__

#ifndef __hidden
#define __hidden __attribute__((visibility("hidden")))
#endif

__hidden int ktkst_key_get(unsigned char *key1, unsigned char *key2, const unsigned char *key_default);
__hidden int ktkst_key_new(unsigned char *key1, unsigned char *key2, const unsigned char *key_default);

#endif
