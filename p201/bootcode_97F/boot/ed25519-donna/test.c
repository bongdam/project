/*
	Validate ed25519 implementation against the official test vectors from 
	http://ed25519.cr.yp.to/software.html
*/

#include <stdio.h>
#include <string.h>
#include "ed25519.h"
//#include "test-ticks.h"
#include <sys/stat.h>
#include <stdlib.h>
#include <dirent.h>
#include <signature.h>

#undef DEBUG 
#ifdef DEBUG
#define SB_DBG printf
#else
#define SB_DBG
#endif

int verify_signature(int num, unsigned char *data, unsigned int len, unsigned char *sig) 
{
	int ret_val = 0;
	unsigned char *public_key = {0};
	
	if (num == 1)
		public_key = LINUX_PUB_KEY;
	else if (num == 2)
		public_key = ROOTFS_PUB_KEY;
	printf("public_key %s\n", public_key);

	ret_val = ed25519_sign_open(data, len, public_key, sig);
	if (ret_val!=0x0) {
		printf("Check signature fail\n\n");
		printf("ret_val:0x%x\n", ret_val);
		printf("sig\n");
		dump_hex_data(sig, 64);
		printf("public_key, %s\n", public_key);
		return ret_val;
	}

	//  test_main2();
	//	test_main();
	//	test_batch();
	return ret_val;
}

