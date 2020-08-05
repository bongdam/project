all:
	cp -a $(DIR_LINUX)/include/generated/autoconf.h .
	gcc sign_key.c ed25519.c -DED25519_TEST -DED25519_REFHASH -o gen_sig
	cp -a ./gen_sig ../
