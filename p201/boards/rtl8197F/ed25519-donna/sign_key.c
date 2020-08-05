/*
	Validate ed25519 implementation against the official test vectors from 
	http://ed25519.cr.yp.to/software.html
*/

#include <stdio.h>
#include <string.h>
#include "ed25519.h"
#include "test-ticks.h"
#include <sys/stat.h>
#include <stdlib.h>
#include <dirent.h>
#include "autoconf.h"

#undef DEBUG
#ifdef DEBUG
#define SB_DBG printf
#else
#define SB_DBG
#endif

static void
edassert(int check, int round, const char *failreason) {
	if (check)
		return;
	printf("round %d, %s\n", round, failreason);
	exit(1);
}

static void
edassert_die(const unsigned char *a, const unsigned char *b, size_t len, int round, const char *failreason) {
	size_t i;
	if (round > 0)
		printf("round %d, %s\n", round, failreason);
	else
		printf("%s\n", failreason);
	printf("want: "); for (i = 0; i < len; i++) printf("%02x,", a[i]); printf("\n");
	printf("got : "); for (i = 0; i < len; i++) printf("%02x,", b[i]); printf("\n");
	printf("diff: "); for (i = 0; i < len; i++) if (a[i] ^ b[i]) printf("%02x,", a[i] ^ b[i]); else printf("  ,"); printf("\n\n");
	exit(1);
}

static void
edassert_equal(const unsigned char *a, const unsigned char *b, size_t len, const char *failreason) {
	if (memcmp(a, b, len) == 0)
		return;
	edassert_die(a, b, len, -1, failreason);
}

static void
edassert_equal_round(const unsigned char *a, const unsigned char *b, size_t len, int round, const char *failreason) {
	if (memcmp(a, b, len) == 0)
		return;
	edassert_die(a, b, len, round, failreason);
}


/* test data */
typedef struct test_data_t {
	unsigned char sk[32], pk[32], sig[64];
	const char *m;
} test_data;


test_data dataset[] = {
#include "regression.h"
};

/* result of the curve25519 scalarmult ((|255| * basepoint) * basepoint)... 1024 times */
const curved25519_key curved25519_expected = {
	0xac,0xce,0x24,0xb1,0xd4,0xa2,0x36,0x21,
	0x15,0xe2,0x3e,0x84,0x3c,0x23,0x2b,0x5f,
	0x95,0x6c,0xc0,0x7b,0x95,0x82,0xd7,0x93,
	0xd5,0x19,0xb6,0xf1,0xfb,0x96,0xd6,0x04
};


/* from ed25519-donna-batchverify.h */
extern unsigned char batch_point_buffer[3][32];

/* y coordinate of the final point from 'amd64-51-30k' with the same random generator */
static const unsigned char batch_verify_y[32] = {
	0x51,0xe7,0x68,0xe0,0xf7,0xa1,0x88,0x45,
	0xde,0xa1,0xcb,0xd9,0x37,0xd4,0x78,0x53,
	0x1b,0x95,0xdb,0xbe,0x66,0x59,0x29,0x3b,
	0x94,0x51,0x2f,0xbc,0x0d,0x66,0xba,0x3f
};

/*
static const unsigned char batch_verify_y[32] = {
	0x5c,0x63,0x96,0x26,0xca,0xfe,0xfd,0xc4,
	0x2d,0x11,0xa8,0xe4,0xc4,0x46,0x42,0x97,
	0x97,0x92,0xbe,0xe0,0x3c,0xef,0x96,0x01,
	0x50,0xa1,0xcc,0x8f,0x50,0x85,0x76,0x7d
};

Introducing the 128 bit r scalars to the heap _before_ the largest scalar
fits in to 128 bits alters the heap shape and produces a different,
yet still neutral/valid y/z value.

This was the value of introducing the r scalars when the largest scalar fit
in to 135-256 bits. You can produce it with amd64-64-24k / amd64-51-32k
with the random sequence used in the first pass by changing

    unsigned long long hlen=((npoints+1)/2)|1;

to

    unsigned long long hlen=npoints;

in ge25519_multi_scalarmult.c

ed25519-donna-batchverify.h has been modified to match the 
default amd64-64-24k / amd64-51-32k behaviour
*/



/* batch test */
#define test_batch_count 64
#define test_batch_rounds 96

typedef enum batch_test_t {
	batch_no_errors = 0,
	batch_wrong_message = 1,
	batch_wrong_pk = 2,
	batch_wrong_sig = 3
} batch_test;

static int
test_batch_instance(batch_test type, uint64_t *ticks) {
	ed25519_secret_key sks[test_batch_count];
	ed25519_public_key pks[test_batch_count];
	ed25519_signature sigs[test_batch_count];
	unsigned char messages[test_batch_count][128];
	size_t message_lengths[test_batch_count];
	const unsigned char *message_pointers[test_batch_count];
	const unsigned char *pk_pointers[test_batch_count];
	const unsigned char *sig_pointers[test_batch_count];
	int valid[test_batch_count], ret, validret;
	size_t i;
	uint64_t t;

	/* generate keys */
	for (i = 0; i < test_batch_count; i++) {
		ed25519_randombytes_unsafe(sks[i], sizeof(sks[i]));
		ed25519_publickey(sks[i], pks[i]);
		pk_pointers[i] = pks[i];
	}

	/* generate messages */
	ed25519_randombytes_unsafe(messages, sizeof(messages));
	for (i = 0; i < test_batch_count; i++) {
		message_pointers[i] = messages[i];
		message_lengths[i] = (i & 127) + 1;
	}

	/* sign messages */
	for (i = 0; i < test_batch_count; i++) {
		ed25519_sign(message_pointers[i], message_lengths[i], sks[i], pks[i], sigs[i]);
		sig_pointers[i] = sigs[i];
	}

	validret = 0;
	if (type == batch_wrong_message) {
		message_pointers[0] = message_pointers[1];
		validret = 1|2;
	} else if (type == batch_wrong_pk) {
		pk_pointers[0] = pk_pointers[1];
		validret = 1|2;
	} else if (type == batch_wrong_sig) {
		sig_pointers[0] = sig_pointers[1];
		validret = 1|2;
	}

	/* batch verify */
	t = get_ticks();
	ret = ed25519_sign_open_batch(message_pointers, message_lengths, pk_pointers, sig_pointers, test_batch_count, valid);
	*ticks = get_ticks() - t;
	edassert_equal((unsigned char *)&validret, (unsigned char *)&ret, sizeof(int), "batch return code");
	for (i = 0; i < test_batch_count; i++) {
		validret = ((type == batch_no_errors) || (i != 0)) ? 1 : 0;
		edassert_equal((unsigned char *)&validret, (unsigned char *)&valid[i], sizeof(int), "individual batch return code");
	}
	return ret;
}

static void
test_batch(void) {
	uint64_t dummy_ticks, ticks[test_batch_rounds], best = maxticks, sum;
	size_t i, count;

	/* check the first pass for the expected result */
	test_batch_instance(batch_no_errors, &dummy_ticks);
	edassert_equal(batch_verify_y, batch_point_buffer[1], 32, "failed to generate expected result");

	/* make sure ge25519_multi_scalarmult_vartime throws an error on the entire batch with wrong data */
	for (i = 0; i < 4; i++) {
		test_batch_instance(batch_wrong_message, &dummy_ticks);
		test_batch_instance(batch_wrong_pk, &dummy_ticks);
		test_batch_instance(batch_wrong_sig, &dummy_ticks);
	}

	/* speed test */
	for (i = 0; i < test_batch_rounds; i++) {
		test_batch_instance(batch_no_errors, &ticks[i]);
		if (ticks[i] < best)
			best = ticks[i];
	}

	/* take anything within 1% of the best time */
	for (i = 0, sum = 0, count = 0; i < test_batch_rounds; i++) {
		if (ticks[i] < (best * 1.01)) {
			sum += ticks[i];
			count++;
		}
	}
	printf("%.0f ticks/verification\n", (double)sum / (count * test_batch_count));
}

static void
test_main(void) {
	int i, res;
	ed25519_public_key pk;
	ed25519_signature sig;
	unsigned char forge[1024] = {'x'};
	curved25519_key csk[2] = {{255}};
	uint64_t ticks, pkticks = maxticks, signticks = maxticks, openticks = maxticks, curvedticks = maxticks;

	for (i = 0; i < 1024; i++) {
		ed25519_publickey(dataset[i].sk, pk);
		edassert_equal_round(dataset[i].pk, pk, sizeof(pk), i, "public key didn't match");
		ed25519_sign((unsigned char *)dataset[i].m, i, dataset[i].sk, pk, sig);
		edassert_equal_round(dataset[i].sig, sig, sizeof(sig), i, "signature didn't match");
		edassert(!ed25519_sign_open((unsigned char *)dataset[i].m, i, pk, sig), i, "failed to open message");

		memcpy(forge, dataset[i].m, i);
		if (i)
			forge[i - 1] += 1;

		edassert(ed25519_sign_open(forge, (i) ? i : 1, pk, sig), i, "opened forged message");
	}

	for (i = 0; i < 1024; i++)
		curved25519_scalarmult_basepoint(csk[(i & 1) ^ 1], csk[i & 1]);
	edassert_equal(curved25519_expected, csk[0], sizeof(curved25519_key), "curve25519 failed to generate correct value");

	for (i = 0; i < 2048; i++) {
		timeit(ed25519_publickey(dataset[0].sk, pk), pkticks)
		edassert_equal_round(dataset[0].pk, pk, sizeof(pk), i, "public key didn't match");
		timeit(ed25519_sign((unsigned char *)dataset[0].m, 0, dataset[0].sk, pk, sig), signticks)
		edassert_equal_round(dataset[0].sig, sig, sizeof(sig), i, "signature didn't match");
		timeit(res = ed25519_sign_open((unsigned char *)dataset[0].m, 0, pk, sig), openticks)
		edassert(!res, 0, "failed to open message");
		timeit(curved25519_scalarmult_basepoint(csk[1], csk[0]), curvedticks);
	}

	printf("%.0f ticks/public key generation\n", (double)pkticks);
	printf("%.0f ticks/signature\n", (double)signticks);
	printf("%.0f ticks/signature verification\n", (double)openticks);
	printf("%.0f ticks/curve25519 basepoint scalarmult\n", (double)curvedticks);
}

void dump_hex_data(unsigned char *arr, int len)
{
    int i;
    for (i = 0; i < len; i++) {
        if (i != 0 && i%32 == 0)
            SB_DBG("\n");

        SB_DBG("%02X ", arr[i]);
    }
    SB_DBG("\n\n");
}

int ascii_to_hex(char c)
{
        int num = (int) c;
        if(num < 58 && num > 47)
        {
                return num - 48; 
        }
        if(num < 71 && num > 64)
        {
                return num - 55;
        }
	  if(num < 103 && num > 96)
        {
                return num - 87;
        }
        return num;
}

static unsigned char private_key[32] = {0}; 
static unsigned char public_key[32] = {0};
int get_key(num)
{
	int i;
	FILE *fp_ed_pri_in;
	unsigned char c1,c2;
	unsigned char sum;

	if(num==1)
		fp_ed_pri_in = fopen("keys/linux_pri_key.txt", "r");
	else if(num==2)
		fp_ed_pri_in = fopen("keys/rootfs_pri_key.txt", "r");

	if(!fp_ed_pri_in) {
		printf("Generate new keys to package image.\n");
		return 0;
	}

	printf("Use original keys to package image.\n");
	SB_DBG("ED private key: \n");
	for (i = 0; i < 32; i++) {
		c1 = ascii_to_hex(fgetc(fp_ed_pri_in));
		c2 = ascii_to_hex(fgetc(fp_ed_pri_in));
		sum = c1<<4 | c2;
		private_key[i]=sum;
		SB_DBG("%02X ",private_key[i]);
	}
	fclose (fp_ed_pri_in);
	SB_DBG("\n\n");
	return 1;
}

/*
static void
test_main2(void) {
	int i, res, ret_val;
	ed25519_public_key pk;
	ed25519_signature sig;


	i = 31;

	dump_hex_data(dataset[i].sk, 32);
	dump_hex_data(dataset[i].pk, 32);
	dump_hex_data(dataset[i].sig, 64);
	printf("===========================\n");

	printf("sk\n");
	dump_hex_data(dataset[i].sk, 32);
	ed25519_publickey(dataset[i].sk, pk);

	printf("pk\n");
	dump_hex_data(pk, 32);

	ed25519_sign((unsigned char *)dataset[i].m, i, dataset[i].sk, pk, sig);
	printf("sig\n");
	dump_hex_data(sig, 64);

	ret_val = ed25519_sign_open((unsigned char *)dataset[i].m, i, pk, sig);
	printf("ret_val:0x%x\n", ret_val);
	printf("sig\n");
	dump_hex_data(sig, 64);
	return;
}

void dump_efuse_command(unsigned char *buf, int len) //len counted by bytes
{
	int i, j;
	unsigned short sum=0, tmp;

	j = (len/2)*2;

	for (i=0; i<j; i+=2) {
		tmp = *((unsigned short *)(buf + i));
		sum += tmp;
	}

	if ( len % 2 ) {
		tmp = buf[len-1];
		sum += tmp;
	}
	SB_DBG("\nED 25519 public key Checksum: %04x\n\n", 0xFFFF&(~sum+1));


	printf("\n=======  cut burn efuse command here (ED public key) =======\n");
	printf("bek ");
	for(i=0;i<len;i++){
		printf("%02X", buf[i]);
	}
	printf(" 1 %04X\n", 0xFFFF&(~sum+1));
    	printf("=======  cut burn efuse command here (ED public key) =======\n\n");
	//return ~sum+1;
	return;
}
*/

#define RANDOM_KEY 1
void gen_private_key(unsigned char *sk, int bit_size)
{
     #if RANDOM_KEY
     int i;
     for(i=0;i<bit_size/8;i++)
        sk[i] = rand()&0xFF;   
     #else
     for(i=0;i<bit_size/8;i++)
        sk[i] = i;
     #endif
     if(bit_size==256){
         sk[0] &= 248;
         sk[31] &= 127;
         sk[31] |= 64;     
     }      
	 return;
}

void gen_key_files(int num, unsigned char *public_key, unsigned char *private_key)
{
	FILE *fp_out_pri, *fp_out_pub;
	int i;
	unsigned char pub_key_file[65] = {0};
	unsigned char pri_key_file[65] = {0};

	DIR* dir = opendir("keys");
	if (dir) {
		closedir(dir);
	} else {
		mkdir("keys", 0775);
		printf("keys/ not exist, generate keys/ folder\n");
	}
	
	if(num==1)
	{
		fp_out_pub = fopen("keys/linux_pub_key.txt", "w");
		fp_out_pri = fopen("keys/linux_pri_key.txt", "w");
	}
	else if(num==2)
	{
		fp_out_pub = fopen("keys/rootfs_pub_key.txt", "w");
		fp_out_pri = fopen("keys/rootfs_pri_key.txt", "w");
	}

	for (i = 0; i < 32; i++) {
		sprintf(pub_key_file, "%s%02X", pub_key_file, public_key[i]);
	}
	for (i = 0; i < 32; i++) {
		sprintf(pri_key_file, "%s%02X", pri_key_file, private_key[i]);
	}
	fwrite(pub_key_file, 64, 1, fp_out_pub);
	fclose(fp_out_pub);
	fwrite(pri_key_file, 64, 1, fp_out_pri);   	
	fclose(fp_out_pri);
	return;
}

int
main(int argc, char *argv[]) {
	FILE *fp;
	FILE *fp_out;
	FILE *fp_check;
	struct stat st;

	unsigned char sig[64] = {0};
	unsigned char *data;
	unsigned int len;
	int ret_val = 1;

	int data_size = 0;
	int linux_size = 0;
	int root_size = 0;

	if (argc < 2) {
		printf("ED25519 Wrong input.\n");
		return -1;
	}

	if ((strcmp(argv[1],"linux")==0)) {
		printf("Linux protect\n");
		linux_size = CONFIG_RTL_ROOT_IMAGE_OFFSET - CONFIG_RTL_LINUX_IMAGE_OFFSET;
		data_size = linux_size;	
	} else if  ((strcmp(argv[1],"rootfs")==0)) {
		printf("Rootfs protect\n");
#ifdef CONFIG_RTL_FLASH_DUAL_IMAGE_ENABLE
		root_size = CONFIG_RTL_FLASH_DUAL_IMAGE_OFFSET - CONFIG_RTL_LINUX_IMAGE_OFFSET;
#else
		root_size = CONFIG_RTL_FLASH_SIZE - CONFIG_RTL_LINUX_IMAGE_OFFSET;
#endif
		data_size = root_size;
	} else {
		printf("ED25519 Wrong input %s.\n", argv[1]);
		return -1;
	}

	SB_DBG("linux_size 0x%08x, root_size 0x%08x, data_size 0x%08x \n", linux_size, root_size, data_size);
	data = malloc(data_size);
	if( data == NULL ) {
		printf("Error: unable to allocate required memory\n");
		return -1;
	}

	if ((strcmp(argv[1],"linux")==0)) {
		//printf("Linux protect\n");
		stat("nfjrom", &st);
		len = (unsigned int)st.st_size;
		if(!get_key(1)) {
			srand(time(NULL));
			gen_private_key(private_key, 256);
		}
	} else if  ((strcmp(argv[1],"rootfs")==0)) {
		//printf("Rootfs protect\n");
		stat("squashfs-lzma.o", &st);
		len = (unsigned int)st.st_size;
		if(!get_key(2)) {
			srand(time(NULL));
			gen_private_key(private_key, 256);
		}
	}

	//dump_hex_data(public_key, 32);
	//dump_hex_data(sk, 32);

	//printf("===========================\n");
	//get_key();
	
	if ((strcmp(argv[1],"linux")==0)) {
		fp = fopen("nfjrom", "rb");
		if(!fp) {
			printf("ERROR: get nfjrom fail\n");
			if (data != NULL)
				free(data);
			return -1;
		}
		fread(data, len, 1, fp);
		fclose(fp);
	} else if  ((strcmp(argv[1],"rootfs")==0)) {
		fp = fopen("squashfs-lzma.o", "rb");
		if(!fp) {
			printf("ERROR: get squashfs-lzma.o fail\n");
			if (data != NULL)
				free(data);
			return -1;
		}
		fread(data, len, 1, fp);
		fclose(fp);

		/* cvimg will change image data in squashfs-lzma.o */
		int i;
		unsigned char c1,c2;
		unsigned char sum;
		unsigned int root_len;
		unsigned char root_len_string[16] = {0};

		root_len = len - 640 + 0x40; //SQFS_SUPER_BLOCK = 640, signature = 0x40
		sprintf(root_len_string, "%s%02X", "00", root_len);
		for (i = 0; i < 4; i++) {
			c1 = ascii_to_hex(root_len_string[2*i]);
			c2 = ascii_to_hex(root_len_string[2*i + 1]);
			sum = c1<<4 | c2;
			data[i + 8] = sum;
		}
#ifdef DEBUG
		SB_DBG("data\n");
		for(i = 0; i < 16; i++)
			SB_DBG("%02X ", data[i]);
		SB_DBG("\n\n");
#endif
	}

	//printf("===========================\n");
	SB_DBG("ED 25519 private key\n");
	dump_hex_data(private_key, 32);

	SB_DBG("ED 25519 public key\n");
	ed25519_publickey(private_key, public_key);
	dump_hex_data(public_key, 32);
	//dump_efuse_command(public_key, 32);

	SB_DBG("len 0x%X\n\n", len);
	ed25519_sign(data, len, private_key, public_key, sig);
	SB_DBG("sig\n");
	dump_hex_data(sig, 64);

	ret_val = ed25519_sign_open(data, len, public_key, sig);
	if (ret_val!=0x0) {
		printf("Check signature fail\n\n");
		SB_DBG("ret_val:0x%x\n", ret_val);
		SB_DBG("sig\n");
		dump_hex_data(sig, 64);
		if (data != NULL)
			free(data);
		return -1;
	}

	if ((strcmp(argv[1],"linux")==0)) {
		fp_out = fopen("sig_linux.bin", "wb");
		gen_key_files(1, public_key, private_key);
	} else if  ((strcmp(argv[1],"rootfs")==0)) {
		fp_out = fopen("sig_rootfs.bin", "wb");	
		gen_key_files(2, public_key, private_key);
	}
	fwrite(sig, 64, 1, fp_out);
	fclose(fp_out);
	printf("Image signed.\n\n");
	if (data != NULL)
		free(data);
	return 0;
}

