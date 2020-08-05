#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <goods.h>
#include <furl.h>
#include "apmib.h"

/* x^8 + x^2 + x + 1 polynomial */
static uint8_t crc8(uint8_t *pdata, int len, uint8_t crc)
{
	int i;

	while (len > 0) {
		crc = crc ^ *pdata++;
		for (i = 0; i < 8; i++) {
			if ((crc & 0x80)) {
				crc <<= 1;
				crc ^= 0x07;
			} else
				crc <<= 1;
		}
		len--;
	}
	return crc;
}

static uint16_t read_hdr_and_csum(const char *path, IMG_HEADER_Tp phdr)
{
	FILE *f;
	uint16_t cksum;

	f = fopen(path, "r");
	if (f == NULL) {
		perror(path);
		exit(EXIT_FAILURE);
		return 0;
	}
	fread(phdr, 1, sizeof(IMG_HEADER_T), f);
	fseek(f, 0 - sizeof(uint16_t), SEEK_END);
	fread(&cksum, 1, sizeof(uint16_t), f);
	fclose(f);
	return cksum;
}
/*      - - - - - ->
          linux                      linux IMG_HEADER_T (18 octets)
	+---+---+    +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
	| cksum | +  |               |               |               |               | +
	+---+---+    +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+

         rootfs                     rootfs IMG_HEADER_T (17 octest excluding last significant byte)
	+---+---+    +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
	| cksum | +  |               |   startAddr   |               |     len   /   |
	+---+---+    +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
                                            ^                                ^
                                            |                                |
                                            +---------  swapping ------------+
 */
int main(int argc, char **argv)
{
	FILE *f;
	IMG_HEADER_T kern, rootfs;
	uint16_t kern_crc, rootfs_crc;
	struct goods_tag *gt;
	unsigned int tmp;

	if (argc < 4) {
		exit(EXIT_FAILURE);
		return -1;
	}

	kern_crc = read_hdr_and_csum(argv[1], &kern);
	rootfs_crc = read_hdr_and_csum(argv[2], &rootfs);
	/* swapping - rootfs's startAddr not used actually */
	rootfs.startAddr = rootfs.len;

	gt = (struct goods_tag *)&rootfs.len;
	gt->ver = htons((uint16_t)strtol(argv[3], NULL, 0));
	gt->id = (argc > 4) ? (uint8_t)strtol(argv[4], NULL, 0) : GOODS_ID;

	gt->crc = crc8((uint8_t *)&kern_crc, sizeof(uint16_t), 0);
	gt->crc = crc8((uint8_t *)&kern, sizeof(IMG_HEADER_T), gt->crc);

	gt->crc = crc8((uint8_t *)&rootfs_crc, sizeof(uint16_t), gt->crc);
	gt->crc = crc8((uint8_t *)&rootfs, sizeof(IMG_HEADER_T) - sizeof(char), gt->crc);

	/* re-swapping */
	tmp = rootfs.startAddr;
	rootfs.startAddr = rootfs.len;
	rootfs.len = tmp;

	f = fopen(argv[2], "r+");
	if (f == NULL) {
		exit(EXIT_FAILURE);
		return -1;
	}
	fwrite(&rootfs, 1, sizeof(IMG_HEADER_T), f);
	fclose(f);
	return ;
}
