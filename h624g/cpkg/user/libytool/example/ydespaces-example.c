#include <stdio.h>
#include <string.h>
#include "../libytool.h"

static void mdisp(unsigned char *p, unsigned int s, unsigned char *base)
{
	int i, c;

	while ((int)s > 0) {
		printf("%08x: ", (unsigned int)base);

		for (i = 0; i < 16; i++) {
			if (i < (int)s)
				printf("%02x ", p[i] & 0xFF);
			else
				printf("   ");

			if (i == 7)
				printf(" ");
		}
		printf(" |");
		for (i = 0; i < 16; i++) {
			if (i < (int)s) {
				c = p[i] & 0xFF;
				if ((c < 0x20) || (c >= 0x7F))
					c = '.';
			} else
				c = ' ';

			printf("%c", c);
		}
		printf("|\n");
		s -= 16;
		p += 16;
		base += 16;
	}
}

int main(void)
{
	char buffer[16];

	strncpy(buffer, "  Hello World! ", sizeof(buffer));
	mdisp((unsigned char *)buffer, sizeof(buffer), (unsigned char *)buffer);
	ydespaces(buffer);
	mdisp((unsigned char *)buffer, sizeof(buffer), (unsigned char *)buffer);
	return 0;
}

