#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <ctype.h>

#include "mibtbl.c"
#include "nvram_mib.h"

static struct mib *_mib;
static int _mib_size;
static size_t _mib_max_fieldsiz = 0;

static int
xfer_mibtbl_descriptor(struct mib *dst, mib_table_entry_T *src, unsigned sect)
{
	int i;

	for (i = 0; src->id > 0; i++, src++) {
		if (!dst)
			continue;
		dst[i].id = src->id;
		dst[i].name = src->name;
		dst[i].type = src->type;
		if (src->type > TABLE_LIST_T && src->unit_size) {
			dst[i].size = src->total_size / src->unit_size;
			if (_mib_max_fieldsiz < src->unit_size)
				_mib_max_fieldsiz = src->unit_size;
		} else {
			dst[i].size = src->size;
			if (src->type < TABLE_LIST_T && _mib_max_fieldsiz < src->size)
				_mib_max_fieldsiz = src->size;
		}
		dst[i].section = sect;
	}

	return i;
}

static int
mib_idcompar(const struct mib *e1, const struct mib *e2)
{
	return e1->id - e2->id;
}

int main(int argc, char **argv)
{
	struct {
		mib_table_entry_T *t;
		unsigned section;
	} tables[] = {
		{ mib_table,        0         },
		{ mib_wlan_table,   WLAN_SECT },
		{ hwmib_table,      HW_SECT   },
		{ hwmib_wlan_table, HW_SECT | WLAN_SECT },
		{ NULL,             -1        }
	};
	int i, n;

	for (i = _mib_size = 0; tables[i].t; i++)
		_mib_size += xfer_mibtbl_descriptor(NULL, tables[i].t, tables[i].section);

	if (_mib_size <= 0)
		return -1;
	_mib = (struct mib *)malloc(_mib_size * sizeof(struct mib));
	if (_mib == NULL)
		return -1;
	for (i = n = 0; tables[i].t; i++)
		n += xfer_mibtbl_descriptor(&_mib[n], tables[i].t, tables[i].section);

	qsort(_mib, _mib_size, sizeof(struct mib), (void *)mib_idcompar);

	printf("// Automatically generated code: don't edit\n\n");
	printf("#include <stdlib.h>\n");
	printf("#include \"nvram_mib.h\"\n\n");

	printf("static const struct mib _mib[] = {\n");
	for (i = 0; i < _mib_size; i++)
		printf("  { %d, \"%s\", %d, %d, %d },\n",
		       _mib[i].id, _mib[i].name,
		       _mib[i].type, _mib[i].size, _mib[i].section);
	printf("};\n");

	printf(
"static const int _mib_size = %d;\n"
"const size_t _mib_max_unitsiz = %u;\n\n"
"static int mib_idcompar(const struct mib *e1, const struct mib *e2)\n"
"{\n"
"\treturn e1->id - e2->id;\n"
"}\n"
"\n"
"const struct mib *ysearch_mib_struct(int id)\n"
"{\n"
"\tstruct mib K = { .id = id };\n"
"\treturn bsearch(&K, _mib, _mib_size, sizeof(struct mib), (void *)mib_idcompar);\n"
"}\n"
"\n"
"const struct mib *ymib_first(void)\n"
"{\n"
"\treturn _mib;\n"
"}\n"
"\n"
"const struct mib *ymib_next(const struct mib *p)\n"
"{\n"
"\tif ((unsigned int)p < (unsigned int)_mib ||\n"
"\t    (unsigned int)p >= (unsigned int)(&_mib[_mib_size - 1]) ||\n"
"\t    (((unsigned int)p - (unsigned int)_mib) %% sizeof(struct mib)))\n"
"\t\treturn NULL;\n"
"\treturn ++p;\n"
"}\n", _mib_size, _mib_max_fieldsiz);
	free(_mib);
	return 0;
}
