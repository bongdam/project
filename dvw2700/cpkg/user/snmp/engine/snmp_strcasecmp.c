/* This file provides strcasecmp() for those architectures that don't
   appear to have it. */

#ifdef SNMP_CONFIG_H
#  include "snmp_config.h"
#endif

#include <ctype.h>

#include "snmp_string.h"

int
snmp_strcasecmp (a, b)
     char *a, *b;
{
  int diff;

  do
    {
      diff = tolower (*a) - tolower (*b);
      if (diff)
	return diff;
    }
  while (*a++ && *b++);
  return 0;
}
