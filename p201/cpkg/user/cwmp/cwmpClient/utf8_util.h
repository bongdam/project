/*
  Basic UTF-8 manipulation routines
  by Jeff Bezanson
  placed in the public domain Fall 2005

  This code is designed to provide the utilities you need to manipulate
  UTF-8 as an internal string encoding. These functions do not perform the
  error checking normally needed when handling UTF-8 data, so if you happen
  to be from the Unicode Consortium you will want to flay me alive.
  I do this because error checking can be performed at the boundaries (I/O),
  with these routines reserved for higher performance on data known to be
  valid.
*/

#define isutf(c) (((c)&0xC0)!=0x80)

/* returns length of next utf-8 sequence */
int u8_seqlen(char *s);

/* conversions without error checking
   only works for valid UTF-8, i.e. no 5- or 6-byte sequences
   srcsz = source size in bytes, or -1 if 0-terminated
   sz = dest size in # of wide characters

   returns # characters converted
   dest will always be L'\0'-terminated, even if there isn't enough room
   for all the characters.
   if sz = srcsz+1 (i.e. 4*srcsz+4 bytes), there will always be enough space.
*/
int u8_toucs(u_int32_t *dest, int sz, char *src, int srcsz);


/* srcsz = number of source characters, or -1 if 0-terminated
   sz = size of dest buffer in bytes

   returns # characters converted
   dest will only be '\0'-terminated if there is enough space. this is
   for consistency; imagine there are 2 bytes of space left, but the next
   character requires 3 bytes. in this case we could NUL-terminate, but in
   general we can't when there's insufficient space. therefore this function
   only NUL-terminates if all the characters fit, and there's space for
   the NUL as well.
   the destination string will never be bigger than the source string.
*/
int u8_toutf8(char *dest, int sz, u_int32_t *src, int srcsz);

int u8_wc_toutf8(char *dest, u_int32_t ch);

/* charnum => byte offset */
int u8_offset(char *str, int charnum);

/* byte offset => charnum */
int u8_charnum(char *s, int offset);

/* number of characters */
int u8_STRLEN(char *s);

/* reads the next utf-8 sequence out of a string, updating an index */
u_int32_t u8_nextchar(char *s, int *i);

void u8_inc(char *s, int *i);

void u8_dec(char *s, int *i);

int octal_digit(char c);

int hex_digit(char c);

/* assumes that src points to the character after a backslash
   returns number of input characters processed */
int u8_read_escape_sequence(char *str, u_int32_t *dest);

/* convert a string with literal \uxxxx or \Uxxxxxxxx characters to UTF-8
   example: u8_unescape(mybuf, 256, "hello\\u220e")
   note the double backslash is needed if called on a C string literal */
int u8_unescape(char *buf, int sz, char *src);

int u8_escape_wchar(char *buf, int sz, u_int32_t ch);

int u8_escape(char *buf, int sz, char *src, int escape_quotes);

char *u8_strchr(char *s, u_int32_t ch, int *charn);

char *u8_memchr(char *s, u_int32_t ch, size_t sz, int *charn);

int u8_is_locale_utf8(char *locale);

int u8_vprintf(char *fmt, va_list ap);

int u8_printf(char *fmt, ...);
