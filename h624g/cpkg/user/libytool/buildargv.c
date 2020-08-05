#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define isspace(c) ((((c) == ' ') || (((unsigned int)((c) - 9)) <= (13 - 9))))

static inline void skip_whitespace(char **sp)
{
	while (isspace(**sp))
		(*sp)++;
}

char **ybuildargv(char *sp, int *argcp)
{
	char *cp;
	int squote = 0;
	int dquote = 0;
	int bsquote = 0;
	int argc = 0;
	int maxargc = 0;
	char **argv = NULL;
	char **nargv;

	if (sp == NULL)
		return NULL;

	skip_whitespace(&sp);

	while (*sp != '\0') {
		if ((maxargc == 0) || (argc >= (maxargc - 1))) {
			maxargc += 8;
			nargv = (char **)realloc(argv, maxargc * sizeof(char *));
			if (nargv == NULL) {
				if (argv != NULL)
					free(argv);
				return NULL;
			}
			argv = nargv;
		}

		cp = sp;
		argv[argc++] = cp;
		while (*sp != '\0') {
			if (isspace(*sp) &&
			    !squote && !dquote && !bsquote) {
				break;
			} else {
				if (bsquote) {
					bsquote = 0;
					*cp++ = *sp;
				} else if (*sp == '\\') {
					bsquote = 1;
				} else if (squote) {
					if (*sp == '\'')
						squote = 0;
					else
						*cp++ = *sp;
				} else if (dquote) {
					if (*sp == '"')
						dquote = 0;
					else
						*cp++ = *sp;
				} else {
					if (*sp == '\'')
						squote = 1;
					else if (*sp == '"')
						dquote = 1;
					else
						*cp++ = *sp;
				}
				sp++;
			}
		}

		skip_whitespace(&sp);
		*cp = '\0';
		argv[argc] = NULL;
	}

	if (argcp)
		*argcp = argc;

	return (argv);
}
