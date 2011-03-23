#include <ctype.h>

#include "common.h"

int empty_line_or_comment(char *s)
{
    while (isspace(*s)) s++;
    if (!*s) return 1;
    if (*s == ';')	return 1;
    return 0;
}

char *skip_white_space(char *s)
{
    while (isspace(*s)) s++;
    if (*s == ';') {
	while (*s) s++;
    }
    if (*s == ')') {
	if (file_info->paren_mode) {
	    file_info->paren_mode = 0;
	    s++;
	    return skip_white_space(s);
	} else {
	    return bitch("unexpected closing parenthesis");
	}
    }
    if (*s == '(') {
	if (file_info->paren_mode) {
	    return bitch("unexpected opening parenthesis");
	} else {
	    file_info->paren_mode = 1;
	    s++;
	    return skip_white_space(s);
	}
    }
    if (*s == 0) {
	if (file_info->paren_mode) {
	    if (fgets(file_info->buf, 2048, file_info->file)) {
		file_info->line++;
		return skip_white_space(file_info->buf);
	    } else {
		return bitch("unexpected end of file");
	    }
	}
    }
    return s;
}

char *extract_name(char **input, char *what)
{
    char *s = *input;
    char *r = NULL;
    char *end = NULL;

    if (*s == '@') {
	s++;
	if (*s && !isspace(*s)) {
	    return bitch("literal @ in %s is not all by itself", what);
	}
	if (!G.opt.current_origin) {
	    return bitch("do not know origin to expand @ in %s", what);
	}
	r = quickstrdup(G.opt.current_origin);
    } else {
	if (!(isalnum(*s) || *s == '_')) {
	    return bitch("%s expected", what);
	}
	s++;
	while (isalnum(*s) || *s == '.' || *s == '-' || *s == '_')
	    s++;
	if (*s && !isspace(*s)) {
	    return bitch("%s is not valid", what);
	}
	if (!*s)	end = s;
	*s++ = '\0';
	if (*(s-2) == '.') {
	    r = quickstrdup(*input);
	} else {
	    if (!G.opt.current_origin) {
		return bitch("do not know origin to determine %s", what);
	    }
	    r = getmem(strlen(*input) + 1 + strlen(G.opt.current_origin) + 1);
	    strcpy(stpcpy(stpcpy(r, *input), "."), G.opt.current_origin);
	}
    }
    if (end) {
	*input = end;
    } else {
	*input = skip_white_space(s);
	if (!*input)
	    return NULL;  /* bitching's done elsewhere */
    }
    s = r;
    while (*s) {
	*s = tolower(*s);
	s++;
    }
    return r;
}

char *extract_label(char **input, char *what, void *is_temporary)
{
    char *s = *input;
    char *r = NULL;
    char *end = NULL;

    if (!isalpha(*s)) {
	return bitch("%s expected", what);
    }
    s++;
    while (isalnum(*s))
	s++;
    if (*s && !isspace(*s)) {
	return bitch("%s is not valid", what);
    }
    if (!*s)	end = s;
    *s++ = '\0';
    if (is_temporary) {
	r = quickstrdup_temp(*input);
    } else {
	r = quickstrdup(*input);
    }

    if (end) {
	*input = end;
    } else {
	*input = skip_white_space(s);
	if (!*input)
	    return NULL;  /* bitching's done elsewhere */
    }
    s = r;
    while (*s) {
	*s = tolower(*s);
	s++;
    }
    return r;
}

long extract_integer(char **input, char *what)
{
    char *s = *input;
    int r = -1;
    char *end = NULL;
    char c;

    if (!isdigit(*s)) {
	bitch("%s expected", what);
	return -1;
    }
    s++;
    while (isdigit(*s))
	s++;
    if (*s && !isspace(*s) && *s != ';' && *s != ')') {
	bitch("%s is not valid", what);
	return -1;
    }
    if (!*s)	end = s;
    c = *s;
    *s = '\0';
    r = strtol(*input, NULL, 10);
    *s = c;

    if (end) {
	*input = end;
    } else {
	*input = skip_white_space(s);
	if (!*input)
	    return -1;  /* bitching's done elsewhere */
    }
    return r;
}

long extract_timevalue(char **input, char *what)
{
    char *s = *input;
    int r = 0;

    if (!isdigit(*s)) {
	bitch("%s expected", what);
	return -1;
    }
    while (isdigit(*s)) {
	r *= 10;
	r += *s - '0';
	s++;
    }
    if (tolower(*s) == 's') {
	s++;
    } else if (tolower(*s) == 'm') {
	r *= 60;
	s++;
    } else if (tolower(*s) == 'h') {
	r *= 3600;
	s++;
    } else if (tolower(*s) == 'd') {
	r *= 86400;
	s++;
    } else if (tolower(*s) == 'w') {
	r *= 604800;
	s++;
    }

    if (*s && !isspace(*s) && *s != ';' && *s != ')') {
	bitch("%s is not valid", what);
	return -1;
    }
    *input = skip_white_space(s);
    if (!*input)
	return -1;  /* bitching's done elsewhere */
    return r;
}

uint32_t extract_ip(char **input, char *what)
{
    char *s = *input;
    unsigned octet = 0;
    unsigned ip = 0;

    if (!isdigit(*s)) {
	bitch("%s expected", what);
	return 0;
    }
    while (isdigit(*s)) {
	octet = 10*octet + *s - '0';
	s++;
    }
    if (octet > 255 || *s != '.') {
	bitch("%s is not valid", what);
	return 0;
    }
    s++;
    if (!isdigit(*s)) {
	bitch("%s is not valid", what);
	return 0;
    }
    ip = 256*ip + octet;
    octet = 0;
    while (isdigit(*s)) {
	octet = 10*octet + *s - '0';
	s++;
    }
    if (octet > 255 || *s != '.') {
	bitch("%s is not valid", what);
	return 0;
    }
    s++;
    if (!isdigit(*s)) {
	bitch("%s is not valid", what);
	return 0;
    }
    ip = 256*ip + octet;
    octet = 0;
    while (isdigit(*s)) {
	octet = 10*octet + *s - '0';
	s++;
    }
    if (octet > 255 || *s != '.') {
	bitch("%s is not valid", what);
	return 0;
    }
    s++;
    if (!isdigit(*s)) {
	bitch("%s is not valid", what);
	return 0;
    }
    ip = 256*ip + octet;
    octet = 0;
    while (isdigit(*s)) {
	octet = 10*octet + *s - '0';
	s++;
    }
    ip = 256*ip + octet;

    if (*s && !isspace(*s) && *s != ';' && *s != ')') {
	bitch("%s is not valid", what);
	return 0;
    }

    *input = skip_white_space(s);
    if (!*input) {
	return 0;  /* bitching's done elsewhere */
    }

    return ip;
}

