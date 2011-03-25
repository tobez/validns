#ifndef _TEXTPARSE_H_
#define _TEXTPARSE_H_

struct binary_data {
	int length;
	char *data;
};

int empty_line_or_comment(char *s);
char *skip_white_space(char *s);
char *extract_name(char **input, char *what);
char *extract_label(char **input, char *what, void *is_temporary);
long extract_integer(char **input, char *what);
long extract_timevalue(char **input, char *what);
long extract_timestamp(char **input, char *what);
uint32_t extract_ip(char **input, char *what);
struct binary_data extract_base64_binary_data(char **input, char *what);
struct binary_data extract_text(char **input, char *what);

#endif
