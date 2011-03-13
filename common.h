#ifndef _COMMON_H_
#define _COMMON_H_ 1

struct file_info
{
	struct file_info *next;
	FILE *file;
	int  line;
	char name[0];
};

extern struct file_info *file_info;

struct command_line_options
{
	int die_on_first_error;
	int no_output;
	int summary;
	int verbose;
	char *include_path;
	char *current_origin;
	/* not really options */
	int exit_code;
};

extern struct command_line_options opt;

#endif
