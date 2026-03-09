#ifndef CELLUI2_H
#define CELLUI2_H

#include <stdbool.h>
#include <stddef.h>
#include <time.h>

#define DEFAULT_CELLMGR_CONF "/etc/cellmgr.conf"
#define DEFAULT_CELL_DATA_DIR "/var/cellmgr/cells"
#define REFRESH_EVERY_SEC 4

#define MAX_STATUS_OUTPUT_CHARS 240
#define MAX_STATUS_CHARS 2048
#define MAX_CMD_INPUT 1024

#define DETAIL_CONTENT_LINES 9
#define DETAIL_PANEL_LINES (DETAIL_CONTENT_LINES + 2)
#define HELP_LINES_COUNT 2
#define COMMAND_PANEL_LINES 3

#define MIN_TABLE_BODY_HEIGHT 1

typedef enum {
	MODE_NORMAL = 0,
	MODE_COMMAND = 1,
} InputMode;

typedef enum {
	FILTER_ALL = 0,
	FILTER_RUNNING = 1,
	FILTER_STOPPED = 2,
} FilterMode;

typedef struct {
	char *name;
	char *cid;
	bool running;
	char *refs;
	char *procs;
	char *root;
	char *autostart;
	char *supervise_cmd;
	char *cpu1s;
	char *cpu10s;
	char *memory;
} CellRow;

typedef struct {
	const char *name;
	const char *page_fg;
	const char *page_bg;
	const char *header_fg;
	const char *header_bg;
	const char *subheader_fg;
	const char *subheader_bg;
	const char *help_fg;
	const char *help_bg;
	const char *help_sep_fg;
	const char *panel_fg;
	const char *panel_bg;
	const char *panel_border_fg;
	const char *table_header_fg;
	const char *selected_fg;
	const char *selected_bg;
	const char *key_fg;
	const char *key_bg;
	const char *error_fg;
	const char *running_fg;
	const char *stopped_fg;
	const char *state_default_fg;
} Theme;

typedef struct {
	CellRow *rows;
	size_t row_count;
	int cursor;
	InputMode mode;
	FilterMode filter;
	int width;
	int height;
	bool loading;
	char status[MAX_STATUS_CHARS];
	bool status_is_error;
	time_t last_refresh;
	char cmd_input[MAX_CMD_INPUT + 1];
	size_t cmd_len;
	int theme_index;
	int spinner_index;
	time_t next_refresh_due;
} Model;

enum {
	PAIR_PAGE = 1,
	PAIR_HEADER,
	PAIR_SUBHEADER,
	PAIR_HELP,
	PAIR_HELP_SEP,
	PAIR_PANEL,
	PAIR_PANEL_BORDER,
	PAIR_TABLE_HEADER,
	PAIR_SELECTED,
	PAIR_KEY,
	PAIR_ERROR,
	PAIR_RUNNING,
	PAIR_STOPPED,
	PAIR_STATE_DEFAULT,
};

extern bool has_color;
extern Model *spinner_model;

char *xstrdup(const char *s);
void set_string(char **dst, const char *src);
char *xasprintf(const char *fmt, ...);
char *trim_inplace(char *s);
bool is_blank(const char *s);
const char *blank_if(const char *value, const char *fallback);
void append_error(char **joined, const char *msg);
void shorten_to(const char *s, int max, char *out, size_t outsz);
void concat_limited(char *dst, size_t dstsz, const char *src);
void format_prefixed(char *dst, size_t dstsz, const char *prefix, const char *value);
bool path_join2(char *dst, size_t dstsz, const char *a, const char *b);
bool path_join3(char *dst, size_t dstsz, const char *a, const char *b, const char *c);
int split_shell_words(const char *input, char ***argv_out, int *argc_out, char **err_out);
void free_argv(char **argv, int argc);

void free_cell_row(CellRow *row);
void clear_model_rows(Model *m);
void set_status(Model *m, bool is_error, const char *fmt, ...);
void append_status_output(Model *m, const char *output);
const char *filter_label(FilterMode mode);
void clamp_cursor(Model *m);
CellRow *selected_cell(Model *m);
int table_body_height(const Model *m, int term_h);
int running_count(const Model *m);
void model_refresh(Model *m);
void run_capture_action(Model *m, const char *title, bool refresh_after,
	const char *const argv[]);
void run_interactive_action(Model *m, const char *title, bool refresh_after,
	const char *const argv[], const char *env_key, const char *env_val);
void init_model(Model *m);

int run_capture_command(const char *prog, const char *const argv[], char **output_out,
	char **err_out);
int run_interactive_command(const char *prog, const char *const argv[], const char *env_key,
	const char *env_val, char **err_out);
int load_rows(CellRow **rows_out, size_t *count_out, char **err_out);

const Theme *current_theme(const Model *m);
void apply_theme(Model *m, int index);
void rotate_theme(Model *m);

void draw_ui(Model *m);
void handle_command_key(Model *m, int ch);
void handle_normal_key(Model *m, int ch, bool *quit);

#endif
