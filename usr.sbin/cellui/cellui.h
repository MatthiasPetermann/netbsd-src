#ifndef CELLUI2_H
#define CELLUI2_H

#include <stdbool.h>
#include <stddef.h>
#include <time.h>

#define REFRESH_EVERY_SEC 4
#define STATUS_ERROR_STICKY_SEC 4

#define MAX_STATUS_OUTPUT_CHARS 240
#define MAX_STATUS_CHARS 2048

#define DETAIL_CONTENT_LINES 12
#define DETAIL_PANEL_LINES (DETAIL_CONTENT_LINES + 2)
#define HELP_LINES_COUNT 2

#define MIN_TABLE_BODY_HEIGHT 1

typedef enum {
	FILTER_ALL = 0,
	FILTER_RUNNING = 1,
	FILTER_STOPPED = 2,
} FilterMode;

typedef enum {
	MODE_CELLS = 0,
	MODE_STORAGE = 1,
} UIMode;

typedef enum {
	CONFIRM_NONE = 0,
	CONFIRM_RESTORE_BACKUP = 1,
	CONFIRM_DELETE_BACKUP = 2,
	CONFIRM_RESTORE_BACKUP_WITH_MANIFEST = 3,
} ConfirmAction;

typedef struct {
	char *name;
	char *cid;
	bool running;
	char *refs;
	char *procs;
	char *root;
	char *autostart;
	char *create_profile;
	char *create_reserved_ports;
	char *create_rlimit_nofile;
	char *create_rlimit_as;
	char *create_rlimit_core;
	char *supervise_cmd;
	char *cpu1s;
	char *cpu10s;
	char *memory;
	char *age;
	bool manifest_present;
} CellRow;

typedef struct {
	char *kind;
	char *name;
	bool manifest_present;
	bool runtime_present;
	bool mounted;
	char *refs;
	char *mode;
	char *path;
	char *used_by;
} VolumeRow;

typedef struct {
	char *volume;
	char *timestamp;
	char *size;
	char *archive;
} BackupRow;

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
	VolumeRow *volume_rows;
	size_t volume_row_count;
	int volume_cursor;
	BackupRow *backup_rows;
	size_t backup_row_count;
	int backup_cursor;
	char *backup_target_key;
	UIMode mode;
	bool confirm_open;
	ConfirmAction confirm_action;
	char *confirm_storage_kind;
	char *confirm_storage_name;
	char *confirm_archive_path;
	FilterMode filter;
	int width;
	int height;
	bool loading;
	bool disconnected;
	char disconnect_reason[MAX_STATUS_CHARS];
	char status[MAX_STATUS_CHARS];
	bool status_is_error;
	time_t status_error_sticky_until;
	time_t last_refresh;
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

void free_cell_row(CellRow *row);
void clear_model_rows(Model *m);
void free_volume_row(VolumeRow *row);
void clear_model_volume_rows(Model *m);
void free_backup_row(BackupRow *row);
void clear_model_backups(Model *m);
void set_status(Model *m, bool is_error, const char *fmt, ...);
void append_status_output(Model *m, const char *output);
const char *filter_label(FilterMode mode);
const char *mode_label(UIMode mode);
void clamp_cursor(Model *m);
CellRow *selected_cell(Model *m);
void clamp_volume_cursor(Model *m);
VolumeRow *selected_volume(Model *m);
void clamp_backup_cursor(Model *m);
BackupRow *selected_backup(Model *m);
int table_body_height(const Model *m, int term_h);
int running_count(const Model *m);
int missing_manifest_count(const Model *m);
int runtime_volume_count(const Model *m);
int mounted_volume_count(const Model *m);
int storage_kind_count(const Model *m, const char *kind);
int storage_backup_eligible_count(const Model *m);
void clear_confirmation(Model *m);
void start_confirmation(Model *m, ConfirmAction action, const char *storage_kind,
	const char *storage_name, const char *archive_path);
void sync_volume_backups(Model *m, bool force);
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
void shutdown_command_bridge(void);
bool command_bridge_is_disconnected(void);
const char *command_bridge_disconnect_reason(void);
int command_bridge_reconnect(char **err_out);
int load_rows(CellRow **rows_out, size_t *count_out, char **err_out);
int load_volume_rows(VolumeRow **rows_out, size_t *count_out, char **err_out);
int load_storage_backups(const char *storage_kind, const char *storage_name,
	BackupRow **rows_out, size_t *count_out, char **err_out);

const Theme *current_theme(const Model *m);
void apply_theme(Model *m, int index);
void rotate_theme(Model *m);
void load_theme_preference(Model *m);
void save_theme_preference(const Model *m);

void draw_ui(Model *m);
void handle_normal_key(Model *m, int ch, bool *quit);
void destroy_model(Model *m);

#endif
