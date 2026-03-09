#include "cellui.h"

#include <curses.h>
#include <stdbool.h>
#include <time.h>

int main(void) {
  Model m;
  bool quit = false;
  bool need_redraw = true;

  init_model(&m);

  (void)initscr();
  (void)cbreak();
  (void)noecho();
  (void)keypad(stdscr, TRUE);
  (void)nodelay(stdscr, TRUE);
  (void)timeout(100);

  has_color = has_colors();
  if (has_color) {
    (void)start_color();
    (void)use_default_colors();
  }

  apply_theme(&m, 0);
  m.loading = true;
  model_refresh(&m);

  while (!quit) {
    int ch;
    time_t now;

    if (need_redraw) {
      draw_ui(&m);
      need_redraw = false;
    }

    ch = getch();
    if (ch != ERR) {
      if (m.mode == MODE_COMMAND) {
        handle_command_key(&m, ch);
      } else {
        handle_normal_key(&m, ch, &quit);
      }
      need_redraw = true;
    }

    now = time(NULL);
    if (!quit && m.mode == MODE_NORMAL && !m.loading &&
        now >= m.next_refresh_due) {
      m.loading = true;
      model_refresh(&m);
      need_redraw = true;
    }
  }

  clear_model_rows(&m);
  (void)endwin();
  return 0;
}
