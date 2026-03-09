#include "cellui.h"

#include <curses.h>
#include <signal.h>
#include <stdbool.h>
#include <time.h>

static volatile sig_atomic_t g_sigint_requested = 0;

static void on_sigint(int signo) {
  (void)signo;
  g_sigint_requested = 1;
}

int main(void) {
  Model m;
  bool quit = false;
  bool need_redraw = true;

  init_model(&m);
  (void)signal(SIGPIPE, SIG_IGN);
  (void)signal(SIGINT, on_sigint);

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

  apply_theme(&m, m.theme_index);
  m.loading = true;
  draw_ui(&m);
  model_refresh(&m);

  while (!quit) {
    int ch;
    time_t now;

    if (g_sigint_requested) {
      quit = true;
      continue;
    }

    if (need_redraw) {
      draw_ui(&m);
      need_redraw = false;
    }

    ch = getch();
    if (g_sigint_requested) {
      quit = true;
      continue;
    }
    if (ch != ERR) {
      handle_normal_key(&m, ch, &quit);
      need_redraw = true;
    }

    now = time(NULL);
    if (!quit && !m.loading && !m.confirm_open && !m.disconnected &&
        now >= m.next_refresh_due) {
      m.loading = true;
      draw_ui(&m);
      model_refresh(&m);
      need_redraw = true;
    }
  }

  destroy_model(&m);
  (void)endwin();
  return 0;
}
