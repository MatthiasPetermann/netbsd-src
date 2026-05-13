/* $NetBSD$ */

/*-
 * Copyright (c) 2026 Matthias Petermann
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

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
    if (!quit && !m.loading && !m.confirm_open && now >= m.next_refresh_due) {
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
