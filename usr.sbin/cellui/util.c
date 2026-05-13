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

#define _POSIX_C_SOURCE 200809L

#include "cellui.h"

#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char *xstrdup(const char *s) {
  char *copy;

  if (s == NULL) {
    s = "";
  }
  copy = strdup(s);
  if (copy == NULL) {
    perror("strdup");
    exit(1);
  }
  return copy;
}

void set_string(char **dst, const char *src) {
  free(*dst);
  *dst = xstrdup(src);
}

char *xasprintf(const char *fmt, ...) {
  va_list ap;
  va_list ap2;
  int n;
  char *buf;

  va_start(ap, fmt);
  va_copy(ap2, ap);
  n = vsnprintf(NULL, 0, fmt, ap);
  va_end(ap);
  if (n < 0) {
    va_end(ap2);
    return xstrdup("format error");
  }
  buf = malloc((size_t)n + 1);
  if (buf == NULL) {
    va_end(ap2);
    perror("malloc");
    exit(1);
  }
  (void)vsnprintf(buf, (size_t)n + 1, fmt, ap2);
  va_end(ap2);
  return buf;
}

char *trim_inplace(char *s) {
  char *end;

  while (*s != '\0' && isspace((unsigned char)*s)) {
    s++;
  }
  if (*s == '\0') {
    return s;
  }
  end = s + strlen(s) - 1;
  while (end > s && isspace((unsigned char)*end)) {
    *end = '\0';
    end--;
  }
  return s;
}

bool is_blank(const char *s) {
  if (s == NULL) {
    return true;
  }
  while (*s != '\0') {
    if (!isspace((unsigned char)*s)) {
      return false;
    }
    s++;
  }
  return true;
}

const char *blank_if(const char *value, const char *fallback) {
  if (is_blank(value)) {
    return fallback;
  }
  return value;
}

void append_error(char **joined, const char *msg) {
  char *next;

  if (msg == NULL || *msg == '\0') {
    return;
  }
  if (*joined == NULL) {
    *joined = xstrdup(msg);
    return;
  }
  next = xasprintf("%s; %s", *joined, msg);
  free(*joined);
  *joined = next;
}

void shorten_to(const char *s, int max, char *out, size_t outsz) {
  int n;

  if (outsz == 0) {
    return;
  }
  if (max <= 0) {
    out[0] = '\0';
    return;
  }
  n = (int)strlen(blank_if(s, ""));
  if (n <= max) {
    (void)snprintf(out, outsz, "%s", blank_if(s, ""));
    return;
  }
  if (max <= 3) {
    (void)snprintf(out, outsz, "%.*s", max, blank_if(s, ""));
    return;
  }
  (void)snprintf(out, outsz, "%.*s...", max - 3, blank_if(s, ""));
}

void concat_limited(char *dst, size_t dstsz, const char *src) {
  size_t len;
  size_t rem;

  if (dstsz == 0) {
    return;
  }
  len = strlen(dst);
  if (len >= dstsz - 1) {
    return;
  }
  rem = dstsz - len - 1;
  strncat(dst, src, rem);
}

void format_prefixed(char *dst, size_t dstsz, const char *prefix,
                     const char *value) {
  if (dstsz == 0) {
    return;
  }
  dst[0] = '\0';
  concat_limited(dst, dstsz, prefix);
  concat_limited(dst, dstsz, value);
}

bool path_join2(char *dst, size_t dstsz, const char *a, const char *b) {
  size_t alen = strlen(a);
  size_t blen = strlen(b);
  size_t total;

  if (alen == 0 || blen == 0) {
    return false;
  }
  total = alen + 1 + blen + 1;
  if (total > dstsz) {
    return false;
  }
  memcpy(dst, a, alen);
  dst[alen] = '/';
  memcpy(dst + alen + 1, b, blen);
  dst[alen + 1 + blen] = '\0';
  return true;
}

bool path_join3(char *dst, size_t dstsz, const char *a, const char *b,
                const char *c) {
  size_t alen = strlen(a);
  size_t blen = strlen(b);
  size_t clen = strlen(c);
  size_t total;

  if (alen == 0 || blen == 0 || clen == 0) {
    return false;
  }
  total = alen + 1 + blen + 1 + clen + 1;
  if (total > dstsz) {
    return false;
  }
  memcpy(dst, a, alen);
  dst[alen] = '/';
  memcpy(dst + alen + 1, b, blen);
  dst[alen + 1 + blen] = '/';
  memcpy(dst + alen + 1 + blen + 1, c, clen);
  dst[alen + 1 + blen + 1 + clen] = '\0';
  return true;
}
