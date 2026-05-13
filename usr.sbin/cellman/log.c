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

/*
 * Layer: cellman shared logging/output layer.
 *
 * Centralize structured log and payload output behavior across CLI/API
 * execution paths.
 *
 * Extension guidance: Add logging/payload formatting behavior here; keep
 * command logic outside of this module.
 */

#include "cellman.h"

#include <stdarg.h>
#include <stdio.h>

static void
cellman_vlog(const char *level, const char *fmt, va_list ap)
{
	(void)fprintf(stderr, "cellman: %s: ", level);
	(void)vfprintf(stderr, fmt, ap);
	(void)fputc('\n', stderr);
}

void
cellman_log_info(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	cellman_vlog("info", fmt, ap);
	va_end(ap);
}

void
cellman_log_warn(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	cellman_vlog("warn", fmt, ap);
	va_end(ap);
}

void
cellman_log_error(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	cellman_vlog("error", fmt, ap);
	va_end(ap);
}

void
cellman_log_debug(bool enabled, const char *fmt, ...)
{
	va_list ap;

	if (!enabled)
		return;

	va_start(ap, fmt);
	cellman_vlog("debug", fmt, ap);
	va_end(ap);
}

int
cellman_payload_printf(const char *fmt, ...)
{
	va_list ap;
	int rc;

	va_start(ap, fmt);
	rc = vfprintf(stdout, fmt, ap);
	va_end(ap);
	return rc;
}
