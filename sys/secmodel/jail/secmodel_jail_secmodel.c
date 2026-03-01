/* $NetBSD$ */
/*-
 * Copyright (c) 2026
 * The NetBSD Foundation, Inc.
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

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD$");

#include <sys/types.h>
#include <sys/systm.h>
#include <sys/syslog.h>

#include <secmodel/jail/secmodel_jail_int.h>

/*
 * secmodel_jail_eval() handles only policy decisions that can succeed/fail.
 *
 * The complementary state/accounting updates are handled by
 * secmodel_jail_setinfo(); keeping these paths separate makes call sites
 * self-documenting and avoids conflating admission checks with telemetry.
 */
int
secmodel_jail_eval(const char *what, void *arg, void *ret)
{
	const struct secmodel_jail_eval_admit_args *aa;
	const struct secmodel_jail_eval_sockbuf_charge_args *sba;
	const struct secmodel_jail_eval_cpu_can_run_args *cra;
	bool *okp;

	if (strcmp(what, SECMODEL_JAIL_EVAL_MEMORY_ADMIT) == 0) {
		if (arg == NULL || ret == NULL)
			return EINVAL;
		aa = arg;
		okp = ret;
		*okp = secmodel_jail_memory_admit(aa->cred, aa->current, aa->delta);
		return 0;
	}

	if (strcmp(what, SECMODEL_JAIL_EVAL_FD_ADMIT) == 0) {
		if (arg == NULL || ret == NULL)
			return EINVAL;
		aa = arg;
		okp = ret;
		*okp = secmodel_jail_fd_admit(aa->cred, aa->current, aa->delta);
		return 0;
	}

	if (strcmp(what, SECMODEL_JAIL_EVAL_SOCKBUF_CHARGE) == 0) {
		if (arg == NULL || ret == NULL)
			return EINVAL;
		sba = arg;
		okp = ret;
		*okp = secmodel_jail_sockbuf_charge(sba->cred, sba->bytes);
		return 0;
	}

	if (strcmp(what, SECMODEL_JAIL_EVAL_CPU_CAN_RUN) == 0) {
		if (arg == NULL || ret == NULL)
			return EINVAL;
		cra = arg;
		okp = ret;
		*okp = secmodel_jail_cpu_can_run(cra->cred);
		return 0;
	}

	return ENOENT;
}

/*
 * secmodel_jail_setinfo() receives best-effort runtime updates from other
 * subsystems. These updates are intentionally side-effect free from an access
 * control perspective: failure to deliver an update must not grant or deny a
 * permission check.
 */
static int
secmodel_jail_setinfo(const char *what, void *arg)
{
	const struct secmodel_jail_setinfo_set_current_args *sca;
	const struct secmodel_jail_setinfo_sockbuf_args *sba;

	if (strcmp(what, SECMODEL_JAIL_SETINFO_MEMORY_SET_CURRENT) == 0) {
		if (arg == NULL)
			return EINVAL;
		sca = arg;
		secmodel_jail_memory_set_current(sca->cred, sca->current);
		return 0;
	}

	if (strcmp(what, SECMODEL_JAIL_SETINFO_FD_SET_CURRENT) == 0) {
		if (arg == NULL)
			return EINVAL;
		sca = arg;
		secmodel_jail_fd_set_current(sca->cred, sca->current);
		return 0;
	}

	if (strcmp(what, SECMODEL_JAIL_SETINFO_SOCKBUF_UNCHARGE) == 0) {
		if (arg == NULL)
			return EINVAL;
		sba = arg;
		secmodel_jail_sockbuf_uncharge(sba->cred, sba->bytes);
		return 0;
	}

	return ENOENT;
}

/*
 * secmodel_setinfo_t currently passes an opaque argument only. Use a tiny
 * adapter so secmodel_jail_setinfo() can keep its named-operation dispatch.
 */
struct secmodel_jail_setinfo_call {
	const char *what;
	void *arg;
};

int
secmodel_jail_setinfo_adapter(void *v)
{
	const struct secmodel_jail_setinfo_call *call;

	if (v == NULL)
		return EINVAL;

	call = v;
	if (call->what == NULL)
		return EINVAL;

	return secmodel_jail_setinfo(call->what, call->arg);
}
