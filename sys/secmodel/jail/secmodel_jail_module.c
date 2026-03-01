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
#include <sys/module.h>
#include <sys/kauth.h>
#include <sys/systm.h>
#include <sys/syslog.h>

#include <secmodel/jail/secmodel_jail_int.h>

MODULE(MODULE_CLASS_SECMODEL, secmodel_jail, NULL);

/*
 * Module command handler: register/deregister the security model.
 */
static int
secmodel_jail_modcmd(modcmd_t cmd, void *arg)
{
	int error = 0;
	int init_error;

	(void)arg;

	switch (cmd) {
	case MODULE_CMD_INIT:
		error = secmodel_register(&jail_sm,
		    SECMODEL_JAIL_ID, SECMODEL_JAIL_NAME,
		    NULL, secmodel_jail_eval, secmodel_jail_setinfo_adapter);
		if (error != 0) {
			printf("secmodel_jail_modcmd::init: "
			    "secmodel_register returned %d\n", error);
			return error;
		}

		init_error = secmodel_jail_init();
		if (init_error != 0) {
			error = secmodel_deregister(jail_sm);
			if (error != 0)
				printf("secmodel_jail_modcmd::init: "
				    "secmodel_deregister returned %d\n", error);
			return init_error;
		}
		secmodel_jail_start();
		log(LOG_INFO, "secmodel_jail: loaded\n");
		break;

	case MODULE_CMD_FINI:
		if (secmodel_jail_has_entries())
			return EBUSY;

		log(LOG_INFO, "secmodel_jail: unloading\n");
		secmodel_jail_stop();

		error = secmodel_deregister(jail_sm);
		if (error != 0)
			printf("secmodel_jail_modcmd::fini: "
			    "secmodel_deregister returned %d\n", error);
		break;

	case MODULE_CMD_AUTOUNLOAD:
		error = EPERM;
		break;

	default:
		error = ENOTTY;
		break;
	}

	return error;
}
