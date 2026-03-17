//go:build netbsd && cgo

package main

/*
#cgo LDFLAGS: -lpam
#include <stdlib.h>
#include <security/pam_appl.h>

typedef struct {
	const char *password;
} cellweb_pam_data;

static int cellweb_pam_conv(int num_msg, const struct pam_message **msg,
	struct pam_response **resp, void *appdata_ptr)
{
	cellweb_pam_data *data = (cellweb_pam_data *)appdata_ptr;
	struct pam_response *responses = calloc((size_t)num_msg, sizeof(struct pam_response));
	if (responses == NULL) {
		return PAM_CONV_ERR;
	}

	for (int i = 0; i < num_msg; i++) {
		switch (msg[i]->msg_style) {
		case PAM_PROMPT_ECHO_OFF:
		case PAM_PROMPT_ECHO_ON:
			responses[i].resp = strdup(data->password);
			if (responses[i].resp == NULL) {
				for (int j = 0; j < i; j++) {
					free(responses[j].resp);
				}
				free(responses);
				return PAM_CONV_ERR;
			}
			responses[i].resp_retcode = 0;
			break;
		case PAM_ERROR_MSG:
		case PAM_TEXT_INFO:
			responses[i].resp = NULL;
			responses[i].resp_retcode = 0;
			break;
		default:
			for (int j = 0; j <= i; j++) {
				free(responses[j].resp);
			}
			free(responses);
			return PAM_CONV_ERR;
		}
	}

	*resp = responses;
	return PAM_SUCCESS;
}

static int cellweb_pam_auth(const char *service, const char *username, const char *password)
{
	pam_handle_t *pamh = NULL;
	cellweb_pam_data data = { password };
	struct pam_conv conv = { cellweb_pam_conv, &data };
	int rc = pam_start(service, username, &conv, &pamh);
	if (rc != PAM_SUCCESS) {
		if (pamh != NULL) {
			pam_end(pamh, rc);
		}
		return rc;
	}

	rc = pam_authenticate(pamh, 0);
	if (rc == PAM_SUCCESS) {
		rc = pam_acct_mgmt(pamh, 0);
	}

	pam_end(pamh, rc);
	return rc;
}
*/
import "C"

import (
	"context"
	"fmt"
	"strings"
	"unsafe"
)

type pamAuthenticator struct {
	service string
}

func newPAMAuthenticator(service string) authenticator {
	if strings.TrimSpace(service) == "" {
		service = "login"
	}
	return pamAuthenticator{service: service}
}

func (p pamAuthenticator) Authenticate(ctx context.Context, username, password string) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	cService := C.CString(p.service)
	cUser := C.CString(username)
	cPass := C.CString(password)
	defer C.free(unsafe.Pointer(cService))
	defer C.free(unsafe.Pointer(cUser))
	defer C.free(unsafe.Pointer(cPass))

	rc := C.cellweb_pam_auth(cService, cUser, cPass)
	if rc != C.PAM_SUCCESS {
		return fmt.Errorf("pam authentication failed (%d)", int(rc))
	}
	return nil
}
