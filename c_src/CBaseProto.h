/*
 * CBaseProto.h
 *
 *  Created on: 20 мар. 2018 г.
 *      Author: muaddib
 */

#ifndef CBASEPROTO_H_
#define CBASEPROTO_H_

#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <pwd.h>
#include <stdarg.h>
#include <string>
#include <vector>

#define PAM_ERR_INIT -1
#define PAM_ERR_AUTH -2
#define PAM_ERR_MEM -3
#define PAM_ERR_GID -4
#define PAM_ERR_VALID -5
#define PAM_ERR_SESSION -6
#define PAM_ERR_CRED -7
#define PAM_ERR_CMD -8


class CBaseProto
{
private:

protected:
	pam_response *reply;
    int retval;
    pam_handle_t *pamh;
    pam_conv conv;

    static int function_conversation(int num_msg, const struct pam_message **msg, struct pam_response **resp, void *appdata_ptr);
public:
	static pam_response *sreply;

	CBaseProto(void);
	virtual ~CBaseProto(void);

	int getRetVal(void) { return retval; }
	static std::string format(const char *fmt, ...);
};

#endif /* CBASEPROTO_H_ */
