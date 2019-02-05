/*
 * CRadProto.cpp
 *
 *  Created on: 20 мар. 2018 г.
 *      Author: muaddib
 */

#include "CRadProto.h"

CRadProto::CRadProto() : CBaseProto()
{

}

CRadProto::~CRadProto()
{
	pam_end(pamh, retval);
	//printf("Pam close Ok!\n");
}

std::string CRadProto::authenticate_system(const char *username, const char *password, const char *service)
{
	//Инициализация библиотеки
	retval = pam_start(service, username, &conv, &pamh);

	if (retval != PAM_SUCCESS)
        return format("%d", PAM_ERR_INIT);

    //Задание пароля
    reply = (struct pam_response *)malloc(sizeof(struct pam_response));
    if (reply == NULL)
    {
    	return format("%d", PAM_ERR_MEM);
    }
    reply[0].resp = strdup(password);
    reply[0].resp_retcode = 0;

    sreply = reply;

    //Аутентификация
    retval = pam_authenticate(pamh, 0);

    if (retval != PAM_SUCCESS)
    {
    	return format("%d,%d", PAM_ERR_AUTH, retval);
    }

    //Проверка учетной записи на валидность
    retval = pam_acct_mgmt(pamh, 0);
    if (retval != PAM_SUCCESS)
    {
        return format("%d", PAM_ERR_VALID);
    }

    /*retval = pam_open_session(pamh, 0);
    if (retval != PAM_SUCCESS) {
    	//printf("pam open session error\n");
        return format("%d",PAM_ERR_SESSION);
    }

    retval = pam_setcred(pamh, PAM_ESTABLISH_CRED);
    if (retval != PAM_SUCCESS) {
    	//printf("pam setcred error\n");
        return format("%d", PAM_ERR_CRED);
    }*/

    //Получение группы
    struct passwd *ppwd = getpwnam(username);

    if (ppwd == NULL)
    	return format("%d", PAM_ERR_GID);

    return format("%d", ppwd->pw_gid);
}

std::string CRadProto::execCmd(std::string cmd)
{
    retval = PAM_author_acct(pamh, (char*)cmd.c_str());
    if (retval != PAM_SUCCESS)
    {
        return format("%d", PAM_ERR_CMD);
    }

    return std::string("0");
}


int CRadProto::PAM_author_acct(pam_handle_t *pamh, char *cmd) {
    const int MAX_CMD_LENGTH=512;
	char buf[MAX_CMD_LENGTH + 32];
    snprintf(buf, MAX_CMD_LENGTH + 32, "full_cmd=%s", cmd);
    int ret = pam_putenv(pamh, buf);
    if (ret != PAM_SUCCESS) {
        //printf("pam putenv error\n");
        return -1;
    }
    char *pch = strtok(cmd, " ");
    //printf("cmd: %s\n", pch);
    snprintf(buf, MAX_CMD_LENGTH + 32, "cmd=%s", pch);
    ret = pam_putenv(pamh, buf);
    if (ret != PAM_SUCCESS) {
        //printf("pam putenv error\n");
        return -2;
    }
    int arg_count = 0;
    while (pch != NULL) {
        pch = strtok(NULL, " ");
        if (pch != NULL) {
            //printf("cmd-arg: %s\n", pch);
            snprintf(buf, MAX_CMD_LENGTH + 32, "cmd-arg%d=%s", arg_count, pch);
            ret = pam_putenv(pamh, buf);
            if (ret != PAM_SUCCESS) {
                //printf("pam putenv error\n");
                return -3;
            }
            arg_count++;
        }
    }
    snprintf(buf, MAX_CMD_LENGTH + 32, "cmd-arg_count=%d", arg_count);
    ret = pam_putenv(pamh, buf);
    if (ret != PAM_SUCCESS) {
        //printf("pam putenv error\n");
        return -4;
    }
    ret = pam_acct_mgmt(pamh, 0);
    if (ret == PAM_SUCCESS) {
        //accounting
        //pam_close_session(pamh, 0);
    } else {
        //printf("ret=%d\n", ret);
        //printf("pam acct mgmt error\n");
        return -5;
    }
    return 0;
}


