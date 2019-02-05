/*
 * CLocalProto.cpp
 *
 *  Created on: 27 мар. 2018 г.
 *      Author: muaddib
 */

#include "CLocalProto.h"


CLocalProto::CLocalProto() : CBaseProto()
{

}

CLocalProto::~CLocalProto()
{
	pam_end(pamh, retval);
	//printf("Pam close Ok!\n");
}

std::string CLocalProto::getGroups(const char *username)
{
	int gid;
	int i;
	int ngroups = 20;
	gid_t *groups = new gid_t[ngroups];
	int n;
	std::stringstream ss;
	struct passwd *ppwd = getpwnam(username);
	if (ppwd == NULL)
		return std::string();
	gid = ppwd->pw_gid;
	getgrouplist(username, gid, groups, &ngroups);
	//std::cout<<"Gid: "<<gid<<"\n";
	//std::cout<<"ngroups: "<<ngroups<<"\n";
	if (likely(ngroups > 0))
	{
		ss << groups[0];
		n = ngroups;
		if (unlikely(n > 20))
			n = 20;
	    for (i = 1; i < n; i++)
	  	  ss << "," << groups[i];
	}

	delete []groups;

	return ss.str();
}


std::string CLocalProto::authenticate_system(const char *username, const char *password, const char *service)
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

    //Получение группы
    std::string str = getGroups(username);

    if (str.empty())
       return format("%d", PAM_ERR_GID);

    return str;
}
