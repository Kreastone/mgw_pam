/*
 * CRadProto.h
 *
 *  Created on: 20 мар. 2018 г.
 *      Author: muaddib
 */

#ifndef CRADPROTO_H_
#define CRADPROTO_H_

#include "CBaseProto.h"

class CRadProto : public CBaseProto
{
private:
	int PAM_author_acct(pam_handle_t *pamh, char *cmd);
public:
	CRadProto();
	virtual ~CRadProto();
	std::string authenticate_system(const char *username, const char *password, const char *service);
	std::string execCmd(std::string cmd);
};

#endif /* CRADPROTO_H_ */
