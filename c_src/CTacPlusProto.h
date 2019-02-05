/*
 * CTacPlusProto.h
 *
 *  Created on: 20 мар. 2018 г.
 *      Author: muaddib
 */

#ifndef CTACPLUSPROTO_H_
#define CTACPLUSPROTO_H_

#include "CBaseProto.h"

#define MAX_CMD_LENGTH 512

class CTacPlusProto : public CBaseProto
{
private:
	int PAM_author_acct(pam_handle_t *pamh, char *cmd);
public:
	CTacPlusProto();
	std::string authenticate_system(const char *username, const char *password, const char *service);
	std::string execCmd(std::string cmd);
	~CTacPlusProto(void);
};

#endif /* CTACPLUSPROTO_H_ */
