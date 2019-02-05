/*
 * CLocalProto.h
 *
 *  Created on: 27 мар. 2018 г.
 *      Author: muaddib
 */

#ifndef CLOCALPROTO_H_
#define CLOCALPROTO_H_

#include "CBaseProto.h"
#include <grp.h>
#include <sstream>
#include <iostream>

#define likely(x)      __builtin_expect(!!(x), 1)
#define unlikely(x)    __builtin_expect(!!(x), 0)

class CLocalProto : public CBaseProto
{
private:

public:
	CLocalProto();
	virtual ~CLocalProto();
	std::string authenticate_system(const char *username, const char *password, const char *service);
	static std::string getGroups(const char *username);
};

#endif /* CLOCALPROTO_H_ */
