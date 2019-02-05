//============================================================================
// Name        : pamlogin.cpp
// Author      : mmm
// Version     :
// Copyright   : Your copyright notice
// Description : Hello World in C++, Ansi-style
//============================================================================

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <unistd.h>
#include <pwd.h>
#include <map>
#include "CTacPlusProto.h"
#include "CRadProto.h"
#include "CLocalProto.h"
#include <iostream>
#include <string>
#include <vector>
#include <stdarg.h>
#include <sstream>

//расшифровка <номер ошибки1>:
//-1 - Ошибка инициализации pam
//-2 - Ошибка аутентификации
//-3 - Ошибка выделения памяти malloc
//-4 - Ошибка получения GID
//-5 - Ошибка валидации учетной записи
//расшифровка <-2>:
//6 - Ошибка доступа
//7 - Ошибка авторизации
//9 - Удаленный сервер недоступен
//28 - отсутствует вызываемый модуль (pam_raduis.so, pam_tacacs.so)
//10 - ошибка получения информации о пользователе (GID) с удаленного сервера, ошибка возникает при неверных настройках сервера

std::map<int, CBaseProto*> gTable;
int id = 0;

std::string format(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    std::vector<char> v(1024);
    while (true)
    {
        va_list args2;
        va_copy(args2, args);
        int res = vsnprintf(v.data(), v.size(), fmt, args2);
        if ((res >= 0) && (res < static_cast<int>(v.size())))
        {
            va_end(args);
            va_end(args2);
            return std::string(v.data());
        }
        size_t size;
        if (res < 0)
            size = v.size() * 2;
        else
            size = static_cast<size_t>(res) + 1;
        v.clear();
        v.resize(size);
        va_end(args2);
    }
}

int add(CBaseProto* obj)
{
	int resid;
	if (gTable.empty() == false)
	{
    	//std::map<int, CBaseProto*>::iterator it;
    	while (gTable.find(id) != gTable.end())
    	{
    	   id++;
    	   if (id > 65530)
    		   id = 0;
    	}
	}

	gTable[id] = obj;
	resid = id;
    id++;
    if (id > 65530)
	   id = 0;
    return resid;
}

CBaseProto *remove(int lid)
{
	CBaseProto *obj = NULL;
	std::map<int, CBaseProto*>::iterator it = gTable.find(lid);
	if (it != gTable.end())
	{
		obj = it->second;
		gTable.erase(it);
	}
	return obj;
}

std::string authenticate_tacplus(unsigned int handle, std::string username, std::string password)
{
    std::string str;
	CTacPlusProto *obj = new CTacPlusProto();
    //handle уже существует
	if (gTable.find(handle) != gTable.end())
    	return("0");
    str = obj->authenticate_system(username.c_str(), password.c_str(), "remote");
    gTable[handle] = obj;
    return str;
}

std::string exec_tac_cmd(int handle, std::string cmd)
{
    std::string str = "1";

	CBaseProto *obj = NULL;
	std::map<int, CBaseProto*>::iterator it = gTable.find(handle);
	if (it != gTable.end())
	{
        obj = it->second;
	    str = ((CTacPlusProto*)obj)->execCmd(cmd);
	}

    return str;
}

std::string exec_rad_cmd(int handle, std::string cmd)
{
    std::string str = "1";

	CBaseProto *obj = NULL;
	std::map<int, CBaseProto*>::iterator it = gTable.find(handle);
	if (it != gTable.end())
	{
        obj = it->second;
	    str = ((CRadProto*)obj)->execCmd(cmd);
	}

    return str;
}


std::string authenticate_radius(unsigned int handle, std::string username, std::string password)
{
    std::string str;
	CRadProto *obj = new CRadProto();
    if (gTable.find(handle) != gTable.end())
    	return("0");
    str = obj->authenticate_system(username.c_str(), password.c_str(), "remote");
    gTable[handle] = obj;

    return str;
}

std::string authenticate_local(unsigned int handle, char* username, char* password)
{
	std::string str;
	CLocalProto *obj = new CLocalProto();
//    if (gTable.find(handle) != gTable.end())
//    	return("0");
    str = obj->authenticate_system(username, password, "local");
//    if (str == "0")
//        gTable[handle] = obj;
    free(obj);
	return str;
}

int logout(int h)
{
	CBaseProto *obj = remove(h);
	if (obj != NULL)
	{
		delete obj;
		return 0;
	}
	return 1;
}

void logoutall(void)
{
    while (gTable.empty() == false)
       logout(gTable.begin()->first);
}

std::string list(void)
{
	std::stringstream ss;
	std::map<int, CBaseProto*>::iterator it = gTable.begin();
    if (gTable.empty() == false)
       ss<<it->first;
    else
       return ss.str();
    it++;
    while (it != gTable.end())
    {
        ss<<","<<it->first;
        it++;
    }
    return ss.str();
}


