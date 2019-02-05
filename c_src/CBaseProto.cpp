/*
 * CBaseProto.cpp
 *
 *  Created on: 20 мар. 2018 г.
 *      Author: muaddib
 */

#include "CBaseProto.h"

pam_response *CBaseProto::sreply = NULL;


CBaseProto::CBaseProto() : reply(NULL), retval(0), pamh(NULL)
{
    conv.conv = function_conversation;
    conv.appdata_ptr = NULL;

}

CBaseProto::~CBaseProto(void)
{

}

int CBaseProto::function_conversation(int num_msg, const struct pam_message **msg, struct pam_response **resp, void *appdata_ptr)
{
	if (msg[0]->msg_style == PAM_PROMPT_ECHO_OFF)
		*resp = sreply;
	else
	{
       printf("msg: \n");
	   if (msg[0]->msg_style == PAM_TEXT_INFO)
		fputc('\n', stdin);
	}

    return PAM_SUCCESS;
}

std::string CBaseProto::format(const char *fmt, ...)
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
