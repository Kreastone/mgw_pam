#include <iostream>
#include <erl_driver.h>
#include <fcntl.h>
#include <unistd.h>
#include <cstring>
#include <ei.h>
#include <sys/ioctl.h>
#include "pamlogin.h"


ErlDrvTid ThreadPid;
int Handle;
typedef struct {
    ErlDrvPort port;
} erl_data;


extern "C" ErlDrvData erldrv_start(ErlDrvPort port, char *buff)
{
    erl_data *d=(erl_data*)driver_alloc(sizeof(erl_data));
    d->port = port;
    return (ErlDrvData)d;
}

extern "C" void erldrv_stop(ErlDrvData handle)
{
    driver_free((char*)handle);
}

#define LOGIN_LOCAL 0
#define LOGIN_TAC_PLUS 1
#define LOGIN_RADIUS 2
#define LOGOUT 3

extern "C" ErlDrvSSizeT erldrv_control(ErlDrvData handle, unsigned int command,
                               char *buf, ErlDrvSizeT len,
                               char **rbuf, ErlDrvSizeT rlen)
{
    ErlDrvSSizeT result;
    erl_data* d = (erl_data*)handle;

    int index = 0, version, arity, type, size;
    if (ei_decode_version(buf, &index, &version)) return (ErlDrvSSizeT)ERL_DRV_ERROR_BADARG;
    if (ei_decode_tuple_header(buf, &index, &arity)) return (ErlDrvSSizeT)ERL_DRV_ERROR_BADARG;
    if (arity!=2) return (ErlDrvSSizeT)ERL_DRV_ERROR_BADARG;

    if (ei_get_type(buf, &index, &type, &size)) return (ErlDrvSSizeT)ERL_DRV_ERROR_BADARG;
    if (type != ERL_BINARY_EXT) return (ErlDrvSSizeT)ERL_DRV_ERROR_BADARG;
    char login[128];
    memset(login, 0, 128);
    ei_decode_binary(buf, &index, login, (long *)&size);

    if (ei_get_type(buf, &index, &type, &size)) return (ErlDrvSSizeT)ERL_DRV_ERROR_BADARG;
    if (type != ERL_BINARY_EXT) return (ErlDrvSSizeT)ERL_DRV_ERROR_BADARG;
    char password[128];
    memset(password, 0, 128);
    ei_decode_binary(buf, &index, password, (long *)&size);

    switch (command)
    {
        case LOGIN_LOCAL:
        {
            std::string result = (authenticate_local(0, login, password));
            driver_output(d->port, (char*)result.c_str(), result.size());
            return 0;
        }
        case LOGIN_TAC_PLUS:
        {
            return 0;
        }
        case LOGIN_RADIUS:
        {
            return 0;
        }
        case LOGOUT:
        {
            return 0;
        }
        default:
            return (ErlDrvSSizeT)ERL_DRV_ERROR_BADARG;
    }
}

extern "C" void erldrv_output(ErlDrvData handle, char *buff,
			       ErlDrvSizeT bufflen)
{
    erl_data* d = (erl_data*)handle;
    std::string str = "this is pam_drv";
    driver_output(d->port, (char*)str.c_str(), str.size());
}

ErlDrvEntry erldriver_entry = {
    NULL,			// F_PTR init, called when driver is loaded
	erldrv_start,		// L_PTR start, called when port is opened
	erldrv_stop,		// F_PTR stop, called when port is closed
	erldrv_output,		// F_PTR output, called when erlang has sent
    NULL,			// F_PTR ready_input, called when input descriptor ready
    NULL,			// F_PTR ready_output, called when output descriptor ready
    (char*)"pam_drv",		// char *driver_name, the argument to open_port
    NULL,			// F_PTR finish, called when unloaded
    NULL,                       // void *handle, Reserved by VM
    erldrv_control,			// F_PTR control, port_command callback
    NULL,			// F_PTR timeout, reserved
    NULL,			// F_PTR outputv, reserved
    NULL,                       // F_PTR ready_async, only for async drivers
    NULL,                       // F_PTR flush, called when port is about to be closed, but there is data in driver queue
    NULL,                       // F_PTR call, much like control, sync call to driver
    NULL,                       // unused
    (int)ERL_DRV_EXTENDED_MARKER,    // int extended marker, Should always be set to indicate driver versioning
    ERL_DRV_EXTENDED_MAJOR_VERSION, // int major_version, should always be set to this value
    ERL_DRV_EXTENDED_MINOR_VERSION, // int minor_version, should always be set to this value
    0,                          // int driver_flags, see documentation
    NULL,                       // void *handle2, reserved for VM use
    NULL,                       // F_PTR process_exit, called when a monitored process dies
    NULL                        // F_PTR stop_select, called to close an event object
};

extern "C" DRIVER_INIT(slics_drv) /* must match name in driver_entry */
{
    return &erldriver_entry;
}