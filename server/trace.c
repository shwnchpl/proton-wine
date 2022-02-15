/*
 * Server request tracing
 *
 * Copyright (C) 1999 Alexandre Julliard
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

#include "config.h"

#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <sys/types.h>

#ifdef HAVE_SYS_UIO_H
#include <sys/uio.h>
#endif

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winbase.h"
#include "wincon.h"
#include "winternl.h"
#include "winuser.h"
#include "winioctl.h"
#include "wine/condrv.h"
#include "ddk/wdm.h"
#include "ddk/ntddser.h"
#define USE_WS_PREFIX
#include "winsock2.h"
#include "file.h"
#include "request.h"
#include "unicode.h"

static const void *cur_data;
static data_size_t cur_size;

static const char *get_status_name( unsigned int status );

/* utility functions */

static inline void remove_data( data_size_t size )
{
    cur_data = (const char *)cur_data + size;
    cur_size -= size;
}

static void dump_uints( const char *prefix, const unsigned int *ptr, int len )
{
    SERVER_LOG( LOG_ALWAYS, "%s{", prefix );
    while (len > 0)
    {
        SERVER_LOG( LOG_ALWAYS, "%08x", *ptr++ );
        if (--len) SERVER_LOG( LOG_ALWAYS, "," );
    }
    SERVER_LOG( LOG_ALWAYS,  "}" );
}

static void dump_handles( const char *prefix, const obj_handle_t *data, data_size_t size )
{
    data_size_t len = size / sizeof(*data);

    SERVER_LOG( LOG_ALWAYS, "%s{", prefix );
    while (len > 0)
    {
        SERVER_LOG( LOG_ALWAYS, "%04x", *data++ );
        if (--len) SERVER_LOG( LOG_ALWAYS, "," );
    }
    SERVER_LOG( LOG_ALWAYS, "}" );
}

static void dump_timeout( const char *prefix, const timeout_t *time )
{
    SERVER_LOG( LOG_ALWAYS, "%s%s", prefix, get_timeout_str(*time) );
}

static void dump_abstime( const char *prefix, const abstime_t *when )
{
    timeout_t timeout = abstime_to_timeout( *when );
    dump_timeout( prefix, &timeout );
}

static void dump_uint64( const char *prefix, const unsigned __int64 *val )
{
    if ((unsigned int)*val != *val)
        SERVER_LOG( LOG_ALWAYS, "%s%x%08x", prefix, (unsigned int)(*val >> 32), (unsigned int)*val );
    else
        SERVER_LOG( LOG_ALWAYS, "%s%08x", prefix, (unsigned int)*val );
}

static void dump_uint128( const char *prefix, const unsigned __int64 val[2] )
{
    unsigned __int64 low = val[0], high = val[1];

    if ((unsigned int)high != high)
        SERVER_LOG( LOG_ALWAYS, "%s%x%08x%08x%08x", prefix, (unsigned int)(high >> 32), (unsigned int)high,
                 (unsigned int)(low >> 32), (unsigned int)low );
    else if (high)
        SERVER_LOG( LOG_ALWAYS, "%s%x%08x%08x", prefix, (unsigned int)high,
                 (unsigned int)(low >> 32), (unsigned int)low );
    else if ((unsigned int)low != low)
        SERVER_LOG( LOG_ALWAYS, "%s%x%08x", prefix, (unsigned int)(low >> 32), (unsigned int)low );
    else
        SERVER_LOG( LOG_ALWAYS, "%s%x", prefix, (unsigned int)low );
}

static void dump_rectangle( const char *prefix, const rectangle_t *rect )
{
    SERVER_LOG( LOG_ALWAYS, "%s{%d,%d;%d,%d}", prefix,
             rect->left, rect->top, rect->right, rect->bottom );
}

static void dump_ioctl_code( const char *prefix, const ioctl_code_t *code )
{
    switch(*code)
    {
#define CASE(c) case c: SERVER_LOG( LOG_ALWAYS, "%s%s", prefix, #c ); break
        CASE(IOCTL_CONDRV_ACTIVATE);
        CASE(IOCTL_CONDRV_BIND_PID);
        CASE(IOCTL_CONDRV_CTRL_EVENT);
        CASE(IOCTL_CONDRV_FILL_OUTPUT);
        CASE(IOCTL_CONDRV_GET_INPUT_INFO);
        CASE(IOCTL_CONDRV_GET_MODE);
        CASE(IOCTL_CONDRV_GET_OUTPUT_INFO);
        CASE(IOCTL_CONDRV_GET_TITLE);
        CASE(IOCTL_CONDRV_PEEK);
        CASE(IOCTL_CONDRV_READ_CONSOLE);
        CASE(IOCTL_CONDRV_READ_INPUT);
        CASE(IOCTL_CONDRV_READ_OUTPUT);
        CASE(IOCTL_CONDRV_SET_MODE);
        CASE(IOCTL_CONDRV_SET_OUTPUT_INFO);
        CASE(IOCTL_CONDRV_SETUP_INPUT);
        CASE(IOCTL_CONDRV_WRITE_CONSOLE);
        CASE(IOCTL_CONDRV_WRITE_INPUT);
        CASE(IOCTL_CONDRV_WRITE_OUTPUT);
        CASE(FSCTL_DISMOUNT_VOLUME);
        CASE(FSCTL_PIPE_DISCONNECT);
        CASE(FSCTL_PIPE_LISTEN);
        CASE(FSCTL_PIPE_PEEK);
        CASE(FSCTL_PIPE_WAIT);
        CASE(IOCTL_SERIAL_GET_TIMEOUTS);
        CASE(IOCTL_SERIAL_GET_WAIT_MASK);
        CASE(IOCTL_SERIAL_SET_TIMEOUTS);
        CASE(IOCTL_SERIAL_SET_WAIT_MASK);
        CASE(WS_SIO_ADDRESS_LIST_CHANGE);
        default: SERVER_LOG( LOG_ALWAYS, "%s%08x", prefix, *code ); break;
#undef CASE
    }
}

static void dump_apc_call( const char *prefix, const apc_call_t *call )
{
    SERVER_LOG( LOG_ALWAYS, "%s{", prefix );
    switch(call->type)
    {
    case APC_NONE:
        SERVER_LOG( LOG_ALWAYS, "APC_NONE" );
        break;
    case APC_USER:
        dump_uint64( "APC_USER,func=", &call->user.func );
        dump_uint64( ",args={", &call->user.args[0] );
        dump_uint64( ",", &call->user.args[1] );
        dump_uint64( ",", &call->user.args[2] );
        SERVER_LOG( LOG_ALWAYS, "}" );
        break;
    case APC_ASYNC_IO:
        dump_uint64( "APC_ASYNC_IO,user=", &call->async_io.user );
        dump_uint64( ",sb=", &call->async_io.sb );
        SERVER_LOG( LOG_ALWAYS, ",status=%s,result=%u", get_status_name(call->async_io.status), call->async_io.result );
        break;
    case APC_VIRTUAL_ALLOC:
        dump_uint64( "APC_VIRTUAL_ALLOC,addr==", &call->virtual_alloc.addr );
        dump_uint64( ",size=", &call->virtual_alloc.size );
        dump_uint64( ",zero_bits=", &call->virtual_alloc.zero_bits );
        SERVER_LOG( LOG_ALWAYS, ",op_type=%x,prot=%x", call->virtual_alloc.op_type, call->virtual_alloc.prot );
        break;
    case APC_VIRTUAL_FREE:
        dump_uint64( "APC_VIRTUAL_FREE,addr=", &call->virtual_free.addr );
        dump_uint64( ",size=", &call->virtual_free.size );
        SERVER_LOG( LOG_ALWAYS, ",op_type=%x", call->virtual_free.op_type );
        break;
    case APC_VIRTUAL_QUERY:
        dump_uint64( "APC_VIRTUAL_QUERY,addr=", &call->virtual_query.addr );
        break;
    case APC_VIRTUAL_PROTECT:
        dump_uint64( "APC_VIRTUAL_PROTECT,addr=", &call->virtual_protect.addr );
        dump_uint64( ",size=", &call->virtual_protect.size );
        SERVER_LOG( LOG_ALWAYS, ",prot=%x", call->virtual_protect.prot );
        break;
    case APC_VIRTUAL_FLUSH:
        dump_uint64( "APC_VIRTUAL_FLUSH,addr=", &call->virtual_flush.addr );
        dump_uint64( ",size=", &call->virtual_flush.size );
        break;
    case APC_VIRTUAL_LOCK:
        dump_uint64( "APC_VIRTUAL_LOCK,addr=", &call->virtual_lock.addr );
        dump_uint64( ",size=", &call->virtual_lock.size );
        break;
    case APC_VIRTUAL_UNLOCK:
        dump_uint64( "APC_VIRTUAL_UNLOCK,addr=", &call->virtual_unlock.addr );
        dump_uint64( ",size=", &call->virtual_unlock.size );
        break;
    case APC_MAP_VIEW:
        SERVER_LOG( LOG_ALWAYS, "APC_MAP_VIEW,handle=%04x", call->map_view.handle );
        dump_uint64( ",addr=", &call->map_view.addr );
        dump_uint64( ",size=", &call->map_view.size );
        dump_uint64( ",offset=", &call->map_view.offset );
        dump_uint64( ",zero_bits=", &call->map_view.zero_bits );
        SERVER_LOG( LOG_ALWAYS, ",alloc_type=%x,prot=%x", call->map_view.alloc_type, call->map_view.prot );
        break;
    case APC_UNMAP_VIEW:
        dump_uint64( "APC_UNMAP_VIEW,addr=", &call->unmap_view.addr );
        break;
    case APC_CREATE_THREAD:
        dump_uint64( "APC_CREATE_THREAD,func=", &call->create_thread.func );
        dump_uint64( ",arg=", &call->create_thread.arg );
        dump_uint64( ",zero_bits=", &call->create_thread.zero_bits );
        dump_uint64( ",reserve=", &call->create_thread.reserve );
        dump_uint64( ",commit=", &call->create_thread.commit );
        SERVER_LOG( LOG_ALWAYS, ",flags=%x", call->create_thread.flags );
        break;
    case APC_DUP_HANDLE:
        SERVER_LOG( LOG_ALWAYS, "APC_DUP_HANDLE,src_handle=%04x,dst_process=%04x,access=%x,attributes=%x,options=%x",
                 call->dup_handle.src_handle, call->dup_handle.dst_process, call->dup_handle.access,
                 call->dup_handle.attributes, call->dup_handle.options );
        break;
    default:
        SERVER_LOG( LOG_ALWAYS, "type=%u", call->type );
        break;
    }
    SERVER_LOG( LOG_ALWAYS, "}" );
}

static void dump_apc_result( const char *prefix, const apc_result_t *result )
{
    SERVER_LOG( LOG_ALWAYS, "%s{", prefix );
    switch(result->type)
    {
    case APC_NONE:
        break;
    case APC_ASYNC_IO:
        SERVER_LOG( LOG_ALWAYS, "APC_ASYNC_IO,status=%s,total=%u",
                 get_status_name( result->async_io.status ), result->async_io.total );
        break;
    case APC_VIRTUAL_ALLOC:
        SERVER_LOG( LOG_ALWAYS, "APC_VIRTUAL_ALLOC,status=%s",
                 get_status_name( result->virtual_alloc.status ));
        dump_uint64( ",addr=", &result->virtual_alloc.addr );
        dump_uint64( ",size=", &result->virtual_alloc.size );
        break;
    case APC_VIRTUAL_FREE:
        SERVER_LOG( LOG_ALWAYS, "APC_VIRTUAL_FREE,status=%s",
                 get_status_name( result->virtual_free.status ));
        dump_uint64( ",addr=", &result->virtual_free.addr );
        dump_uint64( ",size=", &result->virtual_free.size );
        break;
    case APC_VIRTUAL_QUERY:
        SERVER_LOG( LOG_ALWAYS, "APC_VIRTUAL_QUERY,status=%s",
                 get_status_name( result->virtual_query.status ));
        dump_uint64( ",base=", &result->virtual_query.base );
        dump_uint64( ",alloc_base=", &result->virtual_query.alloc_base );
        dump_uint64( ",size=", &result->virtual_query.size );
        SERVER_LOG( LOG_ALWAYS, ",state=%x,prot=%x,alloc_prot=%x,alloc_type=%x",
                 result->virtual_query.state, result->virtual_query.prot,
                 result->virtual_query.alloc_prot, result->virtual_query.alloc_type );
        break;
    case APC_VIRTUAL_PROTECT:
        SERVER_LOG( LOG_ALWAYS, "APC_VIRTUAL_PROTECT,status=%s",
                 get_status_name( result->virtual_protect.status ));
        dump_uint64( ",addr=", &result->virtual_protect.addr );
        dump_uint64( ",size=", &result->virtual_protect.size );
        SERVER_LOG( LOG_ALWAYS, ",prot=%x", result->virtual_protect.prot );
        break;
    case APC_VIRTUAL_FLUSH:
        SERVER_LOG( LOG_ALWAYS, "APC_VIRTUAL_FLUSH,status=%s",
                 get_status_name( result->virtual_flush.status ));
        dump_uint64( ",addr=", &result->virtual_flush.addr );
        dump_uint64( ",size=", &result->virtual_flush.size );
        break;
    case APC_VIRTUAL_LOCK:
        SERVER_LOG( LOG_ALWAYS, "APC_VIRTUAL_LOCK,status=%s",
                 get_status_name( result->virtual_lock.status ));
        dump_uint64( ",addr=", &result->virtual_lock.addr );
        dump_uint64( ",size=", &result->virtual_lock.size );
        break;
    case APC_VIRTUAL_UNLOCK:
        SERVER_LOG( LOG_ALWAYS, "APC_VIRTUAL_UNLOCK,status=%s",
                 get_status_name( result->virtual_unlock.status ));
        dump_uint64( ",addr=", &result->virtual_unlock.addr );
        dump_uint64( ",size=", &result->virtual_unlock.size );
        break;
    case APC_MAP_VIEW:
        SERVER_LOG( LOG_ALWAYS, "APC_MAP_VIEW,status=%s",
                 get_status_name( result->map_view.status ));
        dump_uint64( ",addr=", &result->map_view.addr );
        dump_uint64( ",size=", &result->map_view.size );
        break;
    case APC_UNMAP_VIEW:
        SERVER_LOG( LOG_ALWAYS, "APC_UNMAP_VIEW,status=%s",
                 get_status_name( result->unmap_view.status ) );
        break;
    case APC_CREATE_THREAD:
        SERVER_LOG( LOG_ALWAYS, "APC_CREATE_THREAD,status=%s,pid=%04x,tid=%04x,handle=%04x",
                 get_status_name( result->create_thread.status ),
                 result->create_thread.pid, result->create_thread.tid, result->create_thread.handle );
        break;
    case APC_DUP_HANDLE:
        SERVER_LOG( LOG_ALWAYS, "APC_DUP_HANDLE,status=%s,handle=%04x",
                 get_status_name( result->dup_handle.status ), result->dup_handle.handle );
        break;
    default:
        SERVER_LOG( LOG_ALWAYS, "type=%u", result->type );
        break;
    }
    SERVER_LOG( LOG_ALWAYS, "}" );
}

static void dump_async_data( const char *prefix, const async_data_t *data )
{
    SERVER_LOG( LOG_ALWAYS, "%s{handle=%04x,event=%04x", prefix, data->handle, data->event );
    dump_uint64( ",iosb=", &data->iosb );
    dump_uint64( ",user=", &data->user );
    dump_uint64( ",apc=", &data->apc );
    dump_uint64( ",apc_context=", &data->apc_context );
    SERVER_LOG( LOG_ALWAYS, "}" );
}

static void dump_irp_params( const char *prefix, const irp_params_t *data )
{
    switch (data->type)
    {
    case IRP_CALL_NONE:
        SERVER_LOG( LOG_ALWAYS, "%s{NONE}", prefix );
        break;
    case IRP_CALL_CREATE:
        SERVER_LOG( LOG_ALWAYS, "%s{CREATE,access=%08x,sharing=%08x,options=%08x",
                 prefix, data->create.access, data->create.sharing, data->create.options );
        dump_uint64( ",device=", &data->create.device );
        SERVER_LOG( LOG_ALWAYS, ",file=%08x}", data->create.file );
        break;
    case IRP_CALL_CLOSE:
        SERVER_LOG( LOG_ALWAYS, "%s{CLOSE", prefix );
        dump_uint64( ",file=", &data->close.file );
        SERVER_LOG( LOG_ALWAYS, "}" );
        break;
    case IRP_CALL_READ:
        SERVER_LOG( LOG_ALWAYS, "%s{READ,key=%08x,out_size=%u", prefix, data->read.key,
                 data->read.out_size );
        dump_uint64( ",pos=", &data->read.pos );
        dump_uint64( ",file=", &data->read.file );
        SERVER_LOG( LOG_ALWAYS, "}" );
        break;
    case IRP_CALL_WRITE:
        SERVER_LOG( LOG_ALWAYS, "%s{WRITE,key=%08x", prefix, data->write.key );
        dump_uint64( ",pos=", &data->write.pos );
        dump_uint64( ",file=", &data->write.file );
        SERVER_LOG( LOG_ALWAYS, "}" );
        break;
    case IRP_CALL_FLUSH:
        SERVER_LOG( LOG_ALWAYS, "%s{FLUSH", prefix );
        dump_uint64( ",file=", &data->flush.file );
        SERVER_LOG( LOG_ALWAYS, "}" );
        break;
    case IRP_CALL_IOCTL:
        SERVER_LOG( LOG_ALWAYS, "%s{IOCTL", prefix );
        dump_ioctl_code( ",code=", &data->ioctl.code );
        SERVER_LOG( LOG_ALWAYS, ",out_size=%u", data->ioctl.out_size );
        dump_uint64( ",file=", &data->ioctl.file );
        SERVER_LOG( LOG_ALWAYS, "}" );
        break;
    case IRP_CALL_VOLUME:
        SERVER_LOG( LOG_ALWAYS, "%s{VOLUME,class=%u,out_size=%u", prefix,
                 data->volume.info_class, data->volume.out_size );
        dump_uint64( ",file=", &data->volume.file );
        SERVER_LOG( LOG_ALWAYS, "}" );
        break;
    case IRP_CALL_FREE:
        SERVER_LOG( LOG_ALWAYS, "%s{FREE", prefix );
        dump_uint64( ",obj=", &data->free.obj );
        SERVER_LOG( LOG_ALWAYS, "}" );
        break;
    case IRP_CALL_CANCEL:
        SERVER_LOG( LOG_ALWAYS, "%s{CANCEL", prefix );
        dump_uint64( ",irp=", &data->cancel.irp );
        SERVER_LOG( LOG_ALWAYS, "}" );
        break;
    }
}

static void dump_rawinput( const char *prefix, const union rawinput *rawinput )
{
    switch (rawinput->type)
    {
    case RIM_TYPEMOUSE:
        SERVER_LOG( LOG_ALWAYS, "%s{type=MOUSE,x=%d,y=%d,data=%08x}", prefix, rawinput->mouse.x,
                 rawinput->mouse.y, rawinput->mouse.data );
        break;
    case RIM_TYPEKEYBOARD:
        SERVER_LOG( LOG_ALWAYS, "%s{type=KEYBOARD,message=%04x,vkey=%04hx,scan=%04hx}", prefix,
                 rawinput->kbd.message, rawinput->kbd.vkey, rawinput->kbd.scan );
        break;
    case RIM_TYPEHID:
        SERVER_LOG( LOG_ALWAYS, "%s{type=HID,device=%04x,param=%04x,page=%04hx,usage=%04hx,count=%u,length=%u}",
                 prefix, rawinput->hid.device, rawinput->hid.param, rawinput->hid.usage_page,
                 rawinput->hid.usage, rawinput->hid.count, rawinput->hid.length );
        break;
    default:
        SERVER_LOG( LOG_ALWAYS, "%s{type=%04x}", prefix, rawinput->type );
        break;
    }
}

static void dump_hw_input( const char *prefix, const hw_input_t *input )
{
    switch (input->type)
    {
    case INPUT_MOUSE:
        SERVER_LOG( LOG_ALWAYS, "%s{type=MOUSE,x=%d,y=%d,data=%08x,flags=%08x,time=%u",
                 prefix, input->mouse.x, input->mouse.y, input->mouse.data, input->mouse.flags,
                 input->mouse.time );
        dump_uint64( ",info=", &input->mouse.info );
        SERVER_LOG( LOG_ALWAYS, "}" );
        break;
    case INPUT_KEYBOARD:
        SERVER_LOG( LOG_ALWAYS, "%s{type=KEYBOARD,vkey=%04hx,scan=%04hx,flags=%08x,time=%u",
                 prefix, input->kbd.vkey, input->kbd.scan, input->kbd.flags, input->kbd.time );
        dump_uint64( ",info=", &input->kbd.info );
        SERVER_LOG( LOG_ALWAYS, "}" );
        break;
    case INPUT_HARDWARE:
        SERVER_LOG( LOG_ALWAYS, "%s{type=HARDWARE,msg=%04x", prefix, input->hw.msg );
        dump_uint64( ",lparam=", &input->hw.lparam );
        switch (input->hw.msg)
        {
        case WM_INPUT:
        case WM_INPUT_DEVICE_CHANGE:
            dump_rawinput( ",rawinput=", &input->hw.rawinput );
        }
        SERVER_LOG( LOG_ALWAYS, "}" );
        break;
    default:
        SERVER_LOG( LOG_ALWAYS, "%s{type=%04x}", prefix, input->type );
        break;
    }
}

static void dump_luid( const char *prefix, const luid_t *luid )
{
    SERVER_LOG( LOG_ALWAYS, "%s%d.%u", prefix, luid->high_part, luid->low_part );
}

static void dump_generic_map( const char *prefix, const generic_map_t *map )
{
    SERVER_LOG( LOG_ALWAYS, "%s{r=%08x,w=%08x,x=%08x,a=%08x}",
             prefix, map->read, map->write, map->exec, map->all );
}

static void dump_varargs_ints( const char *prefix, data_size_t size )
{
    const int *data = cur_data;
    data_size_t len = size / sizeof(*data);

    SERVER_LOG( LOG_ALWAYS, "%s{", prefix );
    while (len > 0)
    {
        SERVER_LOG( LOG_ALWAYS, "%d", *data++ );
        if (--len) SERVER_LOG( LOG_ALWAYS, "," );
    }
    SERVER_LOG( LOG_ALWAYS, "}" );
    remove_data( size );
}

static void dump_varargs_uints( const char *prefix, data_size_t size )
{
    const unsigned int *data = cur_data;

    dump_uints( prefix, data, size / sizeof(*data) );
    remove_data( size );
}

static void dump_varargs_uints64( const char *prefix, data_size_t size )
{
    const unsigned __int64 *data = cur_data;
    data_size_t len = size / sizeof(*data);

    SERVER_LOG( LOG_ALWAYS, "%s{", prefix );
    while (len > 0)
    {
        dump_uint64( "", data++ );
        if (--len) SERVER_LOG( LOG_ALWAYS, "," );
    }
    SERVER_LOG( LOG_ALWAYS, "}" );
    remove_data( size );
}

static void dump_varargs_ushorts( const char *prefix, data_size_t size )
{
    const unsigned short *data = cur_data;
    data_size_t len = size / sizeof(*data);

    SERVER_LOG( LOG_ALWAYS, "%s{", prefix );
    while (len > 0)
    {
        SERVER_LOG( LOG_ALWAYS, "%04x", *data++ );
        if (--len) SERVER_LOG( LOG_ALWAYS, "," );
    }
    SERVER_LOG( LOG_ALWAYS, "}" );
    remove_data( size );
}

static void dump_varargs_apc_result( const char *prefix, data_size_t size )
{
    const apc_result_t *result = cur_data;

    if (size >= sizeof(*result))
    {
        dump_apc_result( prefix, result );
        size = sizeof(*result);
    }
    remove_data( size );
}

static void dump_varargs_select_op( const char *prefix, data_size_t size )
{
    select_op_t data;

    if (!size)
    {
        SERVER_LOG( LOG_ALWAYS, "%s{}", prefix );
        return;
    }
    memset( &data, 0, sizeof(data) );
    memcpy( &data, cur_data, min( size, sizeof(data) ));

    SERVER_LOG( LOG_ALWAYS, "%s{", prefix );
    switch (data.op)
    {
    case SELECT_NONE:
        SERVER_LOG( LOG_ALWAYS, "NONE" );
        break;
    case SELECT_WAIT:
    case SELECT_WAIT_ALL:
        SERVER_LOG( LOG_ALWAYS, "%s", data.op == SELECT_WAIT ? "WAIT" : "WAIT_ALL" );
        if (size > offsetof( select_op_t, wait.handles ))
            dump_handles( ",handles=", data.wait.handles,
                          min( size, sizeof(data.wait) ) - offsetof( select_op_t, wait.handles ));
        break;
    case SELECT_SIGNAL_AND_WAIT:
        SERVER_LOG( LOG_ALWAYS, "SIGNAL_AND_WAIT,signal=%04x,wait=%04x",
                 data.signal_and_wait.signal, data.signal_and_wait.wait );
        break;
    case SELECT_KEYED_EVENT_WAIT:
    case SELECT_KEYED_EVENT_RELEASE:
        SERVER_LOG( LOG_ALWAYS, "KEYED_EVENT_%s,handle=%04x",
                 data.op == SELECT_KEYED_EVENT_WAIT ? "WAIT" : "RELEASE",
                 data.keyed_event.handle );
        dump_uint64( ",key=", &data.keyed_event.key );
        break;
    default:
        SERVER_LOG( LOG_ALWAYS, "op=%u", data.op );
        break;
    }
    SERVER_LOG( LOG_ALWAYS, "}" );
    remove_data( size );
}

static void dump_varargs_user_handles( const char *prefix, data_size_t size )
{
    const user_handle_t *data = cur_data;
    data_size_t len = size / sizeof(*data);

    SERVER_LOG( LOG_ALWAYS, "%s{", prefix );
    while (len > 0)
    {
        SERVER_LOG( LOG_ALWAYS, "%08x", *data++ );
        if (--len) SERVER_LOG( LOG_ALWAYS, "," );
    }
    SERVER_LOG( LOG_ALWAYS, "}" );
    remove_data( size );
}

static void dump_varargs_bytes( const char *prefix, data_size_t size )
{
    const unsigned char *data = cur_data;
    data_size_t len = min( 1024, size );

    SERVER_LOG( LOG_ALWAYS, "%s{", prefix );
    while (len > 0)
    {
        SERVER_LOG( LOG_ALWAYS, "%02x", *data++ );
        if (--len) SERVER_LOG( LOG_ALWAYS, "," );
    }
    if (size > 1024) SERVER_LOG( LOG_ALWAYS, "...(total %u)", size );
    SERVER_LOG( LOG_ALWAYS, "}" );
    remove_data( size );
}

static void dump_varargs_string( const char *prefix, data_size_t size )
{
    SERVER_LOG( LOG_ALWAYS, "%s\"%.*s\"", prefix, (int)size, (const char *)cur_data );
    remove_data( size );
}

static void dump_varargs_unicode_str( const char *prefix, data_size_t size )
{
    SERVER_LOG( LOG_ALWAYS, "%sL\"", prefix );
    dump_strW( cur_data, size, stderr, "\"\"" );
    SERVER_LOG( LOG_ALWAYS, "\"" );
    remove_data( size );
}

static void dump_varargs_context( const char *prefix, data_size_t size )
{
    const context_t *context = cur_data;
    context_t ctx;
    unsigned int i;

    if (!size)
    {
        SERVER_LOG( LOG_ALWAYS, "%s{}", prefix );
        return;
    }
    size = min( size, sizeof(ctx) );
    memset( &ctx, 0, sizeof(ctx) );
    memcpy( &ctx, context, size );

    switch (ctx.machine)
    {
    case IMAGE_FILE_MACHINE_I386:
        SERVER_LOG( LOG_ALWAYS, "%s{machine=i386", prefix );
        if (ctx.flags & SERVER_CTX_CONTROL)
            SERVER_LOG( LOG_ALWAYS, ",eip=%08x,esp=%08x,ebp=%08x,eflags=%08x,cs=%04x,ss=%04x",
                     ctx.ctl.i386_regs.eip, ctx.ctl.i386_regs.esp, ctx.ctl.i386_regs.ebp,
                     ctx.ctl.i386_regs.eflags, ctx.ctl.i386_regs.cs, ctx.ctl.i386_regs.ss );
        if (ctx.flags & SERVER_CTX_SEGMENTS)
            SERVER_LOG( LOG_ALWAYS, ",ds=%04x,es=%04x,fs=%04x,gs=%04x",
                     ctx.seg.i386_regs.ds, ctx.seg.i386_regs.es,
                     ctx.seg.i386_regs.fs, ctx.seg.i386_regs.gs );
        if (ctx.flags & SERVER_CTX_INTEGER)
            SERVER_LOG( LOG_ALWAYS, ",eax=%08x,ebx=%08x,ecx=%08x,edx=%08x,esi=%08x,edi=%08x",
                     ctx.integer.i386_regs.eax, ctx.integer.i386_regs.ebx, ctx.integer.i386_regs.ecx,
                     ctx.integer.i386_regs.edx, ctx.integer.i386_regs.esi, ctx.integer.i386_regs.edi );
        if (ctx.flags & SERVER_CTX_DEBUG_REGISTERS)
            SERVER_LOG( LOG_ALWAYS, ",dr0=%08x,dr1=%08x,dr2=%08x,dr3=%08x,dr6=%08x,dr7=%08x",
                     ctx.debug.i386_regs.dr0, ctx.debug.i386_regs.dr1, ctx.debug.i386_regs.dr2,
                     ctx.debug.i386_regs.dr3, ctx.debug.i386_regs.dr6, ctx.debug.i386_regs.dr7 );
        if (ctx.flags & SERVER_CTX_FLOATING_POINT)
        {
            SERVER_LOG( LOG_ALWAYS, ",fp.ctrl=%08x,fp.status=%08x,fp.tag=%08x,fp.err_off=%08x,fp.err_sel=%08x",
                     ctx.fp.i386_regs.ctrl, ctx.fp.i386_regs.status, ctx.fp.i386_regs.tag,
                     ctx.fp.i386_regs.err_off, ctx.fp.i386_regs.err_sel );
            SERVER_LOG( LOG_ALWAYS, ",fp.data_off=%08x,fp.data_sel=%08x,fp.cr0npx=%08x",
                     ctx.fp.i386_regs.data_off, ctx.fp.i386_regs.data_sel, ctx.fp.i386_regs.cr0npx );
            for (i = 0; i < 8; i++)
            {
                unsigned __int64 reg[2];
                memset( reg, 0, sizeof(reg) );
                memcpy( reg, &ctx.fp.i386_regs.regs[10 * i], 10 );
                SERVER_LOG( LOG_ALWAYS, ",fp.reg%u=", i );
                dump_uint128( "", reg );
            }
        }
        if (ctx.flags & SERVER_CTX_EXTENDED_REGISTERS)
            dump_uints( ",extended=", (const unsigned int *)ctx.ext.i386_regs,
                        sizeof(ctx.ext.i386_regs) / sizeof(int) );
        if (ctx.flags & SERVER_CTX_YMM_REGISTERS)
            for (i = 0; i < 16; i++)
            {
                SERVER_LOG( LOG_ALWAYS, ",ymm%u=", i );
                dump_uint128( "", (const unsigned __int64 *)&ctx.ymm.regs.ymm_high[i] );
            }
        break;
    case IMAGE_FILE_MACHINE_AMD64:
        SERVER_LOG( LOG_ALWAYS, "%s{machine=x86_64", prefix );
        if (ctx.flags & SERVER_CTX_CONTROL)
        {
            dump_uint64( ",rip=", &ctx.ctl.x86_64_regs.rip );
            dump_uint64( ",rbp=", &ctx.ctl.x86_64_regs.rbp );
            dump_uint64( ",rsp=", &ctx.ctl.x86_64_regs.rsp );
            SERVER_LOG( LOG_ALWAYS, ",cs=%04x,ss=%04x,flags=%08x",
                     ctx.ctl.x86_64_regs.cs, ctx.ctl.x86_64_regs.ss, ctx.ctl.x86_64_regs.flags );
        }
        if (ctx.flags & SERVER_CTX_INTEGER)
        {
            dump_uint64( ",rax=", &ctx.integer.x86_64_regs.rax );
            dump_uint64( ",rbx=", &ctx.integer.x86_64_regs.rbx );
            dump_uint64( ",rcx=", &ctx.integer.x86_64_regs.rcx );
            dump_uint64( ",rdx=", &ctx.integer.x86_64_regs.rdx );
            dump_uint64( ",rsi=", &ctx.integer.x86_64_regs.rsi );
            dump_uint64( ",rdi=", &ctx.integer.x86_64_regs.rdi );
            dump_uint64( ",r8=",  &ctx.integer.x86_64_regs.r8 );
            dump_uint64( ",r9=",  &ctx.integer.x86_64_regs.r9 );
            dump_uint64( ",r10=", &ctx.integer.x86_64_regs.r10 );
            dump_uint64( ",r11=", &ctx.integer.x86_64_regs.r11 );
            dump_uint64( ",r12=", &ctx.integer.x86_64_regs.r12 );
            dump_uint64( ",r13=", &ctx.integer.x86_64_regs.r13 );
            dump_uint64( ",r14=", &ctx.integer.x86_64_regs.r14 );
            dump_uint64( ",r15=", &ctx.integer.x86_64_regs.r15 );
        }
        if (ctx.flags & SERVER_CTX_SEGMENTS)
            SERVER_LOG( LOG_ALWAYS, ",ds=%04x,es=%04x,fs=%04x,gs=%04x",
                     ctx.seg.x86_64_regs.ds, ctx.seg.x86_64_regs.es,
                     ctx.seg.x86_64_regs.fs, ctx.seg.x86_64_regs.gs );
        if (ctx.flags & SERVER_CTX_DEBUG_REGISTERS)
        {
            dump_uint64( ",dr0=", &ctx.debug.x86_64_regs.dr0 );
            dump_uint64( ",dr1=", &ctx.debug.x86_64_regs.dr1 );
            dump_uint64( ",dr2=", &ctx.debug.x86_64_regs.dr2 );
            dump_uint64( ",dr3=", &ctx.debug.x86_64_regs.dr3 );
            dump_uint64( ",dr6=", &ctx.debug.x86_64_regs.dr6 );
            dump_uint64( ",dr7=", &ctx.debug.x86_64_regs.dr7 );
        }
        if (ctx.flags & SERVER_CTX_FLOATING_POINT)
            for (i = 0; i < 32; i++)
            {
                SERVER_LOG( LOG_ALWAYS, ",fp%u=", i );
                dump_uint128( "", (const unsigned __int64 *)&ctx.fp.x86_64_regs.fpregs[i] );
            }
        if (ctx.flags & SERVER_CTX_YMM_REGISTERS)
            for (i = 0; i < 16; i++)
            {
                SERVER_LOG( LOG_ALWAYS, ",ymm%u=", i );
                dump_uint128( "", (const unsigned __int64 *)&ctx.ymm.regs.ymm_high[i] );
            }
        break;
    case IMAGE_FILE_MACHINE_ARMNT:
        SERVER_LOG( LOG_ALWAYS, "%s{machine=arm", prefix );
        if (ctx.flags & SERVER_CTX_CONTROL)
            SERVER_LOG( LOG_ALWAYS, ",sp=%08x,lr=%08x,pc=%08x,cpsr=%08x",
                     ctx.ctl.arm_regs.sp, ctx.ctl.arm_regs.lr,
                     ctx.ctl.arm_regs.pc, ctx.ctl.arm_regs.cpsr );
        if (ctx.flags & SERVER_CTX_INTEGER)
            for (i = 0; i < 13; i++) SERVER_LOG( LOG_ALWAYS, ",r%u=%08x", i, ctx.integer.arm_regs.r[i] );
        if (ctx.flags & SERVER_CTX_DEBUG_REGISTERS)
        {
            for (i = 0; i < 8; i++)
                SERVER_LOG( LOG_ALWAYS, ",bcr%u=%08x,bvr%u=%08x",
                         i, ctx.debug.arm_regs.bcr[i], i, ctx.debug.arm_regs.bvr[i] );
            SERVER_LOG( LOG_ALWAYS, ",wcr0=%08x,wvr0=%08x",
                     ctx.debug.arm_regs.wcr[0], ctx.debug.arm_regs.wvr[0] );
        }
        if (ctx.flags & SERVER_CTX_FLOATING_POINT)
        {
            for (i = 0; i < 32; i++)
            {
                SERVER_LOG( LOG_ALWAYS, ",d%u=", i );
                dump_uint64( "", &ctx.fp.arm_regs.d[i] );
            }
            SERVER_LOG( LOG_ALWAYS, ",fpscr=%08x", ctx.fp.arm_regs.fpscr );
        }
        break;
    case IMAGE_FILE_MACHINE_ARM64:
        SERVER_LOG( LOG_ALWAYS, "%s{machine=arm64", prefix );
        if (ctx.flags & SERVER_CTX_CONTROL)
        {
            dump_uint64( ",sp=", &ctx.ctl.arm64_regs.sp );
            dump_uint64( ",pc=", &ctx.ctl.arm64_regs.pc );
            dump_uint64( ",pstate=", &ctx.ctl.arm64_regs.pstate );
        }
        if (ctx.flags & SERVER_CTX_INTEGER)
        {
            for (i = 0; i < 31; i++)
            {
                SERVER_LOG( LOG_ALWAYS, ",x%u=", i );
                dump_uint64( "", &ctx.integer.arm64_regs.x[i] );
            }
        }
        if (ctx.flags & SERVER_CTX_DEBUG_REGISTERS)
        {
            for (i = 0; i < 8; i++)
            {
                SERVER_LOG( LOG_ALWAYS, ",bcr%u=%08x,bvr%u=", i, ctx.debug.arm64_regs.bcr[i], i );
                dump_uint64( "", &ctx.debug.arm64_regs.bvr[i] );
            }
            for (i = 0; i < 2; i++)
            {
                SERVER_LOG( LOG_ALWAYS, ",wcr%u=%08x,wvr%u=", i, ctx.debug.arm64_regs.wcr[i], i );
                dump_uint64( "", &ctx.debug.arm64_regs.wvr[i] );
            }
        }
        if (ctx.flags & SERVER_CTX_FLOATING_POINT)
        {
            for (i = 0; i < 32; i++)
            {
                SERVER_LOG( LOG_ALWAYS, ",q%u=", i );
                dump_uint64( "", &ctx.fp.arm64_regs.q[i].high );
                dump_uint64( "", &ctx.fp.arm64_regs.q[i].low );
            }
            SERVER_LOG( LOG_ALWAYS, ",fpcr=%08x,fpsr=%08x", ctx.fp.arm64_regs.fpcr, ctx.fp.arm64_regs.fpsr );
        }
        break;
    default:
        SERVER_LOG( LOG_ALWAYS, "%s{machine=%04x", prefix, ctx.machine );
        break;
    }
    SERVER_LOG( LOG_ALWAYS, "}" );
    remove_data( size );
}

static void dump_varargs_contexts( const char *prefix, data_size_t size )
{
    if (!size)
    {
        SERVER_LOG( LOG_ALWAYS, "%s{}", prefix );
        return;
    }
    SERVER_LOG( LOG_ALWAYS, "%s{", prefix );
    while (cur_size)
    {
        dump_varargs_context( "", cur_size );
        SERVER_LOG( LOG_ALWAYS, cur_size ? "," : "}" );
    }
}

static void dump_varargs_debug_event( const char *prefix, data_size_t size )
{
    debug_event_t event;
    unsigned int i;

    if (!size)
    {
        SERVER_LOG( LOG_ALWAYS, "%s{}", prefix );
        return;
    }
    size = min( size, sizeof(event) );
    memset( &event, 0, sizeof(event) );
    memcpy( &event, cur_data, size );

    switch(event.code)
    {
    case DbgIdle:
        SERVER_LOG( LOG_ALWAYS, "%s{idle}", prefix );
        break;
    case DbgReplyPending:
        SERVER_LOG( LOG_ALWAYS, "%s{pending}", prefix );
        break;
    case DbgCreateThreadStateChange:
        SERVER_LOG( LOG_ALWAYS, "%s{create_thread,thread=%04x", prefix, event.create_thread.handle );
        dump_uint64( ",start=", &event.create_thread.start );
        SERVER_LOG( LOG_ALWAYS, "}" );
        break;
    case DbgCreateProcessStateChange:
        SERVER_LOG( LOG_ALWAYS, "%s{create_process,file=%04x,process=%04x,thread=%04x", prefix,
                 event.create_process.file, event.create_process.process,
                 event.create_process.thread );
        dump_uint64( ",base=", &event.create_process.base );
        SERVER_LOG( LOG_ALWAYS, ",offset=%d,size=%d",
                 event.create_process.dbg_offset, event.create_process.dbg_size );
        dump_uint64( ",start=", &event.create_process.start );
        SERVER_LOG( LOG_ALWAYS, "}" );
        break;
    case DbgExitThreadStateChange:
        SERVER_LOG( LOG_ALWAYS, "%s{exit_thread,code=%d}", prefix, event.exit.exit_code );
        break;
    case DbgExitProcessStateChange:
        SERVER_LOG( LOG_ALWAYS, "%s{exit_process,code=%d}", prefix, event.exit.exit_code );
        break;
    case DbgExceptionStateChange:
    case DbgBreakpointStateChange:
    case DbgSingleStepStateChange:
        SERVER_LOG( LOG_ALWAYS, "%s{%s,first=%d,exc_code=%08x,flags=%08x", prefix,
                 event.code == DbgBreakpointStateChange ? "breakpoint" :
                 event.code == DbgSingleStepStateChange ? "singlestep" : "exception",
                 event.exception.first, event.exception.exc_code, event.exception.flags );
        dump_uint64( ",record=", &event.exception.record );
        dump_uint64( ",address=", &event.exception.address );
        SERVER_LOG( LOG_ALWAYS, ",params={" );
        event.exception.nb_params = min( event.exception.nb_params, EXCEPTION_MAXIMUM_PARAMETERS );
        for (i = 0; i < event.exception.nb_params; i++)
        {
            dump_uint64( "", &event.exception.params[i] );
            if (i < event.exception.nb_params) SERVER_LOG( LOG_ALWAYS, "," );
        }
        SERVER_LOG( LOG_ALWAYS, "}}" );
        break;
    case DbgLoadDllStateChange:
        SERVER_LOG( LOG_ALWAYS, "%s{load_dll,file=%04x", prefix, event.load_dll.handle );
        dump_uint64( ",base=", &event.load_dll.base );
        SERVER_LOG( LOG_ALWAYS, ",offset=%d,size=%d",
                 event.load_dll.dbg_offset, event.load_dll.dbg_size );
        dump_uint64( ",name=", &event.load_dll.name );
        SERVER_LOG( LOG_ALWAYS, "}" );
        break;
    case DbgUnloadDllStateChange:
        SERVER_LOG( LOG_ALWAYS, "%s{unload_dll", prefix );
        dump_uint64( ",base=", &event.unload_dll.base );
        SERVER_LOG( LOG_ALWAYS, "}" );
        break;
    default:
        SERVER_LOG( LOG_ALWAYS, "%s{code=??? (%d)}", prefix, event.code );
        break;
    }
    remove_data( size );
}

/* dump a unicode string contained in a buffer; helper for dump_varargs_startup_info */
static data_size_t dump_inline_unicode_string( const char *prefix, data_size_t pos, data_size_t len, data_size_t total_size )
{
    fputs( prefix, stderr );
    if (pos >= total_size) return pos;
    if (len > total_size - pos) len = total_size - pos;
    dump_strW( (const WCHAR *)cur_data + pos/sizeof(WCHAR), len, stderr, "\"\"" );
    return pos + (len / sizeof(WCHAR)) * sizeof(WCHAR);
}

static void dump_varargs_startup_info( const char *prefix, data_size_t size )
{
    /* FIXME: Improve startup info dump when trace marking. */
    startup_info_t info;
    data_size_t pos = sizeof(info);

    memset( &info, 0, sizeof(info) );
    memcpy( &info, cur_data, min( size, sizeof(info) ));

    SERVER_LOG( LOG_ALWAYS,
             "%s{debug_flags=%x,console_flags=%x,console=%04x,hstdin=%04x,hstdout=%04x,hstderr=%04x,"
             "x=%u,y=%u,xsize=%u,ysize=%u,xchars=%u,ychars=%u,attribute=%02x,flags=%x,show=%u",
             prefix, info.debug_flags, info.console_flags, info.console,
             info.hstdin, info.hstdout, info.hstderr, info.x, info.y, info.xsize, info.ysize,
             info.xchars, info.ychars, info.attribute, info.flags, info.show );
    pos = dump_inline_unicode_string( ",curdir=L\"", pos, info.curdir_len, size );
    pos = dump_inline_unicode_string( "\",dllpath=L\"", pos, info.dllpath_len, size );
    pos = dump_inline_unicode_string( "\",imagepath=L\"", pos, info.imagepath_len, size );
    pos = dump_inline_unicode_string( "\",cmdline=L\"", pos, info.cmdline_len, size );
    pos = dump_inline_unicode_string( "\",title=L\"", pos, info.title_len, size );
    pos = dump_inline_unicode_string( "\",desktop=L\"", pos, info.desktop_len, size );
    pos = dump_inline_unicode_string( "\",shellinfo=L\"", pos, info.shellinfo_len, size );
    pos = dump_inline_unicode_string( "\",runtime=L\"", pos, info.runtime_len, size );
    SERVER_LOG( LOG_ALWAYS, "\"}" );
    remove_data( size );
}

static void dump_varargs_rectangles( const char *prefix, data_size_t size )
{
    const rectangle_t *rect = cur_data;
    data_size_t len = size / sizeof(*rect);

    SERVER_LOG( LOG_ALWAYS, "%s{", prefix );
    while (len > 0)
    {
        dump_rectangle( "", rect++ );
        if (--len) SERVER_LOG( LOG_ALWAYS, "," );
    }
    SERVER_LOG( LOG_ALWAYS, "}" );
    remove_data( size );
}

static void dump_varargs_cursor_positions( const char *prefix, data_size_t size )
{
    const cursor_pos_t *pos = cur_data;
    data_size_t len = size / sizeof(*pos);

    SERVER_LOG( LOG_ALWAYS, "%s{", prefix );
    while (len > 0)
    {
        SERVER_LOG( LOG_ALWAYS, "{x=%d,y=%d,time=%u", pos->x, pos->y, pos->time );
        dump_uint64( ",info=", &pos->info );
        SERVER_LOG( LOG_ALWAYS, "}" );
        pos++;
        if (--len) SERVER_LOG( LOG_ALWAYS, "," );
    }
    SERVER_LOG( LOG_ALWAYS, "}" );
    remove_data( size );
}

static void dump_varargs_message_data( const char *prefix, data_size_t size )
{
    /* FIXME: dump the structured data */
    dump_varargs_bytes( prefix, size );
}

static void dump_varargs_properties( const char *prefix, data_size_t size )
{
    const property_data_t *prop = cur_data;
    data_size_t len = size / sizeof(*prop);

    SERVER_LOG( LOG_ALWAYS, "%s{", prefix );
    while (len > 0)
    {
        SERVER_LOG( LOG_ALWAYS, "{atom=%04x,str=%d", prop->atom, prop->string );
        dump_uint64( ",data=", &prop->data );
        SERVER_LOG( LOG_ALWAYS, "}" );
        prop++;
        if (--len) SERVER_LOG( LOG_ALWAYS, "," );
    }
    SERVER_LOG( LOG_ALWAYS, "}" );
    remove_data( size );
}

static void dump_varargs_LUID_AND_ATTRIBUTES( const char *prefix, data_size_t size )
{
    const LUID_AND_ATTRIBUTES *lat = cur_data;
    data_size_t len = size / sizeof(*lat);

    SERVER_LOG( LOG_ALWAYS, "%s{", prefix );
    while (len > 0)
    {
        SERVER_LOG( LOG_ALWAYS, "{luid=%08x%08x,attr=%x}",
                 lat->Luid.HighPart, lat->Luid.LowPart, lat->Attributes );
        lat++;
        if (--len) SERVER_LOG( LOG_ALWAYS, "," );
    }
    SERVER_LOG( LOG_ALWAYS, "}" );
    remove_data( size );
}

static void dump_inline_sid( const char *prefix, const SID *sid, data_size_t size )
{
    DWORD i;

    /* security check */
    if ((FIELD_OFFSET(SID, SubAuthority[0]) > size) ||
        (FIELD_OFFSET(SID, SubAuthority[sid->SubAuthorityCount]) > size))
    {
        SERVER_LOG( LOG_ALWAYS, "<invalid sid>" );
        return;
    }

    SERVER_LOG( LOG_ALWAYS, "%s{", prefix );
    SERVER_LOG( LOG_ALWAYS, "S-%u-%u", sid->Revision, MAKELONG(
        MAKEWORD( sid->IdentifierAuthority.Value[5],
                  sid->IdentifierAuthority.Value[4] ),
        MAKEWORD( sid->IdentifierAuthority.Value[3],
                  sid->IdentifierAuthority.Value[2] ) ) );
    for (i = 0; i < sid->SubAuthorityCount; i++)
        SERVER_LOG( LOG_ALWAYS, "-%u", sid->SubAuthority[i] );
    SERVER_LOG( LOG_ALWAYS, "}" );
}

static void dump_varargs_SID( const char *prefix, data_size_t size )
{
    const SID *sid = cur_data;
    dump_inline_sid( prefix, sid, size );
    remove_data( size );
}

static void dump_inline_acl( const char *prefix, const ACL *acl, data_size_t size )
{
    const ACE_HEADER *ace;
    ULONG i;

    SERVER_LOG( LOG_ALWAYS, "%s{", prefix );
    if (size)
    {
        if (size < sizeof(ACL))
        {
            SERVER_LOG( LOG_ALWAYS, "<invalid acl>}" );
            return;
        }
        size -= sizeof(ACL);
        ace = (const ACE_HEADER *)(acl + 1);
        for (i = 0; i < acl->AceCount; i++)
        {
            const SID *sid = NULL;
            data_size_t sid_size = 0;

            if (size < sizeof(ACE_HEADER) || size < ace->AceSize) break;
            size -= ace->AceSize;
            if (i != 0) SERVER_LOG( LOG_ALWAYS, "," );
            SERVER_LOG( LOG_ALWAYS, "{AceType=" );
            switch (ace->AceType)
            {
            case ACCESS_DENIED_ACE_TYPE:
                sid = (const SID *)&((const ACCESS_DENIED_ACE *)ace)->SidStart;
                sid_size = ace->AceSize - FIELD_OFFSET(ACCESS_DENIED_ACE, SidStart);
                SERVER_LOG( LOG_ALWAYS, "ACCESS_DENIED_ACE_TYPE,Mask=%x",
                         ((const ACCESS_DENIED_ACE *)ace)->Mask );
                break;
            case ACCESS_ALLOWED_ACE_TYPE:
                sid = (const SID *)&((const ACCESS_ALLOWED_ACE *)ace)->SidStart;
                sid_size = ace->AceSize - FIELD_OFFSET(ACCESS_ALLOWED_ACE, SidStart);
                SERVER_LOG( LOG_ALWAYS, "ACCESS_ALLOWED_ACE_TYPE,Mask=%x",
                         ((const ACCESS_ALLOWED_ACE *)ace)->Mask );
                break;
            case SYSTEM_AUDIT_ACE_TYPE:
                sid = (const SID *)&((const SYSTEM_AUDIT_ACE *)ace)->SidStart;
                sid_size = ace->AceSize - FIELD_OFFSET(SYSTEM_AUDIT_ACE, SidStart);
                SERVER_LOG( LOG_ALWAYS, "SYSTEM_AUDIT_ACE_TYPE,Mask=%x",
                         ((const SYSTEM_AUDIT_ACE *)ace)->Mask );
                break;
            case SYSTEM_ALARM_ACE_TYPE:
                sid = (const SID *)&((const SYSTEM_ALARM_ACE *)ace)->SidStart;
                sid_size = ace->AceSize - FIELD_OFFSET(SYSTEM_ALARM_ACE, SidStart);
                SERVER_LOG( LOG_ALWAYS, "SYSTEM_ALARM_ACE_TYPE,Mask=%x",
                         ((const SYSTEM_ALARM_ACE *)ace)->Mask );
                break;
            case SYSTEM_MANDATORY_LABEL_ACE_TYPE:
                sid = (const SID *)&((const SYSTEM_MANDATORY_LABEL_ACE *)ace)->SidStart;
                sid_size = ace->AceSize - FIELD_OFFSET(SYSTEM_MANDATORY_LABEL_ACE, SidStart);
                SERVER_LOG( LOG_ALWAYS, "SYSTEM_MANDATORY_LABEL_ACE_TYPE,Mask=%x",
                         ((const SYSTEM_MANDATORY_LABEL_ACE *)ace)->Mask );
                break;
            default:
                SERVER_LOG( LOG_ALWAYS, "unknown<%d>", ace->AceType );
                break;
            }
            SERVER_LOG( LOG_ALWAYS, ",AceFlags=%x", ace->AceFlags );
            if (sid)
                dump_inline_sid( ",Sid=", sid, sid_size );
            ace = (const ACE_HEADER *)((const char *)ace + ace->AceSize);
            SERVER_LOG( LOG_ALWAYS, "}" );
        }
    }
    SERVER_LOG( LOG_ALWAYS, "}" );
}

static void dump_varargs_ACL( const char *prefix, data_size_t size )
{
    const ACL *acl = cur_data;
    dump_inline_acl( prefix, acl, size );
    remove_data( size );
}

static void dump_inline_security_descriptor( const char *prefix, const struct security_descriptor *sd, data_size_t size )
{
    SERVER_LOG( LOG_ALWAYS, "%s{", prefix );
    if (size >= sizeof(struct security_descriptor))
    {
        size_t offset = sizeof(struct security_descriptor);
        SERVER_LOG( LOG_ALWAYS, "control=%08x", sd->control );
        if ((sd->owner_len > FIELD_OFFSET(SID, SubAuthority[255])) || (offset + sd->owner_len > size))
            return;
        if (sd->owner_len)
            dump_inline_sid( ",owner=", (const SID *)((const char *)sd + offset), sd->owner_len );
        else
            SERVER_LOG( LOG_ALWAYS, ",owner=<not present>" );
        offset += sd->owner_len;
        if ((sd->group_len > FIELD_OFFSET(SID, SubAuthority[255])) || (offset + sd->group_len > size))
            return;
        if (sd->group_len)
            dump_inline_sid( ",group=", (const SID *)((const char *)sd + offset), sd->group_len );
        else
            SERVER_LOG( LOG_ALWAYS, ",group=<not present>" );
        offset += sd->group_len;
        if ((sd->sacl_len >= MAX_ACL_LEN) || (offset + sd->sacl_len > size))
            return;
        dump_inline_acl( ",sacl=", (const ACL *)((const char *)sd + offset), sd->sacl_len );
        offset += sd->sacl_len;
        if ((sd->dacl_len >= MAX_ACL_LEN) || (offset + sd->dacl_len > size))
            return;
        dump_inline_acl( ",dacl=", (const ACL *)((const char *)sd + offset), sd->dacl_len );
        offset += sd->dacl_len;
    }
    SERVER_LOG( LOG_ALWAYS, "}" );
}

static void dump_varargs_security_descriptor( const char *prefix, data_size_t size )
{
    const struct security_descriptor *sd = cur_data;
    dump_inline_security_descriptor( prefix, sd, size );
    remove_data( size );
}

static void dump_varargs_token_groups( const char *prefix, data_size_t size )
{
    const struct token_groups *tg = cur_data;

    SERVER_LOG( LOG_ALWAYS, "%s{", prefix );
    if (size >= sizeof(struct token_groups))
    {
        size_t offset = sizeof(*tg);
        SERVER_LOG( LOG_ALWAYS, "count=%08x,", tg->count );
        if (tg->count * sizeof(unsigned int) <= size)
        {
            unsigned int i;
            const unsigned int *attr = (const unsigned int *)(tg + 1);

            offset += tg->count * sizeof(unsigned int);

            SERVER_LOG( LOG_ALWAYS, "[" );
            for (i = 0; i < tg->count; i++)
            {
                const SID *sid = (const SID *)((const char *)cur_data + offset);
                if (i != 0)
                    SERVER_LOG( LOG_ALWAYS, "," );
                SERVER_LOG( LOG_ALWAYS, "{" );
                SERVER_LOG( LOG_ALWAYS, "attributes=%08x", attr[i] );
                dump_inline_sid( ",sid=", sid, size - offset );
                if ((offset + FIELD_OFFSET(SID, SubAuthority[0]) > size) ||
                    (offset + FIELD_OFFSET(SID, SubAuthority[sid->SubAuthorityCount]) > size))
                    break;
                offset += FIELD_OFFSET(SID, SubAuthority[sid->SubAuthorityCount]);
                SERVER_LOG( LOG_ALWAYS, "}" );
            }
            SERVER_LOG( LOG_ALWAYS, "]" );
        }
    }
    SERVER_LOG( LOG_ALWAYS, "}" );
}

static void dump_varargs_process_info( const char *prefix, data_size_t size )
{
    data_size_t pos = 0;
    unsigned int i;

    SERVER_LOG( LOG_ALWAYS, "%s{", prefix );

    while (size - pos >= sizeof(struct process_info))
    {
        const struct process_info *process;
        pos = (pos + 7) & ~7;
        process = (const struct process_info *)((const char *)cur_data + pos);
        if (size - pos < sizeof(*process)) break;
        if (pos) SERVER_LOG( LOG_ALWAYS, "," );
        dump_timeout( "{start_time=", &process->start_time );
        SERVER_LOG( LOG_ALWAYS, ",thread_count=%u,priority=%d,pid=%04x,parent_pid=%04x,session_id=%08x,handle_count=%u,unix_pid=%d,",
                 process->thread_count, process->priority, process->pid,
                 process->parent_pid, process->session_id, process->handle_count, process->unix_pid );
        pos += sizeof(*process);

        pos = dump_inline_unicode_string( "name=L\"", pos, process->name_len, size );

        pos = (pos + 7) & ~7;
        SERVER_LOG( LOG_ALWAYS, "\",threads={" );
        for (i = 0; i < process->thread_count; i++)
        {
            const struct thread_info *thread = (const struct thread_info *)((const char *)cur_data + pos);
            if (size - pos < sizeof(*thread)) break;
            if (i) SERVER_LOG( LOG_ALWAYS, "," );
            dump_timeout( "{start_time=", &thread->start_time );
            SERVER_LOG( LOG_ALWAYS, ",tid=%04x,base_priority=%d,current_priority=%d,unix_tid=%d}",
                     thread->tid, thread->base_priority, thread->current_priority, thread->unix_tid );
            pos += sizeof(*thread);
        }
        SERVER_LOG( LOG_ALWAYS, "}}" );
    }
    SERVER_LOG( LOG_ALWAYS, "}" );
    remove_data( size );
}

static void dump_varargs_object_attributes( const char *prefix, data_size_t size )
{
    const struct object_attributes *objattr = cur_data;

    SERVER_LOG( LOG_ALWAYS, "%s{", prefix );
    if (size)
    {
        const WCHAR *str;

        if (size < sizeof(*objattr) ||
            (size - sizeof(*objattr) < objattr->sd_len) ||
            (size - sizeof(*objattr) - objattr->sd_len < objattr->name_len))
        {
            SERVER_LOG( LOG_ALWAYS, "***invalid***}" );
            remove_data( size );
            return;
        }

        SERVER_LOG( LOG_ALWAYS, "rootdir=%04x,attributes=%08x", objattr->rootdir, objattr->attributes );
        dump_inline_security_descriptor( ",sd=", (const struct security_descriptor *)(objattr + 1), objattr->sd_len );
        str = (const WCHAR *)objattr + (sizeof(*objattr) + objattr->sd_len) / sizeof(WCHAR);
        SERVER_LOG( LOG_ALWAYS, ",name=L\"" );
        dump_strW( str, objattr->name_len, stderr, "\"\"" );
        SERVER_LOG( LOG_ALWAYS, "\"" );
        remove_data( (sizeof(*objattr) + (objattr->sd_len & ~1) + (objattr->name_len & ~1) + 3) & ~3 );
    }
    SERVER_LOG( LOG_ALWAYS, "}" );
}

static void dump_varargs_object_type_info( const char *prefix, data_size_t size )
{
    const struct object_type_info *info = cur_data;

    SERVER_LOG( LOG_ALWAYS, "%s{", prefix );
    if (size)
    {
        if (size < sizeof(*info) || (size - sizeof(*info) < info->name_len))
        {
            SERVER_LOG( LOG_ALWAYS, "***invalid***}" );
            remove_data( size );
            return;
        }

        SERVER_LOG( LOG_ALWAYS, "index=%u,obj_count=%u,handle_count=%u,obj_max=%u,handle_max=%u,valid=%08x",
                 info->index,info->obj_count, info->handle_count, info->obj_max, info->handle_max,
                 info->valid_access );
        dump_generic_map( ",access=", &info->mapping );
        SERVER_LOG( LOG_ALWAYS, ",name=L\"" );
        dump_strW( (const WCHAR *)(info + 1), info->name_len, stderr, "\"\"" );
        SERVER_LOG( LOG_ALWAYS, "\"" );
        remove_data( min( size, sizeof(*info) + ((info->name_len + 2) & ~3 )));
    }
    SERVER_LOG( LOG_ALWAYS, "}" );
}

static void dump_varargs_object_types_info( const char *prefix, data_size_t size )
{
    SERVER_LOG( LOG_ALWAYS, "%s{", prefix );
    while (cur_size) dump_varargs_object_type_info( ",", cur_size );
    SERVER_LOG( LOG_ALWAYS, "}" );
}

static void dump_varargs_filesystem_event( const char *prefix, data_size_t size )
{
    static const char * const actions[] = {
        NULL,
        "ADDED",
        "REMOVED",
        "MODIFIED",
        "RENAMED_OLD_NAME",
        "RENAMED_NEW_NAME",
        "ADDED_STREAM",
        "REMOVED_STREAM",
        "MODIFIED_STREAM"
    };

    SERVER_LOG( LOG_ALWAYS, "%s{", prefix );
    while (size)
    {
        const struct filesystem_event *event = cur_data;
        data_size_t len = (offsetof( struct filesystem_event, name[event->len] ) + sizeof(int)-1)
                           / sizeof(int) * sizeof(int);
        if (size < len) break;
        if (event->action < ARRAY_SIZE( actions ) && actions[event->action])
            SERVER_LOG( LOG_ALWAYS, "{action=%s", actions[event->action] );
        else
            SERVER_LOG( LOG_ALWAYS, "{action=%u", event->action );
        SERVER_LOG( LOG_ALWAYS, ",name=\"%.*s\"}", event->len, event->name );
        size -= len;
        remove_data( len );
        if (size)SERVER_LOG( LOG_ALWAYS, "," );
    }
    SERVER_LOG( LOG_ALWAYS, "}" );
}

static void dump_varargs_pe_image_info( const char *prefix, data_size_t size )
{
    pe_image_info_t info;

    if (!size)
    {
        SERVER_LOG( LOG_ALWAYS, "%s{}", prefix );
        return;
    }
    memset( &info, 0, sizeof(info) );
    memcpy( &info, cur_data, min( size, sizeof(info) ));

    SERVER_LOG( LOG_ALWAYS, "%s{", prefix );
    dump_uint64( "base=", &info.base );
    dump_uint64( ",stack_size=", &info.stack_size );
    dump_uint64( ",stack_commit=", &info.stack_commit );
    SERVER_LOG( LOG_ALWAYS, ",entry_point=%08x,map_size=%08x,zerobits=%08x,subsystem=%08x,subsystem_minor=%04x,subsystem_major=%04x"
             ",osversion_major=%04x,osversion_minor=%04x,image_charact=%04x,dll_charact=%04x,machine=%04x"
             ",contains_code=%u,image_flags=%02x"
             ",loader_flags=%08x,header_size=%08x,file_size=%08x,checksum=%08x}",
             info.entry_point, info.map_size, info.zerobits, info.subsystem, info.subsystem_minor,
             info.subsystem_major, info.osversion_major, info.osversion_minor, info.image_charact,
             info.dll_charact, info.machine, info.contains_code, info.image_flags, info.loader_flags,
             info.header_size, info.file_size, info.checksum );
    remove_data( min( size, sizeof(info) ));
}

static void dump_varargs_rawinput_devices(const char *prefix, data_size_t size )
{
    const struct rawinput_device *device;

    SERVER_LOG( LOG_ALWAYS, "%s{", prefix );
    while (size >= sizeof(*device))
    {
        device = cur_data;
        SERVER_LOG( LOG_ALWAYS, "{usage_page=%04x,usage=%04x,flags=%08x,target=%08x}",
                 device->usage_page, device->usage, device->flags, device->target );
        size -= sizeof(*device);
        remove_data( sizeof(*device) );
        if (size) SERVER_LOG( LOG_ALWAYS, "," );
    }
    SERVER_LOG( LOG_ALWAYS, "}" );
}

static void dump_varargs_handle_infos( const char *prefix, data_size_t size )
{
    const struct handle_info *handle;

    SERVER_LOG( LOG_ALWAYS, "%s{", prefix );
    while (size >= sizeof(*handle))
    {
        handle = cur_data;
        SERVER_LOG( LOG_ALWAYS, "{owner=%04x,handle=%04x,access=%08x,attributes=%08x,type=%u}",
                 handle->owner, handle->handle, handle->access, handle->attributes, handle->type );
        size -= sizeof(*handle);
        remove_data( sizeof(*handle) );
        if (size) SERVER_LOG( LOG_ALWAYS, "," );
    }
    SERVER_LOG( LOG_ALWAYS, "}" );
}

static void dump_varargs_cpu_topology_override( const char *prefix, data_size_t size )
{
    const struct cpu_topology_override *cpu_topology = cur_data;
    unsigned int i;

    if (size < sizeof(*cpu_topology))
        return;

    SERVER_LOG( LOG_ALWAYS, "%s{", prefix );
    for (i = 0; i < cpu_topology->cpu_count; ++i)
    {
        if (i) SERVER_LOG( LOG_ALWAYS, "," );
        SERVER_LOG( LOG_ALWAYS, "%u", cpu_topology->host_cpu_id[i] );
    }
    SERVER_LOG( LOG_ALWAYS, "}" );
    remove_data( size );
}

typedef void (*dump_func)( const void *req );

/* Everything below this line is generated automatically by tools/make_requests */
/* ### make_requests begin ### */

static void dump_new_process_request( const struct new_process_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " token=%04x", req->token );
    SERVER_LOG( LOG_ALWAYS, ", debug=%04x", req->debug );
    SERVER_LOG( LOG_ALWAYS, ", parent_process=%04x", req->parent_process );
    SERVER_LOG( LOG_ALWAYS, ", flags=%08x", req->flags );
    SERVER_LOG( LOG_ALWAYS, ", socket_fd=%d", req->socket_fd );
    SERVER_LOG( LOG_ALWAYS, ", access=%08x", req->access );
    SERVER_LOG( LOG_ALWAYS, ", machine=%04x", req->machine );
    SERVER_LOG( LOG_ALWAYS, ", info_size=%u", req->info_size );
    SERVER_LOG( LOG_ALWAYS, ", handles_size=%u", req->handles_size );
    SERVER_LOG( LOG_ALWAYS, ", jobs_size=%u", req->jobs_size );
    dump_varargs_object_attributes( ", objattr=", cur_size );
    dump_varargs_uints( ", handles=", min(cur_size,req->handles_size) );
    dump_varargs_uints( ", jobs=", min(cur_size,req->jobs_size) );
    dump_varargs_startup_info( ", info=", min(cur_size,req->info_size) );
    dump_varargs_unicode_str( ", env=", cur_size );
}

static void dump_new_process_reply( const struct new_process_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " info=%04x", req->info );
    SERVER_LOG( LOG_ALWAYS, ", pid=%04x", req->pid );
    SERVER_LOG( LOG_ALWAYS, ", handle=%04x", req->handle );
}

static void dump_get_new_process_info_request( const struct get_new_process_info_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " info=%04x", req->info );
}

static void dump_get_new_process_info_reply( const struct get_new_process_info_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " success=%d", req->success );
    SERVER_LOG( LOG_ALWAYS, ", exit_code=%d", req->exit_code );
}

static void dump_new_thread_request( const struct new_thread_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " process=%04x", req->process );
    SERVER_LOG( LOG_ALWAYS, ", access=%08x", req->access );
    SERVER_LOG( LOG_ALWAYS, ", flags=%08x", req->flags );
    SERVER_LOG( LOG_ALWAYS, ", request_fd=%d", req->request_fd );
    dump_varargs_object_attributes( ", objattr=", cur_size );
}

static void dump_new_thread_reply( const struct new_thread_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " tid=%04x", req->tid );
    SERVER_LOG( LOG_ALWAYS, ", handle=%04x", req->handle );
}

static void dump_get_startup_info_request( const struct get_startup_info_request *req )
{
}

static void dump_get_startup_info_reply( const struct get_startup_info_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " info_size=%u", req->info_size );
    dump_varargs_startup_info( ", info=", min(cur_size,req->info_size) );
    dump_varargs_unicode_str( ", env=", cur_size );
}

static void dump_init_process_done_request( const struct init_process_done_request *req )
{
    dump_uint64( " teb=", &req->teb );
    dump_uint64( ", peb=", &req->peb );
    dump_uint64( ", ldt_copy=", &req->ldt_copy );
}

static void dump_init_process_done_reply( const struct init_process_done_reply *req )
{
    dump_uint64( " entry=", &req->entry );
    dump_varargs_cpu_topology_override( ", cpu_override=", cur_size );
    SERVER_LOG( LOG_ALWAYS, ", suspend=%d", req->suspend );
}

static void dump_init_first_thread_request( const struct init_first_thread_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " unix_pid=%d", req->unix_pid );
    SERVER_LOG( LOG_ALWAYS, ", unix_tid=%d", req->unix_tid );
    SERVER_LOG( LOG_ALWAYS, ", debug_log_level=%d", req->debug_log_level );
    SERVER_LOG( LOG_ALWAYS, ", reply_fd=%d", req->reply_fd );
    SERVER_LOG( LOG_ALWAYS, ", wait_fd=%d", req->wait_fd );
}

static void dump_init_first_thread_reply( const struct init_first_thread_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " pid=%04x", req->pid );
    SERVER_LOG( LOG_ALWAYS, ", tid=%04x", req->tid );
    dump_timeout( ", server_start=", &req->server_start );
    SERVER_LOG( LOG_ALWAYS, ", session_id=%08x", req->session_id );
    SERVER_LOG( LOG_ALWAYS, ", info_size=%u", req->info_size );
    dump_varargs_ushorts( ", machines=", cur_size );
}

static void dump_init_thread_request( const struct init_thread_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " unix_tid=%d", req->unix_tid );
    SERVER_LOG( LOG_ALWAYS, ", reply_fd=%d", req->reply_fd );
    SERVER_LOG( LOG_ALWAYS, ", wait_fd=%d", req->wait_fd );
    dump_uint64( ", teb=", &req->teb );
    dump_uint64( ", entry=", &req->entry );
}

static void dump_init_thread_reply( const struct init_thread_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " suspend=%d", req->suspend );
}

static void dump_terminate_process_request( const struct terminate_process_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%04x", req->handle );
    SERVER_LOG( LOG_ALWAYS, ", exit_code=%d", req->exit_code );
}

static void dump_terminate_process_reply( const struct terminate_process_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " self=%d", req->self );
}

static void dump_terminate_thread_request( const struct terminate_thread_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%04x", req->handle );
    SERVER_LOG( LOG_ALWAYS, ", exit_code=%d", req->exit_code );
}

static void dump_terminate_thread_reply( const struct terminate_thread_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " self=%d", req->self );
}

static void dump_get_process_info_request( const struct get_process_info_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%04x", req->handle );
}

static void dump_get_process_info_reply( const struct get_process_info_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " pid=%04x", req->pid );
    SERVER_LOG( LOG_ALWAYS, ", ppid=%04x", req->ppid );
    dump_uint64( ", affinity=", &req->affinity );
    dump_uint64( ", peb=", &req->peb );
    dump_timeout( ", start_time=", &req->start_time );
    dump_timeout( ", end_time=", &req->end_time );
    SERVER_LOG( LOG_ALWAYS, ", session_id=%08x", req->session_id );
    SERVER_LOG( LOG_ALWAYS, ", exit_code=%d", req->exit_code );
    SERVER_LOG( LOG_ALWAYS, ", priority=%d", req->priority );
    SERVER_LOG( LOG_ALWAYS, ", machine=%04x", req->machine );
    dump_varargs_pe_image_info( ", image=", cur_size );
}

static void dump_get_process_debug_info_request( const struct get_process_debug_info_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%04x", req->handle );
}

static void dump_get_process_debug_info_reply( const struct get_process_debug_info_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " debug=%04x", req->debug );
    SERVER_LOG( LOG_ALWAYS, ", debug_children=%d", req->debug_children );
    dump_varargs_pe_image_info( ", image=", cur_size );
}

static void dump_get_process_image_name_request( const struct get_process_image_name_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%04x", req->handle );
    SERVER_LOG( LOG_ALWAYS, ", win32=%d", req->win32 );
}

static void dump_get_process_image_name_reply( const struct get_process_image_name_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " len=%u", req->len );
    dump_varargs_unicode_str( ", name=", cur_size );
}

static void dump_get_process_vm_counters_request( const struct get_process_vm_counters_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%04x", req->handle );
}

static void dump_get_process_vm_counters_reply( const struct get_process_vm_counters_reply *req )
{
    dump_uint64( " peak_virtual_size=", &req->peak_virtual_size );
    dump_uint64( ", virtual_size=", &req->virtual_size );
    dump_uint64( ", peak_working_set_size=", &req->peak_working_set_size );
    dump_uint64( ", working_set_size=", &req->working_set_size );
    dump_uint64( ", pagefile_usage=", &req->pagefile_usage );
    dump_uint64( ", peak_pagefile_usage=", &req->peak_pagefile_usage );
}

static void dump_set_process_info_request( const struct set_process_info_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%04x", req->handle );
    SERVER_LOG( LOG_ALWAYS, ", mask=%d", req->mask );
    SERVER_LOG( LOG_ALWAYS, ", priority=%d", req->priority );
    dump_uint64( ", affinity=", &req->affinity );
}

static void dump_get_thread_info_request( const struct get_thread_info_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%04x", req->handle );
    SERVER_LOG( LOG_ALWAYS, ", access=%08x", req->access );
}

static void dump_get_thread_info_reply( const struct get_thread_info_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " pid=%04x", req->pid );
    SERVER_LOG( LOG_ALWAYS, ", tid=%04x", req->tid );
    dump_uint64( ", teb=", &req->teb );
    dump_uint64( ", entry_point=", &req->entry_point );
    dump_uint64( ", affinity=", &req->affinity );
    SERVER_LOG( LOG_ALWAYS, ", exit_code=%d", req->exit_code );
    SERVER_LOG( LOG_ALWAYS, ", priority=%d", req->priority );
    SERVER_LOG( LOG_ALWAYS, ", last=%d", req->last );
    SERVER_LOG( LOG_ALWAYS, ", suspend_count=%d", req->suspend_count );
    SERVER_LOG( LOG_ALWAYS, ", dbg_hidden=%d", req->dbg_hidden );
    SERVER_LOG( LOG_ALWAYS, ", desc_len=%u", req->desc_len );
    dump_varargs_unicode_str( ", desc=", cur_size );
}

static void dump_get_thread_times_request( const struct get_thread_times_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%04x", req->handle );
}

static void dump_get_thread_times_reply( const struct get_thread_times_reply *req )
{
    dump_timeout( " creation_time=", &req->creation_time );
    dump_timeout( ", exit_time=", &req->exit_time );
    SERVER_LOG( LOG_ALWAYS, ", unix_pid=%d", req->unix_pid );
    SERVER_LOG( LOG_ALWAYS, ", unix_tid=%d", req->unix_tid );
}

static void dump_set_thread_info_request( const struct set_thread_info_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%04x", req->handle );
    SERVER_LOG( LOG_ALWAYS, ", mask=%d", req->mask );
    SERVER_LOG( LOG_ALWAYS, ", priority=%d", req->priority );
    dump_uint64( ", affinity=", &req->affinity );
    dump_uint64( ", entry_point=", &req->entry_point );
    SERVER_LOG( LOG_ALWAYS, ", token=%04x", req->token );
    dump_varargs_unicode_str( ", desc=", cur_size );
}

static void dump_suspend_thread_request( const struct suspend_thread_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%04x", req->handle );
}

static void dump_suspend_thread_reply( const struct suspend_thread_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " count=%d", req->count );
}

static void dump_resume_thread_request( const struct resume_thread_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%04x", req->handle );
}

static void dump_resume_thread_reply( const struct resume_thread_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " count=%d", req->count );
}

static void dump_queue_apc_request( const struct queue_apc_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%04x", req->handle );
    dump_apc_call( ", call=", &req->call );
}

static void dump_queue_apc_reply( const struct queue_apc_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%04x", req->handle );
    SERVER_LOG( LOG_ALWAYS, ", self=%d", req->self );
}

static void dump_get_apc_result_request( const struct get_apc_result_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%04x", req->handle );
}

static void dump_get_apc_result_reply( const struct get_apc_result_reply *req )
{
    dump_apc_result( " result=", &req->result );
}

static void dump_close_handle_request( const struct close_handle_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%04x", req->handle );
}

static void dump_set_handle_info_request( const struct set_handle_info_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%04x", req->handle );
    SERVER_LOG( LOG_ALWAYS, ", flags=%d", req->flags );
    SERVER_LOG( LOG_ALWAYS, ", mask=%d", req->mask );
}

static void dump_set_handle_info_reply( const struct set_handle_info_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " old_flags=%d", req->old_flags );
}

static void dump_dup_handle_request( const struct dup_handle_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " src_process=%04x", req->src_process );
    SERVER_LOG( LOG_ALWAYS, ", src_handle=%04x", req->src_handle );
    SERVER_LOG( LOG_ALWAYS, ", dst_process=%04x", req->dst_process );
    SERVER_LOG( LOG_ALWAYS, ", access=%08x", req->access );
    SERVER_LOG( LOG_ALWAYS, ", attributes=%08x", req->attributes );
    SERVER_LOG( LOG_ALWAYS, ", options=%08x", req->options );
}

static void dump_dup_handle_reply( const struct dup_handle_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%04x", req->handle );
}

static void dump_compare_objects_request( const struct compare_objects_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " first=%04x", req->first );
    SERVER_LOG( LOG_ALWAYS, ", second=%04x", req->second );
}

static void dump_make_temporary_request( const struct make_temporary_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%04x", req->handle );
}

static void dump_open_process_request( const struct open_process_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " pid=%04x", req->pid );
    SERVER_LOG( LOG_ALWAYS, ", access=%08x", req->access );
    SERVER_LOG( LOG_ALWAYS, ", attributes=%08x", req->attributes );
}

static void dump_open_process_reply( const struct open_process_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%04x", req->handle );
}

static void dump_open_thread_request( const struct open_thread_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " tid=%04x", req->tid );
    SERVER_LOG( LOG_ALWAYS, ", access=%08x", req->access );
    SERVER_LOG( LOG_ALWAYS, ", attributes=%08x", req->attributes );
}

static void dump_open_thread_reply( const struct open_thread_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%04x", req->handle );
}

static void dump_select_request( const struct select_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " flags=%d", req->flags );
    dump_uint64( ", cookie=", &req->cookie );
    dump_abstime( ", timeout=", &req->timeout );
    SERVER_LOG( LOG_ALWAYS, ", size=%u", req->size );
    SERVER_LOG( LOG_ALWAYS, ", prev_apc=%04x", req->prev_apc );
    dump_varargs_apc_result( ", result=", cur_size );
    dump_varargs_select_op( ", data=", min(cur_size,req->size) );
    dump_varargs_contexts( ", contexts=", cur_size );
}

static void dump_select_reply( const struct select_reply *req )
{
    dump_apc_call( " call=", &req->call );
    SERVER_LOG( LOG_ALWAYS, ", apc_handle=%04x", req->apc_handle );
    SERVER_LOG( LOG_ALWAYS, ", signaled=%d", req->signaled );
    dump_varargs_contexts( ", contexts=", cur_size );
}

static void dump_create_event_request( const struct create_event_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " access=%08x", req->access );
    SERVER_LOG( LOG_ALWAYS, ", manual_reset=%d", req->manual_reset );
    SERVER_LOG( LOG_ALWAYS, ", initial_state=%d", req->initial_state );
    dump_varargs_object_attributes( ", objattr=", cur_size );
}

static void dump_create_event_reply( const struct create_event_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%04x", req->handle );
}

static void dump_event_op_request( const struct event_op_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%04x", req->handle );
    SERVER_LOG( LOG_ALWAYS, ", op=%d", req->op );
}

static void dump_event_op_reply( const struct event_op_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " state=%d", req->state );
}

static void dump_query_event_request( const struct query_event_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%04x", req->handle );
}

static void dump_query_event_reply( const struct query_event_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " manual_reset=%d", req->manual_reset );
    SERVER_LOG( LOG_ALWAYS, ", state=%d", req->state );
}

static void dump_open_event_request( const struct open_event_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " access=%08x", req->access );
    SERVER_LOG( LOG_ALWAYS, ", attributes=%08x", req->attributes );
    SERVER_LOG( LOG_ALWAYS, ", rootdir=%04x", req->rootdir );
    dump_varargs_unicode_str( ", name=", cur_size );
}

static void dump_open_event_reply( const struct open_event_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%04x", req->handle );
}

static void dump_create_keyed_event_request( const struct create_keyed_event_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " access=%08x", req->access );
    dump_varargs_object_attributes( ", objattr=", cur_size );
}

static void dump_create_keyed_event_reply( const struct create_keyed_event_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%04x", req->handle );
}

static void dump_open_keyed_event_request( const struct open_keyed_event_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " access=%08x", req->access );
    SERVER_LOG( LOG_ALWAYS, ", attributes=%08x", req->attributes );
    SERVER_LOG( LOG_ALWAYS, ", rootdir=%04x", req->rootdir );
    dump_varargs_unicode_str( ", name=", cur_size );
}

static void dump_open_keyed_event_reply( const struct open_keyed_event_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%04x", req->handle );
}

static void dump_create_mutex_request( const struct create_mutex_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " access=%08x", req->access );
    SERVER_LOG( LOG_ALWAYS, ", owned=%d", req->owned );
    dump_varargs_object_attributes( ", objattr=", cur_size );
}

static void dump_create_mutex_reply( const struct create_mutex_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%04x", req->handle );
}

static void dump_release_mutex_request( const struct release_mutex_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%04x", req->handle );
}

static void dump_release_mutex_reply( const struct release_mutex_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " prev_count=%08x", req->prev_count );
}

static void dump_open_mutex_request( const struct open_mutex_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " access=%08x", req->access );
    SERVER_LOG( LOG_ALWAYS, ", attributes=%08x", req->attributes );
    SERVER_LOG( LOG_ALWAYS, ", rootdir=%04x", req->rootdir );
    dump_varargs_unicode_str( ", name=", cur_size );
}

static void dump_open_mutex_reply( const struct open_mutex_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%04x", req->handle );
}

static void dump_query_mutex_request( const struct query_mutex_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%04x", req->handle );
}

static void dump_query_mutex_reply( const struct query_mutex_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " count=%08x", req->count );
    SERVER_LOG( LOG_ALWAYS, ", owned=%d", req->owned );
    SERVER_LOG( LOG_ALWAYS, ", abandoned=%d", req->abandoned );
}

static void dump_create_semaphore_request( const struct create_semaphore_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " access=%08x", req->access );
    SERVER_LOG( LOG_ALWAYS, ", initial=%08x", req->initial );
    SERVER_LOG( LOG_ALWAYS, ", max=%08x", req->max );
    dump_varargs_object_attributes( ", objattr=", cur_size );
}

static void dump_create_semaphore_reply( const struct create_semaphore_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%04x", req->handle );
}

static void dump_release_semaphore_request( const struct release_semaphore_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%04x", req->handle );
    SERVER_LOG( LOG_ALWAYS, ", count=%08x", req->count );
}

static void dump_release_semaphore_reply( const struct release_semaphore_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " prev_count=%08x", req->prev_count );
}

static void dump_query_semaphore_request( const struct query_semaphore_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%04x", req->handle );
}

static void dump_query_semaphore_reply( const struct query_semaphore_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " current=%08x", req->current );
    SERVER_LOG( LOG_ALWAYS, ", max=%08x", req->max );
}

static void dump_open_semaphore_request( const struct open_semaphore_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " access=%08x", req->access );
    SERVER_LOG( LOG_ALWAYS, ", attributes=%08x", req->attributes );
    SERVER_LOG( LOG_ALWAYS, ", rootdir=%04x", req->rootdir );
    dump_varargs_unicode_str( ", name=", cur_size );
}

static void dump_open_semaphore_reply( const struct open_semaphore_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%04x", req->handle );
}

static void dump_create_file_request( const struct create_file_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " access=%08x", req->access );
    SERVER_LOG( LOG_ALWAYS, ", sharing=%08x", req->sharing );
    SERVER_LOG( LOG_ALWAYS, ", create=%d", req->create );
    SERVER_LOG( LOG_ALWAYS, ", options=%08x", req->options );
    SERVER_LOG( LOG_ALWAYS, ", attrs=%08x", req->attrs );
    dump_varargs_object_attributes( ", objattr=", cur_size );
    dump_varargs_string( ", filename=", cur_size );
}

static void dump_create_file_reply( const struct create_file_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%04x", req->handle );
}

static void dump_open_file_object_request( const struct open_file_object_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " access=%08x", req->access );
    SERVER_LOG( LOG_ALWAYS, ", attributes=%08x", req->attributes );
    SERVER_LOG( LOG_ALWAYS, ", rootdir=%04x", req->rootdir );
    SERVER_LOG( LOG_ALWAYS, ", sharing=%08x", req->sharing );
    SERVER_LOG( LOG_ALWAYS, ", options=%08x", req->options );
    dump_varargs_unicode_str( ", filename=", cur_size );
}

static void dump_open_file_object_reply( const struct open_file_object_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%04x", req->handle );
}

static void dump_alloc_file_handle_request( const struct alloc_file_handle_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " access=%08x", req->access );
    SERVER_LOG( LOG_ALWAYS, ", attributes=%08x", req->attributes );
    SERVER_LOG( LOG_ALWAYS, ", fd=%d", req->fd );
}

static void dump_alloc_file_handle_reply( const struct alloc_file_handle_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%04x", req->handle );
}

static void dump_get_handle_unix_name_request( const struct get_handle_unix_name_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%04x", req->handle );
}

static void dump_get_handle_unix_name_reply( const struct get_handle_unix_name_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " name_len=%u", req->name_len );
    dump_varargs_string( ", name=", cur_size );
}

static void dump_get_handle_fd_request( const struct get_handle_fd_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%04x", req->handle );
}

static void dump_get_handle_fd_reply( const struct get_handle_fd_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " type=%d", req->type );
    SERVER_LOG( LOG_ALWAYS, ", cacheable=%d", req->cacheable );
    SERVER_LOG( LOG_ALWAYS, ", access=%08x", req->access );
    SERVER_LOG( LOG_ALWAYS, ", options=%08x", req->options );
}

static void dump_get_directory_cache_entry_request( const struct get_directory_cache_entry_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%04x", req->handle );
}

static void dump_get_directory_cache_entry_reply( const struct get_directory_cache_entry_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " entry=%d", req->entry );
    dump_varargs_ints( ", free=", cur_size );
}

static void dump_flush_request( const struct flush_request *req )
{
    dump_async_data( " async=", &req->async );
}

static void dump_flush_reply( const struct flush_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " event=%04x", req->event );
}

static void dump_get_file_info_request( const struct get_file_info_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%04x", req->handle );
    SERVER_LOG( LOG_ALWAYS, ", info_class=%08x", req->info_class );
}

static void dump_get_file_info_reply( const struct get_file_info_reply *req )
{
    dump_varargs_bytes( " data=", cur_size );
}

static void dump_get_volume_info_request( const struct get_volume_info_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%04x", req->handle );
    dump_async_data( ", async=", &req->async );
    SERVER_LOG( LOG_ALWAYS, ", info_class=%08x", req->info_class );
}

static void dump_get_volume_info_reply( const struct get_volume_info_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " wait=%04x", req->wait );
    dump_varargs_bytes( ", data=", cur_size );
}

static void dump_lock_file_request( const struct lock_file_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%04x", req->handle );
    dump_uint64( ", offset=", &req->offset );
    dump_uint64( ", count=", &req->count );
    SERVER_LOG( LOG_ALWAYS, ", shared=%d", req->shared );
    SERVER_LOG( LOG_ALWAYS, ", wait=%d", req->wait );
}

static void dump_lock_file_reply( const struct lock_file_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%04x", req->handle );
    SERVER_LOG( LOG_ALWAYS, ", overlapped=%d", req->overlapped );
}

static void dump_unlock_file_request( const struct unlock_file_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%04x", req->handle );
    dump_uint64( ", offset=", &req->offset );
    dump_uint64( ", count=", &req->count );
}

static void dump_recv_socket_request( const struct recv_socket_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " oob=%d", req->oob );
    dump_async_data( ", async=", &req->async );
    SERVER_LOG( LOG_ALWAYS, ", status=%08x", req->status );
    SERVER_LOG( LOG_ALWAYS, ", total=%08x", req->total );
}

static void dump_recv_socket_reply( const struct recv_socket_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " wait=%04x", req->wait );
    SERVER_LOG( LOG_ALWAYS, ", options=%08x", req->options );
}

static void dump_send_socket_request( const struct send_socket_request *req )
{
    dump_async_data( " async=", &req->async );
    SERVER_LOG( LOG_ALWAYS, ", status=%08x", req->status );
    SERVER_LOG( LOG_ALWAYS, ", total=%08x", req->total );
}

static void dump_send_socket_reply( const struct send_socket_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " wait=%04x", req->wait );
    SERVER_LOG( LOG_ALWAYS, ", options=%08x", req->options );
}

static void dump_get_next_console_request_request( const struct get_next_console_request_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%04x", req->handle );
    SERVER_LOG( LOG_ALWAYS, ", signal=%d", req->signal );
    SERVER_LOG( LOG_ALWAYS, ", read=%d", req->read );
    SERVER_LOG( LOG_ALWAYS, ", status=%08x", req->status );
    dump_varargs_bytes( ", out_data=", cur_size );
}

static void dump_get_next_console_request_reply( const struct get_next_console_request_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " code=%08x", req->code );
    SERVER_LOG( LOG_ALWAYS, ", output=%08x", req->output );
    SERVER_LOG( LOG_ALWAYS, ", out_size=%u", req->out_size );
    dump_varargs_bytes( ", in_data=", cur_size );
}

static void dump_read_directory_changes_request( const struct read_directory_changes_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " filter=%08x", req->filter );
    SERVER_LOG( LOG_ALWAYS, ", subtree=%d", req->subtree );
    SERVER_LOG( LOG_ALWAYS, ", want_data=%d", req->want_data );
    dump_async_data( ", async=", &req->async );
}

static void dump_read_change_request( const struct read_change_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%04x", req->handle );
}

static void dump_read_change_reply( const struct read_change_reply *req )
{
    dump_varargs_filesystem_event( " events=", cur_size );
}

static void dump_create_mapping_request( const struct create_mapping_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " access=%08x", req->access );
    SERVER_LOG( LOG_ALWAYS, ", flags=%08x", req->flags );
    SERVER_LOG( LOG_ALWAYS, ", file_access=%08x", req->file_access );
    dump_uint64( ", size=", &req->size );
    SERVER_LOG( LOG_ALWAYS, ", file_handle=%04x", req->file_handle );
    dump_varargs_object_attributes( ", objattr=", cur_size );
}

static void dump_create_mapping_reply( const struct create_mapping_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%04x", req->handle );
}

static void dump_open_mapping_request( const struct open_mapping_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " access=%08x", req->access );
    SERVER_LOG( LOG_ALWAYS, ", attributes=%08x", req->attributes );
    SERVER_LOG( LOG_ALWAYS, ", rootdir=%04x", req->rootdir );
    dump_varargs_unicode_str( ", name=", cur_size );
}

static void dump_open_mapping_reply( const struct open_mapping_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%04x", req->handle );
}

static void dump_get_mapping_info_request( const struct get_mapping_info_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%04x", req->handle );
    SERVER_LOG( LOG_ALWAYS, ", access=%08x", req->access );
}

static void dump_get_mapping_info_reply( const struct get_mapping_info_reply *req )
{
    dump_uint64( " size=", &req->size );
    SERVER_LOG( LOG_ALWAYS, ", flags=%08x", req->flags );
    SERVER_LOG( LOG_ALWAYS, ", shared_file=%04x", req->shared_file );
    SERVER_LOG( LOG_ALWAYS, ", total=%u", req->total );
    dump_varargs_pe_image_info( ", image=", cur_size );
    dump_varargs_unicode_str( ", name=", cur_size );
}

static void dump_map_view_request( const struct map_view_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " mapping=%04x", req->mapping );
    SERVER_LOG( LOG_ALWAYS, ", access=%08x", req->access );
    dump_uint64( ", base=", &req->base );
    dump_uint64( ", size=", &req->size );
    dump_uint64( ", start=", &req->start );
    dump_varargs_pe_image_info( ", image=", cur_size );
    dump_varargs_unicode_str( ", name=", cur_size );
}

static void dump_unmap_view_request( const struct unmap_view_request *req )
{
    dump_uint64( " base=", &req->base );
}

static void dump_get_mapping_committed_range_request( const struct get_mapping_committed_range_request *req )
{
    dump_uint64( " base=", &req->base );
    dump_uint64( ", offset=", &req->offset );
}

static void dump_get_mapping_committed_range_reply( const struct get_mapping_committed_range_reply *req )
{
    dump_uint64( " size=", &req->size );
    SERVER_LOG( LOG_ALWAYS, ", committed=%d", req->committed );
}

static void dump_add_mapping_committed_range_request( const struct add_mapping_committed_range_request *req )
{
    dump_uint64( " base=", &req->base );
    dump_uint64( ", offset=", &req->offset );
    dump_uint64( ", size=", &req->size );
}

static void dump_is_same_mapping_request( const struct is_same_mapping_request *req )
{
    dump_uint64( " base1=", &req->base1 );
    dump_uint64( ", base2=", &req->base2 );
}

static void dump_get_mapping_filename_request( const struct get_mapping_filename_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " process=%04x", req->process );
    dump_uint64( ", addr=", &req->addr );
}

static void dump_get_mapping_filename_reply( const struct get_mapping_filename_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " len=%u", req->len );
    dump_varargs_unicode_str( ", filename=", cur_size );
}

static void dump_list_processes_request( const struct list_processes_request *req )
{
}

static void dump_list_processes_reply( const struct list_processes_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " info_size=%u", req->info_size );
    SERVER_LOG( LOG_ALWAYS, ", process_count=%d", req->process_count );
    SERVER_LOG( LOG_ALWAYS, ", total_thread_count=%d", req->total_thread_count );
    SERVER_LOG( LOG_ALWAYS, ", total_name_len=%u", req->total_name_len );
    dump_varargs_process_info( ", data=", min(cur_size,req->info_size) );
}

static void dump_create_debug_obj_request( const struct create_debug_obj_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " access=%08x", req->access );
    SERVER_LOG( LOG_ALWAYS, ", flags=%08x", req->flags );
    dump_varargs_object_attributes( ", objattr=", cur_size );
}

static void dump_create_debug_obj_reply( const struct create_debug_obj_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%04x", req->handle );
}

static void dump_wait_debug_event_request( const struct wait_debug_event_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " debug=%04x", req->debug );
}

static void dump_wait_debug_event_reply( const struct wait_debug_event_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " pid=%04x", req->pid );
    SERVER_LOG( LOG_ALWAYS, ", tid=%04x", req->tid );
    dump_varargs_debug_event( ", event=", cur_size );
}

static void dump_queue_exception_event_request( const struct queue_exception_event_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " first=%d", req->first );
    SERVER_LOG( LOG_ALWAYS, ", code=%08x", req->code );
    SERVER_LOG( LOG_ALWAYS, ", flags=%08x", req->flags );
    dump_uint64( ", record=", &req->record );
    dump_uint64( ", address=", &req->address );
    SERVER_LOG( LOG_ALWAYS, ", len=%u", req->len );
    dump_varargs_uints64( ", params=", min(cur_size,req->len) );
}

static void dump_queue_exception_event_reply( const struct queue_exception_event_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%04x", req->handle );
}

static void dump_get_exception_status_request( const struct get_exception_status_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%04x", req->handle );
}

static void dump_continue_debug_event_request( const struct continue_debug_event_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " debug=%04x", req->debug );
    SERVER_LOG( LOG_ALWAYS, ", pid=%04x", req->pid );
    SERVER_LOG( LOG_ALWAYS, ", tid=%04x", req->tid );
    SERVER_LOG( LOG_ALWAYS, ", status=%08x", req->status );
}

static void dump_debug_process_request( const struct debug_process_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%04x", req->handle );
    SERVER_LOG( LOG_ALWAYS, ", debug=%04x", req->debug );
    SERVER_LOG( LOG_ALWAYS, ", attach=%d", req->attach );
}

static void dump_set_debug_obj_info_request( const struct set_debug_obj_info_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " debug=%04x", req->debug );
    SERVER_LOG( LOG_ALWAYS, ", flags=%08x", req->flags );
}

static void dump_read_process_memory_request( const struct read_process_memory_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%04x", req->handle );
    dump_uint64( ", addr=", &req->addr );
}

static void dump_read_process_memory_reply( const struct read_process_memory_reply *req )
{
    dump_varargs_bytes( " data=", cur_size );
}

static void dump_write_process_memory_request( const struct write_process_memory_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%04x", req->handle );
    dump_uint64( ", addr=", &req->addr );
    dump_varargs_bytes( ", data=", cur_size );
}

static void dump_create_key_request( const struct create_key_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " access=%08x", req->access );
    SERVER_LOG( LOG_ALWAYS, ", options=%08x", req->options );
    dump_varargs_object_attributes( ", objattr=", cur_size );
    dump_varargs_unicode_str( ", class=", cur_size );
}

static void dump_create_key_reply( const struct create_key_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " hkey=%04x", req->hkey );
    SERVER_LOG( LOG_ALWAYS, ", created=%d", req->created );
}

static void dump_open_key_request( const struct open_key_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " parent=%04x", req->parent );
    SERVER_LOG( LOG_ALWAYS, ", access=%08x", req->access );
    SERVER_LOG( LOG_ALWAYS, ", attributes=%08x", req->attributes );
    dump_varargs_unicode_str( ", name=", cur_size );
}

static void dump_open_key_reply( const struct open_key_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " hkey=%04x", req->hkey );
}

static void dump_delete_key_request( const struct delete_key_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " hkey=%04x", req->hkey );
}

static void dump_flush_key_request( const struct flush_key_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " hkey=%04x", req->hkey );
}

static void dump_enum_key_request( const struct enum_key_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " hkey=%04x", req->hkey );
    SERVER_LOG( LOG_ALWAYS, ", index=%d", req->index );
    SERVER_LOG( LOG_ALWAYS, ", info_class=%d", req->info_class );
}

static void dump_enum_key_reply( const struct enum_key_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " subkeys=%d", req->subkeys );
    SERVER_LOG( LOG_ALWAYS, ", max_subkey=%d", req->max_subkey );
    SERVER_LOG( LOG_ALWAYS, ", max_class=%d", req->max_class );
    SERVER_LOG( LOG_ALWAYS, ", values=%d", req->values );
    SERVER_LOG( LOG_ALWAYS, ", max_value=%d", req->max_value );
    SERVER_LOG( LOG_ALWAYS, ", max_data=%d", req->max_data );
    dump_timeout( ", modif=", &req->modif );
    SERVER_LOG( LOG_ALWAYS, ", total=%u", req->total );
    SERVER_LOG( LOG_ALWAYS, ", namelen=%u", req->namelen );
    dump_varargs_unicode_str( ", name=", min(cur_size,req->namelen) );
    dump_varargs_unicode_str( ", class=", cur_size );
}

static void dump_set_key_value_request( const struct set_key_value_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " hkey=%04x", req->hkey );
    SERVER_LOG( LOG_ALWAYS, ", type=%d", req->type );
    SERVER_LOG( LOG_ALWAYS, ", namelen=%u", req->namelen );
    dump_varargs_unicode_str( ", name=", min(cur_size,req->namelen) );
    dump_varargs_bytes( ", data=", cur_size );
}

static void dump_get_key_value_request( const struct get_key_value_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " hkey=%04x", req->hkey );
    dump_varargs_unicode_str( ", name=", cur_size );
}

static void dump_get_key_value_reply( const struct get_key_value_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " type=%d", req->type );
    SERVER_LOG( LOG_ALWAYS, ", total=%u", req->total );
    dump_varargs_bytes( ", data=", cur_size );
}

static void dump_enum_key_value_request( const struct enum_key_value_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " hkey=%04x", req->hkey );
    SERVER_LOG( LOG_ALWAYS, ", index=%d", req->index );
    SERVER_LOG( LOG_ALWAYS, ", info_class=%d", req->info_class );
}

static void dump_enum_key_value_reply( const struct enum_key_value_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " type=%d", req->type );
    SERVER_LOG( LOG_ALWAYS, ", total=%u", req->total );
    SERVER_LOG( LOG_ALWAYS, ", namelen=%u", req->namelen );
    dump_varargs_unicode_str( ", name=", min(cur_size,req->namelen) );
    dump_varargs_bytes( ", data=", cur_size );
}

static void dump_delete_key_value_request( const struct delete_key_value_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " hkey=%04x", req->hkey );
    dump_varargs_unicode_str( ", name=", cur_size );
}

static void dump_load_registry_request( const struct load_registry_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " file=%04x", req->file );
    dump_varargs_object_attributes( ", objattr=", cur_size );
}

static void dump_unload_registry_request( const struct unload_registry_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " parent=%04x", req->parent );
    SERVER_LOG( LOG_ALWAYS, ", attributes=%08x", req->attributes );
    dump_varargs_unicode_str( ", name=", cur_size );
}

static void dump_save_registry_request( const struct save_registry_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " hkey=%04x", req->hkey );
    SERVER_LOG( LOG_ALWAYS, ", file=%04x", req->file );
}

static void dump_set_registry_notification_request( const struct set_registry_notification_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " hkey=%04x", req->hkey );
    SERVER_LOG( LOG_ALWAYS, ", event=%04x", req->event );
    SERVER_LOG( LOG_ALWAYS, ", subtree=%d", req->subtree );
    SERVER_LOG( LOG_ALWAYS, ", filter=%08x", req->filter );
}

static void dump_create_timer_request( const struct create_timer_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " access=%08x", req->access );
    SERVER_LOG( LOG_ALWAYS, ", manual=%d", req->manual );
    dump_varargs_object_attributes( ", objattr=", cur_size );
}

static void dump_create_timer_reply( const struct create_timer_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%04x", req->handle );
}

static void dump_open_timer_request( const struct open_timer_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " access=%08x", req->access );
    SERVER_LOG( LOG_ALWAYS, ", attributes=%08x", req->attributes );
    SERVER_LOG( LOG_ALWAYS, ", rootdir=%04x", req->rootdir );
    dump_varargs_unicode_str( ", name=", cur_size );
}

static void dump_open_timer_reply( const struct open_timer_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%04x", req->handle );
}

static void dump_set_timer_request( const struct set_timer_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%04x", req->handle );
    dump_timeout( ", expire=", &req->expire );
    dump_uint64( ", callback=", &req->callback );
    dump_uint64( ", arg=", &req->arg );
    SERVER_LOG( LOG_ALWAYS, ", period=%d", req->period );
}

static void dump_set_timer_reply( const struct set_timer_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " signaled=%d", req->signaled );
}

static void dump_cancel_timer_request( const struct cancel_timer_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%04x", req->handle );
}

static void dump_cancel_timer_reply( const struct cancel_timer_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " signaled=%d", req->signaled );
}

static void dump_get_timer_info_request( const struct get_timer_info_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%04x", req->handle );
}

static void dump_get_timer_info_reply( const struct get_timer_info_reply *req )
{
    dump_timeout( " when=", &req->when );
    SERVER_LOG( LOG_ALWAYS, ", signaled=%d", req->signaled );
}

static void dump_get_thread_context_request( const struct get_thread_context_request *req )
{
    SERVER_LOG( LOG_ALWAYS," handle=%04x", req->handle );
    SERVER_LOG( LOG_ALWAYS,", context=%04x", req->context );
    SERVER_LOG( LOG_ALWAYS,", flags=%08x", req->flags );
    SERVER_LOG( LOG_ALWAYS,", machine=%04x", req->machine );
}

static void dump_get_thread_context_reply( const struct get_thread_context_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " self=%d", req->self );
    SERVER_LOG( LOG_ALWAYS, ", handle=%04x", req->handle );
    dump_varargs_contexts( ", contexts=", cur_size );
}

static void dump_set_thread_context_request( const struct set_thread_context_request *req )
{
    SERVER_LOG( LOG_ALWAYS," handle=%04x", req->handle );
    dump_varargs_contexts( ", contexts=", cur_size );
}

static void dump_set_thread_context_reply( const struct set_thread_context_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " self=%d", req->self );
}

static void dump_get_selector_entry_request( const struct get_selector_entry_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%04x", req->handle );
    SERVER_LOG( LOG_ALWAYS, ", entry=%d", req->entry );
}

static void dump_get_selector_entry_reply( const struct get_selector_entry_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " base=%08x", req->base );
    SERVER_LOG( LOG_ALWAYS, ", limit=%08x", req->limit );
    SERVER_LOG( LOG_ALWAYS, ", flags=%02x", req->flags );
}

static void dump_add_atom_request( const struct add_atom_request *req )
{
    dump_varargs_unicode_str( " name=", cur_size );
}

static void dump_add_atom_reply( const struct add_atom_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " atom=%04x", req->atom );
}

static void dump_delete_atom_request( const struct delete_atom_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " atom=%04x", req->atom );
}

static void dump_find_atom_request( const struct find_atom_request *req )
{
    dump_varargs_unicode_str( " name=", cur_size );
}

static void dump_find_atom_reply( const struct find_atom_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " atom=%04x", req->atom );
}

static void dump_get_atom_information_request( const struct get_atom_information_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " atom=%04x", req->atom );
}

static void dump_get_atom_information_reply( const struct get_atom_information_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " count=%d", req->count );
    SERVER_LOG( LOG_ALWAYS, ", pinned=%d", req->pinned );
    SERVER_LOG( LOG_ALWAYS, ", total=%u", req->total );
    dump_varargs_unicode_str( ", name=", cur_size );
}

static void dump_get_msg_queue_request( const struct get_msg_queue_request *req )
{
}

static void dump_get_msg_queue_reply( const struct get_msg_queue_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%04x", req->handle );
}

static void dump_set_queue_fd_request( const struct set_queue_fd_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%04x", req->handle );
}

static void dump_set_queue_mask_request( const struct set_queue_mask_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " wake_mask=%08x", req->wake_mask );
    SERVER_LOG( LOG_ALWAYS, ", changed_mask=%08x", req->changed_mask );
    SERVER_LOG( LOG_ALWAYS, ", skip_wait=%d", req->skip_wait );
}

static void dump_set_queue_mask_reply( const struct set_queue_mask_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " wake_bits=%08x", req->wake_bits );
    SERVER_LOG( LOG_ALWAYS, ", changed_bits=%08x", req->changed_bits );
}

static void dump_get_queue_status_request( const struct get_queue_status_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " clear_bits=%08x", req->clear_bits );
}

static void dump_get_queue_status_reply( const struct get_queue_status_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " wake_bits=%08x", req->wake_bits );
    SERVER_LOG( LOG_ALWAYS, ", changed_bits=%08x", req->changed_bits );
}

static void dump_get_process_idle_event_request( const struct get_process_idle_event_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%04x", req->handle );
}

static void dump_get_process_idle_event_reply( const struct get_process_idle_event_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " event=%04x", req->event );
}

static void dump_send_message_request( const struct send_message_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " id=%04x", req->id );
    SERVER_LOG( LOG_ALWAYS, ", type=%d", req->type );
    SERVER_LOG( LOG_ALWAYS, ", flags=%d", req->flags );
    SERVER_LOG( LOG_ALWAYS, ", win=%08x", req->win );
    SERVER_LOG( LOG_ALWAYS, ", msg=%08x", req->msg );
    dump_uint64( ", wparam=", &req->wparam );
    dump_uint64( ", lparam=", &req->lparam );
    dump_timeout( ", timeout=", &req->timeout );
    dump_varargs_message_data( ", data=", cur_size );
}

static void dump_post_quit_message_request( const struct post_quit_message_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " exit_code=%d", req->exit_code );
}

static void dump_send_hardware_message_request( const struct send_hardware_message_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " win=%08x", req->win );
    dump_hw_input( ", input=", &req->input );
    SERVER_LOG( LOG_ALWAYS, ", flags=%08x", req->flags );
    dump_varargs_bytes( ", report=", cur_size );
}

static void dump_send_hardware_message_reply( const struct send_hardware_message_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " wait=%d", req->wait );
    SERVER_LOG( LOG_ALWAYS, ", prev_x=%d", req->prev_x );
    SERVER_LOG( LOG_ALWAYS, ", prev_y=%d", req->prev_y );
    SERVER_LOG( LOG_ALWAYS, ", new_x=%d", req->new_x );
    SERVER_LOG( LOG_ALWAYS, ", new_y=%d", req->new_y );
    dump_varargs_bytes( ", keystate=", cur_size );
}

static void dump_get_message_request( const struct get_message_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " flags=%08x", req->flags );
    SERVER_LOG( LOG_ALWAYS, ", get_win=%08x", req->get_win );
    SERVER_LOG( LOG_ALWAYS, ", get_first=%08x", req->get_first );
    SERVER_LOG( LOG_ALWAYS, ", get_last=%08x", req->get_last );
    SERVER_LOG( LOG_ALWAYS, ", hw_id=%08x", req->hw_id );
    SERVER_LOG( LOG_ALWAYS, ", wake_mask=%08x", req->wake_mask );
    SERVER_LOG( LOG_ALWAYS, ", changed_mask=%08x", req->changed_mask );
}

static void dump_get_message_reply( const struct get_message_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " win=%08x", req->win );
    SERVER_LOG( LOG_ALWAYS, ", msg=%08x", req->msg );
    dump_uint64( ", wparam=", &req->wparam );
    dump_uint64( ", lparam=", &req->lparam );
    SERVER_LOG( LOG_ALWAYS, ", type=%d", req->type );
    SERVER_LOG( LOG_ALWAYS, ", x=%d", req->x );
    SERVER_LOG( LOG_ALWAYS, ", y=%d", req->y );
    SERVER_LOG( LOG_ALWAYS, ", time=%08x", req->time );
    SERVER_LOG( LOG_ALWAYS, ", active_hooks=%08x", req->active_hooks );
    SERVER_LOG( LOG_ALWAYS, ", total=%u", req->total );
    dump_varargs_message_data( ", data=", cur_size );
}

static void dump_reply_message_request( const struct reply_message_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " remove=%d", req->remove );
    dump_uint64( ", result=", &req->result );
    dump_varargs_bytes( ", data=", cur_size );
}

static void dump_accept_hardware_message_request( const struct accept_hardware_message_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " hw_id=%08x", req->hw_id );
}

static void dump_get_message_reply_request( const struct get_message_reply_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " cancel=%d", req->cancel );
}

static void dump_get_message_reply_reply( const struct get_message_reply_reply *req )
{
    dump_uint64( " result=", &req->result );
    dump_varargs_bytes( ", data=", cur_size );
}

static void dump_set_win_timer_request( const struct set_win_timer_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " win=%08x", req->win );
    SERVER_LOG( LOG_ALWAYS, ", msg=%08x", req->msg );
    SERVER_LOG( LOG_ALWAYS, ", rate=%08x", req->rate );
    dump_uint64( ", id=", &req->id );
    dump_uint64( ", lparam=", &req->lparam );
}

static void dump_set_win_timer_reply( const struct set_win_timer_reply *req )
{
    dump_uint64( " id=", &req->id );
}

static void dump_kill_win_timer_request( const struct kill_win_timer_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " win=%08x", req->win );
    dump_uint64( ", id=", &req->id );
    SERVER_LOG( LOG_ALWAYS, ", msg=%08x", req->msg );
}

static void dump_is_window_hung_request( const struct is_window_hung_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " win=%08x", req->win );
}

static void dump_is_window_hung_reply( const struct is_window_hung_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " is_hung=%d", req->is_hung );
}

static void dump_get_serial_info_request( const struct get_serial_info_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%04x", req->handle );
    SERVER_LOG( LOG_ALWAYS, ", flags=%d", req->flags );
}

static void dump_get_serial_info_reply( const struct get_serial_info_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " eventmask=%08x", req->eventmask );
    SERVER_LOG( LOG_ALWAYS, ", cookie=%08x", req->cookie );
    SERVER_LOG( LOG_ALWAYS, ", pending_write=%08x", req->pending_write );
}

static void dump_set_serial_info_request( const struct set_serial_info_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%04x", req->handle );
    SERVER_LOG( LOG_ALWAYS, ", flags=%d", req->flags );
}

static void dump_register_async_request( const struct register_async_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " type=%d", req->type );
    dump_async_data( ", async=", &req->async );
    SERVER_LOG( LOG_ALWAYS, ", count=%d", req->count );
}

static void dump_cancel_async_request( const struct cancel_async_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%04x", req->handle );
    dump_uint64( ", iosb=", &req->iosb );
    SERVER_LOG( LOG_ALWAYS, ", only_thread=%d", req->only_thread );
}

static void dump_get_async_result_request( const struct get_async_result_request *req )
{
    dump_uint64( " user_arg=", &req->user_arg );
}

static void dump_get_async_result_reply( const struct get_async_result_reply *req )
{
    dump_varargs_bytes( " out_data=", cur_size );
}

static void dump_read_request( const struct read_request *req )
{
    dump_async_data( " async=", &req->async );
    dump_uint64( ", pos=", &req->pos );
}

static void dump_read_reply( const struct read_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " wait=%04x", req->wait );
    SERVER_LOG( LOG_ALWAYS, ", options=%08x", req->options );
    dump_varargs_bytes( ", data=", cur_size );
}

static void dump_write_request( const struct write_request *req )
{
    dump_async_data( " async=", &req->async );
    dump_uint64( ", pos=", &req->pos );
    dump_varargs_bytes( ", data=", cur_size );
}

static void dump_write_reply( const struct write_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " wait=%04x", req->wait );
    SERVER_LOG( LOG_ALWAYS, ", options=%08x", req->options );
    SERVER_LOG( LOG_ALWAYS, ", size=%u", req->size );
}

static void dump_ioctl_request( const struct ioctl_request *req )
{
    dump_ioctl_code( " code=", &req->code );
    dump_async_data( ", async=", &req->async );
    dump_varargs_bytes( ", in_data=", cur_size );
}

static void dump_ioctl_reply( const struct ioctl_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " wait=%04x", req->wait );
    SERVER_LOG( LOG_ALWAYS, ", options=%08x", req->options );
    dump_varargs_bytes( ", out_data=", cur_size );
}

static void dump_set_irp_result_request( const struct set_irp_result_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%04x", req->handle );
    SERVER_LOG( LOG_ALWAYS, ", status=%08x", req->status );
    SERVER_LOG( LOG_ALWAYS, ", size=%u", req->size );
    dump_varargs_bytes( ", data=", cur_size );
}

static void dump_create_named_pipe_request( const struct create_named_pipe_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " access=%08x", req->access );
    SERVER_LOG( LOG_ALWAYS, ", options=%08x", req->options );
    SERVER_LOG( LOG_ALWAYS, ", sharing=%08x", req->sharing );
    SERVER_LOG( LOG_ALWAYS, ", maxinstances=%08x", req->maxinstances );
    SERVER_LOG( LOG_ALWAYS, ", outsize=%08x", req->outsize );
    SERVER_LOG( LOG_ALWAYS, ", insize=%08x", req->insize );
    dump_timeout( ", timeout=", &req->timeout );
    SERVER_LOG( LOG_ALWAYS, ", flags=%08x", req->flags );
    dump_varargs_object_attributes( ", objattr=", cur_size );
}

static void dump_create_named_pipe_reply( const struct create_named_pipe_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%04x", req->handle );
}

static void dump_set_named_pipe_info_request( const struct set_named_pipe_info_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%04x", req->handle );
    SERVER_LOG( LOG_ALWAYS, ", flags=%08x", req->flags );
}

static void dump_create_window_request( const struct create_window_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " parent=%08x", req->parent );
    SERVER_LOG( LOG_ALWAYS, ", owner=%08x", req->owner );
    SERVER_LOG( LOG_ALWAYS, ", atom=%04x", req->atom );
    dump_uint64( ", instance=", &req->instance );
    SERVER_LOG( LOG_ALWAYS, ", dpi=%d", req->dpi );
    SERVER_LOG( LOG_ALWAYS, ", awareness=%d", req->awareness );
    SERVER_LOG( LOG_ALWAYS, ", style=%08x", req->style );
    SERVER_LOG( LOG_ALWAYS, ", ex_style=%08x", req->ex_style );
    dump_varargs_unicode_str( ", class=", cur_size );
}

static void dump_create_window_reply( const struct create_window_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%08x", req->handle );
    SERVER_LOG( LOG_ALWAYS, ", parent=%08x", req->parent );
    SERVER_LOG( LOG_ALWAYS, ", owner=%08x", req->owner );
    SERVER_LOG( LOG_ALWAYS, ", extra=%d", req->extra );
    dump_uint64( ", class_ptr=", &req->class_ptr );
    SERVER_LOG( LOG_ALWAYS, ", dpi=%d", req->dpi );
    SERVER_LOG( LOG_ALWAYS, ", awareness=%d", req->awareness );
}

static void dump_destroy_window_request( const struct destroy_window_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%08x", req->handle );
}

static void dump_get_desktop_window_request( const struct get_desktop_window_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " force=%d", req->force );
}

static void dump_get_desktop_window_reply( const struct get_desktop_window_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " top_window=%08x", req->top_window );
    SERVER_LOG( LOG_ALWAYS, ", msg_window=%08x", req->msg_window );
}

static void dump_set_window_owner_request( const struct set_window_owner_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%08x", req->handle );
    SERVER_LOG( LOG_ALWAYS, ", owner=%08x", req->owner );
}

static void dump_set_window_owner_reply( const struct set_window_owner_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " full_owner=%08x", req->full_owner );
    SERVER_LOG( LOG_ALWAYS, ", prev_owner=%08x", req->prev_owner );
}

static void dump_get_window_info_request( const struct get_window_info_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%08x", req->handle );
}

static void dump_get_window_info_reply( const struct get_window_info_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " full_handle=%08x", req->full_handle );
    SERVER_LOG( LOG_ALWAYS, ", last_active=%08x", req->last_active );
    SERVER_LOG( LOG_ALWAYS, ", pid=%04x", req->pid );
    SERVER_LOG( LOG_ALWAYS, ", tid=%04x", req->tid );
    SERVER_LOG( LOG_ALWAYS, ", atom=%04x", req->atom );
    SERVER_LOG( LOG_ALWAYS, ", is_unicode=%d", req->is_unicode );
    SERVER_LOG( LOG_ALWAYS, ", dpi=%d", req->dpi );
    SERVER_LOG( LOG_ALWAYS, ", awareness=%d", req->awareness );
}

static void dump_set_window_info_request( const struct set_window_info_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " flags=%04x", req->flags );
    SERVER_LOG( LOG_ALWAYS, ", is_unicode=%d", req->is_unicode );
    SERVER_LOG( LOG_ALWAYS, ", handle=%08x", req->handle );
    SERVER_LOG( LOG_ALWAYS, ", style=%08x", req->style );
    SERVER_LOG( LOG_ALWAYS, ", ex_style=%08x", req->ex_style );
    SERVER_LOG( LOG_ALWAYS, ", id=%08x", req->id );
    dump_uint64( ", instance=", &req->instance );
    dump_uint64( ", user_data=", &req->user_data );
    SERVER_LOG( LOG_ALWAYS, ", extra_offset=%d", req->extra_offset );
    SERVER_LOG( LOG_ALWAYS, ", extra_size=%u", req->extra_size );
    dump_uint64( ", extra_value=", &req->extra_value );
}

static void dump_set_window_info_reply( const struct set_window_info_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " old_style=%08x", req->old_style );
    SERVER_LOG( LOG_ALWAYS, ", old_ex_style=%08x", req->old_ex_style );
    dump_uint64( ", old_instance=", &req->old_instance );
    dump_uint64( ", old_user_data=", &req->old_user_data );
    dump_uint64( ", old_extra_value=", &req->old_extra_value );
    SERVER_LOG( LOG_ALWAYS, ", old_id=%08x", req->old_id );
}

static void dump_set_parent_request( const struct set_parent_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%08x", req->handle );
    SERVER_LOG( LOG_ALWAYS, ", parent=%08x", req->parent );
}

static void dump_set_parent_reply( const struct set_parent_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " old_parent=%08x", req->old_parent );
    SERVER_LOG( LOG_ALWAYS, ", full_parent=%08x", req->full_parent );
    SERVER_LOG( LOG_ALWAYS, ", dpi=%d", req->dpi );
    SERVER_LOG( LOG_ALWAYS, ", awareness=%d", req->awareness );
}

static void dump_get_window_parents_request( const struct get_window_parents_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%08x", req->handle );
}

static void dump_get_window_parents_reply( const struct get_window_parents_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " count=%d", req->count );
    dump_varargs_user_handles( ", parents=", cur_size );
}

static void dump_get_window_children_request( const struct get_window_children_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " desktop=%04x", req->desktop );
    SERVER_LOG( LOG_ALWAYS, ", parent=%08x", req->parent );
    SERVER_LOG( LOG_ALWAYS, ", atom=%04x", req->atom );
    SERVER_LOG( LOG_ALWAYS, ", tid=%04x", req->tid );
    dump_varargs_unicode_str( ", class=", cur_size );
}

static void dump_get_window_children_reply( const struct get_window_children_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " count=%d", req->count );
    dump_varargs_user_handles( ", children=", cur_size );
}

static void dump_get_window_children_from_point_request( const struct get_window_children_from_point_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " parent=%08x", req->parent );
    SERVER_LOG( LOG_ALWAYS, ", x=%d", req->x );
    SERVER_LOG( LOG_ALWAYS, ", y=%d", req->y );
    SERVER_LOG( LOG_ALWAYS, ", dpi=%d", req->dpi );
}

static void dump_get_window_children_from_point_reply( const struct get_window_children_from_point_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " count=%d", req->count );
    dump_varargs_user_handles( ", children=", cur_size );
}

static void dump_get_window_tree_request( const struct get_window_tree_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%08x", req->handle );
}

static void dump_get_window_tree_reply( const struct get_window_tree_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " parent=%08x", req->parent );
    SERVER_LOG( LOG_ALWAYS, ", owner=%08x", req->owner );
    SERVER_LOG( LOG_ALWAYS, ", next_sibling=%08x", req->next_sibling );
    SERVER_LOG( LOG_ALWAYS, ", prev_sibling=%08x", req->prev_sibling );
    SERVER_LOG( LOG_ALWAYS, ", first_sibling=%08x", req->first_sibling );
    SERVER_LOG( LOG_ALWAYS, ", last_sibling=%08x", req->last_sibling );
    SERVER_LOG( LOG_ALWAYS, ", first_child=%08x", req->first_child );
    SERVER_LOG( LOG_ALWAYS, ", last_child=%08x", req->last_child );
}

static void dump_set_window_pos_request( const struct set_window_pos_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " swp_flags=%04x", req->swp_flags );
    SERVER_LOG( LOG_ALWAYS, ", paint_flags=%04x", req->paint_flags );
    SERVER_LOG( LOG_ALWAYS, ", handle=%08x", req->handle );
    SERVER_LOG( LOG_ALWAYS, ", previous=%08x", req->previous );
    dump_rectangle( ", window=", &req->window );
    dump_rectangle( ", client=", &req->client );
    dump_varargs_rectangles( ", valid=", cur_size );
}

static void dump_set_window_pos_reply( const struct set_window_pos_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " new_style=%08x", req->new_style );
    SERVER_LOG( LOG_ALWAYS, ", new_ex_style=%08x", req->new_ex_style );
    SERVER_LOG( LOG_ALWAYS, ", surface_win=%08x", req->surface_win );
    SERVER_LOG( LOG_ALWAYS, ", needs_update=%d", req->needs_update );
}

static void dump_get_window_rectangles_request( const struct get_window_rectangles_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%08x", req->handle );
    SERVER_LOG( LOG_ALWAYS, ", relative=%d", req->relative );
    SERVER_LOG( LOG_ALWAYS, ", dpi=%d", req->dpi );
}

static void dump_get_window_rectangles_reply( const struct get_window_rectangles_reply *req )
{
    dump_rectangle( " window=", &req->window );
    dump_rectangle( ", client=", &req->client );
}

static void dump_get_window_text_request( const struct get_window_text_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%08x", req->handle );
}

static void dump_get_window_text_reply( const struct get_window_text_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " length=%u", req->length );
    dump_varargs_unicode_str( ", text=", cur_size );
}

static void dump_set_window_text_request( const struct set_window_text_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%08x", req->handle );
    dump_varargs_unicode_str( ", text=", cur_size );
}

static void dump_get_windows_offset_request( const struct get_windows_offset_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " from=%08x", req->from );
    SERVER_LOG( LOG_ALWAYS, ", to=%08x", req->to );
    SERVER_LOG( LOG_ALWAYS, ", dpi=%d", req->dpi );
}

static void dump_get_windows_offset_reply( const struct get_windows_offset_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " x=%d", req->x );
    SERVER_LOG( LOG_ALWAYS, ", y=%d", req->y );
    SERVER_LOG( LOG_ALWAYS, ", mirror=%d", req->mirror );
}

static void dump_get_visible_region_request( const struct get_visible_region_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " window=%08x", req->window );
    SERVER_LOG( LOG_ALWAYS, ", flags=%08x", req->flags );
}

static void dump_get_visible_region_reply( const struct get_visible_region_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " top_win=%08x", req->top_win );
    dump_rectangle( ", top_rect=", &req->top_rect );
    dump_rectangle( ", win_rect=", &req->win_rect );
    SERVER_LOG( LOG_ALWAYS, ", paint_flags=%08x", req->paint_flags );
    SERVER_LOG( LOG_ALWAYS, ", total_size=%u", req->total_size );
    dump_varargs_rectangles( ", region=", cur_size );
}

static void dump_get_surface_region_request( const struct get_surface_region_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " window=%08x", req->window );
}

static void dump_get_surface_region_reply( const struct get_surface_region_reply *req )
{
    dump_rectangle( " visible_rect=", &req->visible_rect );
    SERVER_LOG( LOG_ALWAYS, ", total_size=%u", req->total_size );
    dump_varargs_rectangles( ", region=", cur_size );
}

static void dump_get_window_region_request( const struct get_window_region_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " window=%08x", req->window );
}

static void dump_get_window_region_reply( const struct get_window_region_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " total_size=%u", req->total_size );
    dump_varargs_rectangles( ", region=", cur_size );
}

static void dump_set_window_region_request( const struct set_window_region_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " window=%08x", req->window );
    SERVER_LOG( LOG_ALWAYS, ", redraw=%d", req->redraw );
    dump_varargs_rectangles( ", region=", cur_size );
}

static void dump_get_update_region_request( const struct get_update_region_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " window=%08x", req->window );
    SERVER_LOG( LOG_ALWAYS, ", from_child=%08x", req->from_child );
    SERVER_LOG( LOG_ALWAYS, ", flags=%08x", req->flags );
}

static void dump_get_update_region_reply( const struct get_update_region_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " child=%08x", req->child );
    SERVER_LOG( LOG_ALWAYS, ", flags=%08x", req->flags );
    SERVER_LOG( LOG_ALWAYS, ", total_size=%u", req->total_size );
    dump_varargs_rectangles( ", region=", cur_size );
}

static void dump_update_window_zorder_request( const struct update_window_zorder_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " window=%08x", req->window );
    dump_rectangle( ", rect=", &req->rect );
}

static void dump_redraw_window_request( const struct redraw_window_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " window=%08x", req->window );
    SERVER_LOG( LOG_ALWAYS, ", flags=%08x", req->flags );
    dump_varargs_rectangles( ", region=", cur_size );
}

static void dump_set_window_property_request( const struct set_window_property_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " window=%08x", req->window );
    dump_uint64( ", data=", &req->data );
    SERVER_LOG( LOG_ALWAYS, ", atom=%04x", req->atom );
    dump_varargs_unicode_str( ", name=", cur_size );
}

static void dump_remove_window_property_request( const struct remove_window_property_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " window=%08x", req->window );
    SERVER_LOG( LOG_ALWAYS, ", atom=%04x", req->atom );
    dump_varargs_unicode_str( ", name=", cur_size );
}

static void dump_remove_window_property_reply( const struct remove_window_property_reply *req )
{
    dump_uint64( " data=", &req->data );
}

static void dump_get_window_property_request( const struct get_window_property_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " window=%08x", req->window );
    SERVER_LOG( LOG_ALWAYS, ", atom=%04x", req->atom );
    dump_varargs_unicode_str( ", name=", cur_size );
}

static void dump_get_window_property_reply( const struct get_window_property_reply *req )
{
    dump_uint64( " data=", &req->data );
}

static void dump_get_window_properties_request( const struct get_window_properties_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " window=%08x", req->window );
}

static void dump_get_window_properties_reply( const struct get_window_properties_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " total=%d", req->total );
    dump_varargs_properties( ", props=", cur_size );
}

static void dump_create_winstation_request( const struct create_winstation_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " flags=%08x", req->flags );
    SERVER_LOG( LOG_ALWAYS, ", access=%08x", req->access );
    SERVER_LOG( LOG_ALWAYS, ", attributes=%08x", req->attributes );
    SERVER_LOG( LOG_ALWAYS, ", rootdir=%04x", req->rootdir );
    dump_varargs_unicode_str( ", name=", cur_size );
}

static void dump_create_winstation_reply( const struct create_winstation_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%04x", req->handle );
}

static void dump_open_winstation_request( const struct open_winstation_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " access=%08x", req->access );
    SERVER_LOG( LOG_ALWAYS, ", attributes=%08x", req->attributes );
    SERVER_LOG( LOG_ALWAYS, ", rootdir=%04x", req->rootdir );
    dump_varargs_unicode_str( ", name=", cur_size );
}

static void dump_open_winstation_reply( const struct open_winstation_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%04x", req->handle );
}

static void dump_close_winstation_request( const struct close_winstation_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%04x", req->handle );
}

static void dump_get_process_winstation_request( const struct get_process_winstation_request *req )
{
}

static void dump_get_process_winstation_reply( const struct get_process_winstation_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%04x", req->handle );
}

static void dump_set_process_winstation_request( const struct set_process_winstation_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%04x", req->handle );
}

static void dump_enum_winstation_request( const struct enum_winstation_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " index=%08x", req->index );
}

static void dump_enum_winstation_reply( const struct enum_winstation_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " next=%08x", req->next );
    dump_varargs_unicode_str( ", name=", cur_size );
}

static void dump_create_desktop_request( const struct create_desktop_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " flags=%08x", req->flags );
    SERVER_LOG( LOG_ALWAYS, ", access=%08x", req->access );
    SERVER_LOG( LOG_ALWAYS, ", attributes=%08x", req->attributes );
    dump_varargs_unicode_str( ", name=", cur_size );
}

static void dump_create_desktop_reply( const struct create_desktop_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%04x", req->handle );
}

static void dump_open_desktop_request( const struct open_desktop_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " winsta=%04x", req->winsta );
    SERVER_LOG( LOG_ALWAYS, ", flags=%08x", req->flags );
    SERVER_LOG( LOG_ALWAYS, ", access=%08x", req->access );
    SERVER_LOG( LOG_ALWAYS, ", attributes=%08x", req->attributes );
    dump_varargs_unicode_str( ", name=", cur_size );
}

static void dump_open_desktop_reply( const struct open_desktop_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%04x", req->handle );
}

static void dump_open_input_desktop_request( const struct open_input_desktop_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " flags=%08x", req->flags );
    SERVER_LOG( LOG_ALWAYS, ", access=%08x", req->access );
    SERVER_LOG( LOG_ALWAYS, ", attributes=%08x", req->attributes );
}

static void dump_open_input_desktop_reply( const struct open_input_desktop_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%04x", req->handle );
}

static void dump_close_desktop_request( const struct close_desktop_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%04x", req->handle );
}

static void dump_get_thread_desktop_request( const struct get_thread_desktop_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " tid=%04x", req->tid );
}

static void dump_get_thread_desktop_reply( const struct get_thread_desktop_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%04x", req->handle );
}

static void dump_set_thread_desktop_request( const struct set_thread_desktop_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%04x", req->handle );
}

static void dump_enum_desktop_request( const struct enum_desktop_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " winstation=%04x", req->winstation );
    SERVER_LOG( LOG_ALWAYS, ", index=%08x", req->index );
}

static void dump_enum_desktop_reply( const struct enum_desktop_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " next=%08x", req->next );
    dump_varargs_unicode_str( ", name=", cur_size );
}

static void dump_set_user_object_info_request( const struct set_user_object_info_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%04x", req->handle );
    SERVER_LOG( LOG_ALWAYS, ", flags=%08x", req->flags );
    SERVER_LOG( LOG_ALWAYS, ", obj_flags=%08x", req->obj_flags );
}

static void dump_set_user_object_info_reply( const struct set_user_object_info_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " is_desktop=%d", req->is_desktop );
    SERVER_LOG( LOG_ALWAYS, ", old_obj_flags=%08x", req->old_obj_flags );
    dump_varargs_unicode_str( ", name=", cur_size );
}

static void dump_register_hotkey_request( const struct register_hotkey_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " window=%08x", req->window );
    SERVER_LOG( LOG_ALWAYS, ", id=%d", req->id );
    SERVER_LOG( LOG_ALWAYS, ", flags=%08x", req->flags );
    SERVER_LOG( LOG_ALWAYS, ", vkey=%08x", req->vkey );
}

static void dump_register_hotkey_reply( const struct register_hotkey_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " replaced=%d", req->replaced );
    SERVER_LOG( LOG_ALWAYS, ", flags=%08x", req->flags );
    SERVER_LOG( LOG_ALWAYS, ", vkey=%08x", req->vkey );
}

static void dump_unregister_hotkey_request( const struct unregister_hotkey_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " window=%08x", req->window );
    SERVER_LOG( LOG_ALWAYS, ", id=%d", req->id );
}

static void dump_unregister_hotkey_reply( const struct unregister_hotkey_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " flags=%08x", req->flags );
    SERVER_LOG( LOG_ALWAYS, ", vkey=%08x", req->vkey );
}

static void dump_attach_thread_input_request( const struct attach_thread_input_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " tid_from=%04x", req->tid_from );
    SERVER_LOG( LOG_ALWAYS, ", tid_to=%04x", req->tid_to );
    SERVER_LOG( LOG_ALWAYS, ", attach=%d", req->attach );
}

static void dump_get_thread_input_request( const struct get_thread_input_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " tid=%04x", req->tid );
}

static void dump_get_thread_input_reply( const struct get_thread_input_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " focus=%08x", req->focus );
    SERVER_LOG( LOG_ALWAYS, ", capture=%08x", req->capture );
    SERVER_LOG( LOG_ALWAYS, ", active=%08x", req->active );
    SERVER_LOG( LOG_ALWAYS, ", foreground=%08x", req->foreground );
    SERVER_LOG( LOG_ALWAYS, ", menu_owner=%08x", req->menu_owner );
    SERVER_LOG( LOG_ALWAYS, ", move_size=%08x", req->move_size );
    SERVER_LOG( LOG_ALWAYS, ", caret=%08x", req->caret );
    SERVER_LOG( LOG_ALWAYS, ", cursor=%08x", req->cursor );
    SERVER_LOG( LOG_ALWAYS, ", show_count=%d", req->show_count );
    dump_rectangle( ", rect=", &req->rect );
}

static void dump_get_last_input_time_request( const struct get_last_input_time_request *req )
{
}

static void dump_get_last_input_time_reply( const struct get_last_input_time_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " time=%08x", req->time );
}

static void dump_get_key_state_request( const struct get_key_state_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " async=%d", req->async );
    SERVER_LOG( LOG_ALWAYS, ", key=%d", req->key );
}

static void dump_get_key_state_reply( const struct get_key_state_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " state=%02x", req->state );
    dump_varargs_bytes( ", keystate=", cur_size );
}

static void dump_set_key_state_request( const struct set_key_state_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " async=%d", req->async );
    dump_varargs_bytes( ", keystate=", cur_size );
}

static void dump_set_foreground_window_request( const struct set_foreground_window_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%08x", req->handle );
}

static void dump_set_foreground_window_reply( const struct set_foreground_window_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " previous=%08x", req->previous );
    SERVER_LOG( LOG_ALWAYS, ", send_msg_old=%d", req->send_msg_old );
    SERVER_LOG( LOG_ALWAYS, ", send_msg_new=%d", req->send_msg_new );
}

static void dump_set_focus_window_request( const struct set_focus_window_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%08x", req->handle );
}

static void dump_set_focus_window_reply( const struct set_focus_window_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " previous=%08x", req->previous );
}

static void dump_set_active_window_request( const struct set_active_window_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%08x", req->handle );
}

static void dump_set_active_window_reply( const struct set_active_window_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " previous=%08x", req->previous );
}

static void dump_set_capture_window_request( const struct set_capture_window_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%08x", req->handle );
    SERVER_LOG( LOG_ALWAYS, ", flags=%08x", req->flags );
}

static void dump_set_capture_window_reply( const struct set_capture_window_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " previous=%08x", req->previous );
    SERVER_LOG( LOG_ALWAYS, ", full_handle=%08x", req->full_handle );
}

static void dump_set_caret_window_request( const struct set_caret_window_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%08x", req->handle );
    SERVER_LOG( LOG_ALWAYS, ", width=%d", req->width );
    SERVER_LOG( LOG_ALWAYS, ", height=%d", req->height );
}

static void dump_set_caret_window_reply( const struct set_caret_window_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " previous=%08x", req->previous );
    dump_rectangle( ", old_rect=", &req->old_rect );
    SERVER_LOG( LOG_ALWAYS, ", old_hide=%d", req->old_hide );
    SERVER_LOG( LOG_ALWAYS, ", old_state=%d", req->old_state );
}

static void dump_set_caret_info_request( const struct set_caret_info_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " flags=%08x", req->flags );
    SERVER_LOG( LOG_ALWAYS, ", handle=%08x", req->handle );
    SERVER_LOG( LOG_ALWAYS, ", x=%d", req->x );
    SERVER_LOG( LOG_ALWAYS, ", y=%d", req->y );
    SERVER_LOG( LOG_ALWAYS, ", hide=%d", req->hide );
    SERVER_LOG( LOG_ALWAYS, ", state=%d", req->state );
}

static void dump_set_caret_info_reply( const struct set_caret_info_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " full_handle=%08x", req->full_handle );
    dump_rectangle( ", old_rect=", &req->old_rect );
    SERVER_LOG( LOG_ALWAYS, ", old_hide=%d", req->old_hide );
    SERVER_LOG( LOG_ALWAYS, ", old_state=%d", req->old_state );
}

static void dump_set_hook_request( const struct set_hook_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " id=%d", req->id );
    SERVER_LOG( LOG_ALWAYS, ", pid=%04x", req->pid );
    SERVER_LOG( LOG_ALWAYS, ", tid=%04x", req->tid );
    SERVER_LOG( LOG_ALWAYS, ", event_min=%d", req->event_min );
    SERVER_LOG( LOG_ALWAYS, ", event_max=%d", req->event_max );
    dump_uint64( ", proc=", &req->proc );
    SERVER_LOG( LOG_ALWAYS, ", flags=%d", req->flags );
    SERVER_LOG( LOG_ALWAYS, ", unicode=%d", req->unicode );
    dump_varargs_unicode_str( ", module=", cur_size );
}

static void dump_set_hook_reply( const struct set_hook_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%08x", req->handle );
    SERVER_LOG( LOG_ALWAYS, ", active_hooks=%08x", req->active_hooks );
}

static void dump_remove_hook_request( const struct remove_hook_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%08x", req->handle );
    dump_uint64( ", proc=", &req->proc );
    SERVER_LOG( LOG_ALWAYS, ", id=%d", req->id );
}

static void dump_remove_hook_reply( const struct remove_hook_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " active_hooks=%08x", req->active_hooks );
}

static void dump_start_hook_chain_request( const struct start_hook_chain_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " id=%d", req->id );
    SERVER_LOG( LOG_ALWAYS, ", event=%d", req->event );
    SERVER_LOG( LOG_ALWAYS, ", window=%08x", req->window );
    SERVER_LOG( LOG_ALWAYS, ", object_id=%d", req->object_id );
    SERVER_LOG( LOG_ALWAYS, ", child_id=%d", req->child_id );
}

static void dump_start_hook_chain_reply( const struct start_hook_chain_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%08x", req->handle );
    SERVER_LOG( LOG_ALWAYS, ", pid=%04x", req->pid );
    SERVER_LOG( LOG_ALWAYS, ", tid=%04x", req->tid );
    SERVER_LOG( LOG_ALWAYS, ", unicode=%d", req->unicode );
    dump_uint64( ", proc=", &req->proc );
    SERVER_LOG( LOG_ALWAYS, ", active_hooks=%08x", req->active_hooks );
    dump_varargs_unicode_str( ", module=", cur_size );
}

static void dump_finish_hook_chain_request( const struct finish_hook_chain_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " id=%d", req->id );
}

static void dump_get_hook_info_request( const struct get_hook_info_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%08x", req->handle );
    SERVER_LOG( LOG_ALWAYS, ", get_next=%d", req->get_next );
    SERVER_LOG( LOG_ALWAYS, ", event=%d", req->event );
    SERVER_LOG( LOG_ALWAYS, ", window=%08x", req->window );
    SERVER_LOG( LOG_ALWAYS, ", object_id=%d", req->object_id );
    SERVER_LOG( LOG_ALWAYS, ", child_id=%d", req->child_id );
}

static void dump_get_hook_info_reply( const struct get_hook_info_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%08x", req->handle );
    SERVER_LOG( LOG_ALWAYS, ", id=%d", req->id );
    SERVER_LOG( LOG_ALWAYS, ", pid=%04x", req->pid );
    SERVER_LOG( LOG_ALWAYS, ", tid=%04x", req->tid );
    dump_uint64( ", proc=", &req->proc );
    SERVER_LOG( LOG_ALWAYS, ", unicode=%d", req->unicode );
    dump_varargs_unicode_str( ", module=", cur_size );
}

static void dump_create_class_request( const struct create_class_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " local=%d", req->local );
    SERVER_LOG( LOG_ALWAYS, ", atom=%04x", req->atom );
    SERVER_LOG( LOG_ALWAYS, ", style=%08x", req->style );
    dump_uint64( ", instance=", &req->instance );
    SERVER_LOG( LOG_ALWAYS, ", extra=%d", req->extra );
    SERVER_LOG( LOG_ALWAYS, ", win_extra=%d", req->win_extra );
    dump_uint64( ", client_ptr=", &req->client_ptr );
    SERVER_LOG( LOG_ALWAYS, ", name_offset=%u", req->name_offset );
    dump_varargs_unicode_str( ", name=", cur_size );
}

static void dump_create_class_reply( const struct create_class_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " atom=%04x", req->atom );
}

static void dump_destroy_class_request( const struct destroy_class_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " atom=%04x", req->atom );
    dump_uint64( ", instance=", &req->instance );
    dump_varargs_unicode_str( ", name=", cur_size );
}

static void dump_destroy_class_reply( const struct destroy_class_reply *req )
{
    dump_uint64( " client_ptr=", &req->client_ptr );
}

static void dump_set_class_info_request( const struct set_class_info_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " window=%08x", req->window );
    SERVER_LOG( LOG_ALWAYS, ", flags=%08x", req->flags );
    SERVER_LOG( LOG_ALWAYS, ", atom=%04x", req->atom );
    SERVER_LOG( LOG_ALWAYS, ", style=%08x", req->style );
    SERVER_LOG( LOG_ALWAYS, ", win_extra=%d", req->win_extra );
    dump_uint64( ", instance=", &req->instance );
    SERVER_LOG( LOG_ALWAYS, ", extra_offset=%d", req->extra_offset );
    SERVER_LOG( LOG_ALWAYS, ", extra_size=%u", req->extra_size );
    dump_uint64( ", extra_value=", &req->extra_value );
}

static void dump_set_class_info_reply( const struct set_class_info_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " old_atom=%04x", req->old_atom );
    SERVER_LOG( LOG_ALWAYS, ", base_atom=%04x", req->base_atom );
    dump_uint64( ", old_instance=", &req->old_instance );
    dump_uint64( ", old_extra_value=", &req->old_extra_value );
    SERVER_LOG( LOG_ALWAYS, ", old_style=%08x", req->old_style );
    SERVER_LOG( LOG_ALWAYS, ", old_extra=%d", req->old_extra );
    SERVER_LOG( LOG_ALWAYS, ", old_win_extra=%d", req->old_win_extra );
}

static void dump_open_clipboard_request( const struct open_clipboard_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " window=%08x", req->window );
}

static void dump_open_clipboard_reply( const struct open_clipboard_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " owner=%08x", req->owner );
}

static void dump_close_clipboard_request( const struct close_clipboard_request *req )
{
}

static void dump_close_clipboard_reply( const struct close_clipboard_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " viewer=%08x", req->viewer );
    SERVER_LOG( LOG_ALWAYS, ", owner=%08x", req->owner );
}

static void dump_empty_clipboard_request( const struct empty_clipboard_request *req )
{
}

static void dump_set_clipboard_data_request( const struct set_clipboard_data_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " format=%08x", req->format );
    SERVER_LOG( LOG_ALWAYS, ", lcid=%08x", req->lcid );
    dump_varargs_bytes( ", data=", cur_size );
}

static void dump_set_clipboard_data_reply( const struct set_clipboard_data_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " seqno=%08x", req->seqno );
}

static void dump_get_clipboard_data_request( const struct get_clipboard_data_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " format=%08x", req->format );
    SERVER_LOG( LOG_ALWAYS, ", render=%d", req->render );
    SERVER_LOG( LOG_ALWAYS, ", cached=%d", req->cached );
    SERVER_LOG( LOG_ALWAYS, ", seqno=%08x", req->seqno );
}

static void dump_get_clipboard_data_reply( const struct get_clipboard_data_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " from=%08x", req->from );
    SERVER_LOG( LOG_ALWAYS, ", owner=%08x", req->owner );
    SERVER_LOG( LOG_ALWAYS, ", seqno=%08x", req->seqno );
    SERVER_LOG( LOG_ALWAYS, ", total=%u", req->total );
    dump_varargs_bytes( ", data=", cur_size );
}

static void dump_get_clipboard_formats_request( const struct get_clipboard_formats_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " format=%08x", req->format );
}

static void dump_get_clipboard_formats_reply( const struct get_clipboard_formats_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " count=%08x", req->count );
    dump_varargs_uints( ", formats=", cur_size );
}

static void dump_enum_clipboard_formats_request( const struct enum_clipboard_formats_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " previous=%08x", req->previous );
}

static void dump_enum_clipboard_formats_reply( const struct enum_clipboard_formats_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " format=%08x", req->format );
}

static void dump_release_clipboard_request( const struct release_clipboard_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " owner=%08x", req->owner );
}

static void dump_release_clipboard_reply( const struct release_clipboard_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " viewer=%08x", req->viewer );
    SERVER_LOG( LOG_ALWAYS, ", owner=%08x", req->owner );
}

static void dump_get_clipboard_info_request( const struct get_clipboard_info_request *req )
{
}

static void dump_get_clipboard_info_reply( const struct get_clipboard_info_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " window=%08x", req->window );
    SERVER_LOG( LOG_ALWAYS, ", owner=%08x", req->owner );
    SERVER_LOG( LOG_ALWAYS, ", viewer=%08x", req->viewer );
    SERVER_LOG( LOG_ALWAYS, ", seqno=%08x", req->seqno );
}

static void dump_set_clipboard_viewer_request( const struct set_clipboard_viewer_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " viewer=%08x", req->viewer );
    SERVER_LOG( LOG_ALWAYS, ", previous=%08x", req->previous );
}

static void dump_set_clipboard_viewer_reply( const struct set_clipboard_viewer_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " old_viewer=%08x", req->old_viewer );
    SERVER_LOG( LOG_ALWAYS, ", owner=%08x", req->owner );
}

static void dump_add_clipboard_listener_request( const struct add_clipboard_listener_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " window=%08x", req->window );
}

static void dump_remove_clipboard_listener_request( const struct remove_clipboard_listener_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " window=%08x", req->window );
}

static void dump_open_token_request( const struct open_token_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%04x", req->handle );
    SERVER_LOG( LOG_ALWAYS, ", access=%08x", req->access );
    SERVER_LOG( LOG_ALWAYS, ", attributes=%08x", req->attributes );
    SERVER_LOG( LOG_ALWAYS, ", flags=%08x", req->flags );
}

static void dump_open_token_reply( const struct open_token_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " token=%04x", req->token );
}

static void dump_set_global_windows_request( const struct set_global_windows_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " flags=%08x", req->flags );
    SERVER_LOG( LOG_ALWAYS, ", shell_window=%08x", req->shell_window );
    SERVER_LOG( LOG_ALWAYS, ", shell_listview=%08x", req->shell_listview );
    SERVER_LOG( LOG_ALWAYS, ", progman_window=%08x", req->progman_window );
    SERVER_LOG( LOG_ALWAYS, ", taskman_window=%08x", req->taskman_window );
}

static void dump_set_global_windows_reply( const struct set_global_windows_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " old_shell_window=%08x", req->old_shell_window );
    SERVER_LOG( LOG_ALWAYS, ", old_shell_listview=%08x", req->old_shell_listview );
    SERVER_LOG( LOG_ALWAYS, ", old_progman_window=%08x", req->old_progman_window );
    SERVER_LOG( LOG_ALWAYS, ", old_taskman_window=%08x", req->old_taskman_window );
}

static void dump_adjust_token_privileges_request( const struct adjust_token_privileges_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%04x", req->handle );
    SERVER_LOG( LOG_ALWAYS, ", disable_all=%d", req->disable_all );
    SERVER_LOG( LOG_ALWAYS, ", get_modified_state=%d", req->get_modified_state );
    dump_varargs_LUID_AND_ATTRIBUTES( ", privileges=", cur_size );
}

static void dump_adjust_token_privileges_reply( const struct adjust_token_privileges_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " len=%08x", req->len );
    dump_varargs_LUID_AND_ATTRIBUTES( ", privileges=", cur_size );
}

static void dump_get_token_privileges_request( const struct get_token_privileges_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%04x", req->handle );
}

static void dump_get_token_privileges_reply( const struct get_token_privileges_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " len=%08x", req->len );
    dump_varargs_LUID_AND_ATTRIBUTES( ", privileges=", cur_size );
}

static void dump_check_token_privileges_request( const struct check_token_privileges_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%04x", req->handle );
    SERVER_LOG( LOG_ALWAYS, ", all_required=%d", req->all_required );
    dump_varargs_LUID_AND_ATTRIBUTES( ", privileges=", cur_size );
}

static void dump_check_token_privileges_reply( const struct check_token_privileges_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " has_privileges=%d", req->has_privileges );
    dump_varargs_LUID_AND_ATTRIBUTES( ", privileges=", cur_size );
}

static void dump_duplicate_token_request( const struct duplicate_token_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%04x", req->handle );
    SERVER_LOG( LOG_ALWAYS, ", access=%08x", req->access );
    SERVER_LOG( LOG_ALWAYS, ", primary=%d", req->primary );
    SERVER_LOG( LOG_ALWAYS, ", impersonation_level=%d", req->impersonation_level );
    dump_varargs_object_attributes( ", objattr=", cur_size );
}

static void dump_duplicate_token_reply( const struct duplicate_token_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " new_handle=%04x", req->new_handle );
}

static void dump_filter_token_request( const struct filter_token_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%04x", req->handle );
    SERVER_LOG( LOG_ALWAYS, ", flags=%08x", req->flags );
    SERVER_LOG( LOG_ALWAYS, ", privileges_size=%u", req->privileges_size );
    dump_varargs_LUID_AND_ATTRIBUTES( ", privileges=", min(cur_size,req->privileges_size) );
    dump_varargs_SID( ", disable_sids=", cur_size );
}

static void dump_filter_token_reply( const struct filter_token_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " new_handle=%04x", req->new_handle );
}

static void dump_access_check_request( const struct access_check_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%04x", req->handle );
    SERVER_LOG( LOG_ALWAYS, ", desired_access=%08x", req->desired_access );
    dump_generic_map( ", mapping=", &req->mapping );
    dump_varargs_security_descriptor( ", sd=", cur_size );
}

static void dump_access_check_reply( const struct access_check_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " access_granted=%08x", req->access_granted );
    SERVER_LOG( LOG_ALWAYS, ", access_status=%08x", req->access_status );
    SERVER_LOG( LOG_ALWAYS, ", privileges_len=%08x", req->privileges_len );
    dump_varargs_LUID_AND_ATTRIBUTES( ", privileges=", cur_size );
}

static void dump_get_token_sid_request( const struct get_token_sid_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%04x", req->handle );
    SERVER_LOG( LOG_ALWAYS, ", which_sid=%08x", req->which_sid );
}

static void dump_get_token_sid_reply( const struct get_token_sid_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " sid_len=%u", req->sid_len );
    dump_varargs_SID( ", sid=", cur_size );
}

static void dump_get_token_groups_request( const struct get_token_groups_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%04x", req->handle );
}

static void dump_get_token_groups_reply( const struct get_token_groups_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " user_len=%u", req->user_len );
    dump_varargs_token_groups( ", user=", cur_size );
}

static void dump_get_token_default_dacl_request( const struct get_token_default_dacl_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%04x", req->handle );
}

static void dump_get_token_default_dacl_reply( const struct get_token_default_dacl_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " acl_len=%u", req->acl_len );
    dump_varargs_ACL( ", acl=", cur_size );
}

static void dump_set_token_default_dacl_request( const struct set_token_default_dacl_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%04x", req->handle );
    dump_varargs_ACL( ", acl=", cur_size );
}

static void dump_set_security_object_request( const struct set_security_object_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%04x", req->handle );
    SERVER_LOG( LOG_ALWAYS, ", security_info=%08x", req->security_info );
    dump_varargs_security_descriptor( ", sd=", cur_size );
}

static void dump_get_security_object_request( const struct get_security_object_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%04x", req->handle );
    SERVER_LOG( LOG_ALWAYS, ", security_info=%08x", req->security_info );
}

static void dump_get_security_object_reply( const struct get_security_object_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " sd_len=%08x", req->sd_len );
    dump_varargs_security_descriptor( ", sd=", cur_size );
}

static void dump_get_system_handles_request( const struct get_system_handles_request *req )
{
}

static void dump_get_system_handles_reply( const struct get_system_handles_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " count=%08x", req->count );
    dump_varargs_handle_infos( ", data=", cur_size );
}

static void dump_create_mailslot_request( const struct create_mailslot_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " access=%08x", req->access );
    dump_timeout( ", read_timeout=", &req->read_timeout );
    SERVER_LOG( LOG_ALWAYS, ", max_msgsize=%08x", req->max_msgsize );
    dump_varargs_object_attributes( ", objattr=", cur_size );
}

static void dump_create_mailslot_reply( const struct create_mailslot_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%04x", req->handle );
}

static void dump_set_mailslot_info_request( const struct set_mailslot_info_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%04x", req->handle );
    dump_timeout( ", read_timeout=", &req->read_timeout );
    SERVER_LOG( LOG_ALWAYS, ", flags=%08x", req->flags );
}

static void dump_set_mailslot_info_reply( const struct set_mailslot_info_reply *req )
{
    dump_timeout( " read_timeout=", &req->read_timeout );
    SERVER_LOG( LOG_ALWAYS, ", max_msgsize=%08x", req->max_msgsize );
}

static void dump_create_directory_request( const struct create_directory_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " access=%08x", req->access );
    dump_varargs_object_attributes( ", objattr=", cur_size );
}

static void dump_create_directory_reply( const struct create_directory_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%04x", req->handle );
}

static void dump_open_directory_request( const struct open_directory_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " access=%08x", req->access );
    SERVER_LOG( LOG_ALWAYS, ", attributes=%08x", req->attributes );
    SERVER_LOG( LOG_ALWAYS, ", rootdir=%04x", req->rootdir );
    dump_varargs_unicode_str( ", directory_name=", cur_size );
}

static void dump_open_directory_reply( const struct open_directory_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%04x", req->handle );
}

static void dump_get_directory_entry_request( const struct get_directory_entry_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%04x", req->handle );
    SERVER_LOG( LOG_ALWAYS, ", index=%08x", req->index );
}

static void dump_get_directory_entry_reply( const struct get_directory_entry_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " name_len=%u", req->name_len );
    dump_varargs_unicode_str( ", name=", min(cur_size,req->name_len) );
    dump_varargs_unicode_str( ", type=", cur_size );
}

static void dump_create_symlink_request( const struct create_symlink_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " access=%08x", req->access );
    dump_varargs_object_attributes( ", objattr=", cur_size );
    dump_varargs_unicode_str( ", target_name=", cur_size );
}

static void dump_create_symlink_reply( const struct create_symlink_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%04x", req->handle );
}

static void dump_open_symlink_request( const struct open_symlink_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " access=%08x", req->access );
    SERVER_LOG( LOG_ALWAYS, ", attributes=%08x", req->attributes );
    SERVER_LOG( LOG_ALWAYS, ", rootdir=%04x", req->rootdir );
    dump_varargs_unicode_str( ", name=", cur_size );
}

static void dump_open_symlink_reply( const struct open_symlink_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%04x", req->handle );
}

static void dump_query_symlink_request( const struct query_symlink_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%04x", req->handle );
}

static void dump_query_symlink_reply( const struct query_symlink_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " total=%u", req->total );
    dump_varargs_unicode_str( ", target_name=", cur_size );
}

static void dump_get_object_info_request( const struct get_object_info_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%04x", req->handle );
}

static void dump_get_object_info_reply( const struct get_object_info_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " access=%08x", req->access );
    SERVER_LOG( LOG_ALWAYS, ", ref_count=%08x", req->ref_count );
    SERVER_LOG( LOG_ALWAYS, ", handle_count=%08x", req->handle_count );
}

static void dump_get_object_name_request( const struct get_object_name_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%04x", req->handle );
}

static void dump_get_object_name_reply( const struct get_object_name_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " total=%u", req->total );
    dump_varargs_unicode_str( ", name=", cur_size );
}

static void dump_get_object_type_request( const struct get_object_type_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%04x", req->handle );
}

static void dump_get_object_type_reply( const struct get_object_type_reply *req )
{
    dump_varargs_object_type_info( " info=", cur_size );
}

static void dump_get_object_types_request( const struct get_object_types_request *req )
{
}

static void dump_get_object_types_reply( const struct get_object_types_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " count=%d", req->count );
    dump_varargs_object_types_info( ", info=", cur_size );
}

static void dump_allocate_locally_unique_id_request( const struct allocate_locally_unique_id_request *req )
{
}

static void dump_allocate_locally_unique_id_reply( const struct allocate_locally_unique_id_reply *req )
{
    dump_luid( " luid=", &req->luid );
}

static void dump_create_device_manager_request( const struct create_device_manager_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " access=%08x", req->access );
    SERVER_LOG( LOG_ALWAYS, ", attributes=%08x", req->attributes );
}

static void dump_create_device_manager_reply( const struct create_device_manager_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%04x", req->handle );
}

static void dump_create_device_request( const struct create_device_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " rootdir=%04x", req->rootdir );
    dump_uint64( ", user_ptr=", &req->user_ptr );
    SERVER_LOG( LOG_ALWAYS, ", manager=%04x", req->manager );
    dump_varargs_unicode_str( ", name=", cur_size );
}

static void dump_delete_device_request( const struct delete_device_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " manager=%04x", req->manager );
    dump_uint64( ", device=", &req->device );
}

static void dump_get_next_device_request_request( const struct get_next_device_request_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " manager=%04x", req->manager );
    SERVER_LOG( LOG_ALWAYS, ", prev=%04x", req->prev );
    SERVER_LOG( LOG_ALWAYS, ", status=%08x", req->status );
    dump_uint64( ", user_ptr=", &req->user_ptr );
    SERVER_LOG( LOG_ALWAYS, ", pending=%d", req->pending );
    SERVER_LOG( LOG_ALWAYS, ", iosb_status=%08x", req->iosb_status );
    SERVER_LOG( LOG_ALWAYS, ", result=%u", req->result );
    dump_varargs_bytes( ", data=", cur_size );
}

static void dump_get_next_device_request_reply( const struct get_next_device_request_reply *req )
{
    dump_irp_params( " params=", &req->params );
    SERVER_LOG( LOG_ALWAYS, ", next=%04x", req->next );
    SERVER_LOG( LOG_ALWAYS, ", client_tid=%04x", req->client_tid );
    dump_uint64( ", client_thread=", &req->client_thread );
    SERVER_LOG( LOG_ALWAYS, ", in_size=%u", req->in_size );
    dump_varargs_bytes( ", next_data=", cur_size );
}

static void dump_get_kernel_object_ptr_request( const struct get_kernel_object_ptr_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " manager=%04x", req->manager );
    SERVER_LOG( LOG_ALWAYS, ", handle=%04x", req->handle );
}

static void dump_get_kernel_object_ptr_reply( const struct get_kernel_object_ptr_reply *req )
{
    dump_uint64( " user_ptr=", &req->user_ptr );
}

static void dump_set_kernel_object_ptr_request( const struct set_kernel_object_ptr_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " manager=%04x", req->manager );
    SERVER_LOG( LOG_ALWAYS, ", handle=%04x", req->handle );
    dump_uint64( ", user_ptr=", &req->user_ptr );
}

static void dump_grab_kernel_object_request( const struct grab_kernel_object_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " manager=%04x", req->manager );
    dump_uint64( ", user_ptr=", &req->user_ptr );
}

static void dump_release_kernel_object_request( const struct release_kernel_object_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " manager=%04x", req->manager );
    dump_uint64( ", user_ptr=", &req->user_ptr );
}

static void dump_get_kernel_object_handle_request( const struct get_kernel_object_handle_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " manager=%04x", req->manager );
    dump_uint64( ", user_ptr=", &req->user_ptr );
    SERVER_LOG( LOG_ALWAYS, ", access=%08x", req->access );
}

static void dump_get_kernel_object_handle_reply( const struct get_kernel_object_handle_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%04x", req->handle );
}

static void dump_make_process_system_request( const struct make_process_system_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%04x", req->handle );
}

static void dump_make_process_system_reply( const struct make_process_system_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " event=%04x", req->event );
}

static void dump_get_token_info_request( const struct get_token_info_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%04x", req->handle );
}

static void dump_get_token_info_reply( const struct get_token_info_reply *req )
{
    dump_luid( " token_id=", &req->token_id );
    dump_luid( ", modified_id=", &req->modified_id );
    SERVER_LOG( LOG_ALWAYS, ", session_id=%08x", req->session_id );
    SERVER_LOG( LOG_ALWAYS, ", primary=%d", req->primary );
    SERVER_LOG( LOG_ALWAYS, ", impersonation_level=%d", req->impersonation_level );
    SERVER_LOG( LOG_ALWAYS, ", elevation=%d", req->elevation );
    SERVER_LOG( LOG_ALWAYS, ", group_count=%d", req->group_count );
    SERVER_LOG( LOG_ALWAYS, ", privilege_count=%d", req->privilege_count );
}

static void dump_create_linked_token_request( const struct create_linked_token_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%04x", req->handle );
}

static void dump_create_linked_token_reply( const struct create_linked_token_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " linked=%04x", req->linked );
}

static void dump_create_completion_request( const struct create_completion_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " access=%08x", req->access );
    SERVER_LOG( LOG_ALWAYS, ", concurrent=%08x", req->concurrent );
    dump_varargs_object_attributes( ", objattr=", cur_size );
}

static void dump_create_completion_reply( const struct create_completion_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%04x", req->handle );
}

static void dump_open_completion_request( const struct open_completion_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " access=%08x", req->access );
    SERVER_LOG( LOG_ALWAYS, ", attributes=%08x", req->attributes );
    SERVER_LOG( LOG_ALWAYS, ", rootdir=%04x", req->rootdir );
    dump_varargs_unicode_str( ", filename=", cur_size );
}

static void dump_open_completion_reply( const struct open_completion_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%04x", req->handle );
}

static void dump_add_completion_request( const struct add_completion_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%04x", req->handle );
    dump_uint64( ", ckey=", &req->ckey );
    dump_uint64( ", cvalue=", &req->cvalue );
    dump_uint64( ", information=", &req->information );
    SERVER_LOG( LOG_ALWAYS, ", status=%08x", req->status );
}

static void dump_remove_completion_request( const struct remove_completion_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%04x", req->handle );
}

static void dump_remove_completion_reply( const struct remove_completion_reply *req )
{
    dump_uint64( " ckey=", &req->ckey );
    dump_uint64( ", cvalue=", &req->cvalue );
    dump_uint64( ", information=", &req->information );
    SERVER_LOG( LOG_ALWAYS, ", status=%08x", req->status );
}

static void dump_query_completion_request( const struct query_completion_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%04x", req->handle );
}

static void dump_query_completion_reply( const struct query_completion_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " depth=%08x", req->depth );
}

static void dump_set_completion_info_request( const struct set_completion_info_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%04x", req->handle );
    dump_uint64( ", ckey=", &req->ckey );
    SERVER_LOG( LOG_ALWAYS, ", chandle=%04x", req->chandle );
}

static void dump_add_fd_completion_request( const struct add_fd_completion_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%04x", req->handle );
    dump_uint64( ", cvalue=", &req->cvalue );
    dump_uint64( ", information=", &req->information );
    SERVER_LOG( LOG_ALWAYS, ", status=%08x", req->status );
    SERVER_LOG( LOG_ALWAYS, ", async=%d", req->async );
}

static void dump_set_fd_completion_mode_request( const struct set_fd_completion_mode_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%04x", req->handle );
    SERVER_LOG( LOG_ALWAYS, ", flags=%08x", req->flags );
}

static void dump_set_fd_disp_info_request( const struct set_fd_disp_info_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%04x", req->handle );
    SERVER_LOG( LOG_ALWAYS, ", unlink=%d", req->unlink );
}

static void dump_set_fd_name_info_request( const struct set_fd_name_info_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%04x", req->handle );
    SERVER_LOG( LOG_ALWAYS, ", rootdir=%04x", req->rootdir );
    SERVER_LOG( LOG_ALWAYS, ", namelen=%u", req->namelen );
    SERVER_LOG( LOG_ALWAYS, ", link=%d", req->link );
    SERVER_LOG( LOG_ALWAYS, ", replace=%d", req->replace );
    dump_varargs_unicode_str( ", name=", min(cur_size,req->namelen) );
    dump_varargs_string( ", filename=", cur_size );
}

static void dump_set_fd_eof_info_request( const struct set_fd_eof_info_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%04x", req->handle );
    dump_uint64( ", eof=", &req->eof );
}

static void dump_get_window_layered_info_request( const struct get_window_layered_info_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%08x", req->handle );
}

static void dump_get_window_layered_info_reply( const struct get_window_layered_info_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " color_key=%08x", req->color_key );
    SERVER_LOG( LOG_ALWAYS, ", alpha=%08x", req->alpha );
    SERVER_LOG( LOG_ALWAYS, ", flags=%08x", req->flags );
}

static void dump_set_window_layered_info_request( const struct set_window_layered_info_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%08x", req->handle );
    SERVER_LOG( LOG_ALWAYS, ", color_key=%08x", req->color_key );
    SERVER_LOG( LOG_ALWAYS, ", alpha=%08x", req->alpha );
    SERVER_LOG( LOG_ALWAYS, ", flags=%08x", req->flags );
}

static void dump_alloc_user_handle_request( const struct alloc_user_handle_request *req )
{
}

static void dump_alloc_user_handle_reply( const struct alloc_user_handle_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%08x", req->handle );
}

static void dump_free_user_handle_request( const struct free_user_handle_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%08x", req->handle );
}

static void dump_set_cursor_request( const struct set_cursor_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " flags=%08x", req->flags );
    SERVER_LOG( LOG_ALWAYS, ", handle=%08x", req->handle );
    SERVER_LOG( LOG_ALWAYS, ", show_count=%d", req->show_count );
    SERVER_LOG( LOG_ALWAYS, ", x=%d", req->x );
    SERVER_LOG( LOG_ALWAYS, ", y=%d", req->y );
    dump_rectangle( ", clip=", &req->clip );
    SERVER_LOG( LOG_ALWAYS, ", clip_msg=%08x", req->clip_msg );
}

static void dump_set_cursor_reply( const struct set_cursor_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " prev_handle=%08x", req->prev_handle );
    SERVER_LOG( LOG_ALWAYS, ", prev_count=%d", req->prev_count );
    SERVER_LOG( LOG_ALWAYS, ", prev_x=%d", req->prev_x );
    SERVER_LOG( LOG_ALWAYS, ", prev_y=%d", req->prev_y );
    SERVER_LOG( LOG_ALWAYS, ", new_x=%d", req->new_x );
    SERVER_LOG( LOG_ALWAYS, ", new_y=%d", req->new_y );
    dump_rectangle( ", new_clip=", &req->new_clip );
    SERVER_LOG( LOG_ALWAYS, ", last_change=%08x", req->last_change );
}

static void dump_get_cursor_history_request( const struct get_cursor_history_request *req )
{
}

static void dump_get_cursor_history_reply( const struct get_cursor_history_reply *req )
{
    dump_varargs_cursor_positions( " history=", cur_size );
}

static void dump_get_rawinput_buffer_request( const struct get_rawinput_buffer_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " rawinput_size=%u", req->rawinput_size );
    SERVER_LOG( LOG_ALWAYS, ", buffer_size=%u", req->buffer_size );
}

static void dump_get_rawinput_buffer_reply( const struct get_rawinput_buffer_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " next_size=%u", req->next_size );
    SERVER_LOG( LOG_ALWAYS, ", count=%08x", req->count );
    dump_varargs_bytes( ", data=", cur_size );
}

static void dump_update_rawinput_devices_request( const struct update_rawinput_devices_request *req )
{
    dump_varargs_rawinput_devices( " devices=", cur_size );
}

static void dump_get_rawinput_devices_request( const struct get_rawinput_devices_request *req )
{
}

static void dump_get_rawinput_devices_reply( const struct get_rawinput_devices_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " device_count=%08x", req->device_count );
    dump_varargs_rawinput_devices( ", devices=", cur_size );
}

static void dump_create_job_request( const struct create_job_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " access=%08x", req->access );
    dump_varargs_object_attributes( ", objattr=", cur_size );
}

static void dump_create_job_reply( const struct create_job_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%04x", req->handle );
}

static void dump_open_job_request( const struct open_job_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " access=%08x", req->access );
    SERVER_LOG( LOG_ALWAYS, ", attributes=%08x", req->attributes );
    SERVER_LOG( LOG_ALWAYS, ", rootdir=%04x", req->rootdir );
    dump_varargs_unicode_str( ", name=", cur_size );
}

static void dump_open_job_reply( const struct open_job_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%04x", req->handle );
}

static void dump_assign_job_request( const struct assign_job_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " job=%04x", req->job );
    SERVER_LOG( LOG_ALWAYS, ", process=%04x", req->process );
}

static void dump_process_in_job_request( const struct process_in_job_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " job=%04x", req->job );
    SERVER_LOG( LOG_ALWAYS, ", process=%04x", req->process );
}

static void dump_set_job_limits_request( const struct set_job_limits_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%04x", req->handle );
    SERVER_LOG( LOG_ALWAYS, ", limit_flags=%08x", req->limit_flags );
}

static void dump_set_job_completion_port_request( const struct set_job_completion_port_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " job=%04x", req->job );
    SERVER_LOG( LOG_ALWAYS, ", port=%04x", req->port );
    dump_uint64( ", key=", &req->key );
}

static void dump_get_job_info_request( const struct get_job_info_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%04x", req->handle );
}

static void dump_get_job_info_reply( const struct get_job_info_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " total_processes=%d", req->total_processes );
    SERVER_LOG( LOG_ALWAYS, ", active_processes=%d", req->active_processes );
    dump_varargs_uints( ", pids=", cur_size );
}

static void dump_terminate_job_request( const struct terminate_job_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%04x", req->handle );
    SERVER_LOG( LOG_ALWAYS, ", status=%d", req->status );
}

static void dump_suspend_process_request( const struct suspend_process_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%04x", req->handle );
}

static void dump_resume_process_request( const struct resume_process_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%04x", req->handle );
}

static void dump_get_next_thread_request( const struct get_next_thread_request *req )
{
    SERVER_LOG( LOG_ALWAYS, " process=%04x", req->process );
    SERVER_LOG( LOG_ALWAYS, ", last=%04x", req->last );
    SERVER_LOG( LOG_ALWAYS, ", access=%08x", req->access );
    SERVER_LOG( LOG_ALWAYS, ", attributes=%08x", req->attributes );
    SERVER_LOG( LOG_ALWAYS, ", flags=%08x", req->flags );
}

static void dump_get_next_thread_reply( const struct get_next_thread_reply *req )
{
    SERVER_LOG( LOG_ALWAYS, " handle=%04x", req->handle );
}

static const dump_func req_dumpers[REQ_NB_REQUESTS] = {
    (dump_func)dump_new_process_request,
    (dump_func)dump_get_new_process_info_request,
    (dump_func)dump_new_thread_request,
    (dump_func)dump_get_startup_info_request,
    (dump_func)dump_init_process_done_request,
    (dump_func)dump_init_first_thread_request,
    (dump_func)dump_init_thread_request,
    (dump_func)dump_terminate_process_request,
    (dump_func)dump_terminate_thread_request,
    (dump_func)dump_get_process_info_request,
    (dump_func)dump_get_process_debug_info_request,
    (dump_func)dump_get_process_image_name_request,
    (dump_func)dump_get_process_vm_counters_request,
    (dump_func)dump_set_process_info_request,
    (dump_func)dump_get_thread_info_request,
    (dump_func)dump_get_thread_times_request,
    (dump_func)dump_set_thread_info_request,
    (dump_func)dump_suspend_thread_request,
    (dump_func)dump_resume_thread_request,
    (dump_func)dump_queue_apc_request,
    (dump_func)dump_get_apc_result_request,
    (dump_func)dump_close_handle_request,
    (dump_func)dump_set_handle_info_request,
    (dump_func)dump_dup_handle_request,
    (dump_func)dump_compare_objects_request,
    (dump_func)dump_make_temporary_request,
    (dump_func)dump_open_process_request,
    (dump_func)dump_open_thread_request,
    (dump_func)dump_select_request,
    (dump_func)dump_create_event_request,
    (dump_func)dump_event_op_request,
    (dump_func)dump_query_event_request,
    (dump_func)dump_open_event_request,
    (dump_func)dump_create_keyed_event_request,
    (dump_func)dump_open_keyed_event_request,
    (dump_func)dump_create_mutex_request,
    (dump_func)dump_release_mutex_request,
    (dump_func)dump_open_mutex_request,
    (dump_func)dump_query_mutex_request,
    (dump_func)dump_create_semaphore_request,
    (dump_func)dump_release_semaphore_request,
    (dump_func)dump_query_semaphore_request,
    (dump_func)dump_open_semaphore_request,
    (dump_func)dump_create_file_request,
    (dump_func)dump_open_file_object_request,
    (dump_func)dump_alloc_file_handle_request,
    (dump_func)dump_get_handle_unix_name_request,
    (dump_func)dump_get_handle_fd_request,
    (dump_func)dump_get_directory_cache_entry_request,
    (dump_func)dump_flush_request,
    (dump_func)dump_get_file_info_request,
    (dump_func)dump_get_volume_info_request,
    (dump_func)dump_lock_file_request,
    (dump_func)dump_unlock_file_request,
    (dump_func)dump_recv_socket_request,
    (dump_func)dump_send_socket_request,
    (dump_func)dump_get_next_console_request_request,
    (dump_func)dump_read_directory_changes_request,
    (dump_func)dump_read_change_request,
    (dump_func)dump_create_mapping_request,
    (dump_func)dump_open_mapping_request,
    (dump_func)dump_get_mapping_info_request,
    (dump_func)dump_map_view_request,
    (dump_func)dump_unmap_view_request,
    (dump_func)dump_get_mapping_committed_range_request,
    (dump_func)dump_add_mapping_committed_range_request,
    (dump_func)dump_is_same_mapping_request,
    (dump_func)dump_get_mapping_filename_request,
    (dump_func)dump_list_processes_request,
    (dump_func)dump_create_debug_obj_request,
    (dump_func)dump_wait_debug_event_request,
    (dump_func)dump_queue_exception_event_request,
    (dump_func)dump_get_exception_status_request,
    (dump_func)dump_continue_debug_event_request,
    (dump_func)dump_debug_process_request,
    (dump_func)dump_set_debug_obj_info_request,
    (dump_func)dump_read_process_memory_request,
    (dump_func)dump_write_process_memory_request,
    (dump_func)dump_create_key_request,
    (dump_func)dump_open_key_request,
    (dump_func)dump_delete_key_request,
    (dump_func)dump_flush_key_request,
    (dump_func)dump_enum_key_request,
    (dump_func)dump_set_key_value_request,
    (dump_func)dump_get_key_value_request,
    (dump_func)dump_enum_key_value_request,
    (dump_func)dump_delete_key_value_request,
    (dump_func)dump_load_registry_request,
    (dump_func)dump_unload_registry_request,
    (dump_func)dump_save_registry_request,
    (dump_func)dump_set_registry_notification_request,
    (dump_func)dump_create_timer_request,
    (dump_func)dump_open_timer_request,
    (dump_func)dump_set_timer_request,
    (dump_func)dump_cancel_timer_request,
    (dump_func)dump_get_timer_info_request,
    (dump_func)dump_get_thread_context_request,
    (dump_func)dump_set_thread_context_request,
    (dump_func)dump_get_selector_entry_request,
    (dump_func)dump_add_atom_request,
    (dump_func)dump_delete_atom_request,
    (dump_func)dump_find_atom_request,
    (dump_func)dump_get_atom_information_request,
    (dump_func)dump_get_msg_queue_request,
    (dump_func)dump_set_queue_fd_request,
    (dump_func)dump_set_queue_mask_request,
    (dump_func)dump_get_queue_status_request,
    (dump_func)dump_get_process_idle_event_request,
    (dump_func)dump_send_message_request,
    (dump_func)dump_post_quit_message_request,
    (dump_func)dump_send_hardware_message_request,
    (dump_func)dump_get_message_request,
    (dump_func)dump_reply_message_request,
    (dump_func)dump_accept_hardware_message_request,
    (dump_func)dump_get_message_reply_request,
    (dump_func)dump_set_win_timer_request,
    (dump_func)dump_kill_win_timer_request,
    (dump_func)dump_is_window_hung_request,
    (dump_func)dump_get_serial_info_request,
    (dump_func)dump_set_serial_info_request,
    (dump_func)dump_register_async_request,
    (dump_func)dump_cancel_async_request,
    (dump_func)dump_get_async_result_request,
    (dump_func)dump_read_request,
    (dump_func)dump_write_request,
    (dump_func)dump_ioctl_request,
    (dump_func)dump_set_irp_result_request,
    (dump_func)dump_create_named_pipe_request,
    (dump_func)dump_set_named_pipe_info_request,
    (dump_func)dump_create_window_request,
    (dump_func)dump_destroy_window_request,
    (dump_func)dump_get_desktop_window_request,
    (dump_func)dump_set_window_owner_request,
    (dump_func)dump_get_window_info_request,
    (dump_func)dump_set_window_info_request,
    (dump_func)dump_set_parent_request,
    (dump_func)dump_get_window_parents_request,
    (dump_func)dump_get_window_children_request,
    (dump_func)dump_get_window_children_from_point_request,
    (dump_func)dump_get_window_tree_request,
    (dump_func)dump_set_window_pos_request,
    (dump_func)dump_get_window_rectangles_request,
    (dump_func)dump_get_window_text_request,
    (dump_func)dump_set_window_text_request,
    (dump_func)dump_get_windows_offset_request,
    (dump_func)dump_get_visible_region_request,
    (dump_func)dump_get_surface_region_request,
    (dump_func)dump_get_window_region_request,
    (dump_func)dump_set_window_region_request,
    (dump_func)dump_get_update_region_request,
    (dump_func)dump_update_window_zorder_request,
    (dump_func)dump_redraw_window_request,
    (dump_func)dump_set_window_property_request,
    (dump_func)dump_remove_window_property_request,
    (dump_func)dump_get_window_property_request,
    (dump_func)dump_get_window_properties_request,
    (dump_func)dump_create_winstation_request,
    (dump_func)dump_open_winstation_request,
    (dump_func)dump_close_winstation_request,
    (dump_func)dump_get_process_winstation_request,
    (dump_func)dump_set_process_winstation_request,
    (dump_func)dump_enum_winstation_request,
    (dump_func)dump_create_desktop_request,
    (dump_func)dump_open_desktop_request,
    (dump_func)dump_open_input_desktop_request,
    (dump_func)dump_close_desktop_request,
    (dump_func)dump_get_thread_desktop_request,
    (dump_func)dump_set_thread_desktop_request,
    (dump_func)dump_enum_desktop_request,
    (dump_func)dump_set_user_object_info_request,
    (dump_func)dump_register_hotkey_request,
    (dump_func)dump_unregister_hotkey_request,
    (dump_func)dump_attach_thread_input_request,
    (dump_func)dump_get_thread_input_request,
    (dump_func)dump_get_last_input_time_request,
    (dump_func)dump_get_key_state_request,
    (dump_func)dump_set_key_state_request,
    (dump_func)dump_set_foreground_window_request,
    (dump_func)dump_set_focus_window_request,
    (dump_func)dump_set_active_window_request,
    (dump_func)dump_set_capture_window_request,
    (dump_func)dump_set_caret_window_request,
    (dump_func)dump_set_caret_info_request,
    (dump_func)dump_set_hook_request,
    (dump_func)dump_remove_hook_request,
    (dump_func)dump_start_hook_chain_request,
    (dump_func)dump_finish_hook_chain_request,
    (dump_func)dump_get_hook_info_request,
    (dump_func)dump_create_class_request,
    (dump_func)dump_destroy_class_request,
    (dump_func)dump_set_class_info_request,
    (dump_func)dump_open_clipboard_request,
    (dump_func)dump_close_clipboard_request,
    (dump_func)dump_empty_clipboard_request,
    (dump_func)dump_set_clipboard_data_request,
    (dump_func)dump_get_clipboard_data_request,
    (dump_func)dump_get_clipboard_formats_request,
    (dump_func)dump_enum_clipboard_formats_request,
    (dump_func)dump_release_clipboard_request,
    (dump_func)dump_get_clipboard_info_request,
    (dump_func)dump_set_clipboard_viewer_request,
    (dump_func)dump_add_clipboard_listener_request,
    (dump_func)dump_remove_clipboard_listener_request,
    (dump_func)dump_open_token_request,
    (dump_func)dump_set_global_windows_request,
    (dump_func)dump_adjust_token_privileges_request,
    (dump_func)dump_get_token_privileges_request,
    (dump_func)dump_check_token_privileges_request,
    (dump_func)dump_duplicate_token_request,
    (dump_func)dump_filter_token_request,
    (dump_func)dump_access_check_request,
    (dump_func)dump_get_token_sid_request,
    (dump_func)dump_get_token_groups_request,
    (dump_func)dump_get_token_default_dacl_request,
    (dump_func)dump_set_token_default_dacl_request,
    (dump_func)dump_set_security_object_request,
    (dump_func)dump_get_security_object_request,
    (dump_func)dump_get_system_handles_request,
    (dump_func)dump_create_mailslot_request,
    (dump_func)dump_set_mailslot_info_request,
    (dump_func)dump_create_directory_request,
    (dump_func)dump_open_directory_request,
    (dump_func)dump_get_directory_entry_request,
    (dump_func)dump_create_symlink_request,
    (dump_func)dump_open_symlink_request,
    (dump_func)dump_query_symlink_request,
    (dump_func)dump_get_object_info_request,
    (dump_func)dump_get_object_name_request,
    (dump_func)dump_get_object_type_request,
    (dump_func)dump_get_object_types_request,
    (dump_func)dump_allocate_locally_unique_id_request,
    (dump_func)dump_create_device_manager_request,
    (dump_func)dump_create_device_request,
    (dump_func)dump_delete_device_request,
    (dump_func)dump_get_next_device_request_request,
    (dump_func)dump_get_kernel_object_ptr_request,
    (dump_func)dump_set_kernel_object_ptr_request,
    (dump_func)dump_grab_kernel_object_request,
    (dump_func)dump_release_kernel_object_request,
    (dump_func)dump_get_kernel_object_handle_request,
    (dump_func)dump_make_process_system_request,
    (dump_func)dump_get_token_info_request,
    (dump_func)dump_create_linked_token_request,
    (dump_func)dump_create_completion_request,
    (dump_func)dump_open_completion_request,
    (dump_func)dump_add_completion_request,
    (dump_func)dump_remove_completion_request,
    (dump_func)dump_query_completion_request,
    (dump_func)dump_set_completion_info_request,
    (dump_func)dump_add_fd_completion_request,
    (dump_func)dump_set_fd_completion_mode_request,
    (dump_func)dump_set_fd_disp_info_request,
    (dump_func)dump_set_fd_name_info_request,
    (dump_func)dump_set_fd_eof_info_request,
    (dump_func)dump_get_window_layered_info_request,
    (dump_func)dump_set_window_layered_info_request,
    (dump_func)dump_alloc_user_handle_request,
    (dump_func)dump_free_user_handle_request,
    (dump_func)dump_set_cursor_request,
    (dump_func)dump_get_cursor_history_request,
    (dump_func)dump_get_rawinput_buffer_request,
    (dump_func)dump_update_rawinput_devices_request,
    (dump_func)dump_get_rawinput_devices_request,
    (dump_func)dump_create_job_request,
    (dump_func)dump_open_job_request,
    (dump_func)dump_assign_job_request,
    (dump_func)dump_process_in_job_request,
    (dump_func)dump_set_job_limits_request,
    (dump_func)dump_set_job_completion_port_request,
    (dump_func)dump_get_job_info_request,
    (dump_func)dump_terminate_job_request,
    (dump_func)dump_suspend_process_request,
    (dump_func)dump_resume_process_request,
    (dump_func)dump_get_next_thread_request,
};

static const dump_func reply_dumpers[REQ_NB_REQUESTS] = {
    (dump_func)dump_new_process_reply,
    (dump_func)dump_get_new_process_info_reply,
    (dump_func)dump_new_thread_reply,
    (dump_func)dump_get_startup_info_reply,
    (dump_func)dump_init_process_done_reply,
    (dump_func)dump_init_first_thread_reply,
    (dump_func)dump_init_thread_reply,
    (dump_func)dump_terminate_process_reply,
    (dump_func)dump_terminate_thread_reply,
    (dump_func)dump_get_process_info_reply,
    (dump_func)dump_get_process_debug_info_reply,
    (dump_func)dump_get_process_image_name_reply,
    (dump_func)dump_get_process_vm_counters_reply,
    NULL,
    (dump_func)dump_get_thread_info_reply,
    (dump_func)dump_get_thread_times_reply,
    NULL,
    (dump_func)dump_suspend_thread_reply,
    (dump_func)dump_resume_thread_reply,
    (dump_func)dump_queue_apc_reply,
    (dump_func)dump_get_apc_result_reply,
    NULL,
    (dump_func)dump_set_handle_info_reply,
    (dump_func)dump_dup_handle_reply,
    NULL,
    NULL,
    (dump_func)dump_open_process_reply,
    (dump_func)dump_open_thread_reply,
    (dump_func)dump_select_reply,
    (dump_func)dump_create_event_reply,
    (dump_func)dump_event_op_reply,
    (dump_func)dump_query_event_reply,
    (dump_func)dump_open_event_reply,
    (dump_func)dump_create_keyed_event_reply,
    (dump_func)dump_open_keyed_event_reply,
    (dump_func)dump_create_mutex_reply,
    (dump_func)dump_release_mutex_reply,
    (dump_func)dump_open_mutex_reply,
    (dump_func)dump_query_mutex_reply,
    (dump_func)dump_create_semaphore_reply,
    (dump_func)dump_release_semaphore_reply,
    (dump_func)dump_query_semaphore_reply,
    (dump_func)dump_open_semaphore_reply,
    (dump_func)dump_create_file_reply,
    (dump_func)dump_open_file_object_reply,
    (dump_func)dump_alloc_file_handle_reply,
    (dump_func)dump_get_handle_unix_name_reply,
    (dump_func)dump_get_handle_fd_reply,
    (dump_func)dump_get_directory_cache_entry_reply,
    (dump_func)dump_flush_reply,
    (dump_func)dump_get_file_info_reply,
    (dump_func)dump_get_volume_info_reply,
    (dump_func)dump_lock_file_reply,
    NULL,
    (dump_func)dump_recv_socket_reply,
    (dump_func)dump_send_socket_reply,
    (dump_func)dump_get_next_console_request_reply,
    NULL,
    (dump_func)dump_read_change_reply,
    (dump_func)dump_create_mapping_reply,
    (dump_func)dump_open_mapping_reply,
    (dump_func)dump_get_mapping_info_reply,
    NULL,
    NULL,
    (dump_func)dump_get_mapping_committed_range_reply,
    NULL,
    NULL,
    (dump_func)dump_get_mapping_filename_reply,
    (dump_func)dump_list_processes_reply,
    (dump_func)dump_create_debug_obj_reply,
    (dump_func)dump_wait_debug_event_reply,
    (dump_func)dump_queue_exception_event_reply,
    NULL,
    NULL,
    NULL,
    NULL,
    (dump_func)dump_read_process_memory_reply,
    NULL,
    (dump_func)dump_create_key_reply,
    (dump_func)dump_open_key_reply,
    NULL,
    NULL,
    (dump_func)dump_enum_key_reply,
    NULL,
    (dump_func)dump_get_key_value_reply,
    (dump_func)dump_enum_key_value_reply,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    (dump_func)dump_create_timer_reply,
    (dump_func)dump_open_timer_reply,
    (dump_func)dump_set_timer_reply,
    (dump_func)dump_cancel_timer_reply,
    (dump_func)dump_get_timer_info_reply,
    (dump_func)dump_get_thread_context_reply,
    (dump_func)dump_set_thread_context_reply,
    (dump_func)dump_get_selector_entry_reply,
    (dump_func)dump_add_atom_reply,
    NULL,
    (dump_func)dump_find_atom_reply,
    (dump_func)dump_get_atom_information_reply,
    (dump_func)dump_get_msg_queue_reply,
    NULL,
    (dump_func)dump_set_queue_mask_reply,
    (dump_func)dump_get_queue_status_reply,
    (dump_func)dump_get_process_idle_event_reply,
    NULL,
    NULL,
    (dump_func)dump_send_hardware_message_reply,
    (dump_func)dump_get_message_reply,
    NULL,
    NULL,
    (dump_func)dump_get_message_reply_reply,
    (dump_func)dump_set_win_timer_reply,
    NULL,
    (dump_func)dump_is_window_hung_reply,
    (dump_func)dump_get_serial_info_reply,
    NULL,
    NULL,
    NULL,
    (dump_func)dump_get_async_result_reply,
    (dump_func)dump_read_reply,
    (dump_func)dump_write_reply,
    (dump_func)dump_ioctl_reply,
    NULL,
    (dump_func)dump_create_named_pipe_reply,
    NULL,
    (dump_func)dump_create_window_reply,
    NULL,
    (dump_func)dump_get_desktop_window_reply,
    (dump_func)dump_set_window_owner_reply,
    (dump_func)dump_get_window_info_reply,
    (dump_func)dump_set_window_info_reply,
    (dump_func)dump_set_parent_reply,
    (dump_func)dump_get_window_parents_reply,
    (dump_func)dump_get_window_children_reply,
    (dump_func)dump_get_window_children_from_point_reply,
    (dump_func)dump_get_window_tree_reply,
    (dump_func)dump_set_window_pos_reply,
    (dump_func)dump_get_window_rectangles_reply,
    (dump_func)dump_get_window_text_reply,
    NULL,
    (dump_func)dump_get_windows_offset_reply,
    (dump_func)dump_get_visible_region_reply,
    (dump_func)dump_get_surface_region_reply,
    (dump_func)dump_get_window_region_reply,
    NULL,
    (dump_func)dump_get_update_region_reply,
    NULL,
    NULL,
    NULL,
    (dump_func)dump_remove_window_property_reply,
    (dump_func)dump_get_window_property_reply,
    (dump_func)dump_get_window_properties_reply,
    (dump_func)dump_create_winstation_reply,
    (dump_func)dump_open_winstation_reply,
    NULL,
    (dump_func)dump_get_process_winstation_reply,
    NULL,
    (dump_func)dump_enum_winstation_reply,
    (dump_func)dump_create_desktop_reply,
    (dump_func)dump_open_desktop_reply,
    (dump_func)dump_open_input_desktop_reply,
    NULL,
    (dump_func)dump_get_thread_desktop_reply,
    NULL,
    (dump_func)dump_enum_desktop_reply,
    (dump_func)dump_set_user_object_info_reply,
    (dump_func)dump_register_hotkey_reply,
    (dump_func)dump_unregister_hotkey_reply,
    NULL,
    (dump_func)dump_get_thread_input_reply,
    (dump_func)dump_get_last_input_time_reply,
    (dump_func)dump_get_key_state_reply,
    NULL,
    (dump_func)dump_set_foreground_window_reply,
    (dump_func)dump_set_focus_window_reply,
    (dump_func)dump_set_active_window_reply,
    (dump_func)dump_set_capture_window_reply,
    (dump_func)dump_set_caret_window_reply,
    (dump_func)dump_set_caret_info_reply,
    (dump_func)dump_set_hook_reply,
    (dump_func)dump_remove_hook_reply,
    (dump_func)dump_start_hook_chain_reply,
    NULL,
    (dump_func)dump_get_hook_info_reply,
    (dump_func)dump_create_class_reply,
    (dump_func)dump_destroy_class_reply,
    (dump_func)dump_set_class_info_reply,
    (dump_func)dump_open_clipboard_reply,
    (dump_func)dump_close_clipboard_reply,
    NULL,
    (dump_func)dump_set_clipboard_data_reply,
    (dump_func)dump_get_clipboard_data_reply,
    (dump_func)dump_get_clipboard_formats_reply,
    (dump_func)dump_enum_clipboard_formats_reply,
    (dump_func)dump_release_clipboard_reply,
    (dump_func)dump_get_clipboard_info_reply,
    (dump_func)dump_set_clipboard_viewer_reply,
    NULL,
    NULL,
    (dump_func)dump_open_token_reply,
    (dump_func)dump_set_global_windows_reply,
    (dump_func)dump_adjust_token_privileges_reply,
    (dump_func)dump_get_token_privileges_reply,
    (dump_func)dump_check_token_privileges_reply,
    (dump_func)dump_duplicate_token_reply,
    (dump_func)dump_filter_token_reply,
    (dump_func)dump_access_check_reply,
    (dump_func)dump_get_token_sid_reply,
    (dump_func)dump_get_token_groups_reply,
    (dump_func)dump_get_token_default_dacl_reply,
    NULL,
    NULL,
    (dump_func)dump_get_security_object_reply,
    (dump_func)dump_get_system_handles_reply,
    (dump_func)dump_create_mailslot_reply,
    (dump_func)dump_set_mailslot_info_reply,
    (dump_func)dump_create_directory_reply,
    (dump_func)dump_open_directory_reply,
    (dump_func)dump_get_directory_entry_reply,
    (dump_func)dump_create_symlink_reply,
    (dump_func)dump_open_symlink_reply,
    (dump_func)dump_query_symlink_reply,
    (dump_func)dump_get_object_info_reply,
    (dump_func)dump_get_object_name_reply,
    (dump_func)dump_get_object_type_reply,
    (dump_func)dump_get_object_types_reply,
    (dump_func)dump_allocate_locally_unique_id_reply,
    (dump_func)dump_create_device_manager_reply,
    NULL,
    NULL,
    (dump_func)dump_get_next_device_request_reply,
    (dump_func)dump_get_kernel_object_ptr_reply,
    NULL,
    NULL,
    NULL,
    (dump_func)dump_get_kernel_object_handle_reply,
    (dump_func)dump_make_process_system_reply,
    (dump_func)dump_get_token_info_reply,
    (dump_func)dump_create_linked_token_reply,
    (dump_func)dump_create_completion_reply,
    (dump_func)dump_open_completion_reply,
    NULL,
    (dump_func)dump_remove_completion_reply,
    (dump_func)dump_query_completion_reply,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    (dump_func)dump_get_window_layered_info_reply,
    NULL,
    (dump_func)dump_alloc_user_handle_reply,
    NULL,
    (dump_func)dump_set_cursor_reply,
    (dump_func)dump_get_cursor_history_reply,
    (dump_func)dump_get_rawinput_buffer_reply,
    NULL,
    (dump_func)dump_get_rawinput_devices_reply,
    (dump_func)dump_create_job_reply,
    (dump_func)dump_open_job_reply,
    NULL,
    NULL,
    NULL,
    NULL,
    (dump_func)dump_get_job_info_reply,
    NULL,
    NULL,
    NULL,
    (dump_func)dump_get_next_thread_reply,
};

static const char * const req_names[REQ_NB_REQUESTS] = {
    "new_process",
    "get_new_process_info",
    "new_thread",
    "get_startup_info",
    "init_process_done",
    "init_first_thread",
    "init_thread",
    "terminate_process",
    "terminate_thread",
    "get_process_info",
    "get_process_debug_info",
    "get_process_image_name",
    "get_process_vm_counters",
    "set_process_info",
    "get_thread_info",
    "get_thread_times",
    "set_thread_info",
    "suspend_thread",
    "resume_thread",
    "queue_apc",
    "get_apc_result",
    "close_handle",
    "set_handle_info",
    "dup_handle",
    "compare_objects",
    "make_temporary",
    "open_process",
    "open_thread",
    "select",
    "create_event",
    "event_op",
    "query_event",
    "open_event",
    "create_keyed_event",
    "open_keyed_event",
    "create_mutex",
    "release_mutex",
    "open_mutex",
    "query_mutex",
    "create_semaphore",
    "release_semaphore",
    "query_semaphore",
    "open_semaphore",
    "create_file",
    "open_file_object",
    "alloc_file_handle",
    "get_handle_unix_name",
    "get_handle_fd",
    "get_directory_cache_entry",
    "flush",
    "get_file_info",
    "get_volume_info",
    "lock_file",
    "unlock_file",
    "recv_socket",
    "send_socket",
    "get_next_console_request",
    "read_directory_changes",
    "read_change",
    "create_mapping",
    "open_mapping",
    "get_mapping_info",
    "map_view",
    "unmap_view",
    "get_mapping_committed_range",
    "add_mapping_committed_range",
    "is_same_mapping",
    "get_mapping_filename",
    "list_processes",
    "create_debug_obj",
    "wait_debug_event",
    "queue_exception_event",
    "get_exception_status",
    "continue_debug_event",
    "debug_process",
    "set_debug_obj_info",
    "read_process_memory",
    "write_process_memory",
    "create_key",
    "open_key",
    "delete_key",
    "flush_key",
    "enum_key",
    "set_key_value",
    "get_key_value",
    "enum_key_value",
    "delete_key_value",
    "load_registry",
    "unload_registry",
    "save_registry",
    "set_registry_notification",
    "create_timer",
    "open_timer",
    "set_timer",
    "cancel_timer",
    "get_timer_info",
    "get_thread_context",
    "set_thread_context",
    "get_selector_entry",
    "add_atom",
    "delete_atom",
    "find_atom",
    "get_atom_information",
    "get_msg_queue",
    "set_queue_fd",
    "set_queue_mask",
    "get_queue_status",
    "get_process_idle_event",
    "send_message",
    "post_quit_message",
    "send_hardware_message",
    "get_message",
    "reply_message",
    "accept_hardware_message",
    "get_message_reply",
    "set_win_timer",
    "kill_win_timer",
    "is_window_hung",
    "get_serial_info",
    "set_serial_info",
    "register_async",
    "cancel_async",
    "get_async_result",
    "read",
    "write",
    "ioctl",
    "set_irp_result",
    "create_named_pipe",
    "set_named_pipe_info",
    "create_window",
    "destroy_window",
    "get_desktop_window",
    "set_window_owner",
    "get_window_info",
    "set_window_info",
    "set_parent",
    "get_window_parents",
    "get_window_children",
    "get_window_children_from_point",
    "get_window_tree",
    "set_window_pos",
    "get_window_rectangles",
    "get_window_text",
    "set_window_text",
    "get_windows_offset",
    "get_visible_region",
    "get_surface_region",
    "get_window_region",
    "set_window_region",
    "get_update_region",
    "update_window_zorder",
    "redraw_window",
    "set_window_property",
    "remove_window_property",
    "get_window_property",
    "get_window_properties",
    "create_winstation",
    "open_winstation",
    "close_winstation",
    "get_process_winstation",
    "set_process_winstation",
    "enum_winstation",
    "create_desktop",
    "open_desktop",
    "open_input_desktop",
    "close_desktop",
    "get_thread_desktop",
    "set_thread_desktop",
    "enum_desktop",
    "set_user_object_info",
    "register_hotkey",
    "unregister_hotkey",
    "attach_thread_input",
    "get_thread_input",
    "get_last_input_time",
    "get_key_state",
    "set_key_state",
    "set_foreground_window",
    "set_focus_window",
    "set_active_window",
    "set_capture_window",
    "set_caret_window",
    "set_caret_info",
    "set_hook",
    "remove_hook",
    "start_hook_chain",
    "finish_hook_chain",
    "get_hook_info",
    "create_class",
    "destroy_class",
    "set_class_info",
    "open_clipboard",
    "close_clipboard",
    "empty_clipboard",
    "set_clipboard_data",
    "get_clipboard_data",
    "get_clipboard_formats",
    "enum_clipboard_formats",
    "release_clipboard",
    "get_clipboard_info",
    "set_clipboard_viewer",
    "add_clipboard_listener",
    "remove_clipboard_listener",
    "open_token",
    "set_global_windows",
    "adjust_token_privileges",
    "get_token_privileges",
    "check_token_privileges",
    "duplicate_token",
    "filter_token",
    "access_check",
    "get_token_sid",
    "get_token_groups",
    "get_token_default_dacl",
    "set_token_default_dacl",
    "set_security_object",
    "get_security_object",
    "get_system_handles",
    "create_mailslot",
    "set_mailslot_info",
    "create_directory",
    "open_directory",
    "get_directory_entry",
    "create_symlink",
    "open_symlink",
    "query_symlink",
    "get_object_info",
    "get_object_name",
    "get_object_type",
    "get_object_types",
    "allocate_locally_unique_id",
    "create_device_manager",
    "create_device",
    "delete_device",
    "get_next_device_request",
    "get_kernel_object_ptr",
    "set_kernel_object_ptr",
    "grab_kernel_object",
    "release_kernel_object",
    "get_kernel_object_handle",
    "make_process_system",
    "get_token_info",
    "create_linked_token",
    "create_completion",
    "open_completion",
    "add_completion",
    "remove_completion",
    "query_completion",
    "set_completion_info",
    "add_fd_completion",
    "set_fd_completion_mode",
    "set_fd_disp_info",
    "set_fd_name_info",
    "set_fd_eof_info",
    "get_window_layered_info",
    "set_window_layered_info",
    "alloc_user_handle",
    "free_user_handle",
    "set_cursor",
    "get_cursor_history",
    "get_rawinput_buffer",
    "update_rawinput_devices",
    "get_rawinput_devices",
    "create_job",
    "open_job",
    "assign_job",
    "process_in_job",
    "set_job_limits",
    "set_job_completion_port",
    "get_job_info",
    "terminate_job",
    "suspend_process",
    "resume_process",
    "get_next_thread",
};

static const struct
{
    const char  *name;
    unsigned int value;
} status_names[] =
{
    { "ABANDONED_WAIT_0",            STATUS_ABANDONED_WAIT_0 },
    { "ACCESS_DENIED",               STATUS_ACCESS_DENIED },
    { "ACCESS_VIOLATION",            STATUS_ACCESS_VIOLATION },
    { "ADDRESS_ALREADY_ASSOCIATED",  STATUS_ADDRESS_ALREADY_ASSOCIATED },
    { "ALERTED",                     STATUS_ALERTED },
    { "BAD_DEVICE_TYPE",             STATUS_BAD_DEVICE_TYPE },
    { "BAD_IMPERSONATION_LEVEL",     STATUS_BAD_IMPERSONATION_LEVEL },
    { "BUFFER_OVERFLOW",             STATUS_BUFFER_OVERFLOW },
    { "BUFFER_TOO_SMALL",            STATUS_BUFFER_TOO_SMALL },
    { "CANCELLED",                   STATUS_CANCELLED },
    { "CANNOT_DELETE",               STATUS_CANNOT_DELETE },
    { "CANT_OPEN_ANONYMOUS",         STATUS_CANT_OPEN_ANONYMOUS },
    { "CHILD_MUST_BE_VOLATILE",      STATUS_CHILD_MUST_BE_VOLATILE },
    { "CONNECTION_ABORTED",          STATUS_CONNECTION_ABORTED },
    { "CONNECTION_ACTIVE",           STATUS_CONNECTION_ACTIVE },
    { "CONNECTION_REFUSED",          STATUS_CONNECTION_REFUSED },
    { "CONNECTION_RESET",            STATUS_CONNECTION_RESET },
    { "DEBUGGER_INACTIVE",           STATUS_DEBUGGER_INACTIVE },
    { "DEVICE_BUSY",                 STATUS_DEVICE_BUSY },
    { "DEVICE_NOT_READY",            STATUS_DEVICE_NOT_READY },
    { "DIRECTORY_NOT_EMPTY",         STATUS_DIRECTORY_NOT_EMPTY },
    { "DISK_FULL",                   STATUS_DISK_FULL },
    { "DLL_NOT_FOUND",               STATUS_DLL_NOT_FOUND },
    { "ERROR_CLASS_ALREADY_EXISTS",  0xc0010000 | ERROR_CLASS_ALREADY_EXISTS },
    { "ERROR_CLASS_DOES_NOT_EXIST",  0xc0010000 | ERROR_CLASS_DOES_NOT_EXIST },
    { "ERROR_CLASS_HAS_WINDOWS",     0xc0010000 | ERROR_CLASS_HAS_WINDOWS },
    { "ERROR_CLIPBOARD_NOT_OPEN",    0xc0010000 | ERROR_CLIPBOARD_NOT_OPEN },
    { "ERROR_HOTKEY_ALREADY_REGISTERED", 0xc0010000 | ERROR_HOTKEY_ALREADY_REGISTERED },
    { "ERROR_HOTKEY_NOT_REGISTERED", 0xc0010000 | ERROR_HOTKEY_NOT_REGISTERED },
    { "ERROR_INVALID_CURSOR_HANDLE", 0xc0010000 | ERROR_INVALID_CURSOR_HANDLE },
    { "ERROR_INVALID_INDEX",         0xc0010000 | ERROR_INVALID_INDEX },
    { "ERROR_INVALID_WINDOW_HANDLE", 0xc0010000 | ERROR_INVALID_WINDOW_HANDLE },
    { "ERROR_NO_MORE_USER_HANDLES",  0xc0010000 | ERROR_NO_MORE_USER_HANDLES },
    { "ERROR_WINDOW_OF_OTHER_THREAD", 0xc0010000 | ERROR_WINDOW_OF_OTHER_THREAD },
    { "FILE_DELETED",                STATUS_FILE_DELETED },
    { "FILE_INVALID",                STATUS_FILE_INVALID },
    { "FILE_IS_A_DIRECTORY",         STATUS_FILE_IS_A_DIRECTORY },
    { "FILE_LOCK_CONFLICT",          STATUS_FILE_LOCK_CONFLICT },
    { "GENERIC_NOT_MAPPED",          STATUS_GENERIC_NOT_MAPPED },
    { "HANDLES_CLOSED",              STATUS_HANDLES_CLOSED },
    { "HANDLE_NOT_CLOSABLE",         STATUS_HANDLE_NOT_CLOSABLE },
    { "HOST_UNREACHABLE",            STATUS_HOST_UNREACHABLE },
    { "ILLEGAL_FUNCTION",            STATUS_ILLEGAL_FUNCTION },
    { "IMAGE_NOT_AT_BASE",           STATUS_IMAGE_NOT_AT_BASE },
    { "INFO_LENGTH_MISMATCH",        STATUS_INFO_LENGTH_MISMATCH },
    { "INSTANCE_NOT_AVAILABLE",      STATUS_INSTANCE_NOT_AVAILABLE },
    { "INSUFFICIENT_RESOURCES",      STATUS_INSUFFICIENT_RESOURCES },
    { "INVALID_ADDRESS",             STATUS_INVALID_ADDRESS },
    { "INVALID_ADDRESS_COMPONENT",   STATUS_INVALID_ADDRESS_COMPONENT },
    { "INVALID_CID",                 STATUS_INVALID_CID },
    { "INVALID_CONNECTION",          STATUS_INVALID_CONNECTION },
    { "INVALID_DEVICE_REQUEST",      STATUS_INVALID_DEVICE_REQUEST },
    { "INVALID_FILE_FOR_SECTION",    STATUS_INVALID_FILE_FOR_SECTION },
    { "INVALID_HANDLE",              STATUS_INVALID_HANDLE },
    { "INVALID_IMAGE_FORMAT",        STATUS_INVALID_IMAGE_FORMAT },
    { "INVALID_IMAGE_NE_FORMAT",     STATUS_INVALID_IMAGE_NE_FORMAT },
    { "INVALID_IMAGE_NOT_MZ",        STATUS_INVALID_IMAGE_NOT_MZ },
    { "INVALID_IMAGE_PROTECT",       STATUS_INVALID_IMAGE_PROTECT },
    { "INVALID_IMAGE_WIN_16",        STATUS_INVALID_IMAGE_WIN_16 },
    { "INVALID_IMAGE_WIN_64",        STATUS_INVALID_IMAGE_WIN_64 },
    { "INVALID_LOCK_SEQUENCE",       STATUS_INVALID_LOCK_SEQUENCE },
    { "INVALID_OWNER",               STATUS_INVALID_OWNER },
    { "INVALID_PARAMETER",           STATUS_INVALID_PARAMETER },
    { "INVALID_PIPE_STATE",          STATUS_INVALID_PIPE_STATE },
    { "INVALID_READ_MODE",           STATUS_INVALID_READ_MODE },
    { "INVALID_SECURITY_DESCR",      STATUS_INVALID_SECURITY_DESCR },
    { "IO_TIMEOUT",                  STATUS_IO_TIMEOUT },
    { "KERNEL_APC",                  STATUS_KERNEL_APC },
    { "KEY_DELETED",                 STATUS_KEY_DELETED },
    { "MAPPED_FILE_SIZE_ZERO",       STATUS_MAPPED_FILE_SIZE_ZERO },
    { "MUTANT_NOT_OWNED",            STATUS_MUTANT_NOT_OWNED },
    { "NAME_TOO_LONG",               STATUS_NAME_TOO_LONG },
    { "NETWORK_BUSY",                STATUS_NETWORK_BUSY },
    { "NETWORK_UNREACHABLE",         STATUS_NETWORK_UNREACHABLE },
    { "NOT_ALL_ASSIGNED",            STATUS_NOT_ALL_ASSIGNED },
    { "NOT_A_DIRECTORY",             STATUS_NOT_A_DIRECTORY },
    { "NOT_FOUND",                   STATUS_NOT_FOUND },
    { "NOT_IMPLEMENTED",             STATUS_NOT_IMPLEMENTED },
    { "NOT_MAPPED_VIEW",             STATUS_NOT_MAPPED_VIEW },
    { "NOT_REGISTRY_FILE",           STATUS_NOT_REGISTRY_FILE },
    { "NOT_SAME_DEVICE",             STATUS_NOT_SAME_DEVICE },
    { "NOT_SAME_OBJECT",             STATUS_NOT_SAME_OBJECT },
    { "NOT_SUPPORTED",               STATUS_NOT_SUPPORTED },
    { "NO_DATA_DETECTED",            STATUS_NO_DATA_DETECTED },
    { "NO_IMPERSONATION_TOKEN",      STATUS_NO_IMPERSONATION_TOKEN },
    { "NO_MEMORY",                   STATUS_NO_MEMORY },
    { "NO_MORE_ENTRIES",             STATUS_NO_MORE_ENTRIES },
    { "NO_SUCH_DEVICE",              STATUS_NO_SUCH_DEVICE },
    { "NO_SUCH_FILE",                STATUS_NO_SUCH_FILE },
    { "NO_TOKEN",                    STATUS_NO_TOKEN },
    { "OBJECT_NAME_COLLISION",       STATUS_OBJECT_NAME_COLLISION },
    { "OBJECT_NAME_EXISTS",          STATUS_OBJECT_NAME_EXISTS },
    { "OBJECT_NAME_INVALID",         STATUS_OBJECT_NAME_INVALID },
    { "OBJECT_NAME_NOT_FOUND",       STATUS_OBJECT_NAME_NOT_FOUND },
    { "OBJECT_PATH_INVALID",         STATUS_OBJECT_PATH_INVALID },
    { "OBJECT_PATH_NOT_FOUND",       STATUS_OBJECT_PATH_NOT_FOUND },
    { "OBJECT_PATH_SYNTAX_BAD",      STATUS_OBJECT_PATH_SYNTAX_BAD },
    { "OBJECT_TYPE_MISMATCH",        STATUS_OBJECT_TYPE_MISMATCH },
    { "PENDING",                     STATUS_PENDING },
    { "PIPE_BROKEN",                 STATUS_PIPE_BROKEN },
    { "PIPE_BUSY",                   STATUS_PIPE_BUSY },
    { "PIPE_CLOSING",                STATUS_PIPE_CLOSING },
    { "PIPE_CONNECTED",              STATUS_PIPE_CONNECTED },
    { "PIPE_DISCONNECTED",           STATUS_PIPE_DISCONNECTED },
    { "PIPE_EMPTY",                  STATUS_PIPE_EMPTY },
    { "PIPE_LISTENING",              STATUS_PIPE_LISTENING },
    { "PIPE_NOT_AVAILABLE",          STATUS_PIPE_NOT_AVAILABLE },
    { "PORT_NOT_SET",                STATUS_PORT_NOT_SET },
    { "PREDEFINED_HANDLE",           STATUS_PREDEFINED_HANDLE },
    { "PRIVILEGE_NOT_HELD",          STATUS_PRIVILEGE_NOT_HELD },
    { "PROCESS_IN_JOB",              STATUS_PROCESS_IN_JOB },
    { "PROCESS_IS_TERMINATING",      STATUS_PROCESS_IS_TERMINATING },
    { "PROCESS_NOT_IN_JOB",          STATUS_PROCESS_NOT_IN_JOB },
    { "REPARSE_POINT_NOT_RESOLVED",  STATUS_REPARSE_POINT_NOT_RESOLVED },
    { "SECTION_TOO_BIG",             STATUS_SECTION_TOO_BIG },
    { "SEMAPHORE_LIMIT_EXCEEDED",    STATUS_SEMAPHORE_LIMIT_EXCEEDED },
    { "SHARING_VIOLATION",           STATUS_SHARING_VIOLATION },
    { "SHUTDOWN_IN_PROGRESS",        STATUS_SHUTDOWN_IN_PROGRESS },
    { "SUSPEND_COUNT_EXCEEDED",      STATUS_SUSPEND_COUNT_EXCEEDED },
    { "THREAD_IS_TERMINATING",       STATUS_THREAD_IS_TERMINATING },
    { "TIMEOUT",                     STATUS_TIMEOUT },
    { "TOO_MANY_OPENED_FILES",       STATUS_TOO_MANY_OPENED_FILES },
    { "UNSUCCESSFUL",                STATUS_UNSUCCESSFUL },
    { "USER_APC",                    STATUS_USER_APC },
    { "USER_MAPPED_FILE",            STATUS_USER_MAPPED_FILE },
    { "VOLUME_DISMOUNTED",           STATUS_VOLUME_DISMOUNTED },
    { "WAS_LOCKED",                  STATUS_WAS_LOCKED },
    { "WSAEACCES",                   0xc0010000 | WSAEACCES },
    { "WSAEADDRINUSE",               0xc0010000 | WSAEADDRINUSE },
    { "WSAEADDRNOTAVAIL",            0xc0010000 | WSAEADDRNOTAVAIL },
    { "WSAEAFNOSUPPORT",             0xc0010000 | WSAEAFNOSUPPORT },
    { "WSAEALREADY",                 0xc0010000 | WSAEALREADY },
    { "WSAEBADF",                    0xc0010000 | WSAEBADF },
    { "WSAECONNABORTED",             0xc0010000 | WSAECONNABORTED },
    { "WSAECONNREFUSED",             0xc0010000 | WSAECONNREFUSED },
    { "WSAECONNRESET",               0xc0010000 | WSAECONNRESET },
    { "WSAEDESTADDRREQ",             0xc0010000 | WSAEDESTADDRREQ },
    { "WSAEDQUOT",                   0xc0010000 | WSAEDQUOT },
    { "WSAEFAULT",                   0xc0010000 | WSAEFAULT },
    { "WSAEHOSTDOWN",                0xc0010000 | WSAEHOSTDOWN },
    { "WSAEHOSTUNREACH",             0xc0010000 | WSAEHOSTUNREACH },
    { "WSAEINTR",                    0xc0010000 | WSAEINTR },
    { "WSAEINVAL",                   0xc0010000 | WSAEINVAL },
    { "WSAEISCONN",                  0xc0010000 | WSAEISCONN },
    { "WSAELOOP",                    0xc0010000 | WSAELOOP },
    { "WSAEMFILE",                   0xc0010000 | WSAEMFILE },
    { "WSAEMSGSIZE",                 0xc0010000 | WSAEMSGSIZE },
    { "WSAENAMETOOLONG",             0xc0010000 | WSAENAMETOOLONG },
    { "WSAENETDOWN",                 0xc0010000 | WSAENETDOWN },
    { "WSAENETRESET",                0xc0010000 | WSAENETRESET },
    { "WSAENETUNREACH",              0xc0010000 | WSAENETUNREACH },
    { "WSAENOBUFS",                  0xc0010000 | WSAENOBUFS },
    { "WSAENOPROTOOPT",              0xc0010000 | WSAENOPROTOOPT },
    { "WSAENOTCONN",                 0xc0010000 | WSAENOTCONN },
    { "WSAENOTEMPTY",                0xc0010000 | WSAENOTEMPTY },
    { "WSAENOTSOCK",                 0xc0010000 | WSAENOTSOCK },
    { "WSAEOPNOTSUPP",               0xc0010000 | WSAEOPNOTSUPP },
    { "WSAEPFNOSUPPORT",             0xc0010000 | WSAEPFNOSUPPORT },
    { "WSAEPROCLIM",                 0xc0010000 | WSAEPROCLIM },
    { "WSAEPROTONOSUPPORT",          0xc0010000 | WSAEPROTONOSUPPORT },
    { "WSAEPROTOTYPE",               0xc0010000 | WSAEPROTOTYPE },
    { "WSAEREMOTE",                  0xc0010000 | WSAEREMOTE },
    { "WSAESHUTDOWN",                0xc0010000 | WSAESHUTDOWN },
    { "WSAESOCKTNOSUPPORT",          0xc0010000 | WSAESOCKTNOSUPPORT },
    { "WSAESTALE",                   0xc0010000 | WSAESTALE },
    { "WSAETIMEDOUT",                0xc0010000 | WSAETIMEDOUT },
    { "WSAETOOMANYREFS",             0xc0010000 | WSAETOOMANYREFS },
    { "WSAEUSERS",                   0xc0010000 | WSAEUSERS },
    { "WSAEWOULDBLOCK",              0xc0010000 | WSAEWOULDBLOCK },
    { NULL, 0 }
};

/* ### make_requests end ### */
/* Everything above this line is generated automatically by tools/make_requests */

static const char *get_status_name( unsigned int status )
{
    int i;
    static char buffer[10];

    if (status)
    {
        for (i = 0; status_names[i].name; i++)
            if (status_names[i].value == status) return status_names[i].name;
    }
    sprintf( buffer, "%x", status );
    return buffer;
}

void trace_request(void)
{
    enum request req = current->req.request_header.req;
    if (req < REQ_NB_REQUESTS)
    {
        SERVER_LOG( LOG_ALWAYS, "%04x: %s(", current->id, req_names[req] );
        if (req_dumpers[req])
        {
            cur_data = get_req_data();
            cur_size = get_req_data_size();
            req_dumpers[req]( &current->req );
        }
        SERVER_LOG( LOG_ALWAYS, " )\n" );
    }
    else SERVER_LOG( LOG_ALWAYS, "%04x: %d(?)\n", current->id, req );
}

void trace_reply( enum request req, const union generic_reply *reply )
{
    if (req < REQ_NB_REQUESTS)
    {
        SERVER_LOG( LOG_ALWAYS, "%04x: %s() = %s",
                 current->id, req_names[req], get_status_name(current->error) );
        if (reply_dumpers[req])
        {
            SERVER_LOG( LOG_ALWAYS, " {" );
            cur_data = current->reply_data;
            cur_size = reply->reply_header.reply_size;
            reply_dumpers[req]( reply );
            SERVER_LOG( LOG_ALWAYS, " }" );
        }
        SERVER_LOG( LOG_ALWAYS, "\n" );
    }
    else SERVER_LOG( LOG_ALWAYS, "%04x: %d() = %s\n",
                  current->id, req, get_status_name(current->error) );
}
