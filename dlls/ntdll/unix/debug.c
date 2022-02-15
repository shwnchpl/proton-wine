/*
 * Debugging functions
 *
 * Copyright 2000 Alexandre Julliard
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

#if 0
#pragma makedep unix
#endif

#include "config.h"

#include <assert.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winnt.h"
#include "winternl.h"
#include "unix_private.h"
#include "wine/debug.h"

WINE_DECLARE_DEBUG_CHANNEL(pid);
WINE_DECLARE_DEBUG_CHANNEL(timestamp);
WINE_DECLARE_DEBUG_CHANNEL(microsecs);
WINE_DEFAULT_DEBUG_CHANNEL(ntdll);

struct debug_info
{
    unsigned int str_pos;       /* current position in strings buffer */
    unsigned int out_pos;       /* current position in output buffer */
    char         strings[1020]; /* buffer for temporary strings */
    char         output[1020];  /* current output line */
};

C_ASSERT( sizeof(struct debug_info) == 0x800 );

struct dbg_config
{
    unsigned char default_flags;
    int opts_sz;
    int opts_cnt;
    struct __wine_debug_option *opts;
};

static struct dbg_config log_config = {
    /* default_flags = */   (1 << __WINE_DBCL_ERR) | (1 << __WINE_DBCL_FIXME),
    /* opts_sz = */         0,
    /* opts_cnt = */        0,
    /* opts = */            NULL
};

static BOOL init_done;
static BOOL option_init_done = FALSE;
static struct debug_info initial_info;  /* debug info for initial thread */

static const char * const debug_classes[] = { "fixme", "err", "warn", "trace" };

/* get the debug info pointer for the current thread */
static inline struct debug_info *get_info(void)
{
    if (!init_done) return &initial_info;
#ifdef _WIN64
    return (struct debug_info *)((TEB32 *)((char *)NtCurrentTeb() + teb_offset) + 1);
#else
    return (struct debug_info *)(NtCurrentTeb() + 1);
#endif
}

/* add a string to the output buffer */
static int append_output( struct debug_info *info, const char *str, size_t len )
{
    if (len >= sizeof(info->output) - info->out_pos)
    {
       fprintf( stderr, "wine_dbg_log_output: debugstr buffer overflow (contents: '%s')\n", info->output );
       info->out_pos = 0;
       abort();
    }
    memcpy( info->output + info->out_pos, str, len );
    info->out_pos += len;
    return len;
}

/* add a new debug option at the end of the option list */
static void add_option( struct dbg_config *conf, const char *name, unsigned char set,
                        unsigned char clear )
{
    int min = 0, max = conf->opts_cnt - 1, pos, res;

    if (!name[0])  /* "all" option */
    {
        conf->default_flags = (conf->default_flags & ~clear) | set;
        return;
    }
    if (strlen(name) >= sizeof(conf->opts[0].name)) return;

    while (min <= max)
    {
        pos = (min + max) / 2;
        res = strcmp( name, conf->opts[pos].name );
        if (!res)
        {
            conf->opts[pos].flags = (conf->opts[pos].flags & ~clear) | set;
            return;
        }
        if (res < 0) max = pos - 1;
        else min = pos + 1;
    }
    if (conf->opts_cnt >= conf->opts_sz)
    {
        conf->opts_sz = max( conf->opts_sz * 2, 16 );
        conf->opts = realloc( conf->opts, conf->opts_sz * sizeof(conf->opts[0]) );
    }

    pos = min;
    if (pos < conf->opts_cnt)
        memmove( &conf->opts[pos + 1], &conf->opts[pos],
                (conf->opts_cnt - pos) * sizeof(conf->opts[0]) );
    strcpy( conf->opts[pos].name, name );
    conf->opts[pos].flags = (conf->default_flags & ~clear) | set;
    conf->opts_cnt++;
}

/* parse a set of debugging option specifications and add them to the option list */
static void parse_options( struct dbg_config *conf, const char *str )
{
    char *opt, *next, *options;
    unsigned int i;

    if (!(options = strdup(str))) return;
    for (opt = options; opt; opt = next)
    {
        const char *p;
        unsigned char set = 0, clear = 0;

        if ((next = strchr( opt, ',' ))) *next++ = 0;

        p = opt + strcspn( opt, "+-" );
        if (!p[0]) p = opt;  /* assume it's a debug channel name */

        if (p > opt)
        {
            for (i = 0; i < ARRAY_SIZE(debug_classes); i++)
            {
                int len = strlen(debug_classes[i]);
                if (len != (p - opt)) continue;
                if (!memcmp( opt, debug_classes[i], len ))  /* found it */
                {
                    if (*p == '+') set |= 1 << i;
                    else clear |= 1 << i;
                    break;
                }
            }
            if (i == ARRAY_SIZE(debug_classes)) /* bad class name, skip it */
                continue;
        }
        else
        {
            if (*p == '-') clear = ~0;
            else set = ~0;
        }
        if (*p == '+' || *p == '-') p++;
        if (!p[0]) continue;

        if (!strcmp( p, "all" ))
            conf->default_flags = (conf->default_flags & ~clear) | set;
        else
            add_option( conf, p, set, clear );
    }
    free( options );
}

/* print the usage message */
static void debug_usage(void)
{
    static const char usage[] =
        "Syntax of the WINEDEBUG variable:\n"
        "  WINEDEBUG=[class]+xxx,[class]-yyy,...\n\n"
        "Example: WINEDEBUG=+relay,warn-heap\n"
        "    turns on relay traces, disable heap warnings\n"
        "Available message classes: err, warn, fixme, trace\n";
    write( 2, usage, sizeof(usage) - 1 );
    exit(1);
}

/* initialize all options at startup */
static void init_options(void)
{
    char *wine_debug = getenv("WINEDEBUG");
    struct stat st1, st2;

    option_init_done = TRUE;

    /* check for stderr pointing to /dev/null */
    if (!fstat( 2, &st1 ) && S_ISCHR(st1.st_mode) &&
        !stat( "/dev/null", &st2 ) && S_ISCHR(st2.st_mode) &&
        st1.st_rdev == st2.st_rdev)
    {
        log_config.default_flags = 0;
        return;
    }
    if (!wine_debug) return;
    if (!strcmp( wine_debug, "help" )) debug_usage();
    parse_options( &log_config, wine_debug );
}

/***********************************************************************
 *		__wine_dbg_get_channel_flags  (NTDLL.@)
 *
 * Get the flags to use for a given channel, possibly setting them too in case of lazy init
 */
unsigned char __cdecl __wine_dbg_get_channel_flags( struct __wine_debug_channel *channel,
                                                    enum __wine_debug_target target )
{
    int min, max, pos, res;
    struct dbg_config *conf;
    unsigned char *flags;

    if (!option_init_done) init_options();

    if (target != __WINE_DBTRG_LOG)
        return 0;

    if (!(*flags & (1 << __WINE_DBCL_INIT)))
        return *flags;

    min = 0;
    max = conf->opts_cnt - 1;
    while (min <= max)
    {
        pos = (min + max) / 2;
        res = strcmp( channel->name, conf->opts[pos].name );
        if (!res)
        {
            *flags = conf->opts[pos].flags;
            return conf->opts[pos].flags;
        }
        if (res < 0) max = pos - 1;
        else min = pos + 1;
    }
    /* no option for this channel */
    if (*flags & (1 << __WINE_DBCL_INIT))
        *flags = conf->default_flags;
    return conf->default_flags;
}

/***********************************************************************
 *		__wine_dbg_strdup  (NTDLL.@)
 */
const char * __cdecl __wine_dbg_strdup( const char *str )
{
    struct debug_info *info = get_info();
    unsigned int pos = info->str_pos;
    size_t n = strlen( str ) + 1;

    assert( n <= sizeof(info->strings) );
    if (pos + n > sizeof(info->strings)) pos = 0;
    info->str_pos = pos + n;
    return memcpy( info->strings + pos, str, n );
}

/***********************************************************************
 *		__wine_dbg_write  (NTDLL.@)
 */
int WINAPI __wine_dbg_write( const char *str, unsigned int len )
{
    return write( 2, str, len );
}

/***********************************************************************
 *		__wine_dbg_log_output  (NTDLL.@)
 */
int __cdecl __wine_dbg_log_output( const char *str )
{
    struct debug_info *info = get_info();
    const char *end = strrchr( str, '\n' );
    int ret = 0;

    if (end)
    {
        ret += append_output( info, str, end + 1 - str );
        __wine_dbg_write( info->output, info->out_pos );
        info->out_pos = 0;
        str = end + 1;
    }
    if (*str) ret += append_output( info, str, strlen( str ));
    return ret;
}

/***********************************************************************
 *		__wine_dbg_header  (NTDLL.@)
 */
int __cdecl __wine_dbg_header( enum __wine_debug_class cls, struct __wine_debug_channel *channel,
                               const char *function )
{
    static const char * const classes[] = { "fixme", "err", "warn", "trace" };
    struct debug_info *info = get_info();
    char *pos = info->output;

    if (!(__wine_dbg_get_channel_flags( channel, __WINE_DBTRG_LOG ) & (1 << cls)))
        return -1;

    /* only print header if we are at the beginning of the line */
    if (info->out_pos) return 0;

    if (init_done)
    {
        if (TRACE_ON(microsecs))
        {
            LARGE_INTEGER counter, frequency, microsecs;
            NtQueryPerformanceCounter(&counter, &frequency);
            microsecs.QuadPart = counter.QuadPart * 1000000 / frequency.QuadPart;
            pos += sprintf( pos, "%3u.%06u:", (unsigned int)(microsecs.QuadPart / 1000000), (unsigned int)(microsecs.QuadPart % 1000000) );
        }
        else if (TRACE_ON(timestamp))
        {
            ULONG ticks = NtGetTickCount();
            pos += sprintf( pos, "%3u.%03u:", ticks / 1000, ticks % 1000 );
        }
        if (TRACE_ON(pid)) pos += sprintf( pos, "%04x:", GetCurrentProcessId() );
        pos += sprintf( pos, "%04x:", GetCurrentThreadId() );
    }
    if (function && cls < ARRAY_SIZE( classes ))
        pos += snprintf( pos, sizeof(info->output) - (pos - info->output), "%s:%s:%s ",
                         classes[cls], channel->name, function );
    info->out_pos = pos - info->output;
    return info->out_pos;
}

/***********************************************************************
 *		dbg_init
 */
void dbg_init(void)
{
    struct __wine_debug_option *options, default_option = { 0 };

    setbuf( stdout, NULL );
    setbuf( stderr, NULL );

    if (!option_init_done) init_options();

    options = (struct __wine_debug_option *)((char *)peb + (is_win64 ? 2 : 1) * page_size);

    memcpy( options, log_config.opts, log_config.opts_cnt * sizeof(*options) );
    free( log_config.opts );
    log_config.opts = options;
    log_config.opts[log_config.opts_cnt] = default_option;

    init_done = TRUE;
}


/***********************************************************************
 *              NtTraceControl  (NTDLL.@)
 */
NTSTATUS WINAPI NtTraceControl( ULONG code, void *inbuf, ULONG inbuf_len,
                                void *outbuf, ULONG outbuf_len, ULONG *size )
{
    FIXME( "code %u, inbuf %p, inbuf_len %u, outbuf %p, outbuf_len %u, size %p\n", code, inbuf, inbuf_len,
           outbuf, outbuf_len, size );
    return STATUS_SUCCESS;
}


/***********************************************************************
 *              NtSetDebugFilterState  (NTDLL.@)
 */
NTSTATUS WINAPI NtSetDebugFilterState( ULONG component_id, ULONG level, BOOLEAN state )
{
    FIXME( "component_id %#x, level %u, state %#x stub.\n", component_id, level, state );

    return STATUS_SUCCESS;
}

void CDECL write_crash_log(const char *log_type, const char *log_msg)
{
    const char *dir = getenv("WINE_CRASH_REPORT_DIR");
    const char *sgi;
    char timestr[32];
    char name[MAX_PATH], *c;
    time_t t;
    struct tm lt;
    int f;

    if(!dir || dir[0] == 0)
        return;

    strcpy(name, dir);

    for(c = name + 1; *c; ++c){
        if(*c == '/'){
            *c = 0;
            mkdir(name, 0700);
            *c = '/';
        }
    }
    mkdir(name, 0700);

    sgi = getenv("SteamGameId");

    t = time(NULL);
    localtime_r(&t, &lt);
    strftime(timestr, ARRAY_SIZE(timestr), "%Y-%m-%d_%H:%M:%S", &lt);

    /* /path/to/crash/reports/2021-05-18_13:21:15_appid-976310_crash.log */
    snprintf(name, ARRAY_SIZE(name),
            "%s/%s_appid-%s_%s.log",
            dir,
            timestr,
            sgi ? sgi : "0",
            log_type
            );

    f = open(name, O_CREAT | O_WRONLY, 0644);
    if(f < 0)
        return;

    write(f, log_msg, strlen(log_msg));

    close(f);
}
