/*
** Copyright (C) 2018-2022 Quadrant Information Security <quadrantsec.com>
** Copyright (C) 2018-2022 Champ Clark III <cclark@quadrantsec.com>
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License Version 2 as                                                   ** published by the Free Software Foundation.  You may not use, modify or
** distribute this program under any other version of the GNU General
** Public License.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

/* Redis "input" - Support for "pub/sub" */

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#ifdef HAVE_LIBHIREDIS

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <stdbool.h>
#include <hiredis/hiredis.h>
#include <hiredis/async.h>
#include <hiredis/adapters/libevent.h>

#include "meer-def.h"
#include "meer.h"
#include "util.h"
#include "util-signal.h"

#include "input-plugins/redis.h"

/* Proto for connect callback */

void connectCallback(const redisAsyncContext *c, int status);

extern struct _MeerConfig *MeerConfig;
extern struct _MeerInput *MeerInput;

/*************************************************************/
/* onMessage - Call back for what to do with data from Redis */
/*************************************************************/

void onMessage(redisAsyncContext *c, void *reply, void *privdata)
{

    bool skip_flag = false;

    char *buf = malloc(MeerConfig->payload_buffer_size);

    if ( buf == NULL )
        {
            Meer_Log(ERROR, "[%s, line %d] Fatal Error:  Can't allocate memory for buf! Abort!\n", __FILE__, __LINE__);
        }

    memset(buf, 0, MeerConfig->payload_buffer_size);

    redisReply *r = reply;

    /* Can't allocate for reply */

    if (reply == NULL)
        {
            Meer_Log(WARN, "[%s, line %d] Can't allocate memory for reply!", __FILE__, __LINE__);
            free(buf);
            return;
        }


    /* Get array of data */

    if (r->type == REDIS_REPLY_ARRAY)
        {

            if ( r->element[2]->str != NULL )
                {


                    snprintf(buf, MeerConfig->payload_buffer_size, "%s\n", r->element[2]->str);
                    buf[ MeerConfig->payload_buffer_size -1 ] = '\0';

                    skip_flag = Validate_JSON_String( buf );

                    if ( skip_flag == 0 )
                        {
                            Decode_JSON( buf );
                        }

                }
        }

    free(buf);
}


void Input_Redis_Subscribe( void )
{

    char tmp_command[512] = { 0 };

    struct event_base *base = event_base_new();

    redisAsyncContext *c = redisAsyncConnect(MeerInput->redis_server, MeerInput->redis_port);

    if (c->err)
        {
            Meer_Log(WARN, "[%s, line %d] Redis error: %s", __FILE__, __LINE__, c->errstr);
            redisAsyncFree(c);
            return;
        }


    if ( MeerInput->redis_password[0] != '\0' )
        {

            if ( redisAsyncCommand( c, NULL, NULL, "AUTH %s", MeerInput->redis_password) != REDIS_OK )
                {
                    Meer_Log(ERROR, "ERROR LOGGING IN\n");
                }

        }


    snprintf(tmp_command, sizeof(tmp_command), "SUBSCRIBE %s", MeerInput->redis_key);
    tmp_command[ sizeof(tmp_command) - 1 ] = '\0';

    redisLibeventAttach(c, base);
    redisAsyncSetConnectCallback(c,connectCallback);

    redisAsyncCommand( c, onMessage, NULL, tmp_command );

    event_base_dispatch(base);

    event_base_free(base);

    return;

}


void connectCallback(const redisAsyncContext *c, int status)
{
    if (status != REDIS_OK)
        {
            printf("Error: %s\n", c->errstr);
            return;
        }
    Meer_Log(NORMAL, "Connected and streaming data from \"%s\".....", MeerInput->redis_key );
}

//void disconnectCallback(const redisAsyncContext *c, int status) {
//    if (status != REDIS_OK) {
//        printf("Error: %s\n", c->errstr);
//        return;
//    }

//    Meer_Log(NORMAL, "Disconnect from stream \"%s\"", MeerInput->redis_key );

//}

#endif

