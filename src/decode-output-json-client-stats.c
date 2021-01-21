/*
** Copyright (C) 2018-2020 Quadrant Information Security <quadrantsec.com>
** Copyright (C) 2018-2020 Champ Clark III <cclark@quadrantsec.com>
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License Version 2 as
** published by the Free Software Foundation.  You may not use, modify or
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

/* Decode Sagan "client stats" */

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#ifdef HAVE_LIBJSON_C
#include <json-c/json.h>
#endif


#ifndef HAVE_LIBJSON_C
libjson-c is required for Meer to function!
#endif

#ifdef HAVE_LIBHIREDIS

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <stdbool.h>
#include <string.h>

#include "util.h"
#include "meer.h"
#include "meer-def.h"

#include "decode-json-alert.h"
#include "output-plugins/redis.h"
#include "decode-output-json-client-stats.h"

struct _MeerCounters *MeerCounters;
struct _MeerOutput *MeerOutput;
struct _MeerConfig *MeerConfig;

void Decode_Output_JSON_Client_Stats( struct json_object *json_obj, const char *json_string )
{

    int i = 0;
    char redis_prefix[128] = { 0 };

    /* Decoding structs */

    uint64_t tmp_timestamp_int;

    struct json_object *tmp_t = NULL;
    struct json_object *tmp_timestamp = NULL;

    struct json_object *tmp_p = NULL;
    struct json_object *tmp_program = NULL;

    struct json_object *tmp_m = NULL;
    struct json_object *tmp_message = NULL;

    struct json_object *tmp_i = NULL;
    struct json_object *tmp_ip = NULL;

    struct json_object *tmp_s = NULL;

    char dns[255] = { 0 };
    char sensor_name[255] = { 0 };

    /* Encoding structs */

    struct json_object *encode_json = NULL;

    encode_json = json_object_new_object();

    json_object_object_get_ex(json_obj, "timestamp", &tmp_t);

    if ( tmp_t == NULL )
        {
            Meer_Log(WARN, "[%s, line %d] 'timestamp' appears incomplete or invalid. Abort", __FILE__, __LINE__);
            return;
        }

    json_object_object_get_ex(json_obj, "ip_addresses", &tmp_i);

    if ( tmp_i == NULL )
        {
            Meer_Log(WARN, "[%s, line %d] 'ip_addresses' appears incomplete or invalid. Abort", __FILE__, __LINE__);
            return;
        }

    json_object_object_get_ex(json_obj, "program", &tmp_p);

    if ( tmp_p == NULL )
        {
            Meer_Log(WARN, "[%s, line %d] 'program' appears incomplete or invalid. Abort", __FILE__, __LINE__);
            return;
        }

    json_object_object_get_ex(json_obj, "message", &tmp_m);

    if ( tmp_m == NULL )
        {
            Meer_Log(WARN, "[%s, line %d] 'message' appears incomplete or invalid. Abort", __FILE__, __LINE__);
            return;
        }

    json_object_object_get_ex(json_obj, "sensor_name", &tmp_s);

    if ( tmp_s == NULL )
        {
            Meer_Log(WARN, "[%s, line %d] 'sensor_name' appears incomplete or invalid. Abort", __FILE__, __LINE__);
            return;
        }

    strlcpy(sensor_name, json_object_get_string ( tmp_s ), sizeof(sensor_name));

    for (i = 0; i < json_object_array_length(tmp_t); i++)
        {
            tmp_timestamp = json_object_array_get_idx ( tmp_t, i );

            if ( tmp_timestamp == NULL )
                {
                    Meer_Log(ERROR, "[%s, line %d] Invalid JSON: %s - 'timestamp' is incomplete or invalid. Abort", __FILE__, __LINE__, json_string);
                }

            tmp_ip = json_object_array_get_idx ( tmp_i, i );

            if ( tmp_ip == NULL )
                {
                    Meer_Log(ERROR, "[%s, line %d] Invalid JSON: %s - 'ip_addresses' is incomplete or invalid. Abort", __FILE__, __LINE__, json_string);
                }

            tmp_program = json_object_array_get_idx ( tmp_p, i );

            if ( tmp_program == NULL )
                {
                    Meer_Log(ERROR, "[%s, line %d] Invalid JSON: %s - 'program' is incomplete or invalid. Abort", __FILE__, __LINE__, json_string);
                }


            tmp_message = json_object_array_get_idx ( tmp_m, i );

            if ( tmp_message == NULL )
                {
                    Meer_Log(WARN, "[%s, line %d] Invalid JSON: %s - 'messages' is incomplete or invalid. Abort. %d", __FILE__, __LINE__, json_string);
                    return;
                }

            tmp_timestamp_int = atol( json_object_to_json_string(tmp_timestamp) );

            json_object *jtimestamp = json_object_new_int64( tmp_timestamp_int );
            json_object_object_add(encode_json,"timestamp", jtimestamp);

            json_object *jip = json_object_new_string( json_object_get_string ( tmp_ip ));
            json_object_object_add(encode_json,"ip_address", jip);

            /* Record DNS if the main configuration has it enabled */

            if ( MeerConfig->dns )
                {
                    DNS_Lookup( (char *)json_object_get_string ( tmp_ip ), dns, sizeof(dns));
                    json_object *jdns = json_object_new_string( dns );
                    json_object_object_add(encode_json,"dns", jdns);
                }

            json_object *jprogram = json_object_new_string( json_object_get_string ( tmp_program ) );
            json_object_object_add(encode_json,"program", jprogram);

            json_object *jmessage = json_object_new_string( json_object_get_string ( tmp_message ) );
            json_object_object_add(encode_json,"message", jmessage);

            json_object *jsensor = json_object_new_string( sensor_name );
            json_object_object_add(encode_json,"sensor_name", jsensor);


            /* We put output here because of its limited scope. */

            /* Redis */

#ifdef HAVE_LIBHIREDIS

            if ( MeerOutput->redis_flag )
                {
                    snprintf(redis_prefix, sizeof(redis_prefix), "client_stats|%s", json_object_get_string ( tmp_ip ));
                    Redis_Writer( "SET", redis_prefix, (char*)json_object_to_json_string(encode_json), 0);
                }

#endif

            /* MySQL with INSERT/UPDATE */

        }

}

#endif
