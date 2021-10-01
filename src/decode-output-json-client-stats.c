/*
** Copyright (C) 2018-2021 Quadrant Information Security <quadrantsec.com>
** Copyright (C) 2018-2021 Champ Clark III <cclark@quadrantsec.com>
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

    char redis_prefix[128] = { 0 };
    char dns[255] = { 0 };

    struct json_object *tmp = NULL;

    char *cs_timestamp = NULL;
    char *cs_sensor_name = NULL;
    char *cs_ipaddr = NULL;
    char *cs_program = NULL;
    char *cs_message = NULL;

    /* Encoding structs */

    struct json_object *encode_json = NULL;
    encode_json = json_object_new_object();

    /* Timestamp */

    if (json_object_object_get_ex(json_obj, "timestamp", &tmp))
        {
            cs_timestamp = (char *)json_object_get_string(tmp);
        }

    if ( cs_timestamp == NULL )
        {
            Meer_Log(WARN, "[%s, line %d] 'timestamp' appears incomplete or invalid. Abort", __FILE__, __LINE__);
            json_object_put(encode_json);
            return;
        }

    /* Sensor Name */

    if (json_object_object_get_ex(json_obj, "sensor_name", &tmp))
        {
            cs_sensor_name = (char *)json_object_get_string(tmp);
        }

    if ( cs_sensor_name == NULL )
        {
            Meer_Log(WARN, "[%s, line %d] 'sensor_name' appears incomplete or invalid. Skipping...", __FILE__, __LINE__);
            json_object_put(encode_json);
            return;
        }

    /* IP Address */

    if (json_object_object_get_ex(json_obj, "ip_address", &tmp))
        {
            cs_ipaddr = (char *)json_object_get_string(tmp);
        }

    if ( cs_ipaddr == NULL )
        {
            Meer_Log(WARN, "[%s, line %d] 'ip_address' appears incomplete or invalid. Skipping...", __FILE__, __LINE__);
            json_object_put(encode_json);
            return;
        }

    if ( !Is_IP(cs_ipaddr, IPv4) && !Is_IP(cs_ipaddr, IPv6 ) )
    	{
	    Meer_Log(WARN, "[%s, line %d] 'ip_address' (%s) is invalid. Skipping...", cs_ipaddr,  __FILE__, __LINE__);
	    json_object_put(encode_json);
	    return;
	}

    /* Program */

    if (json_object_object_get_ex(json_obj, "program", &tmp))
        {
            cs_program = (char *)json_object_get_string(tmp);
        }

    if ( cs_program == NULL )
        {
            Meer_Log(WARN, "[%s, line %d] 'program' appears incomplete or invalid. Abort", __FILE__, __LINE__);
            json_object_put(encode_json);
            return;
        }

    /* Message */

    if (json_object_object_get_ex(json_obj, "message", &tmp))
        {
            cs_message = (char *)json_object_get_string(tmp);
        }

    if ( cs_message == NULL )
        {
            Meer_Log(WARN, "[%s, line %d] 'message' appears incomplete or invalid. Abort", __FILE__, __LINE__);
            json_object_put(encode_json);
            return;
        }

    /* Build new client stats JSON for Redis! */

    json_object *jtimestamp = json_object_new_int64( atol(cs_timestamp) );
    json_object_object_add(encode_json,"timestamp", jtimestamp);

    json_object *jip = json_object_new_string( cs_ipaddr );
    json_object_object_add(encode_json,"ip_address", jip);

    json_object *jprogram = json_object_new_string( cs_program );
    json_object_object_add(encode_json,"program", jprogram);

    json_object *jmessage = json_object_new_string( cs_message );
    json_object_object_add(encode_json,"message", jmessage);

    json_object *jsensor_name = json_object_new_string( cs_sensor_name );
    json_object_object_add(encode_json,"sensor_name", jsensor_name);

    if ( MeerConfig->dns )
        {
            DNS_Lookup_Reverse( cs_ipaddr, dns, sizeof(dns) );
            json_object *jdns = json_object_new_string( dns );
            json_object_object_add(encode_json,"dns", jdns);
        }

    if ( MeerOutput->redis_flag )
        {

            // This isn't quite it, but Mark has modified the key format.  We'll need to update it when that
            // change takes place.
            // snprintf(redis_prefix, sizeof(redis_prefix), "client_stats|%s|%s|%s",cs_ipaddr, dns, cs_timestamp );

            snprintf(redis_prefix, sizeof(redis_prefix), "client_stats|%s",cs_ipaddr );
            Redis_Writer( "SET", redis_prefix, (char*)json_object_to_json_string(encode_json), 0);

        }


    json_object_put(encode_json);

}

#endif
