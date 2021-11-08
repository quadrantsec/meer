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

/* EVE JSON decode */

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#ifdef HAVE_LIBJSON_C
#include <json-c/json.h>
#endif


#ifndef HAVE_LIBJSON_C
libjson-c is required for Meer to function!
#endif

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <stdbool.h>
#include <string.h>

#include "decode-json.h"
#include "decode-json-alert.h"
#include "decode-json-dhcp.h"
#include "decode-output-json-client-stats.h"

#include "output-plugins/pipe.h"
#include "output-plugins/file.h"

#include "meer.h"
#include "meer-def.h"
#include "output.h"
#include "get-dns.h"
#include "get-oui.h"
#include "counters.h"

#ifdef HAVE_LIBMAXMINDDB
#include "get-geoip.h"
#endif

#ifdef HAVE_LIBHIREDIS
#include "get-fingerprint.h"
#include "output-plugins/redis.h"
#endif

extern struct _Classifications *MeerClass;
extern struct _MeerOutput *MeerOutput;
extern struct _MeerCounters *MeerCounters;
extern struct _MeerConfig *MeerConfig;
extern struct _MeerHealth *MeerHealth;

bool Decode_JSON( char *json_string )
{

    struct json_object *json_obj = NULL;
    struct json_object *tmp = NULL;

    bool fingerprint_return = false;

    char *event_type = NULL;

#ifdef HAVE_LIBHIREDIS

    char fingerprint_IP_JSON[1024] = { 0 };
    char fingerprint_EVENT_JSON[PACKET_BUFFER_SIZE_DEFAULT] = { 0 };
    char fingerprint_DHCP_JSON[2048] = { 0 };

#endif

    /* We should have gotten a valid string! */

    if ( json_string == NULL )
        {
            MeerCounters->bad++;
            return(false);
        }

    json_obj = json_tokener_parse(json_string);

    if ( json_obj == NULL )
        {
            MeerCounters->bad++;
            Meer_Log(WARN, "Unable t json_tokener_parse: %s", json_string);
            return(false);
        }

    /* Let's add our "description" */

    json_object *jdescription  = json_object_new_string( MeerConfig->description );
    json_object_object_add(json_obj,"sensor_description", jdescription );

    /* Go ahead and get the "event_type".  All JSON should have one */

    if (json_object_object_get_ex(json_obj, "event_type", &tmp))
        {
            event_type = (char *)json_object_get_string(tmp);
        }
    else
        {
            MeerCounters->bad++;
            return(false);
        }

    /* Do we want to add DNS to the JSON? */

    if ( MeerConfig->dns == true )
        {
            json_string = Get_DNS( json_obj );
        }

#ifdef HAVE_LIBHIREDIS

    /* We do "fingerprint" checks early on because we might want to switch the
       "event_type". */

    if ( !strcmp(event_type, "alert") && MeerConfig->fingerprint == true && MeerOutput->redis_enabled == true )
        {

            struct _FingerprintData *FingerprintData;
            FingerprintData = (struct _FingerprintData *) malloc(sizeof(_FingerprintData));

            if ( FingerprintData == NULL )
                {
                    Meer_Log(ERROR, "[%s, line %d] JSON: \"%s\" Failed to allocate memory for _FingerprintData.  Abort!", __FILE__, __LINE__, json_string);
                }

            memset(FingerprintData, 0, sizeof(_FingerprintData));

            /* Determine if the "alert" is a "fingerprint" event or not.  It if is,
               store "fingerprint" data in the FingerprintData array.  Otherwise,  enrich
               the standard "alert" data with "fingerprint" data */

            if ( Is_Fingerprint( json_obj, FingerprintData ) == false )
                {

                    /* This is a standard "alert".  Add any "fingerprint" JSON to the event */

                    char new_json_string[PACKET_BUFFER_SIZE_DEFAULT] = { 0 };
                    Get_Fingerprint( json_obj, json_string, new_json_string, PACKET_BUFFER_SIZE_DEFAULT );
                    json_string = new_json_string;
                }
            else
                {

                    /* This is a fingerprint event,  change the event_type and build out new JSON */

                    event_type = "fingerprint";

                    /* Write Fingerprint data to Redis (for future use) */

                    char new_json_string[PACKET_BUFFER_SIZE_DEFAULT] = { 0 };
                    Fingerprint_JSON_Redis( json_obj, FingerprintData, new_json_string, PACKET_BUFFER_SIZE_DEFAULT);
                    json_string = new_json_string;

                }

            free(FingerprintData);
        }

#endif

    Counters( event_type );

#ifdef HAVE_LIBMAXMINDDB

    /* Add GeoIP information */

    if ( MeerConfig->geoip == true )
        {
            char new_json_string[PACKET_BUFFER_SIZE_DEFAULT] = { 0 };
            Get_GeoIP( json_obj, json_string, new_json_string, PACKET_BUFFER_SIZE_DEFAULT );
            json_string = new_json_string;
        }

#endif

    /* Add OUI / Mac data */

    if ( MeerConfig->oui == true && !strcmp( event_type, "dhcp"  ) )
        {
            char new_json_string[PACKET_BUFFER_SIZE_DEFAULT] = { 0 };
            Get_OUI( json_obj, new_json_string, PACKET_BUFFER_SIZE_DEFAULT );
            json_string = new_json_string;
        }

#if defined(HAVE_LIBMYSQLCLIENT) || defined(HAVE_LIBPQ)

    /* SQL is sort of a difficult output and we only store "alert"
       event_types. We grab and store a bunch of JSON values and
       store them in the struct DecodeAlert */

    if ( !strcmp(event_type, "alert") && MeerOutput->sql_enabled == true )
        {
            struct _DecodeAlert *DecodeAlert;   /* event_type: alert */
            DecodeAlert = Decode_JSON_Alert( json_obj, json_string );
            Output_Alert_SQL( DecodeAlert );
            free( DecodeAlert );
        }

#endif

    if ( MeerOutput->pipe_enabled == true )
        {
            Output_Pipe( json_string, event_type );
        }

    if ( MeerOutput->external_enabled == true )
        {
            Output_External( json_string, json_obj, event_type );
        }


    if ( MeerOutput->file_enabled == true )
        {
            Output_File( json_string, event_type );
        }

#ifdef HAVE_LIBHIREDIS

    if ( MeerOutput->redis_enabled == true )
        {
            Output_Redis( json_string, event_type );
        }

#endif

#ifdef WITH_ELASTICSEARCH

    if ( MeerOutput->elasticsearch_enabled == true )
        {
            Output_Elasticsearch( json_string, event_type );
        }

#endif

#ifdef HAVE_LIBHIREDIS

    /* Process client stats data from Sagan */

    if ( !strcmp(event_type, "client_stats") && MeerConfig->client_stats == true )
        {
            Decode_Output_JSON_Client_Stats( json_obj, json_string );
        }

#endif

    /* Write "stats" to SQL database */

    if ( !strcmp(event_type, "stats" ) && MeerOutput->sql_enabled == true)
        {
            Output_Stats( json_string );
        }

    /* Delete json-c _root_ objects */

    json_object_put(json_obj);

    return 0;
}
