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

#include "fingerprints.h"
#include "decode-output-json-client-stats.h"

#include "meer.h"
#include "meer-def.h"
#include "output.h"

#ifdef HAVE_LIBHIREDIS
#include "output-plugins/redis.h"
#include "output-plugins/fingerprint.h"
#include "fingerprint-to-json.h"
#endif

struct _Classifications *MeerClass;
struct _MeerOutput *MeerOutput;
struct _MeerCounters *MeerCounters;
struct _MeerConfig *MeerConfig;
struct _MeerHealth *MeerHealth;

bool Decode_JSON( char *json_string )
{

    struct json_object *json_obj = NULL;
    struct json_object *tmp = NULL;

    char tmp_type[32] = { 0 };
    bool bad_json = false;
    bool fingerprint_return = false;

#ifdef HAVE_LIBHIREDIS

    char fingerprint_IP_JSON[1024] = { 0 };
    char fingerprint_EVENT_JSON[PACKET_BUFFER_SIZE_DEFAULT] = { 0 };
    char fingerprint_DHCP_JSON[2048] = { 0 };

#endif

    if ( json_string == NULL )
        {
            MeerCounters->InvalidJSONCount++;
            return 1;
        }

    json_obj = json_tokener_parse(json_string);

    if ( json_obj == NULL )
        {
            MeerCounters->InvalidJSONCount++;
            Meer_Log(WARN, "Unable t json_tokener_parse: %s", json_string);
            return 1;
        }

    if (!json_object_object_get_ex(json_obj, "event_type", &tmp))
        {
            bad_json = true;
        }

    if ( tmp == NULL )
        {
            bad_json = true;
        }

    if ( bad_json == false )
        {

            fingerprint_return = false;

            if ( !strcmp(json_object_get_string(tmp), "alert") )
                {

                    struct _DecodeAlert *DecodeAlert;   /* event_type: alert */
                    DecodeAlert = Decode_JSON_Alert( json_obj, json_string );

#ifdef HAVE_LIBHIREDIS

                    /* Added fingerprint */

                    if (MeerConfig->fingerprint == true )
                        {
                            Add_Fingerprint_To_JSON( json_obj, DecodeAlert );
                        }



                    if ( MeerConfig->fingerprint == true )
                        {

                            /* Is this a "fingerprint" signature? */

                            struct _FingerprintData *FingerprintData;
                            FingerprintData = (struct _FingerprintData *) malloc(sizeof(_FingerprintData));

                            if ( FingerprintData == NULL )
                                {
                                    Meer_Log(ERROR, "[%s, line %d] JSON: \"%s\" Failed to allocate memory for _FingerprintData.  Abort!", __FILE__, __LINE__, json_string);
                                }

                            memset(FingerprintData, 0, sizeof(_FingerprintData));
                            Parse_Fingerprint( DecodeAlert, FingerprintData);

                            if ( FingerprintData->ret == true )
                                {

                                    fingerprint_return = FingerprintData->ret;

                                    Fingerprint_IP_JSON( DecodeAlert, fingerprint_IP_JSON, sizeof(fingerprint_IP_JSON));
                                    Output_Fingerprint_IP( DecodeAlert, fingerprint_IP_JSON);

                                    Fingerprint_EVENT_JSON( DecodeAlert, FingerprintData, fingerprint_EVENT_JSON, sizeof(fingerprint_EVENT_JSON));
                                    Output_Fingerprint_EVENT( DecodeAlert, FingerprintData, fingerprint_EVENT_JSON );

                                }

                            free(FingerprintData);

                        }

#endif

#if defined(HAVE_LIBMYSQLCLIENT) || defined(HAVE_LIBPQ)

                    if ( MeerOutput->sql_enabled == true && fingerprint_return == false )
                        {
                            Output_Alert_SQL( DecodeAlert );
                        }
#endif

#ifdef HAVE_LIBHIREDIS
                    if ( fingerprint_return == false && MeerOutput->redis_flag == true )
                        {
                            JSON_To_Redis( DecodeAlert->new_json_string, "alert" );
                        }
#endif

                    if ( MeerOutput->external_enabled == true )
                        {
                            Output_External( DecodeAlert );
                        }

                    free(DecodeAlert);

                }

#ifdef HAVE_LIBHIREDIS

            if ( !strcmp(json_object_get_string(tmp), "dhcp") && MeerConfig->fingerprint == true )
                {

                    struct _DecodeDHCP *DecodeDHCP;   /* event_type: dhcp */
                    DecodeDHCP = (struct _DecodeDHCP *) malloc(sizeof(_DecodeDHCP));

                    if ( DecodeDHCP == NULL )
                        {
                            Meer_Log(ERROR, "[%s, line %d] JSON: \"%s\" Failed to allocate memory for _DecodeDHCP.  Abort!", __FILE__, __LINE__, json_string);
                        }

                    memset(DecodeDHCP, 0, sizeof(_DecodeDHCP));

                    Decode_JSON_DHCP( json_obj, json_string, DecodeDHCP );

                    Fingerprint_DHCP_JSON( DecodeDHCP, fingerprint_DHCP_JSON, sizeof(fingerprint_DHCP_JSON));
                    Output_Fingerprint_DHCP ( DecodeDHCP, fingerprint_DHCP_JSON );

                    free(DecodeDHCP);
                }

#endif

            /* Process Suricata / Sagan stats */

            if ( !strcmp(json_object_get_string(tmp), "stats" ) )
                {
                    Output_Stats( json_string );
                }

            /* Process client stats data from Sagan */

#ifdef HAVE_LIBHIREDIS

            if ( !strcmp(json_object_get_string(tmp), "client_stats") && MeerConfig->client_stats == true )
                {
                    Decode_Output_JSON_Client_Stats( json_obj, json_string );
                }

#endif


            if ( MeerOutput->pipe_enabled == true )
                {
                    strlcpy(tmp_type, json_object_get_string(tmp), sizeof(tmp_type));
                    Output_Pipe(tmp_type, json_string );
                }

#ifdef HAVE_LIBHIREDIS

            if ( MeerOutput->redis_flag == true )
                {

                    if ( !strcmp(json_object_get_string(tmp), "flow") && MeerOutput->redis_flow == true )
                        {
                            JSON_To_Redis( json_string, "flow" );
                        }

                    else if ( !strcmp(json_object_get_string(tmp), "dns") && MeerOutput->redis_dns == true )
                        {
                            JSON_To_Redis( json_string, "dns" );
                        }

                    else if ( !strcmp(json_object_get_string(tmp), "http") && MeerOutput->redis_http == true)
                        {
                            JSON_To_Redis( json_string, "http" );
                        }

                    else if ( !strcmp(json_object_get_string(tmp), "files" ) && MeerOutput->redis_files == true )
                        {
                            JSON_To_Redis( json_string, "files" );
                        }

                    else if ( !strcmp(json_object_get_string(tmp), "tls" ) && MeerOutput->redis_tls == true)
                        {
                            JSON_To_Redis( json_string, "tls" );
                        }

                    else if ( !strcmp(json_object_get_string(tmp), "ssh" ) && MeerOutput->redis_ssh == true)
                        {
                            JSON_To_Redis( json_string, "ssh" );
                        }

                    else if ( !strcmp(json_object_get_string(tmp), "smtp" ) && MeerOutput->redis_smtp == true)
                        {
                            JSON_To_Redis( json_string, "smtp" );
                        }

                    else if ( !strcmp(json_object_get_string(tmp), "fileinfo" ) && MeerOutput->redis_fileinfo == true)
                        {
                            JSON_To_Redis( json_string, "fileinfo" );
                        }

                    else if ( !strcmp(json_object_get_string(tmp), "dhcp" ) && MeerOutput->redis_dhcp == true)
                        {
                            JSON_To_Redis( json_string, "dhcp" );
                        }

                    else if ( !strcmp(json_object_get_string(tmp), "stats" ) && MeerOutput->redis_stats == true)
                        {
                            JSON_To_Redis( json_string, "stats" );
                        }

                }

#endif

        }
    else
        {
            MeerCounters->InvalidJSONCount++;
        }


    /* Delete json-c _root_ objects */

    json_object_put(json_obj);

    return 0;
}
