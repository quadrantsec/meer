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

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#ifdef HAVE_LIBHIREDIS

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <hiredis/hiredis.h>

#include "decode-json-alert.h"

#include "meer.h"
#include "meer-def.h"
#include "util.h"
#include "config-yaml.h"
#include "fingerprint-to-json.h"

#include "output-plugins/redis.h"



struct _Fingerprint_Networks *Fingerprint_Networks;

struct _MeerConfig *MeerConfig;
struct _MeerOutput *MeerOutput;
struct _MeerCounters *MeerCounters;


void Add_Fingerprint_To_JSON( struct json_object *json_obj, _DecodeAlert *DecodeAlert )
{

    int key_count = 0;

    int i = 0;
    int a = 0;
    int z = 0;

    char fingerprint_tmp[PACKET_BUFFER_SIZE_DEFAULT] = { 0 };
    char tmp_command[PACKET_BUFFER_SIZE_DEFAULT] = { 0 };
    char tmp_new_alert[PACKET_BUFFER_SIZE_DEFAULT] = { 0 };
    char tmp_new_new_alert[PACKET_BUFFER_SIZE_DEFAULT] = { 0 };

    unsigned char ip[MAXIPBIT] = { 0 };

    struct json_object *json_obj_fingerprint = NULL;
    struct json_object *tmp = NULL;
    bool  event_changed = false;

    char *tmp_ip = NULL;
    char *tmp_type = NULL;

    bool valid_fingerprint_net = 0;

    char tmp_dhcp[1024] = { 0 };

    redisReply *reply;


    /* Do DHCP */

    for (a = 0; a < 2; a++ )
        {

            valid_fingerprint_net = false;

            if ( a == 0 )
                {
                    tmp_ip = DecodeAlert->src_ip;;
                    tmp_type = "src";

                    IP2Bit(DecodeAlert->src_ip, ip);

                    for ( z = 0; z < MeerCounters->fingerprint_network_count; z++ )
                        {
                            if ( Is_Inrange( ip, (unsigned char *)&Fingerprint_Networks[z].range, 1) )
                                {
                                    valid_fingerprint_net = true;
                                }
                        }

                }
            else
                {
                    tmp_ip = DecodeAlert->dest_ip;
                    tmp_type = "dest";

                    IP2Bit(DecodeAlert->dest_ip, ip);

                    for ( z = 0; z < MeerCounters->fingerprint_network_count; z++ )
                        {
                            if ( Is_Inrange( ip, (unsigned char *)&Fingerprint_Networks[z].range, 1) )
                                {
                                    valid_fingerprint_net = true;
                                }
                        }
                }


            if ( valid_fingerprint_net == true )
                {

                    snprintf(tmp_command, sizeof(tmp_command), "GET %s|dhcp|%s", FINGERPRINT_REDIS_KEY, tmp_ip);
                    Redis_Reader(tmp_command, tmp_dhcp, sizeof(tmp_dhcp));

                    if ( tmp_dhcp[0] != '\0' )
                        {

                            event_changed = true;

                            strlcpy(tmp_new_alert, DecodeAlert->new_json_string, sizeof(tmp_new_alert));
                            tmp_new_alert[ strlen(tmp_new_alert) - 2 ] = '\0';

                            snprintf(tmp_new_new_alert, sizeof(tmp_new_new_alert), "%s, \"fingerprint_dhcp_%s\": %s", tmp_new_alert, tmp_type, tmp_dhcp);

                            snprintf(DecodeAlert->new_json_string, sizeof(DecodeAlert->new_json_string), "%s }", tmp_new_new_alert);
                        }
                }
        }

    /* Get Fingerprints */

    for (a = 0; a < 2; a++ )
        {

            valid_fingerprint_net = false;

            if ( a == 0 )
                {
                    tmp_ip = DecodeAlert->src_ip;
                    tmp_type = "src";

                    IP2Bit(DecodeAlert->src_ip, ip);

                    for ( z = 0; z < MeerCounters->fingerprint_network_count; z++ )
                        {
                            if ( Is_Inrange( ip, (unsigned char *)&Fingerprint_Networks[z].range, 1) )
                                {
                                    valid_fingerprint_net = true;
                                }
                        }

                }
            else
                {
                    tmp_ip = DecodeAlert->dest_ip;
                    tmp_type = "dest";

                    IP2Bit(DecodeAlert->dest_ip, ip);

                    for ( z = 0; z < MeerCounters->fingerprint_network_count; z++ )
                        {
                            if ( Is_Inrange( ip, (unsigned char *)&Fingerprint_Networks[z].range, 1) )
                                {
                                    valid_fingerprint_net = true;
                                }
                        }

                }


            if ( valid_fingerprint_net == true )
                {

                    reply = redisCommand(MeerOutput->c_redis, "SCAN 0 MATCH %s|event|%s|* count 1000000", FINGERPRINT_REDIS_KEY, tmp_ip);
                    key_count = reply->element[1]->elements;

                    if ( key_count > 0 )
                        {
                            event_changed = true;
                            strlcpy(tmp_new_alert, DecodeAlert->new_json_string, sizeof(tmp_new_alert));
                            tmp_new_alert[ strlen(tmp_new_alert) - 2 ] = '\0';
                        }

                    for ( i = 0; i < key_count; i++ )
                        {
                            redisReply *kr = reply->element[1]->element[i];
                            snprintf(tmp_command, sizeof(tmp_command), "GET %s", kr->str);
                            Redis_Reader(tmp_command, fingerprint_tmp, sizeof(fingerprint_tmp));

                            if ( Validate_JSON_String( fingerprint_tmp ) == 0 )
                                {
                                    json_obj_fingerprint = json_tokener_parse(fingerprint_tmp);
                                }
                            else
                                {
                                    Meer_Log(WARN, "Incomplete or invalid fingerprint JSON for flow id %s", DecodeAlert->flowid);
                                    continue;
                                }

                            if ( json_object_object_get_ex(json_obj_fingerprint, "fingerprint", &tmp))
                                {
                                    snprintf(tmp_new_new_alert, sizeof(tmp_new_new_alert), "%s, \"fingerprint_%s_%d\": %s", tmp_new_alert, tmp_type, i, json_object_get_string(tmp));
                                    strlcpy(tmp_new_alert, tmp_new_new_alert, sizeof(tmp_new_alert));
                                }
                        }
                }
        }

    /* Copy new JSON over,  if JSON has been updated */

    if ( event_changed == true )
        {
            /* Append final } */

            snprintf(DecodeAlert->new_json_string, sizeof(DecodeAlert->new_json_string), "%s }", tmp_new_alert);
        }

    json_object_put(json_obj_fingerprint);

}

#endif
