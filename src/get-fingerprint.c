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

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#ifdef HAVE_LIBHIREDIS

#include <stdio.h>
#include <string.h>
#include <json-c/json.h>
#include <hiredis/hiredis.h>

#include "meer-def.h"
#include "meer.h"
#include "oui.h"
#include "util.h"

#include "output-plugins/redis.h"
#include "get-fingerprint.h"

extern struct _MeerConfig *MeerConfig;
extern struct _MeerOutput *MeerOutput;
extern struct _MeerCounters *MeerCounters;
extern struct _Fingerprint_Networks *Fingerprint_Networks;

void Fingerprint_JSON_Redis( struct json_object *json_obj, struct _FingerprintData *FingerprintData, char *str, size_t size)
{

    struct json_object *tmp = NULL;
    struct json_object *json_obj_alert = NULL;
    struct json_object *json_obj_http = NULL;

    struct json_object *encode_json = NULL;
    encode_json = json_object_new_object();

    struct json_object *encode_json_fingerprint = NULL;
    encode_json_fingerprint = json_object_new_object();

    struct json_object *encode_json_http = NULL;
    encode_json_http = json_object_new_object();

    char string[PACKET_BUFFER_SIZE_DEFAULT] = { 0 };
    char http[PACKET_BUFFER_SIZE_DEFAULT / 2] = { 0 };

    char src_ip[64] = { 0 };
    char timestamp[32] = { 0 };
    char app_proto[32] = { 0 };

    uint64_t flow_id = 0;
    uint64_t signature_id = 0;

    char key[128] = { 0 };

    if (json_object_object_get_ex(json_obj, "src_ip", &tmp))
        {
            strlcpy( src_ip, json_object_get_string(tmp), sizeof(src_ip) );
        }

    if ( src_ip[0] == '\0' )
        {
            Meer_Log(WARN, "[%s, line %d] Got a NULL src_ip address!", __FILE__, __LINE__);
        }

    if (json_object_object_get_ex(json_obj, "timestamp", &tmp))
        {
            strlcpy( timestamp, json_object_get_string(tmp), sizeof(timestamp) );
        }

    if ( timestamp[0] == '\0' )
        {
            Meer_Log(WARN, "[%s, line %d] Got a NULL timestamp!", __FILE__, __LINE__);
        }

    if (json_object_object_get_ex(json_obj, "app_proto", &tmp))
        {
            strlcpy( app_proto, json_object_get_string(tmp), sizeof(app_proto) );
        }

    if (json_object_object_get_ex(json_obj, "flow_id", &tmp))
        {
            flow_id = json_object_get_int64(tmp);
        }

    if ( flow_id == 0 )
        {
            Meer_Log(WARN, "[%s, line %d] No flow ID found!", __FILE__, __LINE__);
        }

    /* Write out fingerprint|ip|{IP} key */

    json_object *jtimestamp = json_object_new_string( timestamp );
    json_object_object_add(encode_json,"timestamp", jtimestamp);

    json_object *jip = json_object_new_string( src_ip );
    json_object_object_add(encode_json,"ip", jip);

    snprintf(string, PACKET_BUFFER_SIZE_DEFAULT, "%s", json_object_to_json_string(encode_json));
    string[ sizeof(string) - 1] = '\0';

    snprintf(key, sizeof(key), "%s|ip|%s", FINGERPRINT_REDIS_KEY, src_ip);
    key[ sizeof(key) - 1] = '\0';

    Redis_Writer( "SET", key, string, FINGERPRINT_IP_REDIS_EXPIRE);

    /* Write out fingerprint|event|{IP} key */

    json_object_object_add(encode_json_fingerprint, "event_type", json_object_new_string("fingerprint"));
    json_object_object_add(encode_json_fingerprint, "timestamp", json_object_new_string( timestamp ));
    json_object_object_add(encode_json_fingerprint, "flow_id", json_object_new_int64( flow_id ));
    json_object_object_add(encode_json_fingerprint, "src_ip", json_object_new_string( src_ip ));

    /* Sagan doesn't have an "app_proto" */

    if ( app_proto[0] != '\0' ) 
    {
    json_object_object_add(encode_json_fingerprint, "app_proto", json_object_new_string( app_proto ));
    }


    if (json_object_object_get_ex(json_obj, "src_dns", &tmp))
        {
            json_object_object_add(encode_json_fingerprint, "src_host", json_object_new_string( json_object_get_string(tmp) ));
        }

    if (json_object_object_get_ex(json_obj, "dest_dns", &tmp))
        {
            json_object_object_add(encode_json_fingerprint, "dest_host", json_object_new_string( json_object_get_string(tmp) ));
        }

    /* host */

    if (json_object_object_get_ex(json_obj, "host", &tmp))
        {
            json_object_object_add(encode_json_fingerprint, "host", json_object_new_string( json_object_get_string(tmp) ));
        }
    else
        {
            Meer_Log(WARN, "[%s, line %d] Got a NULL host!", __FILE__, __LINE__);
        }

    /* in_iface */

    if (json_object_object_get_ex(json_obj, "in_iface", &tmp))
        {
            json_object_object_add(encode_json_fingerprint, "in_iface", json_object_new_string( json_object_get_string(tmp) ));
        }
    else
        {
            Meer_Log(WARN, "[%s, line %d] Got a NULL in_iface!", __FILE__, __LINE__);
        }

    /* src_port */

    if (json_object_object_get_ex(json_obj, "src_port", &tmp))
        {
            json_object_object_add(encode_json_fingerprint, "src_port", json_object_new_int( json_object_get_int(tmp) ));
        }
    else
        {
            Meer_Log(WARN, "[%s, line %d] Got a NULL src_port!", __FILE__, __LINE__);
        }

    /* dest_port */

    if (json_object_object_get_ex(json_obj, "dest_ip", &tmp))
        {
            json_object_object_add(encode_json_fingerprint, "dest_ip", json_object_new_string( json_object_get_string(tmp) ));
        }
    else
        {
            Meer_Log(WARN, "[%s, line %d] Got a NULL dest_ip!", __FILE__, __LINE__);
        }

    /* dest_port */

    if (json_object_object_get_ex(json_obj, "dest_port", &tmp))
        {
            json_object_object_add(encode_json_fingerprint, "dest_port", json_object_new_int( json_object_get_int(tmp) ));
        }
    else
        {
            Meer_Log(WARN, "[%s, line %d] Got a NULL dest_port!", __FILE__, __LINE__);
        }

    /* proto */

    if (json_object_object_get_ex(json_obj, "proto", &tmp))
        {
            json_object_object_add(encode_json_fingerprint, "proto", json_object_new_string( json_object_get_string(tmp) ));
        }
    else
        {
            Meer_Log(WARN, "[%s, line %d] Got a NULL proto!", __FILE__, __LINE__);
        }

    /* program (Sagan specific) */

    if (json_object_object_get_ex(json_obj, "payload", &tmp))
        {
            json_object_object_add(encode_json_fingerprint, "payload", json_object_new_string( json_object_get_string(tmp) ));
        }

    /* payload */

    if (json_object_object_get_ex(json_obj, "program", &tmp))
        {
            json_object_object_add(encode_json_fingerprint, "program", json_object_new_string( json_object_get_string(tmp) ));
        }


    /* Specific "fingerprints" */

    if ( FingerprintData->os[0] != '\0' )
        {
            json_object_object_add(encode_json_fingerprint, "os", json_object_new_string( FingerprintData->os ));
        }

    if ( FingerprintData->source[0] != '\0' )
        {
            json_object_object_add(encode_json_fingerprint, "source", json_object_new_string( FingerprintData->source ));
        }

    if ( FingerprintData->type[0] != '\0' )
        {
            json_object_object_add(encode_json_fingerprint, "client_server", json_object_new_string( FingerprintData->type ));
        }

    if ( FingerprintData->expire != 0 )
        {
            json_object_object_add(encode_json_fingerprint, "expire", json_object_new_int( FingerprintData->expire ));
        }

    /***********************************/
    /* Add "alert" data to fingerprint */
    /***********************************/

    if ( json_object_object_get_ex(json_obj, "alert", &tmp))
        {

            const char *alert_data = json_object_get_string(tmp);

            if ( alert_data == NULL )
                {
                    Meer_Log(WARN, "[%s, line %d] Unabled to get alert data!", __FILE__, __LINE__);
                }

            json_obj_alert = json_tokener_parse( alert_data );

            if ( json_obj_alert == NULL )
                {
                    Meer_Log(WARN, "Unable to json_tokener_parse: %s", json_object_get_string(tmp) );
                }

            /* signature_id */

            if (json_object_object_get_ex(json_obj_alert, "signature_id", &tmp))
                {
                    signature_id = json_object_get_int64(tmp);
                    json_object_object_add(encode_json_fingerprint, "signature_id", json_object_new_int64(signature_id));
                }

            /* signature */

            if (json_object_object_get_ex(json_obj_alert, "signature", &tmp))
                {
                    json_object_object_add(encode_json_fingerprint, "signature", json_object_new_string(json_object_get_string(tmp) ));
                }

            /* rev */

            if (json_object_object_get_ex(json_obj_alert, "rev", &tmp))
                {
                    json_object_object_add(encode_json_fingerprint, "rev", json_object_new_int64(json_object_get_int64(tmp) ));
                }

        }
    else
        {
            Meer_Log(WARN, "[%s, line %d] Alert data is NULL?!?!!", __FILE__, __LINE__);
        }



    /***********************************/
    /* Add "http" data to fingerprint */
    /***********************************/

    if ( !strcmp(app_proto, "http" ) )
        {

            if ( json_object_object_get_ex(json_obj, "http", &tmp))
                {

                    const char *http_data = json_object_get_string(tmp);

                    if ( http_data == NULL )
                        {
                            Meer_Log(WARN, "[%s, line %d] Unabled to get http data!", __FILE__, __LINE__);
                            return;
                        }

                    json_obj_http = json_tokener_parse( http_data );

                    if ( json_obj_http == NULL )
                        {
                            Meer_Log(WARN, "Unable to json_tokener_parse: %s", json_object_get_string(tmp) );
                            return;
                        }

                    if (json_object_object_get_ex(json_obj_http, "http_user_agent", &tmp))
                        {
                            json_object_object_add(encode_json_http, "http_user_agent", json_object_new_string(json_object_get_string(tmp) ));
                        }

                    if (json_object_object_get_ex(json_obj_http, "xff", &tmp))
                        {
                            json_object_object_add(encode_json_http, "xff", json_object_new_string(json_object_get_string(tmp) ));
                        }
                }

            snprintf(http, PACKET_BUFFER_SIZE_DEFAULT, "%s", json_object_to_json_string_ext(encode_json_http, JSON_C_TO_STRING_PLAIN));
        }

    snprintf(string, PACKET_BUFFER_SIZE_DEFAULT, "%s", json_object_to_json_string_ext(encode_json_fingerprint, JSON_C_TO_STRING_PLAIN));


    if ( http[0] != '\0' )
        {

            char new_string[PACKET_BUFFER_SIZE_DEFAULT] = { 0 };

            string[ strlen(string) - 1 ] = '\0' ;
            snprintf(new_string, PACKET_BUFFER_SIZE_DEFAULT, "%s, \"http\": %s}", string, http);
            new_string[ sizeof(new_string) - 1] = '\0';

            strlcpy(string, new_string, PACKET_BUFFER_SIZE_DEFAULT);

        }

    snprintf(key, sizeof(key), "%s|event|%s|%" PRIu64 "", FINGERPRINT_REDIS_KEY, src_ip, signature_id);
    Redis_Writer( "SET", key, string, FingerprintData->expire );


    json_object_put(tmp);
    json_object_put(encode_json);
    json_object_put(encode_json_fingerprint);
    json_object_put(encode_json_http);
    json_object_put(json_obj_alert);

    snprintf(str, size, "%s", string);

}

bool Is_Fingerprint( struct json_object *json_obj, struct _FingerprintData *FingerprintData )
{

    struct json_object *tmp = NULL;
    struct json_object *json_obj_alert= NULL;
    struct json_object *json_obj_metadata= NULL;

    bool ret = false;

    const char *alert_data = NULL;
    const char *metadata = NULL;

    char *fingerprint_d_os = NULL;
    char *fingerprint_d_type = NULL;
    char *fingerprint_d_expire = NULL;
    char *fingerprint_d_source = NULL;

    char *fingerprint_os = "unknown";
    char *fingerprint_source = "unknown";
    char *fingerprint_expire = NULL;

    char *ptr1 = NULL;

    if ( json_object_object_get_ex(json_obj, "alert", &tmp) )
        {

            alert_data = json_object_get_string(tmp);

            if ( alert_data == NULL )
                {
                    Meer_Log(WARN, "[%s, line %d] Unable to get alert data!", __FILE__, __LINE__);
                    return(false);
                }

            json_obj_alert = json_tokener_parse(alert_data);

            if ( json_obj_alert == NULL )
                {
                    Meer_Log(WARN, "Unable to json_tokener_parse: %s", alert_data);
                    return(false);
                }

            if ( json_object_object_get_ex(json_obj_alert, "metadata", &tmp) )
                {

                    metadata = json_object_get_string(tmp);
                    json_obj_metadata = json_tokener_parse(metadata);

                    /* Get OS type */

                    if ( json_object_object_get_ex(json_obj_metadata, "fingerprint_os", &tmp))
                        {

                            ret = true;
                            fingerprint_d_os =  (char *)json_object_get_string(tmp);

                            strtok_r(fingerprint_d_os, "\"", &ptr1);

                            if ( ptr1 == NULL )
                                {
                                    Meer_Log(WARN, "[%s, line %d] Failure to decode fingerprint_os from %s", __FILE__, __LINE__, fingerprint_d_os);
                                }

                            fingerprint_os = strtok_r(NULL, "\"", &ptr1);

                            if ( fingerprint_os == NULL )
                                {
                                    Meer_Log(WARN, "[%s, line %d] Failure to decode fingerprint_os from %s", __FILE__, __LINE__, fingerprint_d_os);
                                }

                            strlcpy(FingerprintData->os, fingerprint_os, sizeof(FingerprintData->os));

                        }

                    /* Fingerprint source (packet/log) */

                    if ( json_object_object_get_ex(json_obj_metadata, "fingerprint_source", &tmp))
                        {

                            ret = true;

                            fingerprint_d_source =  (char *)json_object_get_string(tmp);

                            strtok_r(fingerprint_d_source, "\"", &ptr1);

                            if ( ptr1 == NULL )
                                {
                                    Meer_Log(WARN, "[%s, line %d] Failure to decode fingerprint_source from %s", __FILE__, __LINE__, fingerprint_d_source);
                                }

                            fingerprint_source = strtok_r(NULL, "\"", &ptr1);

                            if ( fingerprint_source == NULL )
                                {
                                    Meer_Log(WARN, "[%s, line %d] Failure to decode fingerprint_os from %s", __FILE__, __LINE__, fingerprint_d_source);
                                }

                            strlcpy(FingerprintData->source, fingerprint_source, sizeof(FingerprintData->source));
                        }


                    /* Fingerprint expire time - in seconds */

                    if ( json_object_object_get_ex(json_obj_metadata, "fingerprint_expire", &tmp))
                        {

                            ret = true;

                            fingerprint_d_expire =  (char *)json_object_get_string(tmp);

                            strtok_r(fingerprint_d_expire, "\"", &ptr1);

                            if ( ptr1 == NULL )
                                {
                                    Meer_Log(WARN, "[%s, line %d] Failure to decode fingerprint_expire from %s", __FILE__, __LINE__, fingerprint_d_expire);
                                }

                            fingerprint_expire = strtok_r(NULL, "\"", &ptr1);

                            if ( fingerprint_expire == NULL )
                                {
                                    Meer_Log(WARN, "[%s, line %d] Failure to decode fingerprint_expire from %s", __FILE__, __LINE__, fingerprint_d_expire);
                                }

                            FingerprintData->expire = atoi( fingerprint_expire );
                        }

                    /* Fingerprint type (client/server) */

                    if ( json_object_object_get_ex(json_obj_metadata, "fingerprint_type", &tmp))
                        {

                            ret = true;

                            fingerprint_d_type =  (char *)json_object_get_string(tmp);

                            if ( strcasestr( fingerprint_d_type, "client") )
                                {
                                    strlcpy(FingerprintData->type, "client", sizeof(FingerprintData->type));
                                }

                            else if ( strcasestr( fingerprint_d_type, "server") )
                                {
                                    strlcpy(FingerprintData->type, "server", sizeof(FingerprintData->type));
                                }
                        }

		    json_object_put(tmp);
                    json_object_put(json_obj_alert);
                    json_object_put(json_obj_metadata);

                    return(ret);

                }
            else
                {

                    /* No metadat a found at all */

		    json_object_put(tmp);
                    json_object_put(json_obj_alert);
                    json_object_put(json_obj_metadata);

                    return(false);

                }

        }

    json_object_put(tmp);
    json_object_put(json_obj_alert);
    json_object_put(json_obj_metadata);

    return(false);
}

void Get_Fingerprint( struct json_object *json_obj, const char *json_string, char *str, size_t size )
{

    bool valid_fingerprint_net = false;
    unsigned char ip[MAXIPBIT] = { 0 };

    uint8_t a = 0;
    uint16_t z = 0;
    uint16_t i = 0;

    uint16_t key_count = 0;

    char *tmp_ip = NULL;
    char *tmp_type = NULL;

    char src_ip[64] = { 0 };
    char dest_ip[64] = { 0 };

    char tmp_command[256] = { 0 };
    char tmp_redis[PACKET_BUFFER_SIZE_DEFAULT] = { 0 };

    char new_json_string[PACKET_BUFFER_SIZE_DEFAULT] = { 0 };
    char final_json_string[PACKET_BUFFER_SIZE_DEFAULT] = { 0 };

    redisReply *reply;

    struct json_object *tmp = NULL;
    struct json_object *json_obj_fingerprint = NULL;

    strlcpy( new_json_string, json_string, PACKET_BUFFER_SIZE_DEFAULT);

    if (json_object_object_get_ex(json_obj, "src_ip", &tmp))
        {
            strlcpy(src_ip, json_object_get_string(tmp), sizeof( src_ip ));
        }

    if (json_object_object_get_ex(json_obj, "dest_ip", &tmp))
        {
            strlcpy(dest_ip, json_object_get_string(tmp), sizeof( dest_ip ));
        }

    /* DHCP */

    for (a = 0; a < 2; a++ )
        {

            valid_fingerprint_net = false;

            if ( a == 0 )
                {

                    tmp_ip = src_ip;;
                    tmp_type = "src";

                    IP2Bit(src_ip, ip);

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

                    tmp_ip = dest_ip;
                    tmp_type = "dest";

                    IP2Bit(dest_ip, ip);

                    for ( z = 0; z < MeerCounters->fingerprint_network_count; z++ )
                        {
                            if ( Is_Inrange( ip, (unsigned char *)&Fingerprint_Networks[z].range, 1) )
                                {
                                    valid_fingerprint_net = true;
                                }
                        }
                }

            /* It's a good subnet to look for fingerprints,  lets start */

            if ( valid_fingerprint_net == true )
                {

                    snprintf(tmp_command, sizeof(tmp_command), "GET %s|dhcp|%s", FINGERPRINT_REDIS_KEY, tmp_ip);
                    Redis_Reader(tmp_command, tmp_redis, sizeof(tmp_redis));

                    if ( tmp_redis[0] != '\0' )
                        {

                            new_json_string[ strlen(new_json_string) - 2 ] = '\0';	/* Snip */

                            /* Append DHCP JSON */

                            snprintf(final_json_string, PACKET_BUFFER_SIZE_DEFAULT, "%s, \"fingerprint_dhcp_%s\": %s }", new_json_string, tmp_type, tmp_redis);

                            /* Copy final_json_string to new_json_string in case we have more modifications
                               to make */

                            strlcpy(new_json_string, final_json_string, PACKET_BUFFER_SIZE_DEFAULT);

                            reply = redisCommand(MeerOutput->c_redis, "SCAN 0 MATCH %s|event|%s|* count 1000000", FINGERPRINT_REDIS_KEY, tmp_ip);
                            key_count = reply->element[1]->elements;

                            if ( key_count > 0 )
                                {

                                    /* Start getting individual fingerprint data */

                                    for ( i = 0; i < key_count; i++ )
                                        {

                                            redisReply *kr = reply->element[1]->element[i];
                                            snprintf(tmp_command, sizeof(tmp_command), "GET %s", kr->str);

                                            Redis_Reader(tmp_command, tmp_redis, PACKET_BUFFER_SIZE_DEFAULT);

                                            /* Validate our JSON ! */

                                            if ( Validate_JSON_String( tmp_redis ) == 0 )
                                                {
                                                    json_obj_fingerprint = json_tokener_parse(tmp_redis);
                                                }
                                            else
                                                {
                                                    Meer_Log(WARN, "Incomplete or invalid fingerprint JSON.");
                                                    continue;
                                                }

                                            if ( json_object_object_get_ex(json_obj_fingerprint, "fingerprint", &tmp))
                                                {

                                                    new_json_string[ strlen(new_json_string) - 2 ] = '\0'; /* Snip */

                                                    snprintf(final_json_string, PACKET_BUFFER_SIZE_DEFAULT, "%s, \"fingerprint_%s_%d\": %s }", new_json_string, tmp_type, i, json_object_get_string(tmp) );


                                                    /* Copy final_json_string to new_json_string in case we have more modifications
                                                       to make */

                                                    strlcpy(new_json_string, final_json_string, PACKET_BUFFER_SIZE_DEFAULT);

                                                }
                                        }
                                }
                        }
                }

        }  /* for (a = 0; a < 2; a++ ) */


    json_object_put(json_obj_fingerprint);
    json_object_put(tmp);

    snprintf(str, size, "%s", new_json_string);

}

#endif
