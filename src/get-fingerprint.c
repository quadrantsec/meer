/*
** Copyright (C) 2018-2022 Quadrant Information Security <quadrantsec.com>
** Copyright (C) 2018-2022 Champ Clark III <cclark@quadrantsec.com>
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

void Fingerprint_DHCP ( struct json_object *json_obj, const char *json_string )
{

    struct json_object *tmp = NULL;
    struct json_object *json_obj_dhcp = NULL;
    struct json_object *tmp_dhcp = NULL;

    char key[256] = { 0 };

    char *assigned_ip = NULL;
    char *dest_ip = NULL;

    char *dhcp = NULL;

    if (json_object_object_get_ex(json_obj, "dest_ip", &tmp))
        {
            dest_ip = (char *)json_object_get_string(tmp);
        }


    if (json_object_object_get_ex(json_obj, "dhcp", &tmp))
        {

            dhcp = (char *)json_object_get_string(tmp);

            if ( Validate_JSON_String( dhcp ) == 0 )
                {

                    json_obj_dhcp = json_tokener_parse(dhcp);

                    if (json_object_object_get_ex(json_obj_dhcp, "assigned_ip", &tmp_dhcp))
                        {
                            assigned_ip = (char *)json_object_get_string(tmp_dhcp);
                        }
                }
        }

    if ( !strcmp(assigned_ip, "0.0.0.0" ) && strcmp(dest_ip, "255.255.255.255") )
        {
            assigned_ip = dest_ip;
        }

    snprintf(key, sizeof(key), "%s|dhcp|%s", FINGERPRINT_REDIS_KEY, assigned_ip);
    key[ sizeof( key ) - 1 ] = '\0';

    Redis_Writer( "SET", key, json_string, FINGERPRINT_DHCP_REDIS_EXPIRE );


    free(json_obj_dhcp );

}

bool Fingerprint_JSON_IP_Redis( struct json_object *json_obj )
{

    struct json_object *tmp = NULL;

    struct json_object *encode_json = NULL;
    encode_json = json_object_new_object();


    char key[128] = { 0 };
    char src_ip[64] = { 0 };

    if (json_object_object_get_ex(json_obj, "src_ip", &tmp))
        {
            strlcpy( src_ip, json_object_get_string(tmp), sizeof(src_ip) );
        }
    else
        {
            Meer_Log(WARN, "[%s, line %d] No 'src_ip' detected in JSON.", __FILE__, __LINE__);
            return(false);
        }

    /* Timestamp  */

    if ( json_object_object_get_ex(json_obj, "timestamp", &tmp))
        {
            json_object *jtimestamp = json_object_new_string( json_object_get_string(tmp) );
            json_object_object_add(encode_json,"timestamp", jtimestamp);
        }
    else
        {
            Meer_Log(WARN, "[%s, line %d] No 'timestamp' detected in JSON.", __FILE__, __LINE__);
            return(false);
        }

    if (json_object_object_get_ex(json_obj, "app_proto", &tmp))
        {
            json_object *japp_proto = json_object_new_string( json_object_get_string(tmp) );
            json_object_object_add(encode_json,"app_proto", japp_proto);
        }

    if (json_object_object_get_ex(json_obj, "flow_id", &tmp))
        {
            json_object *jflow_id = json_object_new_int64( json_object_get_int64(tmp) );
            json_object_object_add(encode_json,"flow_id", jflow_id);
        }
    else
        {
            Meer_Log(WARN, "[%s, line %d] No 'flow_id' detected in JSON.", __FILE__, __LINE__);
            return(false);
        }

    /* Add the "ip" (legacy reasons) */

    json_object *jip = json_object_new_string( src_ip );
    json_object_object_add(encode_json,"ip", jip);

    json_object *jsrc_ip = json_object_new_string( src_ip );
    json_object_object_add(encode_json,"src_ip", jsrc_ip);

    /* Built the Redis Key */

    snprintf(key, sizeof(key), "%s|ip|%s", FINGERPRINT_REDIS_KEY, src_ip);  // DEBUG: what exactly is this used for?!
    key[ sizeof(key) - 1] = '\0';

    Redis_Writer( "SET", key, json_object_to_json_string(encode_json), FINGERPRINT_IP_REDIS_EXPIRE);

    json_object_put(encode_json);

    return(true);
}

bool Fingerprint_JSON_Event_Redis( struct json_object *json_obj, char *str, size_t size )
{

    struct json_object *tmp = NULL;
    struct json_object *json_obj_alert = NULL;
    struct json_object *json_obj_metadata = NULL;

    struct json_object *encode_json = NULL;
    encode_json = json_object_new_object();

    const char *alert_data;
    const char *metadata;

    char key[128] = { 0 };
    char src_ip[64] = { 0 };

    uint64_t signature_id = 0;

    char *fingerprint_os = "unknown";
    char *fingerprint_source = "unknown";
    char *fingerprint_type = "unknown";

    char *fingerprint_expire = NULL;
    int fingerprint_expire_int = FINGERPRINT_EVENT_REDIS_EXPIRE;

    char *tmp_string = NULL;
    char *ptr1 = NULL;

    char *string_f = malloc(MeerConfig->payload_buffer_size);

    if ( string_f == NULL )
        {
            fprintf(stderr, "[%s, line %d] Fatal Error:  Can't allocate memory! Abort!\n", __FILE__, __LINE__);
            exit(-1);
        }

    memset(string_f, 0, MeerConfig->payload_buffer_size);

    char *new_string = malloc(MeerConfig->payload_buffer_size);

    if ( new_string == NULL )
        {
            fprintf(stderr, "[%s, line %d] Fatal Error:  Can't allocate memory! Abort!\n", __FILE__, __LINE__);
            exit(-1);
        }

    memset(new_string, 0, MeerConfig->payload_buffer_size);

    /* Legacy stuff - In the main nest of the JSON */

    if (json_object_object_get_ex(json_obj, "src_ip", &tmp))		// Add to json_obj!
        {
            strlcpy(src_ip, json_object_get_string(tmp), sizeof(src_ip) );
            json_object *jip = json_object_new_string( src_ip );
            json_object_object_add(json_obj,"ip", jip);
        }

    if (json_object_object_get_ex(json_obj, "payload", &tmp))		// Add to encode_json!
        {
            json_object *jpayload = json_object_new_string( json_object_get_string(tmp) );
            json_object_object_add(encode_json,"payload", jpayload);
        }

    if ( json_object_object_get_ex(json_obj, "alert", &tmp) )
        {

            alert_data = json_object_get_string(tmp);

            if ( alert_data == NULL )
                {
                    Meer_Log(WARN, "[%s, line %d] Unable to get alert data!", __FILE__, __LINE__);
                    return(false);
                }

            json_obj_alert = json_tokener_parse(alert_data);

            /* Legacy stuff - Add to "fingerprint" data */

            if (json_object_object_get_ex(json_obj_alert, "signature_id", &tmp))
                {

                    signature_id = json_object_get_int64(tmp);

                    json_object *jsignature_id = json_object_new_int64( signature_id );
                    json_object_object_add(encode_json, "signature_id", jsignature_id);
                }

            if (json_object_object_get_ex(json_obj_alert, "rev", &tmp))
                {
                    json_object *jrev = json_object_new_int64( json_object_get_int64(tmp) );
                    json_object_object_add(encode_json, "rev", jrev);
                }

            if (json_object_object_get_ex(json_obj_alert, "signature", &tmp))
                {
                    json_object *jsignature = json_object_new_string( json_object_get_string(tmp) );
                    json_object_object_add(encode_json, "signature", jsignature);
                }

            /* Now get metadata! */

            if ( json_object_object_get_ex(json_obj_alert, "metadata", &tmp) )
                {

                    metadata = json_object_get_string(tmp);
                    json_obj_metadata = json_tokener_parse(metadata);

                    /* OS */

                    if ( json_object_object_get_ex(json_obj_metadata, "fingerprint_os", &tmp))
                        {

                            tmp_string =  (char *)json_object_get_string(tmp);

                            strtok_r(tmp_string, "\"", &ptr1);

                            if ( ptr1 == NULL )
                                {
                                    Meer_Log(WARN, "[%s, line %d] Failure to decode fingerprint_os from %s", __FILE__, __LINE__, tmp_string);
                                }

                            fingerprint_os = strtok_r(NULL, "\"", &ptr1);

                            if ( fingerprint_os == NULL )
                                {
                                    Meer_Log(WARN, "[%s, line %d] Failure to decode fingerprint os from %s", __FILE__, __LINE__, tmp_string);
                                }

                            json_object *jfingerprint_os = json_object_new_string( fingerprint_os );
                            json_object_object_add(encode_json,"os", jfingerprint_os);

                        }

                    /* Source */

                    if ( json_object_object_get_ex(json_obj_metadata, "fingerprint_source", &tmp))
                        {

                            tmp_string =  (char *)json_object_get_string(tmp);

                            strtok_r(tmp_string, "\"", &ptr1);

                            if ( ptr1 == NULL )
                                {
                                    Meer_Log(WARN, "[%s, line %d] Failure to decode fingerprint source from %s", __FILE__, __LINE__, tmp_string);
                                }

                            fingerprint_source = strtok_r(NULL, "\"", &ptr1);

                            if ( fingerprint_source == NULL )
                                {
                                    Meer_Log(WARN, "[%s, line %d] Failure to decode fingerprint source from %s", __FILE__, __LINE__, tmp_string);
                                }

                            json_object *jfingerprint_source = json_object_new_string( fingerprint_source );
                            json_object_object_add(encode_json,"source", jfingerprint_source);

                        }

                    /* Client/Server */

                    if ( json_object_object_get_ex(json_obj_metadata, "fingerprint_type", &tmp))
                        {

                            tmp_string =  (char *)json_object_get_string(tmp);

                            strtok_r(tmp_string, "\"", &ptr1);

                            if ( ptr1 == NULL )
                                {
                                    Meer_Log(WARN, "[%s, line %d] Failure to decode fingerprint type from %s", __FILE__, __LINE__, tmp_string);
                                }

                            fingerprint_type = strtok_r(NULL, "\"", &ptr1);

                            if ( fingerprint_type == NULL )
                                {
                                    Meer_Log(WARN, "[%s, line %d] Failure to decode fingerprint type from %s", __FILE__, __LINE__, tmp_string);
                                }

                            json_object *jfingerprint_type = json_object_new_string( fingerprint_type );
                            json_object_object_add(encode_json,"client_server", jfingerprint_type);

                        }

                    /* Expire */

                    if ( json_object_object_get_ex(json_obj_metadata, "fingerprint_expire", &tmp))
                        {

                            tmp_string = (char *)json_object_get_string(tmp);

                            strtok_r(tmp_string, "\"", &ptr1);

                            if ( ptr1 == NULL )
                                {
                                    Meer_Log(WARN, "[%s, line %d] Failure to decode fingerprint expire from %s", __FILE__, __LINE__, tmp_string);
                                }

                            fingerprint_expire = strtok_r(NULL, "\"", &ptr1);

                            if ( fingerprint_expire == NULL )
                                {
                                    Meer_Log(WARN, "[%s, line %d] Failure to decode fingerprint expire from %s", __FILE__, __LINE__, tmp_string);
                                }

                            fingerprint_expire_int = atol( fingerprint_expire  );

                            if ( fingerprint_expire_int == 0 )
                                {
                                    Meer_Log(WARN, "[%s, line %d] Fingerprint expire is invalid, setting to default of %d", __FILE__, __LINE__, FINGERPRINT_EVENT_REDIS_EXPIRE);
                                    fingerprint_expire_int = FINGERPRINT_EVENT_REDIS_EXPIRE;
                                }

                            json_object *jfingerprint_expire = json_object_new_int64( fingerprint_expire_int );
                            json_object_object_add(encode_json,"expire", jfingerprint_expire);

                        }
                }
        }

    snprintf(key, sizeof(key), "%s|event|%s|%" PRIu64 "", FINGERPRINT_REDIS_KEY, src_ip, signature_id);
    key[ sizeof(key) -1 ] = '\0';

    snprintf(string_f, MeerConfig->payload_buffer_size, "%s", json_object_to_json_string_ext(json_obj, JSON_C_TO_STRING_PLAIN) );
    string_f[ strlen(string_f) - 1] = '\0';

    snprintf(new_string, MeerConfig->payload_buffer_size, "%s, \"fingerprint\": %s}", string_f, json_object_to_json_string_ext(encode_json, JSON_C_TO_STRING_PLAIN) );

    Redis_Writer( "SET", key, new_string, fingerprint_expire_int);

    snprintf(str, size, "%s", new_string);		/* String to return back */

    json_object_put(encode_json);
    json_object_put(json_obj_alert);
    json_object_put(json_obj_metadata);


    free(string_f);
    free(new_string);

    return(true);

}

bool Is_Fingerprint( struct json_object *json_obj )
{

    struct json_object *tmp = NULL;
    struct json_object *json_obj_alert= NULL;
    struct json_object *json_obj_metadata= NULL;

    const char *alert_data = NULL;
    const char *metadata = NULL;

    if ( json_object_object_get_ex(json_obj, "alert", &tmp) )
        {

            alert_data = json_object_get_string(tmp);

            if ( alert_data == NULL )
                {
                    Meer_Log(WARN, "[%s, line %d] Unable to get alert data!", __FILE__, __LINE__);
                    return(false);
                }

            json_obj_alert = json_tokener_parse(alert_data);

            if ( json_object_object_get_ex(json_obj_alert, "metadata", &tmp) )
                {

		    printf("Got alert.Metadata\n");

                    metadata = json_object_get_string(tmp);
                    json_obj_metadata = json_tokener_parse(metadata);


                    /* Does the JSON have "fingerprint" metadata? */

                    if ( json_object_object_get_ex(json_obj_metadata, "fingerprint_os", &tmp))
                        {
                            json_object_put(json_obj_alert);
                            json_object_put(json_obj_metadata);
                            return(true);
                        }

                    else if ( json_object_object_get_ex(json_obj_metadata, "fingerprint_source", &tmp))
                        {
                            json_object_put(json_obj_alert);
                            json_object_put(json_obj_metadata);
                            return(true);
                        }

                    else if ( json_object_object_get_ex(json_obj_metadata, "fingerprint_expire", &tmp))
                        {
                            json_object_put(json_obj_alert);
                            json_object_put(json_obj_metadata);
                            return(true);
                        }

                    else if ( json_object_object_get_ex(json_obj_metadata, "fingerprint_type", &tmp))
                        {
                            json_object_put(json_obj_alert);
                            json_object_put(json_obj_metadata);
                            return(true);
                        }
                }
        }

    json_object_put(json_obj_alert);
    json_object_put(json_obj_metadata);

    return(false);

}

void Get_Fingerprint( struct json_object *json_obj, char *str, size_t size, const char *json_string )
{

#define SRC_IP  0
#define DEST_IP  1

    redisReply *reply_r;
    redisReply *kr;

    struct json_object *tmp = NULL;
    struct json_object *json_obj_fingerprint = NULL;

    char src_ip[64] = { 0 };
    char dest_ip[64] = { 0 };

    char tmp_command[256] = { 0 };

    unsigned char ip[MAXIPBIT] = { 0 };

    char *tmp_ip = NULL;
    char *tmp_type = NULL;

    uint8_t a = 0;
    uint16_t z = 0;
    uint16_t i = 0;

    bool valid_fingerprint_net = false;

    char *tmp_redis = malloc(MeerConfig->payload_buffer_size);

    if ( tmp_redis == NULL )
        {
            fprintf(stderr, "[%s, line %d] Fatal Error: Can't allocate memory! Abort!\n", __FILE__, __LINE__);
            exit(-1);
        }

    memset(tmp_redis, 0, MeerConfig->payload_buffer_size );

    char *new_json_string = malloc(MeerConfig->payload_buffer_size);

    if ( new_json_string == NULL )
        {
            fprintf(stderr, "[%s, line %d] Fatal Error: Can't allocate memory! Abort!\n", __FILE__, __LINE__);
            exit(-1);
        }

    memset(new_json_string, 0, MeerConfig->payload_buffer_size );

    char *tmp_json_string = malloc(MeerConfig->payload_buffer_size);

    if ( tmp_json_string == NULL )
        {
            fprintf(stderr, "[%s, line %d] Fatal Error: Can't allocate memory! Abort!\n", __FILE__, __LINE__);
            exit(-1);
        }

    memset(tmp_json_string, 0, MeerConfig->payload_buffer_size );

    strlcpy(new_json_string, json_string, MeerConfig->payload_buffer_size );

    json_object_object_get_ex(json_obj, "src_ip", &tmp);
    strlcpy( src_ip, json_object_get_string(tmp), sizeof(src_ip) );

    json_object_object_get_ex(json_obj, "dest_ip", &tmp);
    strlcpy( dest_ip, json_object_get_string(tmp), sizeof(dest_ip) );

    /* a = 0 = src,  a = 1 = dest */

    for (a = 0; a < 2; a++ )
        {

            if ( a == SRC_IP )
                {
                    tmp_ip = src_ip;
                    tmp_type = "src";
                }

            if ( a == DEST_IP )
                {
                    tmp_ip = dest_ip;
                    tmp_type = "dest";
                }


            IP2Bit(tmp_ip, ip);

            valid_fingerprint_net = false;

            for ( z = 0; z < MeerCounters->fingerprint_network_count; z++ )
                {
                    if ( Is_Inrange( ip, (unsigned char *)&Fingerprint_Networks[z].range, 1) )
                        {
                            valid_fingerprint_net = true;
                            break;
                        }
                }

            if ( valid_fingerprint_net == true )
                {

                    /* Get any DHCP information we might have */

                    snprintf(tmp_command, sizeof(tmp_command), "GET %s|dhcp|%s", FINGERPRINT_REDIS_KEY, tmp_ip);
                    tmp_command[ sizeof(tmp_command) - 1 ] = '\0';

                    Redis_Reader(tmp_command, tmp_redis, MeerConfig->payload_buffer_size);

                    /* We have DHCP data, we append it to the alert */

                    if ( tmp_redis[0] != '\0' )
                        {

                            new_json_string[ strlen(new_json_string) - 2 ] = '\0';      /* Snip */

                            /* Append DHCP JSON */

                            snprintf(tmp_json_string, MeerConfig->payload_buffer_size, "%s, \"fingerprint_dhcp_%s\": %s }", new_json_string, tmp_type, tmp_redis);
                            tmp_json_string[ MeerConfig->payload_buffer_size - 1 ] = '\0';

                            strlcpy(new_json_string, tmp_json_string, MeerConfig->payload_buffer_size);

                        }

                    reply_r = redisCommand(MeerOutput->c_redis, "SCAN 0 MATCH %s|event|%s|* count 1000000", FINGERPRINT_REDIS_KEY, tmp_ip);

                    if ( reply_r->element[1]->elements > 0 )
                        {


                            /* Grab individual fingerprint */
                            for ( i = 0; i < reply_r->element[1]->elements; i++ )
                                {

                                    kr = reply_r->element[1]->element[i];
                                    snprintf(tmp_command, sizeof(tmp_command), "GET %s", kr->str);
                                    tmp_command[ sizeof(tmp_command) - 1 ] = '\0';

                                    Redis_Reader(tmp_command, tmp_redis, MeerConfig->payload_buffer_size);

                                    /* Validate fingerprint JSON */

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

                                            snprintf(tmp_json_string, MeerConfig->payload_buffer_size, "%s, \"fingerprint_%s_%d\": %s }", new_json_string, tmp_type, i, json_object_get_string(tmp) );

                                            tmp_json_string[ MeerConfig->payload_buffer_size - 1 ] = '\0';


                                            /* Copy final_json_string to new_json_string in case we have more modifications
                                               to make */

                                            strlcpy(new_json_string, tmp_json_string, MeerConfig->payload_buffer_size);

                                        }

                                    json_object_put(json_obj_fingerprint);

                                }

//				freeReplyObject(kr);
                        }

                    freeReplyObject(reply_r);
                }

        } /* for (a = 0; a < 2; a++ ) */

    snprintf(str, MeerConfig->payload_buffer_size, "%s", new_json_string);
    str[ MeerConfig->payload_buffer_size - 1 ] = '\0';

    free(tmp_redis);
    free(tmp_json_string);
    free(new_json_string);

//freeReplyObject(reply_r);
}

bool Fingerprint_In_Range( char *ip_address )
{

    uint16_t z = 0;
    bool valid_fingerprint_net = false;
    unsigned char ip[MAXIPBIT] = { 0 };

    IP2Bit(ip_address, ip);

    for ( z = 0; z < MeerCounters->fingerprint_network_count; z++ )
        {
            if ( Is_Inrange( ip, (unsigned char *)&Fingerprint_Networks[z].range, 1) )
                {
                    valid_fingerprint_net = true;
                    break;
                }
        }

    return( valid_fingerprint_net );
}

#endif
