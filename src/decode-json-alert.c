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

/* Decode Sagan/Suricata "alerts" */

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

#include "util.h"
#include "meer.h"
#include "meer-def.h"

#ifdef HAVE_LIBMAXMINDDB
#include "geoip.h"
#endif

#include "decode-json-alert.h"

struct _MeerCounters *MeerCounters;
struct _MeerConfig *MeerConfig;

struct _DecodeAlert *Decode_JSON_Alert( struct json_object *json_obj, char *json_string )
{

    struct _DecodeAlert *Alert_Return_Struct = NULL;
    struct json_object *tmp = NULL;

    struct json_object *tmp_alert = NULL;
    struct json_object *tmp_flow = NULL;
    struct json_object *tmp_http = NULL;
    struct json_object *tmp_tls = NULL;
    struct json_object *tmp_smtp = NULL;
    struct json_object *tmp_email = NULL;

    struct json_object *tmp_ssh_server = NULL;
    struct json_object *tmp_ssh_server_2 = NULL;
    struct json_object *tmp_ssh_server_3 = NULL;

    struct json_object *tmp_ssh_client = NULL;
    struct json_object *tmp_ssh_client_2 = NULL;
    struct json_object *tmp_ssh_client_3 = NULL;

    struct json_object *json_obj_alert = NULL;
    struct json_object *json_obj_flow = NULL;
    struct json_object *json_obj_http = NULL;
    struct json_object *json_obj_tls = NULL;
    struct json_object *json_obj_smtp = NULL;
    struct json_object *json_obj_email = NULL;

    struct json_object *json_obj_ssh_server = NULL;
    struct json_object *json_obj_ssh_client = NULL;

    bool has_alert = false;
    char new_ip[64];

#ifdef HAVE_LIBMAXMINDDB

    char geoip_src_json[1024] = { 0 };
    char geoip_dest_json[1024] = { 0 };
    char tmp_geoip[PACKET_BUFFER_SIZE_DEFAULT] = { 0 };

#endif

    Alert_Return_Struct = (struct _DecodeAlert *) malloc(sizeof(_DecodeAlert));

    if ( Alert_Return_Struct == NULL )
        {
            Meer_Log(ERROR, "[%s, line %d] JSON: \"%s\" Failed to allocate memory for _DecodeAlert. Abort!", __FILE__, __LINE__, json_string);
        }

    memset(Alert_Return_Struct, 0, sizeof(_DecodeAlert));

    Alert_Return_Struct->json = json_string;
    Remove_Return(Alert_Return_Struct->json);

    Alert_Return_Struct->event_type = "alert";
    Alert_Return_Struct->ip_version = 4;

    Alert_Return_Struct->converted_timestamp[0] = '\0';
    Alert_Return_Struct->app_proto[0] = '\0';

    /* Extra data */

    Alert_Return_Struct->payload[0] = '\0';
    Alert_Return_Struct->src_dns[0] = '\0';
    Alert_Return_Struct->dest_dns[0] = '\0';

    Alert_Return_Struct->alert_action[0] = '\0';
    Alert_Return_Struct->alert_gid[0] = '\0';
    Alert_Return_Struct->alert_rev = 0;
    Alert_Return_Struct->alert_signature[0] = '\0';
    Alert_Return_Struct->alert_category[0] = '\0';
    Alert_Return_Struct->alert_severity[0] = '\0';
    Alert_Return_Struct->alert_metadata[0] = '\0';

    Alert_Return_Struct->alert_has_metadata = false;
    Alert_Return_Struct->alert_signature_id = 0;

    /* Flow */

    Alert_Return_Struct->has_flow = false;

    Alert_Return_Struct->flow_pkts_toserver = 0 ;
    Alert_Return_Struct->flow_pkts_toclient = 0;
    Alert_Return_Struct->flow_bytes_toserver = 0;
    Alert_Return_Struct->flow_bytes_toclient = 0;
    Alert_Return_Struct->flow_start_timestamp[0] = '\0';

    /* SMTP */

    Alert_Return_Struct->has_smtp = false;

    Alert_Return_Struct->smtp_helo[0] = '\0';
    Alert_Return_Struct->smtp_mail_from[0] = '\0';
    Alert_Return_Struct->smtp_rcpt_to[0] = '\0';

    /* HTTP */

    Alert_Return_Struct->has_http = false;

    Alert_Return_Struct->http_hostname[0] = '\0';
    Alert_Return_Struct->http_url[0] = '\0';
    Alert_Return_Struct->http_content_type[0] = '\0';
    Alert_Return_Struct->http_method[0] = '\0';
    Alert_Return_Struct->http_user_agent[0] = '\0';
    Alert_Return_Struct->http_refer[0] = '\0';
    Alert_Return_Struct->http_protocol[0] = '\0';
    Alert_Return_Struct->http_xff[0] = '\0';
    Alert_Return_Struct->http_length = 0;

    /* TLS */

    Alert_Return_Struct->has_tls = false;

    Alert_Return_Struct->tls_session_resumed[0] = '\0';
    Alert_Return_Struct->tls_sni[0] = '\0';
    Alert_Return_Struct->tls_version[0] = '\0';
    Alert_Return_Struct->tls_subject[0] = '\0';
    Alert_Return_Struct->tls_issuerdn[0] = '\0';
    Alert_Return_Struct->tls_notbefore[0] = '\0';
    Alert_Return_Struct->tls_notafter[0] = '\0';
    Alert_Return_Struct->tls_fingerprint[0] = '\0';
    Alert_Return_Struct->tls_serial = 0;


    /* SSH */

    Alert_Return_Struct->has_ssh_server = false;
    Alert_Return_Struct->has_ssh_client = false;

    Alert_Return_Struct->ssh_client_proto_version[0] = '\0';
    Alert_Return_Struct->ssh_client_software_version[0] = '\0';
    Alert_Return_Struct->ssh_server_proto_version[0] = '\0';
    Alert_Return_Struct->ssh_server_software_version[0] = '\0';

    /* Email */

    Alert_Return_Struct->email_status[0] = '\0';
    Alert_Return_Struct->email_from[0] = '\0';
    Alert_Return_Struct->email_to[0] = '\0';
    Alert_Return_Struct->email_cc[0] = '\0';
    Alert_Return_Struct->email_attachment[0] = '\0';




    /* Base information from JSON */

    if (json_object_object_get_ex(json_obj, "timestamp", &tmp))
        {
            Alert_Return_Struct->timestamp = (char *)json_object_get_string(tmp);
            Convert_ISO8601_For_SQL( Alert_Return_Struct->timestamp, Alert_Return_Struct->converted_timestamp, sizeof( Alert_Return_Struct->converted_timestamp) );

        }

    if (json_object_object_get_ex(json_obj, "flow_id", &tmp))
        {
            Alert_Return_Struct->flowid = (char *)json_object_get_string(tmp);
        }

    if (json_object_object_get_ex(json_obj, "in_iface", &tmp))
        {
            Alert_Return_Struct->in_iface = (char *)json_object_get_string(tmp);
        }

    if (json_object_object_get_ex(json_obj, "src_ip", &tmp))
        {
            strlcpy(Alert_Return_Struct->src_ip, json_object_get_string(tmp), sizeof( Alert_Return_Struct->src_ip ));
        }

    if (json_object_object_get_ex(json_obj, "src_port", &tmp))
        {
            Alert_Return_Struct->src_port = (char *)json_object_get_string(tmp);
        }

    if (json_object_object_get_ex(json_obj, "dest_ip", &tmp))
        {
            strlcpy(Alert_Return_Struct->dest_ip, json_object_get_string(tmp), sizeof( Alert_Return_Struct->dest_ip ));
        }

    if (json_object_object_get_ex(json_obj, "dest_port", &tmp))
        {
            Alert_Return_Struct->dest_port = (char *)json_object_get_string(tmp);
        }

    if (json_object_object_get_ex(json_obj, "proto", &tmp))
        {
            Alert_Return_Struct->proto = (char *)json_object_get_string(tmp);
        }

    if (json_object_object_get_ex(json_obj, "host", &tmp))
        {
            Alert_Return_Struct->host = (char *)json_object_get_string(tmp);
        }

    if (json_object_object_get_ex(json_obj, "payload", &tmp))
        {
            strlcpy(Alert_Return_Struct->payload, (char *)json_object_get_string(tmp), sizeof(Alert_Return_Struct->payload));
        }

    if (json_object_object_get_ex(json_obj, "icmp_type", &tmp))
        {
            Alert_Return_Struct->icmp_type = (char *)json_object_get_string(tmp);
        }

    if (json_object_object_get_ex(json_obj, "icmp_code", &tmp))
        {
            Alert_Return_Struct->icmp_code = (char *)json_object_get_string(tmp);
        }

    if (json_object_object_get_ex(json_obj, "app_proto", &tmp))
        {
            strlcpy(Alert_Return_Struct->app_proto, (char *)json_object_get_string(tmp), sizeof(Alert_Return_Struct->app_proto));
        }

    if (json_object_object_get_ex(json_obj, "xff", &tmp))
        {
            Alert_Return_Struct->xff = (char *)json_object_get_string(tmp);
        }

    if (json_object_object_get_ex(json_obj, "facility", &tmp))
        {
            Alert_Return_Struct->facility = (char *)json_object_get_string(tmp);
        }

    if (json_object_object_get_ex(json_obj, "priority", &tmp))
        {
            Alert_Return_Struct->priority = (char *)json_object_get_string(tmp);
        }

    if (json_object_object_get_ex(json_obj, "level", &tmp))
        {
            Alert_Return_Struct->level = (char *)json_object_get_string(tmp);
        }

    if (json_object_object_get_ex(json_obj, "program", &tmp))
        {
            Alert_Return_Struct->program = (char *)json_object_get_string(tmp);
        }

    if ( json_object_object_get_ex(json_obj, "normalize", &tmp))
        {

            if ( (char *)json_object_get_string(tmp) != NULL && Validate_JSON_String( (char *)json_object_get_string(tmp) ) == 0 )
                {
                    Alert_Return_Struct->has_normalize = true;
                    Alert_Return_Struct->normalize = (char *)json_object_get_string(tmp);
                }

        }

    if ( MeerConfig->bluedot == true )
        {

            if ( json_object_object_get_ex(json_obj, "bluedot", &tmp))
                {

                    if ( Validate_JSON_String( (char *)json_object_get_string(tmp) ) == 0 )
                        {

                            MeerCounters->BluedotCount++;

                            Alert_Return_Struct->has_bluedot = true;
                            Alert_Return_Struct->bluedot = (char *)json_object_get_string(tmp);


                        }
                }

        }


    /* Extract "alert" information */

    if (json_object_object_get_ex(json_obj, "alert", &tmp))
        {

            has_alert = true;

            json_obj_alert = json_tokener_parse(json_object_get_string(tmp));

            if (json_object_object_get_ex(json_obj_alert, "action", &tmp_alert))
                {
                    strlcpy(Alert_Return_Struct->alert_action, (char *)json_object_get_string(tmp_alert), sizeof(Alert_Return_Struct->alert_action));
                }

            if (json_object_object_get_ex(json_obj_alert, "gid", &tmp_alert))
                {
                    strlcpy(Alert_Return_Struct->alert_gid, (char *)json_object_get_string(tmp_alert), sizeof(Alert_Return_Struct->alert_action));
                }

            if (json_object_object_get_ex(json_obj_alert, "signature_id", &tmp_alert))
                {
                    Alert_Return_Struct->alert_signature_id = atol((char *)json_object_get_string(tmp_alert));
                }

            if (json_object_object_get_ex(json_obj_alert, "rev", &tmp_alert))
                {
                    Alert_Return_Struct->alert_rev = atol((char *)json_object_get_string(tmp_alert));
                }

            if (json_object_object_get_ex(json_obj_alert, "signature", &tmp_alert))
                {
                    strlcpy(Alert_Return_Struct->alert_signature, (char *)json_object_get_string(tmp_alert), sizeof(Alert_Return_Struct->alert_signature));
                }

            if (json_object_object_get_ex(json_obj_alert, "category", &tmp_alert))
                {
                    strlcpy(Alert_Return_Struct->alert_category, (char *)json_object_get_string(tmp_alert), sizeof(Alert_Return_Struct->alert_category));
                }

            if (json_object_object_get_ex(json_obj_alert, "severity", &tmp_alert))
                {
                    strlcpy(Alert_Return_Struct->alert_severity, (char *)json_object_get_string(tmp_alert), sizeof(Alert_Return_Struct->alert_severity));
                }

            if (json_object_object_get_ex(json_obj_alert, "metadata", &tmp_alert))
                {

                    strlcpy(Alert_Return_Struct->alert_metadata, (char *)json_object_get_string(tmp_alert), sizeof(Alert_Return_Struct->alert_metadata));
                    Alert_Return_Struct->alert_has_metadata = true;
                    MeerCounters->MetadataCount++;

                }

            json_object_put(json_obj_alert);

        }

    /* Decode flow data */

    if ( MeerConfig->flow == true )
        {

            if ( json_object_object_get_ex(json_obj, "flow", &tmp))
                {
                    Alert_Return_Struct->has_flow = true;

                    if ( Validate_JSON_String( (char *)json_object_get_string(tmp) ) == 0 )
                        {

                            MeerCounters->FlowCount++;

                            json_obj_flow = json_tokener_parse(json_object_get_string(tmp));

                            if (json_object_object_get_ex(json_obj_flow, "pkts_toserver", &tmp_flow))
                                {
                                    Alert_Return_Struct->flow_pkts_toserver = atol((char *)json_object_get_string(tmp_flow));
                                }

                            if (json_object_object_get_ex(json_obj_flow, "pkts_toclient", &tmp_flow))
                                {
                                    Alert_Return_Struct->flow_pkts_toclient = atol((char *)json_object_get_string(tmp_flow));
                                }

                            if (json_object_object_get_ex(json_obj_flow, "bytes_toserver", &tmp_flow))
                                {
                                    Alert_Return_Struct->flow_bytes_toserver = atol((char *)json_object_get_string(tmp_flow));
                                }

                            if (json_object_object_get_ex(json_obj_flow, "bytes_toclient", &tmp_flow))
                                {
                                    Alert_Return_Struct->flow_bytes_toclient = atol((char *)json_object_get_string(tmp_flow));
                                }

                            if (json_object_object_get_ex(json_obj_flow, "start", &tmp_flow))
                                {
                                    strlcpy(Alert_Return_Struct->flow_start_timestamp, (char *)json_object_get_string(tmp_flow), sizeof(Alert_Return_Struct->flow_start_timestamp));

                                    Convert_ISO8601_For_SQL( Alert_Return_Struct->flow_start_timestamp, Alert_Return_Struct->flow_start_timestamp_converted, sizeof( Alert_Return_Struct->flow_start_timestamp_converted) );
                                }

                            json_object_put(json_obj_flow);

                        }
                }

        }

    if ( MeerConfig->http == true && !strcmp( Alert_Return_Struct->app_proto, "http" ))
        {

            if ( json_object_object_get_ex(json_obj, "http", &tmp))
                {

                    Alert_Return_Struct->has_http = true;

                    if ( Validate_JSON_String( (char *)json_object_get_string(tmp) ) == 0 )
                        {

                            MeerCounters->HTTPCount++;

                            json_obj_http = json_tokener_parse(json_object_get_string(tmp));

                            if (json_object_object_get_ex(json_obj_http, "hostname", &tmp_http))
                                {
                                    strlcpy(Alert_Return_Struct->http_hostname, (char *)json_object_get_string(tmp_http), sizeof(Alert_Return_Struct->http_hostname));
                                }

                            if (json_object_object_get_ex(json_obj_http, "url", &tmp_http))
                                {
                                    strlcpy(Alert_Return_Struct->http_url, (char *)json_object_get_string(tmp_http), sizeof(Alert_Return_Struct->http_url));
                                }

                            if (json_object_object_get_ex(json_obj_http, "http_content_type", &tmp_http))
                                {
                                    strlcpy(Alert_Return_Struct->http_content_type, (char *)json_object_get_string(tmp_http), sizeof(Alert_Return_Struct->http_content_type));
                                }

                            if (json_object_object_get_ex(json_obj_http, "http_method", &tmp_http))
                                {
                                    strlcpy(Alert_Return_Struct->http_method, (char *)json_object_get_string(tmp_http), sizeof(Alert_Return_Struct->http_method));
                                }

                            if (json_object_object_get_ex(json_obj_http, "http_user_agent", &tmp_http))
                                {
                                    strlcpy(Alert_Return_Struct->http_user_agent, (char *)json_object_get_string(tmp_http), sizeof(Alert_Return_Struct->http_user_agent));
                                }

                            if (json_object_object_get_ex(json_obj_http, "http_refer", &tmp_http))
                                {
                                    strlcpy(Alert_Return_Struct->http_refer, (char *)json_object_get_string(tmp_http), sizeof(Alert_Return_Struct->http_refer));
                                }

                            if (json_object_object_get_ex(json_obj_http, "protocol", &tmp_http))
                                {
                                    strlcpy(Alert_Return_Struct->http_protocol, (char *)json_object_get_string(tmp_http), sizeof(Alert_Return_Struct->http_protocol));
                                }

                            if (json_object_object_get_ex(json_obj_http, "xff", &tmp_http))
                                {
                                    strlcpy(Alert_Return_Struct->http_xff, (char *)json_object_get_string(tmp_http), sizeof(Alert_Return_Struct->http_xff));
                                }

                            if (json_object_object_get_ex(json_obj_http, "status", &tmp_http))
                                {
                                    Alert_Return_Struct->http_status = atoi( (char *)json_object_get_string(tmp_http) );
                                }

                            if (json_object_object_get_ex(json_obj_http, "length", &tmp_http))
                                {
                                    Alert_Return_Struct->http_length = atol( (char *)json_object_get_string(tmp_http) );
                                }

                            json_object_put(json_obj_http);
                        }
                }

        }

    /* Proto is still "smtp",  email is a secondary part */

    if ( MeerConfig->email == true && !strcmp( Alert_Return_Struct->app_proto, "smtp" ))
        {

            Alert_Return_Struct->has_email = true;

            if ( json_object_object_get_ex(json_obj, "email", &tmp))

                if ( Validate_JSON_String( (char *)json_object_get_string(tmp) ) == 0 )
                    {

                        MeerCounters->EmailCount++;

                        json_obj_email = json_tokener_parse(json_object_get_string(tmp));

                        if (json_object_object_get_ex(json_obj_email, "status", &tmp_email))
                            {
                                strlcpy(Alert_Return_Struct->email_status, (char *)json_object_get_string(tmp_email), sizeof(Alert_Return_Struct->email_status));
                            }

                        if (json_object_object_get_ex(json_obj_email, "from", &tmp_email))
                            {
                                strlcpy(Alert_Return_Struct->email_from, (char *)json_object_get_string(tmp_email), sizeof(Alert_Return_Struct->email_from));
                            }

                        if (json_object_object_get_ex(json_obj_email, "to", &tmp_email))
                            {
                                strlcpy(Alert_Return_Struct->email_to, (char *)json_object_get_string(tmp_email), sizeof(Alert_Return_Struct->email_to));
                            }

                        if (json_object_object_get_ex(json_obj_email, "attachment", &tmp_email))
                            {
                                strlcpy(Alert_Return_Struct->email_attachment, (char *)json_object_get_string(tmp_email), sizeof(Alert_Return_Struct->email_attachment));
                            }

                        json_object_put(json_obj_email);
                    }

        }

    if ( MeerConfig->smtp == true && !strcmp( Alert_Return_Struct->app_proto, "smtp" ))
        {

            Alert_Return_Struct->has_smtp = true;

            if ( json_object_object_get_ex(json_obj, "smtp", &tmp))

                if ( Validate_JSON_String( (char *)json_object_get_string(tmp) ) == 0 )
                    {

                        MeerCounters->SMTPCount++;

                        json_obj_smtp = json_tokener_parse(json_object_get_string(tmp));

                        if (json_object_object_get_ex(json_obj_smtp, "helo", &tmp_smtp))
                            {
                                strlcpy(Alert_Return_Struct->smtp_helo, (char *)json_object_get_string(tmp_smtp), sizeof(Alert_Return_Struct->smtp_helo));
                            }

                        if (json_object_object_get_ex(json_obj_smtp, "mail_from", &tmp_smtp))
                            {
                                strlcpy(Alert_Return_Struct->smtp_mail_from, (char *)json_object_get_string(tmp_smtp), sizeof(Alert_Return_Struct->smtp_mail_from));
                            }

                        if (json_object_object_get_ex(json_obj_smtp, "rcpt_to", &tmp_smtp))
                            {
                                strlcpy(Alert_Return_Struct->smtp_rcpt_to, (char *)json_object_get_string(tmp_smtp), sizeof(Alert_Return_Struct->smtp_rcpt_to));
                            }

                        json_object_put(json_obj_smtp);
                    }


        }

    if ( MeerConfig->tls == true && !strcmp( Alert_Return_Struct->app_proto, "tls" ))
        {

            Alert_Return_Struct->has_tls = true;

            if ( json_object_object_get_ex(json_obj, "tls", &tmp))
                {

                    if ( Validate_JSON_String( (char *)json_object_get_string(tmp) ) == 0 )
                        {

                            MeerCounters->TLSCount++;

                            json_obj_tls = json_tokener_parse(json_object_get_string(tmp));

                            if (json_object_object_get_ex(json_obj_tls, "session_resumed", &tmp_tls))
                                {
                                    strlcpy(Alert_Return_Struct->tls_session_resumed, (char *)json_object_get_string(tmp_tls), sizeof(Alert_Return_Struct->tls_session_resumed));
                                }

                            if (json_object_object_get_ex(json_obj_tls, "sni", &tmp_tls))
                                {
                                    strlcpy(Alert_Return_Struct->tls_sni, (char *)json_object_get_string(tmp_tls), sizeof(Alert_Return_Struct->tls_sni));
                                }

                            if (json_object_object_get_ex(json_obj_tls, "version", &tmp_tls))
                                {
                                    strlcpy(Alert_Return_Struct->tls_version, (char *)json_object_get_string(tmp_tls), sizeof(Alert_Return_Struct->tls_version));
                                }

                            if (json_object_object_get_ex(json_obj_tls, "subject", &tmp_tls))
                                {
                                    strlcpy(Alert_Return_Struct->tls_subject, (char *)json_object_get_string(tmp_tls), sizeof(Alert_Return_Struct->tls_subject));
                                }

                            if (json_object_object_get_ex(json_obj_tls, "issuerdn", &tmp_tls))
                                {
                                    strlcpy(Alert_Return_Struct->tls_issuerdn, (char *)json_object_get_string(tmp_tls), sizeof(Alert_Return_Struct->tls_issuerdn));
                                }

                            if (json_object_object_get_ex(json_obj_tls, "notbefore", &tmp_tls))
                                {
                                    strlcpy(Alert_Return_Struct->tls_notbefore, (char *)json_object_get_string(tmp_tls), sizeof(Alert_Return_Struct->tls_notbefore));
                                }

                            if (json_object_object_get_ex(json_obj_tls, "notafter", &tmp_tls))
                                {
                                    strlcpy(Alert_Return_Struct->tls_notafter, (char *)json_object_get_string(tmp_tls), sizeof(Alert_Return_Struct->tls_notafter));
                                }

                            if (json_object_object_get_ex(json_obj_tls, "fingerprint", &tmp_tls))
                                {
                                    strlcpy(Alert_Return_Struct->tls_fingerprint, (char *)json_object_get_string(tmp_tls), sizeof(Alert_Return_Struct->tls_fingerprint));
                                }

                            if (json_object_object_get_ex(json_obj_tls, "serial", &tmp_tls))
                                {
                                    Alert_Return_Struct->tls_serial = atoi( (char *)json_object_get_string(tmp_tls) );
                                }

                            json_object_put(json_obj_tls);

                        }
                }

        }

    if ( MeerConfig->ssh == true && !strcmp( Alert_Return_Struct->app_proto, "ssh" ))
        {

            if ( json_object_object_get_ex(json_obj, "ssh", &tmp))
                {

                    if ( Validate_JSON_String( (char *)json_object_get_string(tmp) ) == 0 )
                        {

                            MeerCounters->SSHCount++;

                            json_obj_ssh_server = json_tokener_parse(json_object_get_string(tmp));

                            if ( json_object_object_get_ex(json_obj_ssh_server, "server", &tmp_ssh_server))
                                {

                                    Alert_Return_Struct->has_ssh_server = true;

                                    if ( Validate_JSON_String( (char *)json_object_get_string(tmp_ssh_server) ) == 0 )
                                        {

                                            tmp_ssh_server_2 = json_tokener_parse(json_object_get_string(tmp_ssh_server));

                                            if ( json_object_object_get_ex(tmp_ssh_server_2, "proto_version", &tmp_ssh_server_3))
                                                {

                                                    strlcpy(Alert_Return_Struct->ssh_server_proto_version, (char *)json_object_get_string(tmp_ssh_server_3), sizeof(Alert_Return_Struct->ssh_server_proto_version));
                                                }

                                            if ( json_object_object_get_ex(tmp_ssh_server_2, "software_version", &tmp_ssh_server_3))
                                                {

                                                    strlcpy(Alert_Return_Struct->ssh_server_software_version, (char *)json_object_get_string(tmp_ssh_server_3), sizeof(Alert_Return_Struct->ssh_server_software_version));
                                                }

                                            json_object_put(tmp_ssh_server_2);
                                        }
                                }

                            if ( json_object_object_get_ex(json_obj_ssh_client, "client", &tmp_ssh_client))
                                {

                                    Alert_Return_Struct->has_ssh_client = true;

                                    if ( Validate_JSON_String( (char *)json_object_get_string(tmp_ssh_client) ) == 0 )
                                        {

                                            tmp_ssh_client_2 = json_tokener_parse(json_object_get_string(tmp_ssh_client));

                                            if ( json_object_object_get_ex(tmp_ssh_client_2, "proto_version", &tmp_ssh_client_3))
                                                {

                                                    strlcpy(Alert_Return_Struct->ssh_client_proto_version, (char *)json_object_get_string(tmp_ssh_client_3), sizeof(Alert_Return_Struct->ssh_client_proto_version));
                                                }

                                            if ( json_object_object_get_ex(tmp_ssh_client_2, "software_version", &tmp_ssh_client_3))
                                                {

                                                    strlcpy(Alert_Return_Struct->ssh_client_software_version, (char *)json_object_get_string(tmp_ssh_client_3), sizeof(Alert_Return_Struct->ssh_client_software_version));
                                                }

                                            json_object_put(tmp_ssh_client_2);
                                        }
                                }

                            json_object_put(json_obj_ssh_server);
                        }
                }
        }

    /* Check the basic information first */

    if ( Alert_Return_Struct->timestamp == NULL )
        {
            Meer_Log(ERROR, "JSON: \"%s\" : No timestamp found in flowid %s.", json_string, Alert_Return_Struct->flowid);
        }

    if ( Alert_Return_Struct->flowid == NULL )
        {
            Alert_Return_Struct->flowid = "0";
        }

    if ( Alert_Return_Struct->src_ip[0] == '\0' )
        {
            Meer_Log(ERROR, "JSON: \"%s\" : No src_ip found in flowid %s. Abort.", json_string, Alert_Return_Struct->flowid);
        }

    if ( Alert_Return_Struct->dest_ip[0] == '\0' )
        {
            Meer_Log(ERROR, "JSON: \"%s\" : No dest_ip found in flowid %s. Abort.", json_string, Alert_Return_Struct->flowid);
        }

    if ( !Is_IP(Alert_Return_Struct->src_ip, IPv4) && !Is_IP(Alert_Return_Struct->src_ip, IPv6 ) )
        {
            Meer_Log(WARN, "JSON: \"%s\" : Invalid src_ip found in flowid %s. Attempting to 'fix'.", json_string, Alert_Return_Struct->flowid);

            if ( Try_And_Fix_IP( Alert_Return_Struct->src_ip, new_ip, sizeof( new_ip )) == true )
                {
                    strlcpy(Alert_Return_Struct->src_ip, new_ip, sizeof( Alert_Return_Struct->src_ip ));
                }
            else
                {
                    Meer_Log(WARN, "Unable to find a usable source IP address for flowid %s. Using %s (BAD_IP) instead.", Alert_Return_Struct->flowid, BAD_IP);

                    /* Store the "orignal" IP address as original_src_ip (the bad IP) */

                    json_object *jsrc_ip_orig = json_object_new_string(Alert_Return_Struct->src_ip);
                    json_object_object_add(json_obj,"original_src_ip", jsrc_ip_orig);

                    /* Over write the src_ip with the BAD_IP value */

                    json_object *jsrc_ip = json_object_new_string(BAD_IP);
                    json_object_object_add(json_obj,"src_ip", jsrc_ip);

                    /* For the internal struct */

                    strlcpy(Alert_Return_Struct->src_ip, BAD_IP, sizeof( Alert_Return_Struct->src_ip ));

                }

        }

    if ( !Is_IP(Alert_Return_Struct->dest_ip, IPv4) && !Is_IP(Alert_Return_Struct->dest_ip, IPv6 ) )
        {
            Meer_Log(WARN, "JSON: \"%s\" : Invalid dest_ip found in flowid %s. Attempting to 'fix'.", json_string, Alert_Return_Struct->flowid);

            if ( Try_And_Fix_IP( Alert_Return_Struct->dest_ip, new_ip, sizeof( new_ip )) == true )
                {
                    strlcpy(Alert_Return_Struct->dest_ip, new_ip, sizeof( new_ip ));

                }
            else
                {

                    Meer_Log(WARN, "Unable to find a usable destination IP address for flowid %s. Using %s (BAD_IP) instead.", Alert_Return_Struct->flowid, BAD_IP);

                    /* Store the "orignal" IP address as original_dest_ip (the bad IP) */

                    json_object *jdest_ip_orig = json_object_new_string(Alert_Return_Struct->dest_ip);
                    json_object_object_add(json_obj,"original_dest_ip", jdest_ip_orig);

                    /* Over write the dest_ip with the BAD_IP value */

                    json_object *jdest_ip = json_object_new_string(BAD_IP);
                    json_object_object_add(json_obj,"dest_ip", jdest_ip);

                    /* For the internal struct */

                    strlcpy(Alert_Return_Struct->dest_ip, BAD_IP, sizeof( Alert_Return_Struct->dest_ip ));


                }

        }

    /* Is this IPv4 or IPv6 */

    if ( Is_IP(Alert_Return_Struct->src_ip, IPv6) != 0 )
        {
            Alert_Return_Struct->ip_version = 6;
        }

    if ( Alert_Return_Struct->proto == NULL )
        {
            Meer_Log(WARN, "JSON: \"%s\" : No proto found in flowid %s.  Setting to Unknown.", json_string, Alert_Return_Struct->flowid);
            Alert_Return_Struct->proto = "Unknown";
        }

    if ( Alert_Return_Struct->payload[0] == '\0' )
        {
            strlcpy(Alert_Return_Struct->payload, "No payload recorded by Meer", sizeof(Alert_Return_Struct->payload));
        }

    /* Do we have all the alert information we'd expect */

    if ( has_alert == false )
        {
            Meer_Log(ERROR, "JSON: \"%s\" : No alert information found in flowid %s.  Abort!", json_string, Alert_Return_Struct->flowid);
        }

    if ( Alert_Return_Struct->alert_action[0] == '\0' )
        {
            Meer_Log(WARN, "JSON: \"%s\" : No alert -> action found in flowid %s.  Setting to NONE.", json_string, Alert_Return_Struct->flowid);
            strlcpy(Alert_Return_Struct->alert_action, "None", sizeof(Alert_Return_Struct->alert_action));
        }

    if ( Alert_Return_Struct->alert_gid[0] == '\0' )
        {
            Meer_Log(WARN, "JSON: \"%s\" : No alert -> gid found in flowid %s.  Setting to 0.", json_string, Alert_Return_Struct->flowid);
            strlcpy(Alert_Return_Struct->alert_gid, "0", sizeof(Alert_Return_Struct->alert_gid));
        }

    if ( Alert_Return_Struct->alert_signature_id == 0 )
        {
            Meer_Log(ERROR, "JSON: \"%s\" : No alert -> signature_id found in flowid %s. Abort.", json_string, Alert_Return_Struct->flowid);
        }

    if ( Alert_Return_Struct->alert_rev == 0 )
        {
            Meer_Log(WARN, "JSON: \"%s\" : No alert -> rev found in flowid %s.  Setting to 0.", json_string, Alert_Return_Struct->flowid);
            Alert_Return_Struct->alert_rev = 0;
        }

    if ( Alert_Return_Struct->alert_signature[0] == '\0' )
        {
            Meer_Log(WARN, "JSON: \"%s\" : No alert -> rev found in flowid %s.  Setting to NONE.", json_string, Alert_Return_Struct->flowid);
            strlcpy(Alert_Return_Struct->alert_signature, "0", sizeof(Alert_Return_Struct->alert_signature));
        }

    if ( Alert_Return_Struct->alert_category[0] == '\0' )
        {
            strlcpy(Alert_Return_Struct->alert_signature, "None", sizeof(Alert_Return_Struct->alert_signature));
        }

    if ( Alert_Return_Struct->alert_severity[0] == '\0' )
        {
            Meer_Log(WARN, "JSON: \"%s\" : No alert -> severity found in flowid %s.  Setting to 0.", json_string, Alert_Return_Struct->flowid);
            strlcpy(Alert_Return_Struct->alert_severity, "0", sizeof(Alert_Return_Struct->alert_severity));
        }

    if ( MeerConfig->dns == true )
        {

            DNS_Lookup_Reverse(Alert_Return_Struct->src_ip, Alert_Return_Struct->src_dns, sizeof(Alert_Return_Struct->src_dns));

            if ( Alert_Return_Struct->src_dns[0] != '\0' )
                {
                    json_object *jsrc_dns = json_object_new_string(Alert_Return_Struct->src_dns);
                    json_object_object_add(json_obj,"src_dns", jsrc_dns);
                }


            DNS_Lookup_Reverse(Alert_Return_Struct->dest_ip, Alert_Return_Struct->dest_dns, sizeof(Alert_Return_Struct->dest_dns));

            if ( Alert_Return_Struct->dest_dns[0] != '\0' )
                {
                    json_object *jdest_dns = json_object_new_string(Alert_Return_Struct->dest_dns);
                    json_object_object_add(json_obj,"dest_dns", jdest_dns);
                }

        }

#ifdef HAVE_LIBMAXMINDDB

    /*************************************************/
    /* Add any GeoIP data for the source/destination */
    /*************************************************/

    if ( MeerConfig->geoip == true )
        {

            struct _GeoIP *GeoIP;

            struct json_object *jobj_geoip;
            jobj_geoip = json_object_new_object();

            GeoIP = malloc(sizeof(_GeoIP));

            if ( GeoIP == NULL )
                {
                    Meer_Log(ERROR, "[%s, line %d] Failed to allocate memory for _GeoIP. Abort!", __FILE__, __LINE__);
                }

            memset(GeoIP, 0, sizeof(_GeoIP));

            /*******************/
            /* Get src_ip data */
            /*******************/

            GeoIP_Lookup( Alert_Return_Struct->src_ip,  GeoIP );

            if ( GeoIP->country[0] != '\0' )
                {

                    json_object *jgeoip_country = json_object_new_string( GeoIP->country );
                    json_object_object_add(jobj_geoip,"country", jgeoip_country);

                    if ( GeoIP->city[0] != '\0' )
                        {
                            json_object *jgeoip_city = json_object_new_string( GeoIP->city );
                            json_object_object_add(jobj_geoip,"city", jgeoip_city);
                        }

                    if ( GeoIP->subdivision[0] != '\0' )
                        {
                            json_object *jgeoip_subdivision = json_object_new_string( GeoIP->subdivision );
                            json_object_object_add(jobj_geoip,"subdivision", jgeoip_subdivision);
                        }

                    if ( GeoIP->postal[0] != '\0' )
                        {
                            json_object *jgeoip_postal = json_object_new_string( GeoIP->postal );
                            json_object_object_add(jobj_geoip,"postal", jgeoip_postal);
                        }

                    if ( GeoIP->timezone[0] != '\0' )
                        {
                            json_object *jgeoip_timezone = json_object_new_string( GeoIP->timezone );
                            json_object_object_add(jobj_geoip,"timezone", jgeoip_timezone);
                        }

                    if ( GeoIP->longitude[0] != '\0' )
                        {
                            json_object *jgeoip_longitude = json_object_new_string( GeoIP->longitude );
                            json_object_object_add(jobj_geoip,"longitude", jgeoip_longitude);
                        }

                    if ( GeoIP->latitude[0] != '\0' )
                        {
                            json_object *jgeoip_latitude = json_object_new_string( GeoIP->latitude );
                            json_object_object_add(jobj_geoip,"latitude", jgeoip_latitude);
                        }

                    snprintf(geoip_src_json, sizeof(geoip_src_json), "%s", json_object_to_json_string(jobj_geoip));
                    geoip_src_json[ sizeof(geoip_src_json) - 1 ] = '\0';

                }

            /*****************************************/
            /* Get dest_ip GeoIP information (reset) */
            /*****************************************/

            memset(GeoIP, 0, sizeof(_GeoIP));

            GeoIP_Lookup( Alert_Return_Struct->dest_ip,  GeoIP );

            if ( GeoIP->country[0] != '\0' )
                {

                    json_object *jgeoip_country = json_object_new_string( GeoIP->country );
                    json_object_object_add(jobj_geoip,"country", jgeoip_country);

                    if ( GeoIP->city[0] != '\0' )
                        {
                            json_object *jgeoip_city = json_object_new_string( GeoIP->city );
                            json_object_object_add(jobj_geoip,"city", jgeoip_city);
                        }

                    if ( GeoIP->subdivision[0] != '\0' )
                        {
                            json_object *jgeoip_subdivision = json_object_new_string( GeoIP->subdivision );
                            json_object_object_add(jobj_geoip,"subdivision", jgeoip_subdivision);
                        }

                    if ( GeoIP->postal[0] != '\0' )
                        {
                            json_object *jgeoip_postal = json_object_new_string( GeoIP->postal );
                            json_object_object_add(jobj_geoip,"postal", jgeoip_postal);
                        }

                    if ( GeoIP->timezone[0] != '\0' )
                        {
                            json_object *jgeoip_timezone = json_object_new_string( GeoIP->timezone );
                            json_object_object_add(jobj_geoip,"timezone", jgeoip_timezone);
                        }

                    if ( GeoIP->longitude[0] != '\0' )
                        {
                            json_object *jgeoip_longitude = json_object_new_string( GeoIP->longitude );
                            json_object_object_add(jobj_geoip,"longitude", jgeoip_longitude);
                        }

                    if ( GeoIP->latitude[0] != '\0' )
                        {
                            json_object *jgeoip_latitude = json_object_new_string( GeoIP->latitude );
                            json_object_object_add(jobj_geoip,"latitude", jgeoip_latitude);
                        }

                    snprintf(geoip_dest_json, sizeof(geoip_dest_json), "%s", json_object_to_json_string(jobj_geoip));
                    geoip_dest_json[ sizeof(geoip_dest_json) - 1 ] = '\0';
                }


            json_object_put(jobj_geoip);
            free(GeoIP);
        }

#endif

    /************************************************************************************/
    /* We make the "final" copy now.  This might be modified if we need to add anything */
    /************************************************************************************/

    strlcpy(Alert_Return_Struct->new_json_string, json_object_to_json_string(json_obj), sizeof(Alert_Return_Struct->new_json_string));

#ifdef HAVE_LIBMAXMINDDB

    /***************************************************************************************/
    /* If we have GeoIP data,  we modify the final JSON to include that.  This is a bit of */
    /* a "hack" as we don't know if JSON_C_TO_STRING_NOSLASHESCAPE is avaliable.           */
    /***************************************************************************************/

    if ( geoip_src_json[0] != '\0' )
        {

            Alert_Return_Struct->new_json_string[ strlen(Alert_Return_Struct->new_json_string) -2 ] = '\0';

            snprintf(tmp_geoip, sizeof(tmp_geoip), "%s, \"geoip_src\": %s", Alert_Return_Struct->new_json_string, geoip_src_json);

            strlcpy(Alert_Return_Struct->new_json_string, tmp_geoip, PACKET_BUFFER_SIZE_DEFAULT);
            strlcat(Alert_Return_Struct->new_json_string, " }", PACKET_BUFFER_SIZE_DEFAULT);

        }

    if ( geoip_dest_json[0] != '\0' )
        {

            Alert_Return_Struct->new_json_string[ strlen(Alert_Return_Struct->new_json_string) -2 ] = '\0';

            snprintf(tmp_geoip, sizeof(tmp_geoip), "%s, \"geoip_dest\": %s", Alert_Return_Struct->new_json_string, geoip_dest_json);

            strlcpy(Alert_Return_Struct->new_json_string, tmp_geoip, PACKET_BUFFER_SIZE_DEFAULT);
            strlcat(Alert_Return_Struct->new_json_string, " }", PACKET_BUFFER_SIZE_DEFAULT);

        }

#endif

    return(Alert_Return_Struct);
}

