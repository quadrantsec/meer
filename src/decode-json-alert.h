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

#ifdef HAVE_LIBJSON_C
#include <json-c/json.h>
#endif

#ifndef HAVE_LIBJSON_C
libjson-c is required for Meer to function!
#endif

#include "meer-def.h"

typedef struct _DecodeAlert _DecodeAlert;
struct _DecodeAlert
{

char *timestamp;
char *flowid;
char *in_iface;
char *event_type;

char src_ip[64];
    char *src_port;
    char src_dns[256];

    char converted_timestamp[64];

    char new_json_string[PACKET_BUFFER_SIZE_DEFAULT];

    char dest_ip[64];
    char *dest_port;
    char dest_dns[256];

    char *proto;
    char app_proto[16];
    char payload[131072];
    char *stream;
    char *packet;
    char *host;

    char *json;

    char *normalize;
    bool has_normalize;

    char *facility;
    char *priority;
    char *level;
    char *program;

    char *bluedot;

    char *xff;

    char *icmp_type;
    char *icmp_code;

    unsigned char ip_version;


    char packet_info_link[32];

    /* Alert data */

    char alert_action[16];
    char alert_gid[5];
    uint64_t alert_signature_id;
    uint32_t alert_rev;
    char alert_signature[512];
    char alert_category[128];
    char alert_severity[5];

    char alert_metadata[1024];
    bool alert_has_metadata;

    /* Bluedot data */

    bool     has_bluedot;

    /* Flow data */

    bool     has_flow;

    uint64_t flow_pkts_toserver;
    uint64_t flow_pkts_toclient;
    uint64_t flow_bytes_toserver;
    uint64_t flow_bytes_toclient;
    char flow_start_timestamp[64];
    char flow_start_timestamp_converted[64];

    /* HTTP data */

    bool     has_http;

    char http_hostname[256];
    char http_url[2100];
    char http_content_type[64];
    char http_method[32];
    char http_user_agent[16384];
    char http_refer[4096];
    char http_protocol[32];
    char http_xff[128];
    int  http_status;
    uint64_t http_length;

    /* TLS */

    bool has_tls;

    char tls_session_resumed[16];
    char tls_sni[255];
    char tls_version[16];
    char tls_subject[256];
    char tls_issuerdn[256];
    char tls_notbefore[64];
    char tls_notafter[64];
    char tls_fingerprint[128];
    uint32_t tls_serial;

    /* DNS */

    bool has_dns;

    /* SSH */

    bool has_ssh_server;
    bool has_ssh_client;

    char ssh_server_proto_version[8];
    char ssh_server_software_version[128];

    char ssh_client_proto_version[8];
    char ssh_client_software_version[128];

    /* SMTP */

    bool has_smtp;

    char smtp_helo[255];
    char smtp_mail_from[255];
    char smtp_rcpt_to[131072];

    /* Email */

    bool has_email;

    char email_status[32];
    char email_from[1024];
    char email_to[10240];
    char email_cc[10240];
    char email_attachment[10240];

};


struct _DecodeAlert *Decode_JSON_Alert( struct json_object *json_obj, char *json_string );

