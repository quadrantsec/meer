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

/* Write EVE data to MySQL databases */


#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "decode-json-alert.h"

#include "meer.h"
#include "meer-def.h"
#include "config-yaml.h"
#include "util.h"
#include "util-base64.h"
#include "references.h"
#include "classifications.h"
#include "output-plugins/sql.h"
#include "lockfile.h"
#include "sid-map.h"

#ifdef HAVE_LIBPQ
#include <postgresql/libpq-fe.h>
#include "output-plugins/postgresql.h"
#endif

#ifdef HAVE_LIBMYSQLCLIENT
#include <mysql/mysql.h>
#include "output-plugins/mysql.h"
#endif

#if defined(HAVE_LIBMYSQLCLIENT) || defined(HAVE_LIBPQ)

extern struct _MeerConfig *MeerConfig;
extern struct _MeerOutput *MeerOutput;
extern struct _MeerCounters *MeerCounters;
extern struct _Classifications *MeerClass;
extern struct _SID_Map *SID_Map;

struct _SignatureCache *SignatureCache;
uint32_t SignatureCacheCount = 0;

struct _ClassificationCache *ClassificationCache;
uint32_t ClassificationCacheCount = 0;

uint32_t SQL_Get_Sensor_ID( void )
{

    char tmp[MAX_SQL_QUERY];
    char *results;

    uint32_t sensor_id = 0;

    /* For some reason Barnyar2 liked the hostname to be "hostname:interface".  We're simply mirroring
       that functionality here */

    snprintf(tmp, sizeof(tmp),
             "SELECT sid FROM sensor WHERE hostname='%s:%s' AND interface='%s' AND detail=1 AND encoding='0'",
             MeerConfig->hostname, MeerConfig->interface, MeerConfig->interface);

    results=SQL_DB_Query(tmp);
    MeerCounters->SELECTCount++;

    /* If we get results,  go ahead and return the value */

    if ( results != NULL )
        {

            sensor_id = atoi(results);
            Meer_Log(NORMAL, "Using Database Sensor ID: %d", sensor_id );
            return( sensor_id );
        }

    snprintf(tmp, sizeof(tmp),
             "INSERT INTO sensor (hostname, interface, filter, detail, encoding, last_cid) VALUES ('%s:%s', '%s', NULL, '1', '0', '0')",
             MeerConfig->hostname, MeerConfig->interface, MeerConfig->interface);

    SQL_DB_Query(tmp);
    MeerCounters->INSERTCount++;

    results = SQL_Get_Last_ID();

    sensor_id = atoi(results);

    Meer_Log(NORMAL, "Using New Database Sensor ID: %d", sensor_id);

    return( sensor_id );

}

uint64_t SQL_Get_Last_CID( void )
{

    char tmp[MAX_SQL_QUERY] = { 0 };
    char *results = NULL;
    int  last_cid = 0;

    snprintf(tmp, sizeof(tmp), "SELECT last_cid FROM sensor WHERE sid=%d ", MeerOutput->sql_sensor_id);

    results=SQL_DB_Query(tmp);
    MeerCounters->SELECTCount++;

    if ( results != NULL )
        {

            last_cid = atoi(results);
            Meer_Log(NORMAL, "Last CID: %d", last_cid );
            return( last_cid );
        }

    return(0);
}


void SQL_Connect ( void )
{

#ifdef HAVE_LIBMYSQLCLIENT

    if ( MeerOutput->sql_driver == DB_MYSQL )
        {
            MySQL_Connect();
        }

#endif

#ifdef HAVE_LIBPQ

    if ( MeerOutput->sql_driver == DB_POSTGRESQL )
        {
            PG_Connect();
        }
#endif

}


char *SQL_DB_Query( char *sql )
{

    char *ret = NULL;

    if ( MeerOutput->sql_debug )
        {
            Meer_Log(DEBUG, "SQL Debug: \"%s\"", sql);
        }

#ifdef HAVE_LIBMYSQLCLIENT

    if ( MeerOutput->sql_driver == DB_MYSQL )
        {

            ret = MySQL_DB_Query( sql );

        }

#endif

#ifdef HAVE_LIBPQ

    if ( MeerOutput->sql_driver == DB_POSTGRESQL )
        {

            ret = PG_DB_Query( sql );

        }

#endif

    return(ret);

}

void SQL_Record_Last_CID ( void )
{

    char tmp[MAX_SQL_QUERY];

    snprintf(tmp, sizeof(tmp),
             "UPDATE sensor SET last_cid='%" PRIu64 "' WHERE sid=%d AND hostname='%s:%s' AND interface='%s' AND detail=1",
             MeerOutput->sql_last_cid, MeerOutput->sql_sensor_id, MeerConfig->hostname, MeerConfig->interface, MeerConfig->interface);

    (void)SQL_DB_Query(tmp);
    MeerCounters->UPDATECount++;

}

int SQL_Get_Class_ID ( struct _DecodeAlert *DecodeAlert )
{

    char tmp[MAX_SQL_QUERY] = { 0 };
    char *results;
    char class[64] = { 0 };

    int class_id = 0;

    int i = 0;

    /* Check cache */

    for (i = 0; i<ClassificationCacheCount; i++)
        {

            if ( !strcmp(DecodeAlert->alert_category, ClassificationCache[i].class_name))
                {
                    MeerCounters->ClassCacheHitCount++;
                    return(ClassificationCache[i].sig_class_id);
                }

        }

    /* Lookup classtype based off the description */

    Class_Lookup( DecodeAlert->alert_category, class, sizeof(class) );

    snprintf(tmp, sizeof(tmp), "SELECT sig_class_id from sig_class where sig_class_name='%s'", class);
    results = SQL_DB_Query(tmp);
    MeerCounters->SELECTCount++;

    /* No classtype found.  Insert it */

    if ( results == NULL )
        {

            snprintf(tmp, sizeof(tmp),  "INSERT INTO sig_class(sig_class_id, sig_class_name) VALUES (DEFAULT, '%s')", class);
            (void)SQL_DB_Query(tmp);
            MeerCounters->INSERTCount++;

            results = SQL_Get_Last_ID();

        }

    class_id = atoi(results);

    /* Insert into cache */

    ClassificationCache = (_ClassificationCache *) realloc(ClassificationCache, (ClassificationCacheCount+1) * sizeof(_ClassificationCache));

    ClassificationCache[ClassificationCacheCount].sig_class_id = class_id;
    strlcpy(ClassificationCache[ClassificationCacheCount].class_name, DecodeAlert->alert_category, sizeof(ClassificationCache[ClassificationCacheCount].class_name));

    ClassificationCacheCount++;
    MeerCounters->ClassCacheMissCount++;

    return(class_id);
}


int SQL_Get_Signature_ID ( struct _DecodeAlert *DecodeAlert, int class_id )
{

    char tmp[MAX_SQL_QUERY];
    char *results;
    int i = 0;
    unsigned sig_priority = 0;

    char e_alert_signature[256];

    int signature_id = 0;

    /* Search cache */

    for (i = 0; i<SignatureCacheCount; i++)
        {

            if (!strcmp(SignatureCache[i].sig_name, DecodeAlert->alert_signature) &&
                    SignatureCache[i].sig_rev == DecodeAlert->alert_rev &&
                    SignatureCache[i].sig_sid == DecodeAlert->alert_signature_id )
                {
                    MeerCounters->SigCacheHitCount++;
                    return(SignatureCache[i].sig_id);
                }

        }

    sig_priority = Class_Lookup_Priority( DecodeAlert->alert_category);

    SQL_Escape_String( DecodeAlert->alert_signature, e_alert_signature, sizeof(e_alert_signature));

    snprintf(tmp, sizeof(tmp), "SELECT sig_id FROM signature WHERE sig_name='%s' AND sig_rev=%d AND sig_sid=%" PRIu64 "",
             e_alert_signature, DecodeAlert->alert_rev, DecodeAlert->alert_signature_id);

    results = SQL_DB_Query(tmp);
    MeerCounters->SELECTCount++;

    if ( results == NULL )
        {

            snprintf(tmp, sizeof(tmp), "INSERT INTO signature (sig_name,sig_class_id,sig_priority,sig_rev,sig_sid,sig_gid) "
                     "VALUES ('%s',%d,%d,%d,%" PRIu64 ",1)", e_alert_signature, class_id, sig_priority,
                     DecodeAlert->alert_rev, DecodeAlert->alert_signature_id);

            (void)SQL_DB_Query(tmp);
            MeerCounters->INSERTCount++;

            results = SQL_Get_Last_ID();

        }

    signature_id = atoi(results);

    /* Add signature to cache */

    SignatureCache = (_SignatureCache *) realloc(SignatureCache, (SignatureCacheCount+1) * sizeof(_SignatureCache));

    SignatureCache[SignatureCacheCount].sig_id = signature_id;
    SignatureCache[SignatureCacheCount].sig_rev = DecodeAlert->alert_rev;
    SignatureCache[SignatureCacheCount].sig_sid = DecodeAlert->alert_signature_id;

    strlcpy(SignatureCache[SignatureCacheCount].sig_name, DecodeAlert->alert_signature, sizeof(SignatureCache[SignatureCacheCount].sig_name));

    SignatureCacheCount++;
    MeerCounters->SigCacheMissCount++;

    return(signature_id);

}


void SQL_Insert_Event ( struct _DecodeAlert *DecodeAlert, int signature_id )
{

    char tmp[MAX_SQL_QUERY];

    snprintf(tmp, sizeof(tmp), "INSERT INTO event(sid,cid,signature,timestamp,app_proto,flow_id) VALUES ('%d','%" PRIu64 "',%d,'%s','%s',%s)", MeerOutput->sql_sensor_id, MeerOutput->sql_last_cid, signature_id, DecodeAlert->converted_timestamp, DecodeAlert->app_proto, DecodeAlert->flowid );


    (void)SQL_DB_Query(tmp);
    MeerCounters->INSERTCount++;


}

void SQL_Insert_Header ( struct _DecodeAlert *DecodeAlert )
{

    char tmp[MAX_SQL_QUERY];
    unsigned char proto = 0;

    unsigned char ip_src_bit[16];
    uint32_t *src_ip_u32 = (uint32_t *)&ip_src_bit[0];

    unsigned char ip_dst_bit[16];
    uint32_t *dst_ip_u32 = (uint32_t *)&ip_dst_bit[0];

    IP2Bit(DecodeAlert->src_ip, ip_src_bit);
    IP2Bit(DecodeAlert->dest_ip, ip_dst_bit);

    if (!strcmp(DecodeAlert->proto, "TCP" ))
        {
            proto = TCP;
        }

    else if (!strcmp(DecodeAlert->proto, "UDP" ))
        {
            proto = UDP;
        }

    else if (!strcmp(DecodeAlert->proto, "ICMP" ))
        {
            proto = ICMP;
        }

    /* Legacy database allow things like ip_len to be set to NULL.  This may break
       functionality on some consoles.  We set it to 0,  even though we shouldn't
       have too :( */

    snprintf(tmp, sizeof(tmp),
             "INSERT INTO iphdr ( sid, cid,ip_src,ip_dst,ip_src_t,ip_dst_t,ip_ver,ip_proto,ip_hlen,ip_tos,ip_len,ip_id,ip_flags,ip_off,ip_ttl,ip_csum) VALUES (%d,%" PRIu64 ",%" PRIu32 ",%" PRIu32 ",'%s','%s',%u,%u,0,0,0,0,0,0,0,0)",
             MeerOutput->sql_sensor_id, MeerOutput->sql_last_cid, htonl(*src_ip_u32), htonl(*dst_ip_u32), DecodeAlert->src_ip, DecodeAlert->dest_ip, DecodeAlert->ip_version, proto );

    (void)SQL_DB_Query(tmp);
    MeerCounters->INSERTCount++;

    if ( proto == TCP )
        {

            snprintf(tmp, sizeof(tmp),
                     "INSERT INTO tcphdr (sid,cid,tcp_sport,tcp_dport,tcp_seq,tcp_ack,tcp_off,tcp_res,tcp_flags,tcp_win,tcp_csum,tcp_urp) VALUES (%d,%" PRIu64 ",%s,%s,0,0,0,0,0,0,0,0)",
                     MeerOutput->sql_sensor_id, MeerOutput->sql_last_cid, DecodeAlert->src_port, DecodeAlert->dest_port  );

            (void)SQL_DB_Query(tmp);
            MeerCounters->INSERTCount++;

        }

    else if ( proto == UDP )
        {

            snprintf(tmp, sizeof(tmp),
                     "INSERT INTO udphdr (sid,cid,udp_sport,udp_dport,udp_len,udp_csum) VALUES (%d,%" PRIu64 ",%s,%s,0,0)",
                     MeerOutput->sql_sensor_id, MeerOutput->sql_last_cid, DecodeAlert->src_port, DecodeAlert->dest_port );

            (void)SQL_DB_Query(tmp);
            MeerCounters->INSERTCount++;

        }

    else if ( proto == ICMP )
        {

            snprintf(tmp, sizeof(tmp), "INSERT INTO icmphdr (sid,cid,icmp_type,icmp_code,icmp_csum,icmp_id,icmp_seq) VALUES (%d,%" PRIu64 ",%s,%s,0,0,0)",
                     MeerOutput->sql_sensor_id, MeerOutput->sql_last_cid, DecodeAlert->icmp_type, DecodeAlert->icmp_code );

            (void)SQL_DB_Query(tmp);
            MeerCounters->INSERTCount++;

        }

}

void SQL_Insert_Payload ( struct _DecodeAlert *DecodeAlert )
{

    char tmp[MAX_SQL_QUERY];

    uint32_t ret;

    char *hex_encode;
    uint8_t *base64_decode = malloc(strlen(DecodeAlert->payload) * 2);

    ret = DecodeBase64( base64_decode, (const uint8_t *)DecodeAlert->payload, strlen(DecodeAlert->payload), 1);
    hex_encode = Hexify( (char*)base64_decode, (int)ret );

    snprintf(tmp, sizeof(tmp),
             "INSERT INTO data(sid, cid, data_payload) VALUES (%d,%" PRIu64 ",'%s')",
             MeerOutput->sql_sensor_id, MeerOutput->sql_last_cid, hex_encode );

    (void)SQL_DB_Query(tmp);
    MeerCounters->INSERTCount++;

    free(base64_decode);
    free(hex_encode);

}

void SQL_Insert_DNS ( struct _DecodeAlert *DecodeAlert )
{

    char tmp[MAX_SQL_QUERY];

    char e_src_host[256] = { 0 };
    char e_dest_host[256] = { 0 };

    /* Both DNS entries are empty,  no reason to insert */

    if ( !strcmp(DecodeAlert->src_dns, "")  && !strcmp(DecodeAlert->dest_dns, "" ) )
        {
            return;
        }

    SQL_Escape_String( DecodeAlert->src_dns, e_src_host, sizeof(e_src_host));
    SQL_Escape_String( DecodeAlert->dest_dns, e_dest_host, sizeof(e_dest_host));

    snprintf(tmp, sizeof(tmp),
             "INSERT INTO dns(sid, cid, src_host, dst_host) VALUES (%d,%" PRIu64 ",'%s','%s')",
             MeerOutput->sql_sensor_id, MeerOutput->sql_last_cid,
             e_src_host,
             e_dest_host );

    (void)SQL_DB_Query(tmp);
    MeerCounters->INSERTCount++;


}

void SQL_Insert_Syslog_Data ( struct _DecodeAlert *DecodeAlert )
{

    char tmp[MAX_SQL_QUERY] = { 0 };
    char e_facility[64] = { 0 };
    char e_priority[64] = { 0 };
    char e_level[64] = { 0 };
    char e_program[128] = { 0 };

    if ( DecodeAlert->facility != NULL )
        {
            SQL_Escape_String( DecodeAlert->facility, e_facility, sizeof(e_facility));
        }

    if ( DecodeAlert->priority != NULL )
        {
            SQL_Escape_String( DecodeAlert->priority, e_priority, sizeof(e_priority));
        }

    if ( DecodeAlert->level != NULL )
        {
            SQL_Escape_String( DecodeAlert->level, e_level, sizeof(e_level));
        }

    if ( DecodeAlert->program != NULL )
        {
            SQL_Escape_String( DecodeAlert->program, e_program, sizeof(e_program));
        }

    snprintf(tmp, sizeof(tmp),
             "INSERT INTO syslog_data (sid,cid,facility,priority,level,program) VALUES (%d,%" PRIu64 ",'%s','%s','%s','%s')",
             MeerOutput->sql_sensor_id, MeerOutput->sql_last_cid, e_facility, e_priority, e_level, e_program);

    (void)SQL_DB_Query(tmp);
    MeerCounters->INSERTCount++;

}

void SQL_Insert_Extra_Data ( struct _DecodeAlert *DecodeAlert )
{

    char tmp[MAX_SQL_QUERY] = { 0 };

    char e_http_hostname[512] = { 0 };
    char e_http_url[3200] = { 0 };

    char e_email_attachment[10240] = { 0 };
    char e_smtp_rcpt_to[10240] = { 0 };
    char e_smtp_mail_from[10240] = { 0 };

    if ( DecodeAlert->xff != NULL )
        {

            snprintf(tmp, sizeof(tmp),
                     "INSERT INTO extra (sid,cid,type,datatype,len,data) VALUES (%d,%" PRIu64 ",%d,1,%d,'%s')",
                     MeerOutput->sql_sensor_id, MeerOutput->sql_last_cid, EXTRA_ORIGNAL_CLIENT_IPV4,
                     (int)strlen( DecodeAlert->xff ), DecodeAlert->xff);

            (void)SQL_DB_Query(tmp);
            MeerCounters->INSERTCount++;

        }

    if ( DecodeAlert->ip_version == 6 )
        {

            snprintf(tmp, sizeof(tmp),
                     "INSERT INTO extra (sid,cid,type,datatype,len,data) VALUES (%d,%" PRIu64 ",%d,1,%d,'%s')",
                     MeerOutput->sql_sensor_id, MeerOutput->sql_last_cid, EXTRA_IPV6_SOURCE_ADDRESS,
                     (int)strlen( DecodeAlert->src_ip ), DecodeAlert->src_ip);

            (void)SQL_DB_Query(tmp);
            MeerCounters->INSERTCount++;

            snprintf(tmp, sizeof(tmp),
                     "INSERT INTO extra (sid,cid,type,datatype,len,data) VALUES (%d,%" PRIu64 ",%d,1,%d,'%s')",
                     MeerOutput->sql_sensor_id, MeerOutput->sql_last_cid, EXTRA_IPV6_DESTINATION_ADDRESS,
                     (int)strlen( DecodeAlert->dest_ip ), DecodeAlert->dest_ip);

            (void)SQL_DB_Query(tmp);
            MeerCounters->INSERTCount++;

        }

    if ( DecodeAlert->has_http == true )
        {

            if ( DecodeAlert->http_hostname[0] != '\0' )
                {

                    SQL_Escape_String( DecodeAlert->http_hostname, e_http_hostname, sizeof(e_http_hostname));

                    snprintf(tmp, sizeof(tmp),
                             "INSERT INTO extra (sid,cid,type,datatype,len,data) VALUES (%d,%" PRIu64 ",%d,1,%d,'%s')",
                             MeerOutput->sql_sensor_id, MeerOutput->sql_last_cid, EXTRA_HTTP_HOSTNAME,
                             (int)strlen( e_http_hostname ), e_http_hostname );

                    (void)SQL_DB_Query(tmp);
                    MeerCounters->INSERTCount++;

                }

            if ( DecodeAlert->http_url[0] != '\0' )
                {

                    SQL_Escape_String( DecodeAlert->http_url, e_http_url, sizeof(e_http_url));

                    snprintf(tmp, sizeof(tmp),
                             "INSERT INTO extra (sid,cid,type,datatype,len,data) VALUES (%d,%" PRIu64 ",%d,1,%d,'%s')",
                             MeerOutput->sql_sensor_id, MeerOutput->sql_last_cid, EXTRA_HTTP_URI,
                             (int)strlen( e_http_url ), e_http_url);

                    (void)SQL_DB_Query(tmp);
                    MeerCounters->INSERTCount++;

                }

        }

    if ( DecodeAlert->has_smtp == true )
        {

            if ( DecodeAlert->email_attachment[0] != '\0' )
                {

                    SQL_Escape_String( DecodeAlert->email_attachment, e_email_attachment, sizeof(e_email_attachment));

                    snprintf(tmp, sizeof(tmp),
                             "INSERT INTO extra (sid,cid,type,datatype,len,data) VALUES (%d,%" PRIu64 ",%d,1,%d,'%s')",
                             MeerOutput->sql_sensor_id, MeerOutput->sql_last_cid, EXTRA_SMTP_FILENAME,
                             (int)strlen( e_http_hostname ), e_email_attachment );

                    (void)SQL_DB_Query(tmp);
                    MeerCounters->INSERTCount++;

                }

            if ( DecodeAlert->smtp_rcpt_to[0] != '\0' )
                {

                    SQL_Escape_String( DecodeAlert->smtp_rcpt_to, e_smtp_rcpt_to, sizeof(e_smtp_rcpt_to));

                    snprintf(tmp, sizeof(tmp),
                             "INSERT INTO extra (sid,cid,type,datatype,len,data) VALUES (%d,%" PRIu64 ",%d,1,%d,'%s')",
                             MeerOutput->sql_sensor_id, MeerOutput->sql_last_cid, EXTRA_SMTP_RCPT_TO,
                             (int)strlen( e_smtp_rcpt_to ), e_smtp_rcpt_to );

                    (void)SQL_DB_Query(tmp);
                    MeerCounters->INSERTCount++;

                }

            if ( DecodeAlert->smtp_mail_from[0] != '\0' )
                {

                    SQL_Escape_String( DecodeAlert->smtp_mail_from, e_smtp_mail_from, sizeof(e_smtp_mail_from));

                    snprintf(tmp, sizeof(tmp),
                             "INSERT INTO extra (sid,cid,type,datatype,len,data) VALUES (%d,%" PRIu64 ",%d,1,%d,'%s')",                             MeerOutput->sql_sensor_id, MeerOutput->sql_last_cid, EXTRA_SMTP_MAIL_FROM,
                             (int)strlen( e_smtp_mail_from ), e_smtp_mail_from );

                    (void)SQL_DB_Query(tmp);
                    MeerCounters->INSERTCount++;

                }

        }

}

void SQL_Insert_Flow ( struct _DecodeAlert *DecodeAlert )
{

    char tmp[MAX_SQL_QUERY] = { 0 };

    snprintf(tmp, sizeof(tmp),
             "INSERT INTO flow (sid,cid,pkts_toserver,pkts_toclient,bytes_toserver,bytes_toclient,start_timestamp) "
             "VALUES (%d,%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",'%s')",
             MeerOutput->sql_sensor_id, MeerOutput->sql_last_cid,
             DecodeAlert->flow_pkts_toserver,
             DecodeAlert->flow_pkts_toclient,
             DecodeAlert->flow_bytes_toserver,
             DecodeAlert->flow_bytes_toclient,
             DecodeAlert->flow_start_timestamp_converted );

    (void)SQL_DB_Query(tmp);
    MeerCounters->INSERTCount++;
}

void SQL_Insert_HTTP ( struct _DecodeAlert *DecodeAlert )
{

    char tmp[MAX_SQL_QUERY] = { 0 };

    char e_http_hostname[512] = { 0 };
    char e_http_url[4100] = { 0 };
    char e_http_user_agent[16384] = { 0 };
    char e_http_refer[4100] = { 0 };
    char e_http_method[128] = { 0 };
    char e_http_content_type[128] = { 0 };
    char e_http_protocol[64] = { 0 };
    char e_http_xff[64] = { 0 };

    SQL_Escape_String( DecodeAlert->http_hostname, e_http_hostname, sizeof(e_http_hostname));
    SQL_Escape_String( DecodeAlert->http_url, e_http_url, sizeof(e_http_url));
    SQL_Escape_String( DecodeAlert->http_user_agent, e_http_user_agent, sizeof(e_http_user_agent));
    SQL_Escape_String( DecodeAlert->http_refer, e_http_refer, sizeof(e_http_refer));
    SQL_Escape_String( DecodeAlert->http_method, e_http_method, sizeof(e_http_method));
    SQL_Escape_String( DecodeAlert->http_content_type, e_http_content_type, sizeof(e_http_content_type));
    SQL_Escape_String( DecodeAlert->http_protocol, e_http_protocol, sizeof(e_http_protocol));
    SQL_Escape_String( DecodeAlert->http_xff, e_http_xff, sizeof(e_http_xff));

    snprintf(tmp, sizeof(tmp),
             "INSERT INTO http (sid,cid,hostname,url,xff,http_content_type,http_method,http_user_agent,http_refer,protocol,status,length) "
             "VALUES (%d,%" PRIu64 ",'%s','%s','%s','%s','%s','%s','%s','%s',%d,%" PRIu64 ")",
             MeerOutput->sql_sensor_id, MeerOutput->sql_last_cid,
             e_http_hostname,
             e_http_url,
             e_http_xff,
             e_http_content_type,
             e_http_method,
             e_http_user_agent,
             e_http_refer,
             e_http_protocol,

             /* These are ints */

             DecodeAlert->http_status,
             DecodeAlert->http_length );

    (void)SQL_DB_Query(tmp);
    MeerCounters->INSERTCount++;

}

void SQL_Insert_TLS ( struct _DecodeAlert *DecodeAlert )
{

    char tmp[MAX_SQL_QUERY] = { 0 };

    char e_tls_issuerdn[256] = { 0 };
    char e_tls_subject[256] = { 0 };
    char e_tls_fingerprint[1024] = { 0 };
    char e_tls_session_resumed[16] = { 0 };
    char e_tls_sni[1024] = { 0 };
    char e_tls_version[32] = { 0 };
    char e_tls_notbefore[32] = { 0 };
    char e_tls_notafter[32] = { 0 };

    SQL_Escape_String( DecodeAlert->tls_issuerdn, e_tls_issuerdn, sizeof(e_tls_issuerdn) );
    SQL_Escape_String( DecodeAlert->tls_subject, e_tls_subject, sizeof(e_tls_subject) );
    SQL_Escape_String( DecodeAlert->tls_fingerprint, e_tls_fingerprint, sizeof(e_tls_fingerprint) );
    SQL_Escape_String( DecodeAlert->tls_session_resumed, e_tls_session_resumed, sizeof(e_tls_session_resumed) );
    SQL_Escape_String( DecodeAlert->tls_sni, e_tls_sni, sizeof(e_tls_sni) );
    SQL_Escape_String( DecodeAlert->tls_version, e_tls_version, sizeof(e_tls_version) );
    SQL_Escape_String( DecodeAlert->tls_notbefore, e_tls_notbefore, sizeof(e_tls_notbefore) );
    SQL_Escape_String( DecodeAlert->tls_notafter, e_tls_notafter, sizeof(e_tls_notafter) );

    if ( DecodeAlert->tls_notbefore[0] == '\0' )
        {
            strlcpy(e_tls_notbefore, "0000-00-00 00:00:00", sizeof(e_tls_notbefore));
        }

    if ( DecodeAlert->tls_notafter[0] == '\0' )
        {
            strlcpy(e_tls_notafter, "0000-00-00 00:00:00", sizeof(e_tls_notafter));
        }

    snprintf(tmp, sizeof(tmp),
             "INSERT INTO tls (sid,cid,subject,issuerdn,serial,fingerprint,session_resumed,sni,version,notbefore,notafter) "
             "VALUES (%d,%" PRIu64 ",'%s','%s',%d,'%s','%s','%s','%s','%s','%s')",
             MeerOutput->sql_sensor_id, MeerOutput->sql_last_cid,
             e_tls_subject,
             e_tls_issuerdn,
             DecodeAlert->tls_serial,
             e_tls_fingerprint,
             e_tls_session_resumed,
             e_tls_sni,
             e_tls_version,
             e_tls_notbefore,
             e_tls_notafter );

    (void)SQL_DB_Query(tmp);
    MeerCounters->INSERTCount++;

}


void SQL_Insert_SSH ( struct _DecodeAlert *DecodeAlert, unsigned char type )
{

    char tmp[MAX_SQL_QUERY] = { 0 };

    char *table = NULL;
    char *proto = NULL;
    char e_software[128] = { 0 };

    if ( type == SSH_CLIENT )
        {

            table = "ssh_client";
            proto = DecodeAlert->ssh_client_proto_version;

            SQL_Escape_String( DecodeAlert->ssh_client_software_version,
                               e_software, sizeof(e_software));

        }
    else
        {

            table = "ssh_server";
            proto = DecodeAlert->ssh_server_proto_version;

            SQL_Escape_String( DecodeAlert->ssh_server_software_version,
                               e_software, sizeof(e_software));

        }

    snprintf(tmp, sizeof(tmp),
             "INSERT INTO %s (sid,cid,proto_version,sofware_version) "
             "VALUES (%d,%" PRIu64 ",'%s','%s')",
             table,MeerOutput->sql_sensor_id, MeerOutput->sql_last_cid,
             proto, e_software );

    (void)SQL_DB_Query(tmp);
    MeerCounters->INSERTCount++;

}

void SQL_Insert_Metadata ( struct _DecodeAlert *DecodeAlert )
{

    char tmp[MAX_SQL_QUERY] = { 0 };
    char e_alert_metadata[1024] = { 0 };

    SQL_Escape_String( DecodeAlert->alert_metadata, e_alert_metadata, sizeof(e_alert_metadata));

    snprintf(tmp, sizeof(tmp),
             "INSERT INTO metadata (sid,cid,metadata) "
             "VALUES (%d,%" PRIu64 ",'%s')",
             MeerOutput->sql_sensor_id, MeerOutput->sql_last_cid,
             e_alert_metadata);

    (void)SQL_DB_Query(tmp);
    MeerCounters->INSERTCount++;

}

void SQL_Insert_JSON ( struct _DecodeAlert *DecodeAlert )
{

    char tmp[MAX_SQL_QUERY] = { 0 };
    char e_json[MAX_SQL_QUERY*2] = { 0 };

    SQL_Escape_String( DecodeAlert->json, e_json, sizeof(e_json));

    snprintf(tmp, sizeof(tmp),
             "INSERT INTO event_json (sid,cid,json) "
             "VALUES (%d,%" PRIu64 ",'%s')",
             MeerOutput->sql_sensor_id, MeerOutput->sql_last_cid,
             e_json);

    (void)SQL_DB_Query(tmp);

    MeerCounters->JSONCount++;
    MeerCounters->INSERTCount++;

}

void SQL_Insert_Stats ( char *json_stats, const char *timestamp, const char *hostname )
{

    char tmp[MAX_SQL_QUERY] = { 0 };
    char e_stats[MAX_SQL_QUERY*2] = { 0 };

    SQL_Escape_String( json_stats, e_stats, sizeof(e_stats));

    snprintf(tmp, sizeof(tmp),
             "INSERT INTO stats (hostname,timestamp,stats) "
             "VALUES ('%s', '%s', '%s')", hostname, timestamp, e_stats);

    (void)SQL_DB_Query(tmp);

    MeerCounters->JSONCount++;
    MeerCounters->INSERTCount++;

}

void SQL_Insert_Normalize ( struct _DecodeAlert *DecodeAlert )
{

    char tmp[MAX_SQL_QUERY] = { 0 };
    char e_normalize[MAX_SQL_QUERY*2] = { 0 };

    SQL_Escape_String( DecodeAlert->normalize, e_normalize, sizeof(e_normalize));

    snprintf(tmp, sizeof(tmp),
             "INSERT INTO normalize (sid,cid,json) "
             "VALUES (%d,%" PRIu64 ",'%s')",
             MeerOutput->sql_sensor_id, MeerOutput->sql_last_cid,
             e_normalize);

    (void)SQL_DB_Query(tmp);

    MeerCounters->JSONCount++;
    MeerCounters->INSERTCount++;

}


void SQL_Insert_Bluedot ( struct _DecodeAlert *DecodeAlert )
{

    char tmp[MAX_SQL_QUERY] = { 0 };
    char e_bluedot[MAX_SQL_QUERY*2] = { 0 };

    Remove_Return( DecodeAlert->bluedot );

    SQL_Escape_String( DecodeAlert->bluedot, e_bluedot, sizeof(e_bluedot));

    snprintf(tmp, sizeof(tmp),
             "INSERT INTO bluedot (sid,cid,bluedot) "
             "VALUES (%d,%" PRIu64 ",'%s')",
             MeerOutput->sql_sensor_id, MeerOutput->sql_last_cid,
             e_bluedot);

    (void)SQL_DB_Query(tmp);
    MeerCounters->INSERTCount++;

}


void SQL_Insert_SMTP ( struct _DecodeAlert *DecodeAlert )
{

    char tmp[MAX_SQL_QUERY] = { 0 };
    char e_helo[255] = { 0 };
    char e_mail_from[255] = { 0 };
    char e_rcpt_to[131072] = { 0 };

    SQL_Escape_String( DecodeAlert->smtp_helo, e_helo, sizeof(e_helo));
    SQL_Escape_String( DecodeAlert->smtp_mail_from, e_mail_from, sizeof(e_mail_from));
    SQL_Escape_String( DecodeAlert->smtp_rcpt_to, e_rcpt_to, sizeof(e_rcpt_to));

    snprintf(tmp, sizeof(tmp),
             "INSERT INTO smtp (sid,cid,helo,mail_from,rcpt_to) "
             "VALUES ( %d,%" PRIu64 ",'%s','%s','%s')",
             MeerOutput->sql_sensor_id, MeerOutput->sql_last_cid,
             e_helo,
             e_mail_from,
             e_rcpt_to);

    (void)SQL_DB_Query(tmp);

    MeerCounters->INSERTCount++;

}

void SQL_Insert_Email ( struct _DecodeAlert *DecodeAlert )
{

    char tmp[MAX_SQL_QUERY] = { 0 };

    char e_from[1024] = { 0 };
    char e_to[10240] = { 0 };
    char e_cc[10240] = { 0 };
    char e_attachment[10240] = { 0 };
    char e_email_status[32] = { 0 };

    SQL_Escape_String( DecodeAlert->email_from, e_from, sizeof(e_from));
    SQL_Escape_String( DecodeAlert->email_to, e_to, sizeof(e_to));
    SQL_Escape_String( DecodeAlert->email_cc, e_cc, sizeof(e_cc));
    SQL_Escape_String( DecodeAlert->email_attachment, e_attachment, sizeof(e_attachment) );
    SQL_Escape_String( DecodeAlert->email_status, e_email_status, sizeof(e_email_status) );

    snprintf(tmp, sizeof(tmp),
             "INSERT INTO email (sid,cid,status,email_from,email_to,email_cc,attachment) "
             "VALUES (%d,%" PRIu64 ",'%s','%s','%s','%s','%s')",
             MeerOutput->sql_sensor_id, MeerOutput->sql_last_cid,
             e_email_status,
             e_from,
             e_to,
             e_cc,
             e_attachment);

    (void)SQL_DB_Query(tmp);

    MeerCounters->INSERTCount++;

}


void SQL_Escape_String( char *sql, char *str, size_t size )
{

#ifdef HAVE_LIBMYSQLCLIENT

    if ( MeerOutput->sql_driver == DB_MYSQL )
        {
            MySQL_Escape_String( sql, str, size );
        }

#endif

#ifdef HAVE_LIBPQ

    if ( MeerOutput->sql_driver == DB_POSTGRESQL )
        {
            PG_Escape_String( sql, str, size );
        }


#endif

    return;

}

int SQL_Legacy_Reference_Handler ( struct _DecodeAlert *DecodeAlert )
{

    char tmp[MAX_SQL_QUERY];
    char *results = NULL;

    int ref_system_id = 0;
    int ref_id = 0;
    int sig_id = 0;

    char sid_map_tmp[1024] = { 0 };

    int i = 0;

    for (i = 0; i <  MeerCounters->SIDMapCount; i++ )
        {

            if ( DecodeAlert->alert_signature_id == SID_Map[i].sid )
                {

                    SQL_Escape_String( SID_Map[i].type, sid_map_tmp, sizeof(sid_map_tmp) );

                    snprintf(tmp, sizeof(tmp),
                             "SELECT ref_system_id FROM reference_system WHERE ref_system_name='%s'",
                             sid_map_tmp);

                    results=SQL_DB_Query(tmp);

                    MeerCounters->SELECTCount++;

                    if ( results == NULL )
                        {

                            snprintf(tmp, sizeof(tmp),
                                     "INSERT INTO reference_system (ref_system_name) VALUES ('%s')",
                                     sid_map_tmp);

                            (void)SQL_DB_Query(tmp);
                            MeerCounters->INSERTCount++;

                            results = SQL_Get_Last_ID();

                        }

                    ref_system_id = atoi(results);

                    SQL_Escape_String( SID_Map[i].location, sid_map_tmp, sizeof(sid_map_tmp) );

                    snprintf(tmp, sizeof(tmp),
                             "SELECT ref_id FROM reference WHERE ref_system_id=%d AND ref_tag='%s'",
                             ref_system_id, sid_map_tmp);

                    results=SQL_DB_Query(tmp);
                    MeerCounters->SELECTCount++;

                    if ( results == NULL )
                        {

                            snprintf(tmp, sizeof(tmp),
                                     "INSERT INTO reference (ref_system_id,ref_tag) VALUES (%d, '%s')",
                                     ref_system_id, sid_map_tmp);

                            (void)SQL_DB_Query(tmp);
                            MeerCounters->INSERTCount++;

                            results = SQL_Get_Last_ID();

                        }

                    ref_id = atoi(results);

                    sig_id = SQL_Get_Sig_ID( DecodeAlert );

                    snprintf(tmp, sizeof(tmp),
                             "SELECT sig_id FROM sig_reference WHERE sig_id=%d AND ref_id=%d",
                             sig_id, ref_id);

                    results=SQL_DB_Query(tmp);
                    MeerCounters->SELECTCount++;

                    if ( results == NULL )
                        {

                            snprintf(tmp, sizeof(tmp),
                                     "INSERT INTO sig_reference (sig_id,ref_seq,ref_id) VALUES (%d,%d,%d)",
                                     sig_id, i, ref_id);

                            (void)SQL_DB_Query(tmp);
                            MeerCounters->INSERTCount++;

                            results = SQL_Get_Last_ID();

                        }

                }

        }

    return(sig_id);	/* DEBUG: Is this return right? */

}


int SQL_Get_Sig_ID( struct _DecodeAlert *DecodeAlert )
{

    char tmp[MAX_SQL_QUERY];
    char *results = NULL;
    char class[64] = { 0 };
    char e_class_tmp[128] = { 0 };

    int sig_class_id = 0;
    int sig_id = 0;

    Class_Lookup( DecodeAlert->alert_category, class, sizeof(class) );

    /* DEBUG: cache here */

    SQL_Escape_String( class, e_class_tmp, sizeof(e_class_tmp) );

    snprintf(tmp, sizeof(tmp),
             "SELECT sig_class_id FROM sig_class WHERE sig_class_name='%s'",
             e_class_tmp);

    results=SQL_DB_Query(tmp);
    MeerCounters->SELECTCount++;

    if ( results == NULL )
        {

            snprintf(tmp, sizeof(tmp),
                     "INSERT INTO sig_class (sig_class_name) VALUES ('%s')",
                     e_class_tmp);

            results=SQL_DB_Query(tmp);
            MeerCounters->INSERTCount++;

            results = SQL_Get_Last_ID();

        }

    sig_class_id = atoi(results);
    sig_id = SQL_Get_Signature_ID( DecodeAlert, sig_class_id );

    return(sig_id);

}

char *SQL_Get_Last_ID( void )
{

    char *ret = NULL;

#ifdef HAVE_LIBMYSQLCLIENT

    if ( MeerOutput->sql_driver == DB_MYSQL )
        {
            ret = MySQL_Get_Last_ID();
        }

#endif

#ifdef HAVE_LIBPQ

    if ( MeerOutput->sql_driver == DB_POSTGRESQL )
        {
            ret = PG_Get_Last_ID();
        }

#endif

    return(ret);

}

#endif
