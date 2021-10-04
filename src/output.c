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

/* Output routines for decoded EVE/JSON */

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>
#include <stdbool.h>
#include <time.h>
#include <string.h>
#include <unistd.h>

#include "decode-json-alert.h"
#include "decode-json-dhcp.h"
#include "fingerprints.h"

#include "meer.h"
#include "meer-def.h"
#include "util.h"
#include "output.h"
#include "references.h"
#include "sid-map.h"
#include "config-yaml.h"

#include "output-plugins/sql.h"
#include "output-plugins/pipe.h"
#include "output-plugins/external.h"
#include "output-plugins/fingerprint.h"

#ifdef WITH_ELASTICSEARCH
#include <output-plugins/elasticsearch.h>
#endif

#ifdef HAVE_LIBMYSQLCLIENT
#include <mysql/mysql.h>
MYSQL    *mysql;
#endif

#ifdef HAVE_LIBHIREDIS
#include <hiredis/hiredis.h>
#include "output-plugins/redis.h"
#endif

#ifdef WITH_BLUEDOT
#include "output-plugins/bluedot.h"
#include "util-http.h"
#endif

#ifdef WITH_ELASTICSEARCH

#include <pthread.h>
pthread_cond_t MeerElasticWork=PTHREAD_COND_INITIALIZER;
pthread_mutex_t MeerElasticMutex=PTHREAD_MUTEX_INITIALIZER;

uint_fast16_t elastic_proc_msgslot = 0;
uint_fast16_t elastic_proc_running = 0;

char big_batch[PACKET_BUFFER_SIZE_DEFAULT * 1000] = { 0 };
char big_batch_THREAD[PACKET_BUFFER_SIZE_DEFAULT * 1000] = { 0 };

extern uint16_t elasticsearch_batch_count;

#endif

extern struct _MeerOutput *MeerOutput;
extern struct _MeerConfig *MeerConfig;
extern struct _MeerCounters *MeerCounters;
extern struct _MeerHealth *MeerHealth;
extern struct _Classifications *MeerClass;

/****************************************************************************
 * Init_Output - Init output pluggins (if needed)
 ****************************************************************************/

void Init_Output( void )
{

    if ( MeerOutput->external_enabled )
        {

            Meer_Log(NORMAL, "--[ External information ]-----------------------------------------");
            Meer_Log(NORMAL, "");
            Meer_Log(NORMAL, "Default external program: %s", MeerOutput->external_program);
            Meer_Log(NORMAL, "Execute on 'security-ips' policy: %s", MeerOutput->external_metadata_security_ips ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Execute on 'balanced-ips' policy: %s", MeerOutput->external_metadata_balanced_ips ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Execute on 'connectivity-ips' policy: %s", MeerOutput->external_metadata_connectivity_ips ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Execute on 'max-detect-ips' policy: %s", MeerOutput->external_metadata_max_detect_ips ? "enabled" : "disabled" );

            Meer_Log(NORMAL, "");
        }

#ifdef HAVE_LIBHIREDIS

    char redis_command[300];
    char redis_reply[5];

    if ( MeerOutput->redis_flag )
        {

            Meer_Log(NORMAL, "--[ Redis information ]--------------------------------------------");
            Meer_Log(NORMAL, "");


            /* Connect to redis database */

            Redis_Connect();

            strlcpy(redis_command, "PING", sizeof(redis_command));

            Redis_Reader(redis_command, redis_reply, sizeof(redis_reply));

            if (!strcmp(redis_reply, "PONG"))
                {
                    Meer_Log(NORMAL, "Got PONG from Redis at %s:%d.", MeerOutput->redis_server, MeerOutput->redis_port);
                }

            Meer_Log(NORMAL, "");
        }

#endif

    if ( MeerOutput->pipe_enabled )
        {
            uint32_t current_pipe_size = 0;
            uint32_t fd_results = 0;

            Meer_Log(NORMAL, "--[ PIPE information ]--------------------------------------------");
            Meer_Log(NORMAL, "");
            Meer_Log(NORMAL, "Pipe Location: %s", MeerOutput->pipe_location);
            Meer_Log(NORMAL, "Pipe Size: %d bytes", MeerOutput->pipe_size);
            Meer_Log(NORMAL, "");
            Meer_Log(NORMAL, "Write 'dns'     : %s", MeerOutput->pipe_dns ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Write 'flow'    : %s", MeerOutput->pipe_flow ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Write 'http'    : %s", MeerOutput->pipe_http ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Write 'tls'     : %s", MeerOutput->pipe_tls ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Write 'ssh'     : %s", MeerOutput->pipe_ssh ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Write 'smtp'    : %s", MeerOutput->pipe_smtp ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Write 'files'   : %s", MeerOutput->pipe_files ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Write 'fileinfo': %s", MeerOutput->pipe_fileinfo ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Write 'dhcp'    : %s", MeerOutput->pipe_dhcp ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Write 'bluedot' : %s", MeerOutput->pipe_bluedot ? "enabled" : "disabled" );

            Meer_Log(NORMAL, "");

            MeerOutput->pipe_fd = open(MeerOutput->pipe_location, O_RDWR);

            if ( MeerOutput->pipe_fd < 0 )
                {
                    Meer_Log(ERROR, "Cannot open %s. Abort!", MeerOutput->pipe_location);
                }

            current_pipe_size = fcntl(MeerOutput->pipe_fd, F_GETPIPE_SZ);
            fd_results = fcntl(MeerOutput->pipe_fd, F_SETPIPE_SZ, MeerOutput->pipe_size);
            fcntl(MeerOutput->pipe_fd, F_SETFL, O_NONBLOCK);

            Meer_Log(NORMAL, "The %s pipe (FIFO) was %d bytes. It is now set to %d bytes.", MeerOutput->pipe_location, current_pipe_size, fd_results);

            Meer_Log(NORMAL, "");

        }

#if defined(HAVE_LIBMYSQLCLIENT) || defined(HAVE_LIBPQ)

    MeerOutput->sql_transaction = false ;

    if ( MeerOutput->sql_enabled )
        {


            Meer_Log(NORMAL, "--[ SQL information ]--------------------------------------------");
            Meer_Log(NORMAL, "");

            if ( MeerOutput->sql_driver == DB_MYSQL )
                {
                    Meer_Log(NORMAL, "SQL Driver: MySQL/MariaDB");
                }

            else if ( MeerOutput->sql_driver == DB_POSTGRESQL )
                {
                    Meer_Log(NORMAL, "SQL Driver: PostgreSQL");
                }

            Meer_Log(NORMAL, "Extra data: %s", MeerOutput->sql_extra_data ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Fingerprinting: %s", MeerOutput->sql_fingerprint ? "enabled" : "disabled" );


            /* Legacy reference system */

            Meer_Log(NORMAL, "Legacy Reference System: %s", MeerOutput->sql_reference_system ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "");

            if ( MeerOutput->sql_reference_system )
                {
                    Load_References();
                    Load_SID_Map();
                    Meer_Log(NORMAL, "");
                }

            SQL_Connect();

            MeerOutput->sql_sensor_id = SQL_Get_Sensor_ID();
            MeerOutput->sql_last_cid = SQL_Get_Last_CID() + 1;

            Meer_Log(NORMAL, "");
            Meer_Log(NORMAL, "Record 'json'    : %s", MeerOutput->sql_json ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Record 'metadata': %s", MeerOutput->sql_metadata ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Record 'flow'    : %s", MeerOutput->sql_flow ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Record 'http'    : %s", MeerOutput->sql_http ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Record 'tls'     : %s", MeerOutput->sql_tls ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Record 'ssh'     : %s", MeerOutput->sql_ssh ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Record 'smtp'    : %s", MeerOutput->sql_smtp ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Record 'email'   : %s", MeerOutput->sql_email ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Record 'bluedot' : %s", MeerOutput->sql_bluedot ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "");

        }

#endif

    if ( MeerConfig->fingerprint == true )
        {

            Meer_Log(NORMAL, "--[ Fingerprinting information ]---------------------------------");
            Meer_Log(NORMAL, "");
            Meer_Log(NORMAL, "Fingerprinting : %s", MeerConfig->fingerprint ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Fingerprint log file : %s", MeerConfig->fingerprint_log );
            Meer_Log(NORMAL, "");

            if (( MeerConfig->fingerprint_log_fd  = fopen(MeerConfig->fingerprint_log, "a" )) == NULL )
                {
                    Meer_Log(ERROR, "Cannot open Meer fingerprint log file %s! [%s]. Abort!", MeerConfig->fingerprint_log, strerror(errno));
                }

        }

#ifdef WITH_BLUEDOT

    if ( MeerOutput->bluedot_flag == true )
        {

            int i = 0;

            url_encoder_rfc_tables_init();

            i = DNS_Lookup_Forward( MeerOutput->bluedot_host, MeerOutput->bluedot_ip, sizeof(MeerOutput->bluedot_ip) );

            if ( i != 0 )
                {
                    Meer_Log(ERROR, "Unable to lookup %s. Abort.", MeerOutput->bluedot_host);
                }

            Meer_Log(NORMAL, "--[ Bluedot information ]----------------------------------------");
            Meer_Log(NORMAL, "");
            Meer_Log(NORMAL, "Bluedot Output          : %s", MeerOutput->bluedot_flag ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Bluedot Server IP       : %s (%s)", MeerOutput->bluedot_ip, MeerOutput->bluedot_host);
            Meer_Log(NORMAL, "");
        }

#endif


#ifdef WITH_ELASTICSEARCH

    if ( MeerOutput->elasticsearch_flag == true )
        {

            Meer_Log(NORMAL, "--[ Elasticsearch output information ]---------------------------");
            Meer_Log(NORMAL, "");
            Meer_Log(NORMAL, "URL to connect to       : \"%s\"", MeerOutput->elasticsearch_url);
            Meer_Log(NORMAL, "Index template          : \"%s\"", MeerOutput->elasticsearch_index);
            Meer_Log(NORMAL, "Batch size per/POST     : %d", MeerOutput->elasticsearch_batch);
            Meer_Log(NORMAL, "Threads                 : %d", MeerOutput->elasticsearch_threads);

            if ( MeerOutput->elasticsearch_username[0] != '\0' || MeerOutput->elasticsearch_password[0] != '\0' )
                {
                    Meer_Log(NORMAL, "Authentication          : enabled");
                }
            else
                {
                    Meer_Log(NORMAL, "Authentication          : disabled");
                }

            Meer_Log(NORMAL, "");
            Meer_Log(NORMAL, "Record 'alert'          : %s", MeerOutput->elasticsearch_alert ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Record 'flow'           : %s", MeerOutput->elasticsearch_flow ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Record 'http'           : %s", MeerOutput->elasticsearch_http ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Record 'tls'            : %s", MeerOutput->elasticsearch_tls ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Record 'ssh'            : %s", MeerOutput->elasticsearch_ssh ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Record 'smtp'           : %s", MeerOutput->elasticsearch_smtp ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Record 'email'          : %s", MeerOutput->elasticsearch_email ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Record 'stats'          : %s", MeerOutput->elasticsearch_stats ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Record 'bluedot'        : %s", MeerOutput->elasticsearch_bluedot ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Record 'fileinfo'       : %s", MeerOutput->elasticsearch_fileinfo ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Record 'dhcp'           : %s", MeerOutput->elasticsearch_dhcp ? "enabled" : "disabled" );


            Elasticsearch_Init();

            Meer_Log(NORMAL, "");


        }



#endif

    Meer_Log(NORMAL, "--[ Meer engine information ]-------------------------------------");
    Meer_Log(NORMAL, "");


}

/****************************************************************************
 * Output_Pipe - Determines what data/JSON should be sent to the named pipe
 ****************************************************************************/

bool Output_Pipe ( char *type, char *json_string )
{

    if ( !strcmp(type, "flow" ) && MeerOutput->pipe_flow == true )
        {
            Pipe_Write( json_string );
            return 0;
        }

    else if ( !strcmp(type, "http" ) && MeerOutput->pipe_http == true )
        {
            Pipe_Write( json_string );
            return 0;
        }

    else if ( !strcmp(type, "smtp" ) && MeerOutput->pipe_smtp == true )
        {
            Pipe_Write( json_string );
            return 0;
        }

    else if ( !strcmp(type, "ssh" ) && MeerOutput->pipe_ssh == true )
        {
            Pipe_Write( json_string );
            return 0;
        }

    else if ( !strcmp(type, "tls" ) && MeerOutput->pipe_tls == true )
        {
            Pipe_Write( json_string );
            return 0;
        }

    else if ( !strcmp(type, "dns" ) && MeerOutput->pipe_dns == true )
        {
            Pipe_Write( json_string );
            return 0;
        }

    else if ( !strcmp(type, "alert" ) && MeerOutput->pipe_alert == true )
        {
            Pipe_Write( json_string );
            return 0;
        }

    else if ( !strcmp(type, "fileinfo" ) && MeerOutput->pipe_fileinfo == true )
        {
            Pipe_Write( json_string );
            return 0;
        }

    else if ( !strcmp(type, "dhcp" ) && MeerOutput->pipe_dhcp == true )
        {
            Pipe_Write( json_string );
            return 0;
        }

    Meer_Log(WARN, "Unknown JSON type '%s'. JSON String: %s", type, json_string);
    MeerCounters->JSONPipeMisses++;
    return 1;

}

/****************************************************************************
 * Output_Alert_SQL - Sends decoded data to a MySQL/PostgreSQL database using
 * a similar format to Barnyard2 (with some extra data added in!)
 ****************************************************************************/

#if defined(HAVE_LIBMYSQLCLIENT) || defined(HAVE_LIBPQ)

bool Output_Alert_SQL ( struct _DecodeAlert *DecodeAlert )
{

    char tmp[MAX_SQL_QUERY] = { 0 };
    char convert_time[16] = { 0 };
    struct tm tm_;

    bool health_flag = 0;
    int i = 0;

    if ( MeerOutput->sql_enabled )
        {

            int signature_id = 0;
            int class_id = 0;

            if ( MeerConfig->health == true )
                {

                    for (i = 0 ; i < MeerCounters->HealthCount; i++ )
                        {

                            if ( MeerHealth[i].health_signature == DecodeAlert->alert_signature_id )
                                {
                                    health_flag = 1;
                                    break;
                                }
                        }

                }


            if ( health_flag == 0 )
                {

                    class_id = SQL_Get_Class_ID( DecodeAlert );

                    SQL_DB_Query("START TRANSACTION");
                    MeerOutput->sql_transaction = true;

                    if ( MeerOutput->sql_reference_system == true )
                        {

                            signature_id = SQL_Legacy_Reference_Handler ( DecodeAlert );

                            /* The SID doesn't have any reference data.  We just get it into the
                                       signature table */

                            if ( signature_id == 0 )
                                {
                                    signature_id = SQL_Get_Signature_ID( DecodeAlert, class_id );
                                }

                        }
                    else
                        {

                            signature_id = SQL_Get_Signature_ID( DecodeAlert, class_id );

                        }

                    SQL_Insert_Event( DecodeAlert, signature_id );

                    SQL_Insert_Header( DecodeAlert );

                    SQL_Insert_Payload ( DecodeAlert );

                    /* Not all events have "syslog data" (only Sagan). */

                    if ( DecodeAlert->facility != NULL || DecodeAlert->priority != NULL ||
                            DecodeAlert->level != NULL || DecodeAlert->program != NULL )
                        {
                            SQL_Insert_Syslog_Data( DecodeAlert );
                        }

                    if ( MeerConfig->json == true )
                        {
                            SQL_Insert_JSON ( DecodeAlert );
                        }

                    if ( MeerConfig->dns == true )
                        {
                            SQL_Insert_DNS ( DecodeAlert );
                        }

                    /* We can have multiple "xff" fields in extra data */

                    if ( MeerOutput->sql_extra_data == true )
                        {
                            SQL_Insert_Extra_Data ( DecodeAlert );
                        }

                    if ( DecodeAlert->has_normalize == true )
                        {
                            SQL_Insert_Normalize ( DecodeAlert );
                        }

                    if ( DecodeAlert->has_flow == true && MeerOutput->sql_flow == true )
                        {
                            SQL_Insert_Flow ( DecodeAlert );
                        }

                    if ( DecodeAlert->has_http == true && MeerOutput->sql_http == true )
                        {
                            SQL_Insert_HTTP ( DecodeAlert );
                        }

                    if ( DecodeAlert->has_tls == true && MeerOutput->sql_tls == true )
                        {
                            SQL_Insert_TLS ( DecodeAlert );
                        }

                    if ( DecodeAlert->has_ssh_server == true && MeerOutput->sql_ssh == true )
                        {
                            SQL_Insert_SSH ( DecodeAlert, SSH_SERVER );
                        }

                    if ( DecodeAlert->has_ssh_client == true && MeerOutput->sql_ssh == true )
                        {
                            SQL_Insert_SSH ( DecodeAlert, SSH_CLIENT );
                        }

                    if ( DecodeAlert->alert_has_metadata == true && MeerOutput->sql_metadata == true )
                        {
                            SQL_Insert_Metadata ( DecodeAlert );
                        }

                    if ( DecodeAlert->has_smtp == true && MeerOutput->sql_smtp == true )
                        {
                            SQL_Insert_SMTP ( DecodeAlert );
                        }

                    if ( DecodeAlert->has_email == true && MeerOutput->sql_email == true )
                        {
                            SQL_Insert_Email ( DecodeAlert );
                        }

                    if ( DecodeAlert->has_bluedot == true && MeerConfig->bluedot == true )
                        {
                            SQL_Insert_Bluedot ( DecodeAlert );
                        }

                    /* Record CID in case of crash/disconnections */

                    snprintf(tmp, sizeof(tmp),
                             "UPDATE sensor SET events_count = events_count+1 WHERE sid = %d",
                             MeerOutput->sql_sensor_id);
                    (void)SQL_DB_Query(tmp);
                    MeerCounters->UPDATECount++;

                    snprintf(tmp, sizeof(tmp),
                             "UPDATE signature SET events_count = events_count+1 WHERE sig_id = %u",
                             signature_id );

                    (void)SQL_DB_Query(tmp);
                    MeerCounters->UPDATECount++;

                    /*
                    #ifdef HAVE_LIBHIREDIS

                                        if ( MeerOutput->redis_flag == true )
                                            {
                                                Redis_Quadrant ( DecodeAlert, signature_id, class_id );
                                            }
                    #endif
                    */


                    /* Convert timestamp from event to epoch */

                    strptime(DecodeAlert->timestamp,"%FT%T",&tm_);
                    strftime(convert_time, sizeof(convert_time),"%F %T",&tm_);

                    snprintf(tmp, sizeof(tmp), "UPDATE sensor SET last_event=%d WHERE sid=%d", (int)mktime(&tm_), MeerOutput->sql_sensor_id);

                    SQL_DB_Query( (char*)tmp );

                    SQL_Record_Last_CID();

                    MeerCounters->UPDATECount++;

                    SQL_DB_Query("COMMIT");
                    MeerOutput->sql_transaction=false;

                    MeerOutput->sql_last_cid++;

                }
            else
                {

                    /* Convert timestamp from event to epoch */

                    strptime(DecodeAlert->timestamp,"%FT%T",&tm_);
                    strftime(convert_time, sizeof(convert_time),"%F %T",&tm_);

                    snprintf(tmp, sizeof(tmp), "UPDATE sensor SET health=%d WHERE sid=%d", (int)mktime(&tm_), MeerOutput->sql_sensor_id);

                    SQL_DB_Query( (char*)tmp );

                    MeerCounters->HealthCountT++;
                    MeerCounters->UPDATECount++;

                }


        }

    return 0;
}

#endif


/****************************************************************************
 * Output_External - Sends certain data to an external program based on
 * the signature triggered.
 ****************************************************************************/

bool Output_External ( struct _DecodeAlert *DecodeAlert )
{

    struct json_object *json_obj = NULL;
    struct json_object *tmp = NULL;

    char *policy = NULL;
    char *meer = NULL;

    /* If we are executing on "all", no reason to check policies, etc */

    if ( MeerOutput->external_execute_on_all == true )
        {
            External( DecodeAlert );
            json_object_put(json_obj);
            return(0);
        }

    if ( DecodeAlert->alert_metadata[0] != '\0' )
        {
            json_obj = json_tokener_parse(DecodeAlert->alert_metadata);

            if (json_object_object_get_ex(json_obj, "meer", &tmp))
                {

                    meer = (char *)json_object_get_string(tmp);

                    if ( strstr( meer, "external" ) )
                        {
                            External( DecodeAlert );
                            json_object_put(json_obj);


                            /* We can return now.  We don't need to check
                               policies, etc */

                            return(0);
                        }

                }

            if ( MeerOutput->external_metadata_security_ips == true ||
                    MeerOutput->external_metadata_max_detect_ips == true ||
                    MeerOutput->external_metadata_connectivity_ips == true ||
                    MeerOutput->external_metadata_balanced_ips == true )
                {

                    if (json_object_object_get_ex(json_obj, "policy", &tmp))
                        {

                            policy = (char *)json_object_get_string(tmp);

                            if ( ( strstr( policy, "security-ips drop" ) && MeerOutput->external_metadata_security_ips == true ) ||
                                    ( strstr( policy, "max-detect-ips drop" ) && MeerOutput->external_metadata_max_detect_ips == true ) ||
                                    ( strstr( policy, "balanced-ips drop" ) && MeerOutput->external_metadata_balanced_ips == true ) ||
                                    ( strstr( policy, "connectivity-ips" ) && MeerOutput->external_metadata_connectivity_ips == true ) )
                                {
                                    External( DecodeAlert );
                                }

                        }

                }
        }

    json_object_put(json_obj);

    return(0);

}

/****************************************************************************
 * Output_Stats - writes stats JSON (from Suricata or Sagan) to a SQL
 * database and/or Redis
 ****************************************************************************/

void Output_Stats ( char *json_string )
{

    struct json_object *json_obj = NULL;
    struct json_object *tmp = NULL;

    char *timestamp = NULL;

    json_obj = json_tokener_parse(json_string);

    if ( json_string == NULL )
        {
            MeerCounters->InvalidJSONCount++;
            Meer_Log(WARN, "Got invalid 'stats' JSON string: %s", json_string);
            json_object_put(json_obj);
            return;
        }

    if ( json_object_object_get_ex(json_obj, "timestamp", &tmp))
        {
            timestamp =  (char *)json_object_get_string(tmp);
        }

    if ( timestamp == NULL )
        {
            MeerCounters->InvalidJSONCount++;
            Meer_Log(WARN, "Warning.  Stats line lacked any 'timestamp'. Skipping. JSON: %s", json_string);
            return;
        }

#if defined(HAVE_LIBMYSQLCLIENT) || defined(HAVE_LIBPQ)

    char *hostname = NULL;

    if ( json_object_object_get_ex(json_obj, "hostname", &tmp))
        {
            hostname =  (char *)json_object_get_string(tmp);
        }

    if ( MeerOutput->sql_stats == true )
        {
            SQL_Insert_Stats ( json_string, timestamp, hostname );
        }

#endif

    json_object_put(json_obj);

}


#ifdef WITH_BLUEDOT

bool Output_Bluedot ( struct _DecodeAlert *DecodeAlert )
{

    struct json_object *json_obj = NULL;
    struct json_object *tmp = NULL;

    const char *meer = NULL;

    if ( DecodeAlert->alert_metadata[0] != '\0' )
        {
            json_obj = json_tokener_parse(DecodeAlert->alert_metadata);

            if (json_object_object_get_ex(json_obj, "meer", &tmp))
                {

                    meer = (char *)json_object_get_string(tmp);

                    if ( strstr( meer, "bluedot" ) )
                        {
                            Bluedot( DecodeAlert );

                            json_object_put(json_obj);
                            return;
                        }

                }

        }

    json_object_put(json_obj); 

}

#endif

#ifdef WITH_ELASTICSEARCH

bool Output_Elasticsearch ( const char *json_string, const char *event_type )
{

    char tmp[PACKET_BUFFER_SIZE_DEFAULT] = { 0 };
    char index_name[512] = { 0 };

    Elasticsearch_Get_Index(index_name, sizeof(index_name), event_type);

    snprintf(tmp, sizeof(tmp), "{\"index\":{\"_index\":\"%s\"}}\n%s\n", index_name, json_string);
    strlcat(big_batch, tmp, sizeof(big_batch) );
    elasticsearch_batch_count++;

    /* Once we hit the batch size,  submit it. */

    if ( elasticsearch_batch_count == MeerOutput->elasticsearch_batch )
        {

            while ( elastic_proc_running >= MeerOutput->elasticsearch_threads )
                {
                    Meer_Log(WARN, "Wating on a free thread! Consider increasing threads?");
                    sleep(5);
                }


            /* Submit the batch ! */

            pthread_mutex_lock(&MeerElasticMutex);

            strlcpy(big_batch_THREAD, big_batch, sizeof(big_batch_THREAD));

            elastic_proc_msgslot++;

            __atomic_add_fetch(&elastic_proc_running, 1, __ATOMIC_SEQ_CST);

            pthread_cond_signal(&MeerElasticWork);
            pthread_mutex_unlock(&MeerElasticMutex);

            /* Clear old batch */

            elasticsearch_batch_count = 0;
            big_batch[0] = '\0';

        }

}

#endif
