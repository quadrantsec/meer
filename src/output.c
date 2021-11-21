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

#include "meer.h"
#include "meer-def.h"
#include "util.h"
#include "util-dns.h"
#include "output.h"
#include "references.h"
#include "sid-map.h"
#include "config-yaml.h"

#include "output-plugins/sql.h"
#include "output-plugins/pipe.h"
#include "output-plugins/external.h"
#include "output-plugins/pipe.h"
#include "output-plugins/file.h"

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

//char big_batch[PACKET_BUFFER_SIZE_DEFAULT * 1000] = { 0 };

extern char *big_batch;
extern char *big_batch_THREAD;

//char big_batch_THREAD[PACKET_BUFFER_SIZE_DEFAULT * 1000] = { 0 };

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
            Meer_Log(NORMAL, "");
            Meer_Log(NORMAL, "Meer metadata : %s", MeerOutput->external_meer_metadata_flag ? "enabled" : "disabled" );

            Meer_Log(NORMAL, "");

            if ( MeerOutput->external_metadata_cisco == true )
                {

                    Meer_Log(NORMAL, "Execute on Cisco 'security-ips' policy: %s", MeerOutput->external_metadata_security_ips ? "enabled" : "disabled" );
                    Meer_Log(NORMAL, "Execute on Cisco 'balanced-ips' policy: %s", MeerOutput->external_metadata_balanced_ips ? "enabled" : "disabled" );
                    Meer_Log(NORMAL, "Execute on Cisco 'connectivity-ips' policy: %s", MeerOutput->external_metadata_connectivity_ips ? "enabled" : "disabled" );
                    Meer_Log(NORMAL, "Execute on Cisco 'max-detect-ips' policy: %s", MeerOutput->external_metadata_max_detect_ips ? "enabled" : "disabled" );

                    Meer_Log(NORMAL, "");
                }

            if ( MeerOutput->external_metadata_et == true )
                {

                    Meer_Log(NORMAL, "Execute on Emerging Threats 'critical': %s", MeerOutput->external_metadata_et_critical ? "enabled" : "disabled" );
                    Meer_Log(NORMAL, "Execute on Emerging Threats 'major': %s", MeerOutput->external_metadata_et_major ? "enabled" : "disabled" );
                    Meer_Log(NORMAL, "Execute on Emerging Threats 'minor': %s", MeerOutput->external_metadata_et_minor ? "enabled" : "disabled" );
                    Meer_Log(NORMAL, "Execute on Emerging Threats 'informational': %s", MeerOutput->external_metadata_et_informational ? "enabled" : "disabled" );
                }


            Meer_Log(NORMAL, "");
            Meer_Log(NORMAL, "Write 'alert'        : %s", MeerOutput->external_alert ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Write 'stats'        : %s", MeerOutput->external_stats ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Write 'email'        : %s", MeerOutput->external_email ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Write 'dns'          : %s", MeerOutput->external_dns ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Write 'flow'         : %s", MeerOutput->external_flow ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Write 'http'         : %s", MeerOutput->external_http ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Write 'tls'          : %s", MeerOutput->external_tls ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Write 'ssh'          : %s", MeerOutput->external_ssh ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Write 'smtp'         : %s", MeerOutput->external_smtp ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Write 'files'        : %s", MeerOutput->external_files ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Write 'fileinfo'     : %s", MeerOutput->external_fileinfo ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Write 'dhcp'         : %s", MeerOutput->external_dhcp ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Write 'rdp'          : %s", MeerOutput->external_rdp ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Write 'sip'          : %s", MeerOutput->external_sip ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Write 'ftp'          : %s", MeerOutput->external_ftp ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Write 'ikev2'        : %s", MeerOutput->external_ikev2 ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Write 'nfs'          : %s", MeerOutput->external_nfs ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Write 'tftp'         : %s", MeerOutput->external_tftp ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Write 'smb'          : %s", MeerOutput->external_smb ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Write 'dcerpc'       : %s", MeerOutput->external_dcerpc ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Write 'mqtt'         : %s", MeerOutput->external_mqtt ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Write 'netflow'      : %s", MeerOutput->external_netflow ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Write 'metadata'     : %s", MeerOutput->external_metadata ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Write 'dnp3'         : %s", MeerOutput->external_dnp3 ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Write 'anomaly'      : %s", MeerOutput->external_anomaly ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Write 'fingerprint'  : %s", MeerOutput->external_fingerprint ? "enabled" : "disabled" );

            Meer_Log(NORMAL, "");

        }

#ifdef HAVE_LIBHIREDIS

    char redis_command[300];
    char redis_reply[5];

    if ( MeerOutput->redis_enabled == true )
        {

            Meer_Log(NORMAL, "--[ Redis information ]--------------------------------------------");
            Meer_Log(NORMAL, "");

            /* Connect to redis database */

            Redis_Init();			/* Init memory, etc */
            Redis_Connect();

            strlcpy(redis_command, "PING", sizeof(redis_command));

            Redis_Reader(redis_command, redis_reply, sizeof(redis_reply));

            if (!strcmp(redis_reply, "PONG"))
                {
                    Meer_Log(NORMAL, "Got PONG from Redis at %s:%d.", MeerOutput->redis_server, MeerOutput->redis_port);
                }

            Meer_Log(NORMAL, "");
            Meer_Log(NORMAL, "Write 'alert'        : %s", MeerOutput->redis_alert ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Write 'stats'        : %s", MeerOutput->redis_stats ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Write 'email'        : %s", MeerOutput->redis_email ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Write 'dns'          : %s", MeerOutput->redis_dns ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Write 'flow'         : %s", MeerOutput->redis_flow ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Write 'http'         : %s", MeerOutput->redis_http ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Write 'tls'          : %s", MeerOutput->redis_tls ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Write 'ssh'          : %s", MeerOutput->redis_ssh ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Write 'smtp'         : %s", MeerOutput->redis_smtp ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Write 'files'        : %s", MeerOutput->redis_files ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Write 'fileinfo'     : %s", MeerOutput->redis_fileinfo ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Write 'dhcp'         : %s", MeerOutput->redis_dhcp ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Write 'rdp'          : %s", MeerOutput->redis_rdp ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Write 'sip'          : %s", MeerOutput->redis_sip ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Write 'ftp'          : %s", MeerOutput->redis_ftp ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Write 'ikev2'        : %s", MeerOutput->redis_ikev2 ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Write 'nfs'          : %s", MeerOutput->redis_nfs ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Write 'tftp'         : %s", MeerOutput->redis_tftp ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Write 'smb'          : %s", MeerOutput->redis_smb ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Write 'dcerpc'       : %s", MeerOutput->redis_dcerpc ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Write 'mqtt'         : %s", MeerOutput->redis_mqtt ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Write 'netflow'      : %s", MeerOutput->redis_netflow ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Write 'metadata'     : %s", MeerOutput->redis_metadata ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Write 'dnp3'         : %s", MeerOutput->redis_dnp3 ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Write 'anomaly'      : %s", MeerOutput->redis_anomaly ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Write 'fingerprint'  : %s", MeerOutput->redis_fingerprint ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Write 'client_stats' : %s", MeerOutput->redis_client_stats ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "");

        }

#endif

    if ( MeerOutput->file_enabled )
        {

            Meer_Log(NORMAL, "--[ File information ]--------------------------------------------");
            Meer_Log(NORMAL, "");
            Meer_Log(NORMAL, "File Location: %s", MeerOutput->file_location);
            Meer_Log(NORMAL, "");
            Meer_Log(NORMAL, "Write 'alert'      : %s", MeerOutput->file_alert ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Write 'stats'      : %s", MeerOutput->file_stats ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Write 'email'      : %s", MeerOutput->file_email ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Write 'dns'        : %s", MeerOutput->file_dns ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Write 'flow'       : %s", MeerOutput->file_flow ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Write 'http'       : %s", MeerOutput->file_http ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Write 'tls'        : %s", MeerOutput->file_tls ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Write 'ssh'        : %s", MeerOutput->file_ssh ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Write 'smtp'       : %s", MeerOutput->file_smtp ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Write 'files'      : %s", MeerOutput->file_files ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Write 'fileinfo'   : %s", MeerOutput->file_fileinfo ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Write 'dhcp'       : %s", MeerOutput->file_dhcp ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Write 'rdp'        : %s", MeerOutput->file_rdp ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Write 'sip'        : %s", MeerOutput->file_sip ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Write 'ftp'        : %s", MeerOutput->file_ftp ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Write 'ikev2'      : %s", MeerOutput->file_ikev2 ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Write 'nfs'        : %s", MeerOutput->file_nfs ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Write 'tftp'       : %s", MeerOutput->file_tftp ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Write 'smb'        : %s", MeerOutput->file_smb ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Write 'dcerpc'     : %s", MeerOutput->file_dcerpc ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Write 'mqtt'       : %s", MeerOutput->file_mqtt ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Write 'netflow'    : %s", MeerOutput->file_netflow ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Write 'metadata'   : %s", MeerOutput->file_metadata ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Write 'dnp3'       : %s", MeerOutput->file_dnp3 ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Write 'anomaly'    : %s", MeerOutput->file_anomaly ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Write 'fingerprint': %s", MeerOutput->file_fingerprint ? "enabled" : "disabled" );

            Meer_Log(NORMAL, "");

            /* Open the new spool file for output */

            if (( MeerOutput->file_fd = fopen(MeerOutput->file_location, "a" )) == NULL )
                {
                    Meer_Log(ERROR, "[%s, line %d] Cannot open '%s' for append. %s", __FILE__,  __LINE__, MeerOutput->file_location, strerror(errno) );
                }

        }


    if ( MeerOutput->pipe_enabled )
        {
            uint32_t current_pipe_size = 0;
            uint32_t fd_results = 0;

            Meer_Log(NORMAL, "--[ PIPE information ]--------------------------------------------");
            Meer_Log(NORMAL, "");
            Meer_Log(NORMAL, "Pipe Location: %s", MeerOutput->pipe_location);
            Meer_Log(NORMAL, "Pipe Size: %d bytes", MeerOutput->pipe_size);
            Meer_Log(NORMAL, "");

            Meer_Log(NORMAL, "Write 'alert'      : %s", MeerOutput->pipe_alert ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Write 'stats'      : %s", MeerOutput->pipe_stats ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Write 'email'      : %s", MeerOutput->pipe_email ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Write 'dns'        : %s", MeerOutput->pipe_dns ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Write 'flow'       : %s", MeerOutput->pipe_flow ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Write 'http'       : %s", MeerOutput->pipe_http ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Write 'tls'        : %s", MeerOutput->pipe_tls ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Write 'ssh'        : %s", MeerOutput->pipe_ssh ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Write 'smtp'       : %s", MeerOutput->pipe_smtp ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Write 'files'      : %s", MeerOutput->pipe_files ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Write 'fileinfo'   : %s", MeerOutput->pipe_fileinfo ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Write 'dhcp'       : %s", MeerOutput->pipe_dhcp ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Write 'rdp'        : %s", MeerOutput->pipe_rdp ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Write 'sip'        : %s", MeerOutput->pipe_sip ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Write 'ftp'        : %s", MeerOutput->pipe_ftp ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Write 'ikev2'      : %s", MeerOutput->pipe_ikev2 ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Write 'nfs'        : %s", MeerOutput->pipe_nfs ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Write 'tftp'       : %s", MeerOutput->pipe_tftp ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Write 'smb'        : %s", MeerOutput->pipe_smb ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Write 'dcerpc'     : %s", MeerOutput->pipe_dcerpc ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Write 'mqtt'       : %s", MeerOutput->pipe_mqtt ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Write 'netflow'    : %s", MeerOutput->pipe_netflow ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Write 'metadata'   : %s", MeerOutput->pipe_metadata ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Write 'dnp3'       : %s", MeerOutput->pipe_dnp3 ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Write 'anomaly'    : %s", MeerOutput->pipe_anomaly ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Write 'fingerprint': %s", MeerOutput->pipe_fingerprint ? "enabled" : "disabled" );


            Meer_Log(NORMAL, "");

            MeerOutput->pipe_fd = open(MeerOutput->pipe_location, O_RDWR);

            if ( MeerOutput->pipe_fd < 0 )
                {
                    Meer_Log(ERROR, "[%s, line %d] Cannot open %s. %s.", __FILE__, __LINE__, MeerOutput->pipe_location, strerror(errno) );
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
        }

#endif

#ifdef HAVE_LIBMAXMINDDB

    if ( MeerConfig->geoip == true )
        {

            Meer_Log(NORMAL, "--[ GeoIP information ]---------------------------------");
            Meer_Log(NORMAL, "");
            Meer_Log(NORMAL, "GeoIP           : %s", MeerConfig->geoip ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "GeoIP database  : %s", MeerConfig->geoip_database );
            Meer_Log(NORMAL, "");
        }

#endif

    if ( MeerConfig->fingerprint == true )
        {

            Meer_Log(NORMAL, "--[ Fingerprinting information ]---------------------------------");
            Meer_Log(NORMAL, "");
            Meer_Log(NORMAL, "Fingerprinting : %s", MeerConfig->fingerprint ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "");
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

    if ( MeerOutput->elasticsearch_enabled == true )
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
            Meer_Log(NORMAL, "Record 'alert'       : %s", MeerOutput->elasticsearch_alert ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Record 'files'       : %s", MeerOutput->elasticsearch_files ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Record 'flow'        : %s", MeerOutput->elasticsearch_flow ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Record 'dns'         : %s", MeerOutput->elasticsearch_dns ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Record 'http'        : %s", MeerOutput->elasticsearch_http ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Record 'tls'         : %s", MeerOutput->elasticsearch_tls ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Record 'ssh'         : %s", MeerOutput->elasticsearch_ssh ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Record 'smtp'        : %s", MeerOutput->elasticsearch_smtp ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Record 'email'       : %s", MeerOutput->elasticsearch_email ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Record 'fileinfo'    : %s", MeerOutput->elasticsearch_fileinfo ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Record 'dhcp'        : %s", MeerOutput->elasticsearch_dhcp ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Record 'stats'       : %s", MeerOutput->elasticsearch_stats ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Record 'rdp'         : %s", MeerOutput->elasticsearch_rdp ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Record 'sip'         : %s", MeerOutput->elasticsearch_sip ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Record 'ftp'         : %s", MeerOutput->elasticsearch_ftp ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Record 'nfs'         : %s", MeerOutput->elasticsearch_nfs ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Record 'tftp'        : %s", MeerOutput->elasticsearch_tftp ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Record 'smb'         : %s", MeerOutput->elasticsearch_smb ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Record 'mqtt'        : %s", MeerOutput->elasticsearch_mqtt ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Record 'dcerpc'      : %s", MeerOutput->elasticsearch_dcerpc ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Record 'netflow'     : %s", MeerOutput->elasticsearch_netflow ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Record 'metadata'    : %s", MeerOutput->elasticsearch_metadata ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Record 'dnp3'        : %s", MeerOutput->elasticsearch_dnp3 ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Record 'anomaly'     : %s", MeerOutput->elasticsearch_anomaly ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Record 'fingerprint' : %s", MeerOutput->elasticsearch_fingerprint ? "enabled" : "disabled" );

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

bool Output_Pipe ( const char *json_string, const char *event_type )
{

    if ( !strcmp(event_type, "alert" ) && MeerOutput->pipe_alert == true )
        {
            Pipe_Write( json_string );
            return(true);
        }

    else if ( !strcmp(event_type, "files" ) && MeerOutput->pipe_files == true )
        {
            Pipe_Write( json_string );
            return(true);
        }

    else if ( !strcmp(event_type, "flow" ) && MeerOutput->pipe_flow == true )
        {
            Pipe_Write( json_string );
            return(true);
        }

    else if ( !strcmp(event_type, "dns" ) && MeerOutput->pipe_dns == true )
        {
            Pipe_Write( json_string );
            return(true);
        }

    else if ( !strcmp(event_type, "http" ) && MeerOutput->pipe_http == true )
        {
            Pipe_Write( json_string );
            return(true);
        }

    else if ( !strcmp(event_type, "ssh" ) && MeerOutput->pipe_ssh == true )
        {
            Pipe_Write( json_string );
            return(true);
        }

    else if ( !strcmp(event_type, "smtp" ) && MeerOutput->pipe_smtp == true )
        {
            Pipe_Write( json_string );
            return(true);
        }

    else if ( !strcmp(event_type, "email" ) && MeerOutput->pipe_email == true )
        {
            Pipe_Write( json_string );
            return(true);
        }

    else if ( !strcmp(event_type, "fileinfo" ) && MeerOutput->pipe_fileinfo == true )
        {
            Pipe_Write( json_string );
            return(true);
        }

    else if ( !strcmp(event_type, "dhcp" ) && MeerOutput->pipe_dhcp == true )
        {
            Pipe_Write( json_string );
            return(true);
        }

    else if ( !strcmp(event_type, "stats" ) && MeerOutput->pipe_stats == true )
        {
            Pipe_Write( json_string );
            return(true);
        }

    else if ( !strcmp(event_type, "rdp" ) && MeerOutput->pipe_rdp == true )
        {
            Pipe_Write( json_string );
            return(true);
        }

    else if ( !strcmp(event_type, "sip" ) && MeerOutput->pipe_sip == true )
        {
            Pipe_Write( json_string );
            return(true);
        }

    else if ( !strcmp(event_type, "ftp" ) && MeerOutput->pipe_ftp == true )
        {
            Pipe_Write( json_string );
            return(true);
        }

    else if ( !strcmp(event_type, "ikev2" ) && MeerOutput->pipe_ikev2 == true )
        {
            Pipe_Write( json_string );
            return(true);
        }

    else if ( !strcmp(event_type, "nfs" ) && MeerOutput->pipe_nfs == true )
        {
            Pipe_Write( json_string );
            return(true);
        }

    else if ( !strcmp(event_type, "tftp" ) && MeerOutput->pipe_tftp == true )
        {
            Pipe_Write( json_string );
            return(true);
        }

    else if ( !strcmp(event_type, "smb" ) && MeerOutput->pipe_smb == true )
        {
            Pipe_Write( json_string );
            return(true);
        }

    else if ( !strcmp(event_type, "dcerpc" ) && MeerOutput->pipe_dcerpc == true )
        {
            Pipe_Write( json_string );
            return(true);
        }

    else if ( !strcmp(event_type, "mqtt" ) && MeerOutput->pipe_mqtt == true )
        {
            Pipe_Write( json_string );
            return(true);
        }

    else if ( !strcmp(event_type, "netflow" ) && MeerOutput->pipe_netflow == true )
        {
            Pipe_Write( json_string );
            return(true);
        }

    else if ( !strcmp(event_type, "metadata" ) && MeerOutput->pipe_metadata == true )
        {
            Pipe_Write( json_string );
            return(true);
        }

    else if ( !strcmp(event_type, "dnp3" ) && MeerOutput->pipe_dnp3 == true )
        {
            Pipe_Write( json_string );
            return(true);
        }

    else if ( !strcmp(event_type, "anomaly" ) && MeerOutput->pipe_anomaly == true )
        {
            Pipe_Write( json_string );
            return(true);
        }

    else if ( !strcmp(event_type, "fingerprint" ) && MeerOutput->pipe_fingerprint == true )
        {
            Pipe_Write( json_string );
            return(true);
        }


    MeerCounters->JSONPipeMisses++;
    return(false);

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

                    SQL_Insert_JSON ( DecodeAlert );
                    SQL_Insert_DNS ( DecodeAlert );

                    /* We can have multiple "xff" fields in extra data */

                    if ( MeerOutput->sql_extra_data == true )
                        {
                            SQL_Insert_Extra_Data ( DecodeAlert );
                        }

                    if ( DecodeAlert->has_normalize == true )
                        {
                            SQL_Insert_Normalize ( DecodeAlert );
                        }

                    if ( DecodeAlert->has_flow == true ) //&& MeerOutput->sql_flow == true )
                        {
                            SQL_Insert_Flow ( DecodeAlert );
                        }

                    if ( DecodeAlert->has_http == true ) // && MeerOutput->sql_http == true )
                        {
                            SQL_Insert_HTTP ( DecodeAlert );
                        }

                    if ( DecodeAlert->has_tls == true ) // && MeerOutput->sql_tls == true )
                        {
                            SQL_Insert_TLS ( DecodeAlert );
                        }

                    if ( DecodeAlert->has_ssh_server == true ) // && MeerOutput->sql_ssh == true )
                        {
                            SQL_Insert_SSH ( DecodeAlert, SSH_SERVER );
                        }

                    if ( DecodeAlert->has_ssh_client == true ) // && MeerOutput->sql_ssh == true )
                        {
                            SQL_Insert_SSH ( DecodeAlert, SSH_CLIENT );
                        }

                    if ( DecodeAlert->alert_has_metadata == true ) // && MeerOutput->sql_metadata == true )
                        {
                            SQL_Insert_Metadata ( DecodeAlert );
                        }

                    if ( DecodeAlert->has_smtp == true ) // && MeerOutput->sql_smtp == true )
                        {
                            SQL_Insert_SMTP ( DecodeAlert );
                        }

                    if ( DecodeAlert->has_email == true ) //  && MeerOutput->sql_email == true )
                        {
                            SQL_Insert_Email ( DecodeAlert );
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

bool Output_External ( const char *json_string, struct json_object *json_obj, const char *event_type )
{

    struct json_object *json_obj_meta = NULL;
    struct json_object *tmp = NULL;

    char *alert = NULL;
    char *policy = NULL;
    char *meer = NULL;

    char alert_metadata[1024] = { 0 };

    /* We treat alerts "special".  We allow some filtering to happen, if the
       user wants, before we send alert EVE to external programs */

    if ( !strcmp(event_type, "alert" ) && MeerOutput->external_alert == true )
        {

            if ( MeerOutput->external_metadata_et == false && MeerOutput->external_metadata_cisco == false &&
                    MeerOutput->external_meer_metadata_flag == false )
                {
                    External( json_string );
                    json_object_put(json_obj_meta);
                    return(true);
                }

            if (json_object_object_get_ex(json_obj, "alert", &tmp))
                {
                    alert = (char *)json_object_get_string(tmp);
                }

            if ( alert == NULL )
                {
                    Meer_Log(WARN, "[%s, line %d] Got NULL alert data (shouldn't ever get this!)", __FILE__, __LINE__);
                    json_object_put(json_obj_meta);
                    return(false);
                }

            json_obj_meta = json_tokener_parse(alert);

            if ( json_object_object_get_ex(json_obj_meta, "metadata", &tmp))
                {
                    char *t = (char *)json_object_get_string(tmp);

                    if ( t == NULL )
                        {
                            Meer_Log(WARN, "[%s, line %d] Got NULL metadata (shouldn't ever get this!)", __FILE__, __LINE__);
                            json_object_put(json_obj_meta);
                            return(false);
                        }

                    strlcpy( alert_metadata, t, sizeof( alert_metadata ) );
                }

            if ( alert_metadata[0] != '\0' )
                {

                    json_obj_meta = json_tokener_parse(alert_metadata);

                    /*******************************************/
                    /* Look for the "meer" flags in "metadata" */
                    /*******************************************/

                    if ( MeerOutput->external_meer_metadata_flag == true )
                        {

                            if (json_object_object_get_ex(json_obj_meta, "meer", &tmp))
                                {

                                    meer = (char *)json_object_get_string(tmp);

                                    if ( strstr( meer, "external" ) )
                                        {

                                            if ( MeerOutput->external_debug )
                                                {
                                                    Meer_Log(DEBUG, "[%s, line %d] Found Meer Metadata.", __FILE__, __LINE__);
                                                }

                                            External( json_string );
                                            json_object_put(json_obj_meta);
                                            return(true);

                                        }
                                }
                        }

                    /********************************************/
                    /* Look for Cisco Talso specific indicators */
                    /********************************************/

                    if ( MeerOutput->external_metadata_cisco == true )
                        {

                            if (json_object_object_get_ex(json_obj_meta, "policy", &tmp))
                                {

                                    policy = (char *)json_object_get_string(tmp);

                                    if ( ( strstr( policy, "security-ips drop" ) && MeerOutput->external_metadata_security_ips == true ) ||
                                            ( strstr( policy, "max-detect-ips drop" ) && MeerOutput->external_metadata_max_detect_ips == true ) ||
                                            ( strstr( policy, "balanced-ips drop" ) && MeerOutput->external_metadata_balanced_ips == true ) ||
                                            ( strstr( policy, "connectivity-ips" ) && MeerOutput->external_metadata_connectivity_ips == true ) )
                                        {

                                            if ( MeerOutput->external_debug )
                                                {
                                                    Meer_Log(DEBUG, "[%s, line %d] Found Cisco Metadata.", __FILE__, __LINE__);
                                                }


                                            External( json_string );
                                            json_object_put(json_obj_meta);
                                            return(true);
                                        }

                                }

                        } /* MeerOutput->external_metadata_cisco == true */


                    /********************************************/
                    /* Look for Cisco Talso specific indicators */
                    /********************************************/

                    if ( MeerOutput->external_metadata_et == true )
                        {


                            if (json_object_object_get_ex(json_obj_meta, "signature_severity", &tmp))
                                {

                                    policy = (char *)json_object_get_string(tmp);

                                    if ( ( strcasestr( policy, "Critical" ) && MeerOutput->external_metadata_et_critical == true ) ||
                                            ( strcasestr( policy, "Major" ) && MeerOutput->external_metadata_et_major == true ) ||
                                            ( strcasestr( policy, "Minor" ) && MeerOutput->external_metadata_et_minor == true ) ||
                                            ( strcasestr( policy, "Informational" ) && MeerOutput->external_metadata_et_informational == true ) )
                                        {

                                            if ( MeerOutput->external_debug )
                                                {
                                                    Meer_Log(DEBUG, "[%s, line %d] Found Emerging Threats Metadata.", __FILE__, __LINE__);
                                                }

                                            External( json_string );
                                            json_object_put(json_obj_meta);
                                            return(true);
                                        }
                                }
                        }
                }

        } /* !strcmp(event_type, "alert" ) ... */


    json_object_put(json_obj_meta);

    /********************************************************************/
    /* Continue on with other event_types.  No "special" considerations */
    /* are needed                                                       */
    /********************************************************************/

    if ( !strcmp(event_type, "files" ) && MeerOutput->external_files == true )
        {
            External( json_string );
            return(true);
        }

    else if ( !strcmp(event_type, "flow" ) && MeerOutput->external_flow == true )
        {
            External( json_string );
            return(true);
        }

    else if ( !strcmp(event_type, "dns" ) && MeerOutput->external_dns == true )
        {
            External( json_string );
            return(true);
        }

    else if ( !strcmp(event_type, "http" ) && MeerOutput->external_http == true )
        {
            External( json_string );
            return(true);
        }

    else if ( !strcmp(event_type, "tls" ) && MeerOutput->external_tls == true )
        {
            External( json_string );
            return(true);
        }

    else if ( !strcmp(event_type, "ssh" ) && MeerOutput->external_ssh == true )
        {
            External( json_string );
            return(true);
        }

    else if ( !strcmp(event_type, "smtp" ) && MeerOutput->external_smtp == true )
        {
            External( json_string );
            return(true);
        }

    else if ( !strcmp(event_type, "email" ) && MeerOutput->external_email == true )
        {
            External( json_string );
            return(true);
        }

    else if ( !strcmp(event_type, "fileinfo" ) && MeerOutput->external_fileinfo == true )
        {
            External( json_string );
            return(true);
        }

    else if ( !strcmp(event_type, "dhcp" ) && MeerOutput->external_dhcp == true )
        {
            External( json_string );
            return(true);
        }

    else if ( !strcmp(event_type, "stats" ) && MeerOutput->external_stats == true )
        {
            External( json_string );
            return(true);
        }

    else if ( !strcmp(event_type, "rdp" ) && MeerOutput->external_rdp == true )
        {
            External( json_string );
            return(true);
        }

    else if ( !strcmp(event_type, "sip" ) && MeerOutput->external_sip == true )
        {
            External( json_string );
            return(true);
        }


    else if ( !strcmp(event_type, "ftp" ) && MeerOutput->external_ftp == true )
        {
            External( json_string );
            return(true);
        }

    else if ( !strcmp(event_type, "ikev2" ) && MeerOutput->external_ikev2 == true )
        {
            External( json_string );
            return(true);
        }

    else if ( !strcmp(event_type, "nfs" ) && MeerOutput->external_nfs == true )
        {
            External( json_string );
            return(true);
        }

    else if ( !strcmp(event_type, "tftp" ) && MeerOutput->external_tftp == true )
        {
            External( json_string );
            return(true);
        }

    else if ( !strcmp(event_type, "smb" ) && MeerOutput->external_smb == true )
        {
            External( json_string );
            return(true);
        }


    else if ( !strcmp(event_type, "mqtt" ) && MeerOutput->external_mqtt == true )
        {
            External( json_string );
            return(true);
        }


    else if ( !strcmp(event_type, "dcerpc" ) && MeerOutput->external_dcerpc == true )
        {
            External( json_string );
            return(true);
        }

    else if ( !strcmp(event_type, "netflow" ) && MeerOutput->external_netflow == true )
        {
            External( json_string );
            return(true);
        }

    else if ( !strcmp(event_type, "metadata" ) && MeerOutput->external_metadata == true )
        {
            External( json_string );
            return(true);
        }

    else if ( !strcmp(event_type, "dnp3" ) && MeerOutput->external_dnp3 == true )
        {
            External( json_string );
            return(true);
        }

    else if ( !strcmp(event_type, "anomaly" ) && MeerOutput->external_anomaly == true )
        {
            External( json_string );
            return(true);
        }

    else if ( !strcmp(event_type, "fingerprint" ) && MeerOutput->external_fingerprint == true )
        {
            External( json_string );
            return(true);
        }

    return(false);
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
            MeerCounters->bad++;
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
            MeerCounters->bad++;
            Meer_Log(WARN, "Warning.  Stats line lacked any 'timestamp'. Skipping. JSON: %s", json_string);
            return;
        }

#if defined(HAVE_LIBMYSQLCLIENT) || defined(HAVE_LIBPQ)

    char *hostname = NULL;

    if ( json_object_object_get_ex(json_obj, "hostname", &tmp))
        {
            hostname =  (char *)json_object_get_string(tmp);
        }

    SQL_Insert_Stats ( json_string, timestamp, hostname );

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
                            return(true);
                        }

                }

        }

    json_object_put(json_obj);

    return(false);
}

#endif

#ifdef WITH_ELASTICSEARCH

bool Output_Elasticsearch ( const char *json_string, const char *event_type )
{

    if ( !strcmp(event_type, "alert" ) && MeerOutput->elasticsearch_alert == true )
        {
            Output_Do_Elasticsearch( json_string, event_type );
            return(true);
        }

    else if ( !strcmp(event_type, "files" ) && MeerOutput->elasticsearch_files == true )
        {
            Output_Do_Elasticsearch( json_string, event_type );
            return(true);
        }

    else if ( !strcmp(event_type, "flow" ) && MeerOutput->elasticsearch_flow == true )
        {
            Output_Do_Elasticsearch( json_string, event_type );
            return(true);
        }

    else if ( !strcmp(event_type, "dns" ) && MeerOutput->elasticsearch_dns == true )
        {
            Output_Do_Elasticsearch( json_string, event_type );
            return(true);
        }

    else if ( !strcmp(event_type, "http" ) && MeerOutput->elasticsearch_http == true )
        {
            Output_Do_Elasticsearch( json_string, event_type );
            return(true);
        }

    else if ( !strcmp(event_type, "tls" ) && MeerOutput->elasticsearch_tls == true )
        {
            Output_Do_Elasticsearch( json_string, event_type );
            return(true);
        }

    else if ( !strcmp(event_type, "ssh" ) && MeerOutput->elasticsearch_ssh == true )
        {
            Output_Do_Elasticsearch( json_string, event_type );
            return(true);
        }

    else if ( !strcmp(event_type, "smtp" ) && MeerOutput->elasticsearch_smtp == true )
        {
            Output_Do_Elasticsearch( json_string, event_type );
            return(true);
        }

    else if ( !strcmp(event_type, "email" ) && MeerOutput->elasticsearch_email == true )
        {
            Output_Do_Elasticsearch( json_string, event_type );
            return(true);
        }

    else if ( !strcmp(event_type, "fileinfo" ) && MeerOutput->elasticsearch_fileinfo == true )
        {
            Output_Do_Elasticsearch( json_string, event_type );
            return(true);
        }

    else if ( !strcmp(event_type, "dhcp" ) && MeerOutput->elasticsearch_dhcp == true )
        {
            Output_Do_Elasticsearch( json_string, event_type );
            return(true);
        }

    else if ( !strcmp(event_type, "stats" ) && MeerOutput->elasticsearch_stats == true )
        {
            Output_Do_Elasticsearch( json_string, event_type );
            return(true);
        }

    else if ( !strcmp(event_type, "rdp" ) && MeerOutput->elasticsearch_rdp == true )
        {
            Output_Do_Elasticsearch( json_string, event_type );
            return(true);
        }

    else if ( !strcmp(event_type, "sip" ) && MeerOutput->elasticsearch_sip == true )
        {
            Output_Do_Elasticsearch( json_string, event_type );
            return(true);
        }

    else if ( !strcmp(event_type, "ftp" ) && MeerOutput->elasticsearch_ftp == true )
        {
            Output_Do_Elasticsearch( json_string, event_type );
            return(true);
        }

    else if ( !strcmp(event_type, "ikev2" ) && MeerOutput->elasticsearch_ikev2 == true )
        {
            Output_Do_Elasticsearch( json_string, event_type );
            return(true);
        }

    else if ( !strcmp(event_type, "nfs" ) && MeerOutput->elasticsearch_nfs == true )
        {
            Output_Do_Elasticsearch( json_string, event_type );
            return(true);
        }

    else if ( !strcmp(event_type, "tftp" ) && MeerOutput->elasticsearch_tftp == true )
        {
            Output_Do_Elasticsearch( json_string, event_type );
            return(true);
        }

    else if ( !strcmp(event_type, "smb" ) && MeerOutput->elasticsearch_smb == true )
        {
            Output_Do_Elasticsearch( json_string, event_type );
            return(true);
        }

    else if ( !strcmp(event_type, "mqtt" ) && MeerOutput->elasticsearch_mqtt == true )
        {
            Output_Do_Elasticsearch( json_string, event_type );
            return(true);
        }

    else if ( !strcmp(event_type, "dcerpc" ) && MeerOutput->elasticsearch_dcerpc == true )
        {
            Output_Do_Elasticsearch( json_string, event_type );
            return(true);
        }

    else if ( !strcmp(event_type, "netflow" ) && MeerOutput->elasticsearch_netflow == true )
        {
            Output_Do_Elasticsearch( json_string, event_type );
            return(true);
        }

    else if ( !strcmp(event_type, "metadata" ) && MeerOutput->elasticsearch_metadata == true )
        {
            Output_Do_Elasticsearch( json_string, event_type );
            return(true);
        }

    else if ( !strcmp(event_type, "dnp3" ) && MeerOutput->elasticsearch_dnp3 == true )
        {
            Output_Do_Elasticsearch( json_string, event_type );
            return(true);
        }


    else if ( !strcmp(event_type, "anomaly" ) && MeerOutput->elasticsearch_anomaly == true )
        {
            Output_Do_Elasticsearch( json_string, event_type );
            return(true);
        }

    else if ( !strcmp(event_type, "fingerprint" ) && MeerOutput->elasticsearch_fingerprint == true )
        {
            Output_Do_Elasticsearch( json_string, event_type );
            return(true);
        }

    return(false);

}


bool Output_Do_Elasticsearch ( const char *json_string, const char *event_type )
{

    char *tmp = malloc((MeerConfig->payload_buffer_size)*sizeof(char));

    if ( tmp == NULL )
        {
            fprintf(stderr, "[%s, line %d] Fatal Error: Can't allocate memory! Abort!\n", __FILE__, __LINE__);
            exit(-1);
        }

    char index_name[512] = { 0 };

    Elasticsearch_Get_Index(index_name, sizeof(index_name), event_type);

    snprintf(tmp, MeerConfig->payload_buffer_size, "{\"index\":{\"_index\":\"%s\"}}\n%s\n", index_name, json_string);

    strlcat(big_batch, tmp, MeerConfig->payload_buffer_size); //  * MeerOutput->elasticsearch_batch ) );
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

            strlcpy( big_batch_THREAD, big_batch, ( MeerConfig->payload_buffer_size * MeerOutput->elasticsearch_batch ) );
            elastic_proc_msgslot++;

            __atomic_add_fetch(&elastic_proc_running, 1, __ATOMIC_SEQ_CST);

            pthread_cond_signal(&MeerElasticWork);
            pthread_mutex_unlock(&MeerElasticMutex);

            /* Clear old batch */

            elasticsearch_batch_count = 0;
            big_batch[0] = '\0';

        }

    free(tmp);
    return(true);
}

#endif

bool Output_File ( const char *json_string, const char *event_type )
{

    if ( !strcmp(event_type, "alert" ) && MeerOutput->file_alert == true )
        {
            Output_Do_File( json_string );
            return(true);
        }

    else if ( !strcmp(event_type, "files" ) && MeerOutput->file_files == true )
        {
            Output_Do_File( json_string );
            return(true);
        }

    else if ( !strcmp(event_type, "flow" ) && MeerOutput->file_flow == true )
        {
            Output_Do_File( json_string );
            return(true);
        }

    else if ( !strcmp(event_type, "dns" ) && MeerOutput->file_dns == true )
        {
            Output_Do_File( json_string );
            return(true);
        }

    else if ( !strcmp(event_type, "http" ) && MeerOutput->file_http == true )
        {
            Output_Do_File( json_string );
            return(true);
        }

    else if ( !strcmp(event_type, "tls" ) && MeerOutput->file_tls == true )
        {
            Output_Do_File( json_string );
            return(true);
        }

    else if ( !strcmp(event_type, "ssh" ) && MeerOutput->file_ssh == true )
        {
            Output_Do_File( json_string );
            return(true);
        }

    else if ( !strcmp(event_type, "smtp" ) && MeerOutput->file_smtp == true )
        {
            Output_Do_File( json_string );
            return(true);
        }

    else if ( !strcmp(event_type, "email" ) && MeerOutput->file_email == true )
        {
            Output_Do_File( json_string );
            return(true);
        }

    else if ( !strcmp(event_type, "fileinfo" ) && MeerOutput->file_fileinfo == true )
        {
            Output_Do_File( json_string );
            return(true);
        }

    else if ( !strcmp(event_type, "dhcp" ) && MeerOutput->file_dhcp == true )
        {
            Output_Do_File( json_string );
            return(true);
        }

    else if ( !strcmp(event_type, "stats" ) && MeerOutput->file_stats == true )
        {
            Output_Do_File( json_string );
            return(true);
        }

    else if ( !strcmp(event_type, "rdp" ) && MeerOutput->file_rdp == true )
        {
            Output_Do_File( json_string );
            return(true);
        }

    else if ( !strcmp(event_type, "sip" ) && MeerOutput->file_sip == true )
        {
            Output_Do_File( json_string );
            return(true);
        }

    else if ( !strcmp(event_type, "ftp" ) && MeerOutput->file_ftp == true )
        {
            Output_Do_File( json_string );
            return(true);
        }

    else if ( !strcmp(event_type, "ikev2" ) && MeerOutput->file_ikev2 == true )
        {
            Output_Do_File( json_string );
            return(true);
        }

    else if ( !strcmp(event_type, "nfs" ) && MeerOutput->file_nfs == true )
        {
            Output_Do_File( json_string );
            return(true);
        }

    else if ( !strcmp(event_type, "tftp" ) && MeerOutput->file_tftp == true )
        {
            Output_Do_File( json_string );
            return(true);
        }

    else if ( !strcmp(event_type, "smb" ) && MeerOutput->file_smb == true )
        {
            Output_Do_File( json_string );
            return(true);
        }

    else if ( !strcmp(event_type, "dcerpc" ) && MeerOutput->file_dcerpc == true )
        {
            Output_Do_File( json_string );
            return(true);
        }

    else if ( !strcmp(event_type, "mqtt" ) && MeerOutput->file_mqtt == true )
        {
            Output_Do_File( json_string );
            return(true);
        }

    else if ( !strcmp(event_type, "netflow" ) && MeerOutput->file_netflow == true )
        {
            Output_Do_File( json_string );
            return(true);
        }

    else if ( !strcmp(event_type, "metadata" ) && MeerOutput->file_metadata == true )
        {
            Output_Do_File( json_string );
            return(true);
        }

    else if ( !strcmp(event_type, "dnp3" ) && MeerOutput->file_dnp3 == true )
        {
            Output_Do_File( json_string );
            return(true);
        }

    else if ( !strcmp(event_type, "anomaly" ) && MeerOutput->file_anomaly == true )
        {
            Output_Do_File( json_string );
            return(true);
        }

    else if ( !strcmp(event_type, "fingerprint" ) && MeerOutput->file_fingerprint == true )
        {
            Output_Do_File( json_string );
            return(true);
        }

    return(false);

}

#ifdef HAVE_LIBHIREDIS

bool Output_Redis( const char *json_string, const char *event_type )
{

    if ( !strcmp( event_type, "alert") && MeerOutput->redis_alert == true )
        {
            JSON_To_Redis( json_string, event_type );
            return(true);
        }

    else if ( !strcmp( event_type, "files") && MeerOutput->redis_files == true )
        {
            JSON_To_Redis( json_string, event_type );
            return(true);
        }

    else if ( !strcmp( event_type, "flow") && MeerOutput->redis_flow == true )
        {
            JSON_To_Redis( json_string, event_type );
            return(true);
        }

    else if ( !strcmp( event_type, "dns") && MeerOutput->redis_dns == true )
        {
            JSON_To_Redis( json_string, event_type );
            return(true);
        }

    else if ( !strcmp( event_type, "http") && MeerOutput->redis_http == true )
        {
            JSON_To_Redis( json_string, event_type );
            return(true);
        }

    else if ( !strcmp( event_type, "tls") && MeerOutput->redis_tls == true )
        {
            JSON_To_Redis( json_string, event_type );
            return(true);
        }

    else if ( !strcmp( event_type, "ssh") && MeerOutput->redis_ssh == true )
        {
            JSON_To_Redis( json_string, event_type );
            return(true);
        }

    else if ( !strcmp( event_type, "smtp") && MeerOutput->redis_smtp == true )
        {
            JSON_To_Redis( json_string, event_type );
            return(true);
        }

    else if ( !strcmp( event_type, "fileinfo") && MeerOutput->redis_fileinfo == true )
        {
            JSON_To_Redis( json_string, event_type );
            return(true);
        }

    else if ( !strcmp( event_type, "dhcp") && MeerOutput->redis_dhcp == true )
        {
            JSON_To_Redis( json_string, event_type );
            return(true);
        }

    else if ( !strcmp( event_type, "stats") && MeerOutput->redis_stats == true )
        {
            JSON_To_Redis( json_string, event_type );
            return(true);
        }

    else if ( !strcmp( event_type, "rdp") && MeerOutput->redis_rdp == true )
        {
            JSON_To_Redis( json_string, event_type );
            return(true);
        }

    else if ( !strcmp( event_type, "sip") && MeerOutput->redis_sip == true )
        {
            JSON_To_Redis( json_string, event_type );
            return(true);
        }

    else if ( !strcmp( event_type, "ftp") && MeerOutput->redis_ftp == true )
        {
            JSON_To_Redis( json_string, event_type );
            return(true);
        }

    else if ( !strcmp( event_type, "ikev2") && MeerOutput->redis_ikev2 == true )
        {
            JSON_To_Redis( json_string, event_type );
            return(true);
        }

    else if ( !strcmp( event_type, "nfs") && MeerOutput->redis_nfs == true )
        {
            JSON_To_Redis( json_string, event_type );
            return(true);
        }

    else if ( !strcmp( event_type, "tftp") && MeerOutput->redis_tftp == true )
        {
            JSON_To_Redis( json_string, event_type );
            return(true);
        }

    else if ( !strcmp( event_type, "smb") && MeerOutput->redis_smb == true )
        {
            JSON_To_Redis( json_string, event_type );
            return(true);
        }

    else if ( !strcmp( event_type, "mqtt") && MeerOutput->redis_mqtt == true )
        {
            JSON_To_Redis( json_string, event_type );
            return(true);
        }

    else if ( !strcmp( event_type, "dcerpc") && MeerOutput->redis_dcerpc == true )
        {
            JSON_To_Redis( json_string, event_type );
            return(true);
        }

    else if ( !strcmp( event_type, "netflow") && MeerOutput->redis_netflow == true )
        {
            JSON_To_Redis( json_string, event_type );
            return(true);
        }

    else if ( !strcmp( event_type, "metadata") && MeerOutput->redis_metadata == true )
        {
            JSON_To_Redis( json_string, event_type );
            return(true);
        }

    else if ( !strcmp( event_type, "dnp3") && MeerOutput->redis_dnp3 == true )
        {
            JSON_To_Redis( json_string, event_type );
            return(true);
        }

    else if ( !strcmp( event_type, "anomaly") && MeerOutput->redis_anomaly == true )
        {
            JSON_To_Redis( json_string, event_type );
            return(true);
        }

    else if ( !strcmp( event_type, "fingerprint") && MeerOutput->redis_fingerprint == true )
        {
            JSON_To_Redis( json_string, event_type );
            return(true);
        }

    else if ( !strcmp( event_type, "client_stats") && MeerOutput->redis_client_stats == true )
        {
            JSON_To_Redis( json_string, event_type );
            return(true);
        }

    return(false);

}

#endif
