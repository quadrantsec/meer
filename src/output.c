/*
** Copyright (C) 2018-2023 Quadrant Information Security <quadrantsec.com>
** Copyright (C) 2018-2023 Champ Clark III <cclark@quadrantsec.com>
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

#include <json-c/json.h>

#include "meer.h"
#include "meer-def.h"
#include "util.h"
#include "util-dns.h"
#include "output.h"
#include "config-yaml.h"

#include "output-plugins/pipe.h"
#include "output-plugins/external.h"
#include "output-plugins/pipe.h"
#include "output-plugins/file.h"

#ifdef WITH_SYSLOG
#include <syslog.h>
#include <output-plugins/syslog.h>
#endif

#ifdef WITH_ELASTICSEARCH
#include <output-plugins/elasticsearch.h>
#endif

#ifdef HAVE_LIBHIREDIS
#include <hiredis/hiredis.h>
#include "output-plugins/redis.h"
#endif

#ifdef WITH_BLUEDOT
#include "output-plugins/bluedot.h"
#endif

#ifdef WITH_ELASTICSEARCH

#include <pthread.h>
pthread_cond_t MeerElasticWork=PTHREAD_COND_INITIALIZER;
pthread_mutex_t MeerElasticMutex=PTHREAD_MUTEX_INITIALIZER;

uint_fast16_t elastic_proc_msgslot = 0;
uint_fast16_t elastic_proc_running = 0;

extern char *big_batch;
extern char *big_batch_THREAD;

extern uint16_t elasticsearch_batch_count;

#endif

extern struct _MeerOutput *MeerOutput;
extern struct _MeerInput *MeerInput;
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

#ifdef WITH_SYSLOG

    if ( MeerOutput->file_enabled )
        {

            Meer_Log(NORMAL, "--[ Syslog information ]------------------------------------------");
            Meer_Log(NORMAL, "");
            Meer_Log(NORMAL, "Write 'alert'      : %s", MeerOutput->syslog_alert ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Write 'stats'      : %s", MeerOutput->syslog_stats ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Write 'email'      : %s", MeerOutput->syslog_email ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Write 'dns'        : %s", MeerOutput->syslog_dns ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Write 'flow'       : %s", MeerOutput->syslog_flow ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Write 'http'       : %s", MeerOutput->syslog_http ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Write 'tls'        : %s", MeerOutput->syslog_tls ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Write 'ssh'        : %s", MeerOutput->syslog_ssh ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Write 'smtp'       : %s", MeerOutput->syslog_smtp ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Write 'files'      : %s", MeerOutput->syslog_files ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Write 'fileinfo'   : %s", MeerOutput->syslog_fileinfo ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Write 'dhcp'       : %s", MeerOutput->syslog_dhcp ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Write 'rdp'        : %s", MeerOutput->syslog_rdp ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Write 'sip'        : %s", MeerOutput->syslog_sip ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Write 'ftp'        : %s", MeerOutput->syslog_ftp ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Write 'ikev2'      : %s", MeerOutput->syslog_ikev2 ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Write 'nfs'        : %s", MeerOutput->syslog_nfs ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Write 'tftp'       : %s", MeerOutput->syslog_tftp ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Write 'smb'        : %s", MeerOutput->syslog_smb ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Write 'dcerpc'     : %s", MeerOutput->syslog_dcerpc ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Write 'mqtt'       : %s", MeerOutput->syslog_mqtt ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Write 'netflow'    : %s", MeerOutput->syslog_netflow ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Write 'metadata'   : %s", MeerOutput->syslog_metadata ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Write 'dnp3'       : %s", MeerOutput->syslog_dnp3 ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Write 'anomaly'    : %s", MeerOutput->syslog_anomaly ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Write 'fingerprint': %s", MeerOutput->syslog_fingerprint ? "enabled" : "disabled" );

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

            Meer_Log(NORMAL, "--[ Bluedot information ]----------------------------------------");
            Meer_Log(NORMAL, "");
            Meer_Log(NORMAL, "Bluedot Output          : %s", MeerOutput->bluedot_flag ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "Bluedot Server URL      : %s", MeerOutput->bluedot_url);
            Meer_Log(NORMAL, "");

            Bluedot_Init();

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
            Meer_Log(NORMAL, "Record 'ndp'         : %s", MeerOutput->elasticsearch_ndp ? "enabled" : "disabled" );


            Elasticsearch_Init();

            Meer_Log(NORMAL, "");

        }

#endif

    Meer_Log(NORMAL, "--[ Meer engine information ]-------------------------------------");
    Meer_Log(NORMAL, "");

    if ( MeerInput->type == YAML_INPUT_FILE )
        {
            Meer_Log(NORMAL, "Input type: \"file\"");
        }

//    else if ( MeerInput->type == YAML_INPUT_PIPE )
//        {
//           Meer_Log(NORMAL, "Input type: \"pipe\"");
//       }

#ifdef HAVE_LIBHIREDIS

    else if ( MeerInput->type == YAML_INPUT_REDIS )
        {
            Meer_Log(NORMAL, "Input type: \"redis\"");
            Meer_Log(NORMAL, "------------------------------------------------------");
            Meer_Log(NORMAL, " * Server: %s:%d", MeerInput->redis_server, MeerInput->redis_port);

            if ( MeerInput->redis_password[0] != '\0' )
                {
                    Meer_Log(NORMAL, " * Password: yes");
                }
        }

#endif


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

    else if ( ( !strcmp(event_type, "ftp" ) || !strcmp(event_type, "ftp_data" ) ) && MeerOutput->pipe_ftp == true )
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


    else if ( ( !strcmp(event_type, "ftp" ) || !strcmp(event_type, "ftp_data" ) )  && MeerOutput->external_ftp == true )
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

#ifdef WITH_BLUEDOT

void Output_Bluedot ( struct json_object *json_obj )
{

    const char *alert = NULL;
    const char *metadata = NULL;

    struct json_object *tmp = NULL;
    struct json_object *json_obj_metadata = NULL;

    /* The event_type has to be "alert", so no need to check */

    json_object_object_get_ex(json_obj, "alert", &tmp);
    alert = json_object_get_string(tmp);

    json_obj_metadata = json_tokener_parse( alert );

    if ( json_object_object_get_ex(json_obj_metadata, "metadata", &tmp) )
        {
            Bluedot( (const char*)json_object_get_string(tmp), json_obj );
        }
    else
        {
            json_object_put(json_obj_metadata);
            return; 	/* There is no "metadata", nothing left to do */
        }

    json_object_put(json_obj_metadata);
}

#endif

#ifdef WITH_ELASTICSEARCH

bool Output_Elasticsearch ( const char *json_string, const char *event_type, const char *id )
{

    if ( !strcmp(event_type, "alert" ) && MeerOutput->elasticsearch_alert == true )
        {
            Output_Do_Elasticsearch( json_string, event_type, NULL );
            return(true);
        }

    else if ( !strcmp(event_type, "files" ) && MeerOutput->elasticsearch_files == true )
        {
            Output_Do_Elasticsearch( json_string, event_type, NULL );
            return(true);
        }

    else if ( !strcmp(event_type, "flow" ) && MeerOutput->elasticsearch_flow == true )
        {
            Output_Do_Elasticsearch( json_string, event_type, NULL );
            return(true);
        }

    else if ( !strcmp(event_type, "dns" ) && MeerOutput->elasticsearch_dns == true )
        {
            Output_Do_Elasticsearch( json_string, event_type, NULL );
            return(true);
        }

    else if ( !strcmp(event_type, "http" ) && MeerOutput->elasticsearch_http == true )
        {
            Output_Do_Elasticsearch( json_string, event_type, NULL );
            return(true);
        }

    else if ( !strcmp(event_type, "tls" ) && MeerOutput->elasticsearch_tls == true )
        {
            Output_Do_Elasticsearch( json_string, event_type, NULL );
            return(true);
        }

    else if ( !strcmp(event_type, "ssh" ) && MeerOutput->elasticsearch_ssh == true )
        {
            Output_Do_Elasticsearch( json_string, event_type, NULL );
            return(true);
        }

    else if ( !strcmp(event_type, "smtp" ) && MeerOutput->elasticsearch_smtp == true )
        {
            Output_Do_Elasticsearch( json_string, event_type, NULL );
            return(true);
        }

    else if ( !strcmp(event_type, "email" ) && MeerOutput->elasticsearch_email == true )
        {
            Output_Do_Elasticsearch( json_string, event_type, NULL );
            return(true);
        }

    else if ( !strcmp(event_type, "fileinfo" ) && MeerOutput->elasticsearch_fileinfo == true )
        {
            Output_Do_Elasticsearch( json_string, event_type, NULL );
            return(true);
        }

    else if ( !strcmp(event_type, "dhcp" ) && MeerOutput->elasticsearch_dhcp == true )
        {
            Output_Do_Elasticsearch( json_string, event_type, NULL );
            return(true);
        }

    else if ( !strcmp(event_type, "stats" ) && MeerOutput->elasticsearch_stats == true )
        {
            Output_Do_Elasticsearch( json_string, event_type, NULL );
            return(true);
        }

    else if ( !strcmp(event_type, "rdp" ) && MeerOutput->elasticsearch_rdp == true )
        {
            Output_Do_Elasticsearch( json_string, event_type, NULL );
            return(true);
        }

    else if ( !strcmp(event_type, "sip" ) && MeerOutput->elasticsearch_sip == true )
        {
            Output_Do_Elasticsearch( json_string, event_type, NULL );
            return(true);
        }

    else if ( ( !strcmp(event_type, "ftp" ) || !strcmp(event_type, "ftp_data" ) ) && MeerOutput->elasticsearch_ftp == true )
        {
            Output_Do_Elasticsearch( json_string, event_type, NULL );
            return(true);
        }

    else if ( !strcmp(event_type, "ikev2" ) && MeerOutput->elasticsearch_ikev2 == true )
        {
            Output_Do_Elasticsearch( json_string, event_type, NULL );
            return(true);
        }

    else if ( !strcmp(event_type, "nfs" ) && MeerOutput->elasticsearch_nfs == true )
        {
            Output_Do_Elasticsearch( json_string, event_type, NULL );
            return(true);
        }

    else if ( !strcmp(event_type, "tftp" ) && MeerOutput->elasticsearch_tftp == true )
        {
            Output_Do_Elasticsearch( json_string, event_type, NULL );
            return(true);
        }

    else if ( !strcmp(event_type, "smb" ) && MeerOutput->elasticsearch_smb == true )
        {
            Output_Do_Elasticsearch( json_string, event_type, NULL );
            return(true);
        }

    else if ( !strcmp(event_type, "mqtt" ) && MeerOutput->elasticsearch_mqtt == true )
        {
            Output_Do_Elasticsearch( json_string, event_type, NULL );
            return(true);
        }

    else if ( !strcmp(event_type, "dcerpc" ) && MeerOutput->elasticsearch_dcerpc == true )
        {
            Output_Do_Elasticsearch( json_string, event_type, NULL );
            return(true);
        }

    else if ( !strcmp(event_type, "netflow" ) && MeerOutput->elasticsearch_netflow == true )
        {
            Output_Do_Elasticsearch( json_string, event_type, NULL );
            return(true);
        }

    else if ( !strcmp(event_type, "metadata" ) && MeerOutput->elasticsearch_metadata == true )
        {
            Output_Do_Elasticsearch( json_string, event_type, NULL );
            return(true);
        }

    else if ( !strcmp(event_type, "dnp3" ) && MeerOutput->elasticsearch_dnp3 == true )
        {
            Output_Do_Elasticsearch( json_string, event_type, NULL );
            return(true);
        }


    else if ( !strcmp(event_type, "anomaly" ) && MeerOutput->elasticsearch_anomaly == true )
        {
            Output_Do_Elasticsearch( json_string, event_type, NULL );
            return(true);
        }

    else if ( !strcmp(event_type, "fingerprint" ) && MeerOutput->elasticsearch_fingerprint == true )
        {
            Output_Do_Elasticsearch( json_string, event_type, NULL );
            return(true);
        }

    else if ( !strcmp(event_type, "ndp" ) && MeerOutput->elasticsearch_ndp == true )
        {
            Output_Do_Elasticsearch( json_string, event_type, id );
            return(true);
        }

    return(false);

}


bool Output_Do_Elasticsearch ( const char *json_string, const char *event_type, const char *id )
{

    char *tmp = malloc(MeerConfig->payload_buffer_size);

    if ( tmp == NULL )
        {
            fprintf(stderr, "[%s, line %d] Fatal Error: Can't allocate memory! Abort!\n", __FILE__, __LINE__);
            exit(-1);
        }

    memset(tmp, 0, MeerConfig->payload_buffer_size);

    char index_name[512] = { 0 };

    Elasticsearch_Get_Index(index_name, sizeof(index_name), event_type);

    if ( id == NULL )
        {
            snprintf(tmp, MeerConfig->payload_buffer_size, "{\"index\":{\"_index\":\"%s\"}}\n%s\n", index_name, json_string);
        }
    else
        {
            snprintf(tmp, MeerConfig->payload_buffer_size, "{\"index\":{\"_index\":\"%s\",\"_id\":\"%s\"}}\n%s\n", index_name, id, json_string);
        }

    tmp[ MeerConfig->payload_buffer_size - 1 ] = '\0';

    strlcat(big_batch, tmp, MeerConfig->payload_buffer_size); //  * MeerOutput->elasticsearch_batch ) );
    elasticsearch_batch_count++;

    /* Once we hit the batch size,  submit it. */

    if ( elasticsearch_batch_count == MeerOutput->elasticsearch_batch )
        {

            while ( elastic_proc_running >= MeerOutput->elasticsearch_threads )
                {
                    Meer_Log(WARN, "Waiting on a free thread! Consider increasing threads?");
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

#ifdef WITH_SYSLOG

bool Output_Syslog ( const char *json_string, const char *event_type )
{

    if ( !strcmp(event_type, "alert" ) && MeerOutput->file_alert == true )
        {
            Output_Do_Syslog( json_string, event_type );
            return(true);
        }

    else if ( !strcmp(event_type, "files" ) && MeerOutput->file_files == true )
        {
            Output_Do_Syslog( json_string, event_type );
            return(true);
        }

    else if ( !strcmp(event_type, "flow" ) && MeerOutput->file_flow == true )
        {
            Output_Do_Syslog( json_string, event_type );
            return(true);
        }

    else if ( !strcmp(event_type, "dns" ) && MeerOutput->file_dns == true )
        {
            Output_Do_Syslog( json_string, event_type );
            return(true);
        }

    else if ( !strcmp(event_type, "http" ) && MeerOutput->file_http == true )
        {
            Output_Do_Syslog( json_string, event_type );
            return(true);
        }

    else if ( !strcmp(event_type, "tls" ) && MeerOutput->file_tls == true )
        {
            Output_Do_Syslog( json_string, event_type );
            return(true);
        }

    else if ( !strcmp(event_type, "ssh" ) && MeerOutput->file_ssh == true )
        {
            Output_Do_Syslog( json_string, event_type );
            return(true);
        }

    else if ( !strcmp(event_type, "smtp" ) && MeerOutput->file_smtp == true )
        {
            Output_Do_Syslog( json_string, event_type );
            return(true);
        }

    else if ( !strcmp(event_type, "email" ) && MeerOutput->file_email == true )
        {
            Output_Do_Syslog( json_string, event_type );
            return(true);
        }

    else if ( !strcmp(event_type, "fileinfo" ) && MeerOutput->file_fileinfo == true )
        {
            Output_Do_Syslog( json_string, event_type );
            return(true);
        }

    else if ( !strcmp(event_type, "dhcp" ) && MeerOutput->file_dhcp == true )
        {
            Output_Do_Syslog( json_string, event_type );
            return(true);
        }

    else if ( !strcmp(event_type, "stats" ) && MeerOutput->file_stats == true )
        {
            Output_Do_Syslog( json_string, event_type );
            return(true);
        }

    else if ( !strcmp(event_type, "rdp" ) && MeerOutput->file_rdp == true )
        {
            Output_Do_Syslog( json_string, event_type );
            return(true);
        }

    else if ( !strcmp(event_type, "sip" ) && MeerOutput->file_sip == true )
        {
            Output_Do_Syslog( json_string, event_type );
            return(true);
        }

    else if ( ( !strcmp(event_type, "ftp" ) || !strcmp(event_type, "ftp_data" ) ) && MeerOutput->file_ftp == true )
        {
            Output_Do_Syslog( json_string, event_type );
            return(true);
        }

    else if ( !strcmp(event_type, "ikev2" ) && MeerOutput->file_ikev2 == true )
        {
            Output_Do_Syslog( json_string, event_type );
            return(true);
        }

    else if ( !strcmp(event_type, "nfs" ) && MeerOutput->file_nfs == true )
        {
            Output_Do_Syslog( json_string, event_type );
            return(true);
        }

    else if ( !strcmp(event_type, "tftp" ) && MeerOutput->file_tftp == true )
        {
            Output_Do_Syslog( json_string, event_type );
            return(true);
        }

    else if ( !strcmp(event_type, "smb" ) && MeerOutput->file_smb == true )
        {
            Output_Do_Syslog( json_string, event_type );
            return(true);
        }

    else if ( !strcmp(event_type, "dcerpc" ) && MeerOutput->file_dcerpc == true )
        {
            Output_Do_Syslog( json_string, event_type );
            return(true);
        }

    else if ( !strcmp(event_type, "mqtt" ) && MeerOutput->file_mqtt == true )
        {
            Output_Do_Syslog( json_string, event_type );
            return(true);
        }

    else if ( !strcmp(event_type, "netflow" ) && MeerOutput->file_netflow == true )
        {
            Output_Do_Syslog( json_string, event_type );
            return(true);
        }

    else if ( !strcmp(event_type, "metadata" ) && MeerOutput->file_metadata == true )
        {
            Output_Do_Syslog( json_string, event_type );
            return(true);
        }

    else if ( !strcmp(event_type, "dnp3" ) && MeerOutput->file_dnp3 == true )
        {
            Output_Do_Syslog( json_string, event_type );
            return(true);
        }

    else if ( !strcmp(event_type, "anomaly" ) && MeerOutput->file_anomaly == true )
        {
            Output_Do_Syslog( json_string, event_type );
            return(true);
        }

    else if ( !strcmp(event_type, "fingerprint" ) && MeerOutput->file_fingerprint == true )
        {
            Output_Do_Syslog( json_string, event_type );
            return(true);
        }

    return(false);

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

    else if ( ( !strcmp(event_type, "ftp" ) || !strcmp(event_type, "ftp_data" ) ) && MeerOutput->file_ftp == true )
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

    else if ( ( !strcmp( event_type, "ftp") || !strcmp(event_type, "ftp_data" ) ) && MeerOutput->redis_ftp == true )
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
