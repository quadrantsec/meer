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

#ifdef HAVE_LIBMYSQLCLIENT
#include <mysql/mysql.h>
#endif

#ifdef HAVE_LIBPQ
#include <postgresql/libpq-fe.h>
#endif

#ifdef HAVE_LIBHIREDIS
#include <hiredis/hiredis.h>
#endif


#include <stdbool.h>
#include <inttypes.h>

#ifndef HAVE_STRLCAT
size_t strlcat(char *, const char *, size_t );
#endif

#ifndef HAVE_STRLCPY
size_t strlcpy(char *, const char *, size_t );
#endif

void Meer_Log (int type, const char *format,... );

/* Global Meer Configs */

typedef struct _MeerConfig _MeerConfig;
struct _MeerConfig
{

    char yaml_file[256];

    char interface[64];
    char hostname[64];
    char runas[32];

    bool daemonize;
    bool quiet;

    char classification_file[256];

    char lock_file[256];
    char waldo_file[256];
    char follow_file[256];

    char meer_log[256];
    FILE *meer_log_fd;
    bool meer_log_on;

    int waldo_fd;

    bool endian;

#ifdef HAVE_LIBMAXMINDDB

    bool geoip;
    char geoip_database[256];

#endif


    bool dns;
    uint32_t dns_cache;

    bool oui;
    char oui_filename[256];

    bool health;
    bool fingerprint;
    char fingerprint_log[256];
    FILE *fingerprint_log_fd;

    bool client_stats;
    uint8_t client_stats_type;

    /* What ever to record */

//    bool flow;
//    bool http;
//    bool tls;
//    bool ssh;
//    bool smtp;
//    bool email;
//    bool dns_meta;	/* NOT DONE */
//    bool metadata;
//    bool json;
    bool bluedot;

};

typedef struct _MeerHealth _MeerHealth;
struct _MeerHealth
{
    uint64_t health_signature;
};

typedef struct _MeerOutput _MeerOutput;
struct _MeerOutput
{

    bool sql_transaction;

#ifdef HAVE_LIBMYSQLCLIENT

    MYSQL *mysql_dbh;

#endif

#ifdef HAVE_LIBPQ

    PGconn   *psql;
    PGresult *result;

#endif

#ifdef HAVE_LIBHIREDIS
    bool redis_flag;
    char redis_server[255];
    int  redis_port;
    int  redis_batch;
    char redis_password[255];
    bool redis_debug;
    bool redis_error;
    char redis_key[128];
    char redis_command[16];
    bool redis_append_id;

    redisContext *c_redis;

    bool redis_alert;
    bool redis_files;
    bool redis_flow;
    bool redis_dns;
    bool redis_http;
    bool redis_tls;
    bool redis_ssh;
    bool redis_smtp;
    bool redis_email;
    bool redis_fileinfo;
    bool redis_dhcp;
    bool redis_stats;
    bool redis_rdp;
    bool redis_sip;
    bool redis_ftp;
    bool redis_ikev2;
    bool redis_nfs;
    bool redis_tftp;
    bool redis_smb;
    bool redis_mqtt;
    bool redis_dcerpc;
    bool redis_netflow;
    bool redis_metadata;
    bool redis_dnp3;
    bool redis_anomaly;
    bool redis_bluedot;
    bool redis_client_stats;

#endif

#ifdef WITH_BLUEDOT

    bool bluedot_flag;
    bool bluedot_debug;
    char bluedot_host[128];
    char bluedot_ip[64];
    char bluedot_uri[512];
    char bluedot_source[128];

#endif

#ifdef WITH_ELASTICSEARCH

    bool elasticsearch_flag;
    bool elasticsearch_debug;
    bool elasticsearch_insecure;
    char elasticsearch_url[8192];
    char elasticsearch_index[512];
    char elasticsearch_username[64];
    char elasticsearch_password[128];
    uint16_t elasticsearch_batch;
    uint8_t elasticsearch_threads;

    bool elasticsearch_alert;
    bool elasticsearch_files;
    bool elasticsearch_flow;
    bool elasticsearch_dns;
    bool elasticsearch_http;
    bool elasticsearch_tls;
    bool elasticsearch_ssh;
    bool elasticsearch_smtp;
    bool elasticsearch_email;
    bool elasticsearch_fileinfo;
    bool elasticsearch_dhcp;
    bool elasticsearch_stats;
    bool elasticsearch_rdp;
    bool elasticsearch_sip;
    bool elasticsearch_ftp;
    bool elasticsearch_ikev2;
    bool elasticsearch_nfs;
    bool elasticsearch_tftp;
    bool elasticsearch_smb;
    bool elasticsearch_mqtt;
    bool elasticsearch_dcerpc;
    bool elasticsearch_netflow;
    bool elasticsearch_metadata;
    bool elasticsearch_dnp3;
    bool elasticsearch_anomaly;
    bool elasticsearch_bluedot;
    //bool elasticsearch_fingerprint;


#endif

    bool sql_enabled;
    bool sql_debug;
    bool sql_extra_data;
    bool sql_fingerprint;
    char sql_server[128];
    uint32_t sql_port;
    char sql_username[64];
    char sql_password[64];
    char sql_database[64];
    uint32_t sql_sensor_id;
    uint64_t sql_last_cid;

    bool sql_reconnect;
    uint32_t sql_reconnect_time;

    /*
        bool sql_flow;
        bool sql_http;
        bool sql_tls;
        bool sql_ssh;
        bool sql_smtp;
        bool sql_email;
        bool sql_metadata;
        bool sql_json;
        bool sql_stats;
        bool sql_bluedot;
        */

    char sql_driver;

    bool sql_reference_system;
    char sql_reference_file[256];
    char sql_sid_map_file[256];

    bool external_enabled;
    bool external_debug;
    bool external_metadata_security_ips;
    bool external_metadata_max_detect_ips;
    bool external_metadata_balanced_ips;
    bool external_metadata_connectivity_ips;
    bool external_execute_on_all;
    char external_program[256];

    bool file_enabled;
    FILE *file_fd;
    char file_location[256];

    bool file_alert;
    bool file_email;
    bool file_files;
    bool file_flow;
    bool file_stats;
    bool file_http;
    bool file_smtp;
    bool file_ssh;
    bool file_tls;
    bool file_dns;
    bool file_fileinfo;
    bool file_dhcp;
    bool file_bluedot;
    bool file_rdp;
    bool file_sip;
    bool file_ftp;
    bool file_ikev2;
    bool file_nfs;
    bool file_tftp;
    bool file_smb;
    bool file_dcerpc;
    bool file_mqtt;
    bool file_netflow;
    bool file_metadata;
    bool file_dnp3;
    bool file_anomaly;


    bool pipe_enabled;
    char pipe_location[256];
    int  pipe_fd;
    uint32_t pipe_size;


    bool pipe_alert;
    bool pipe_files;
    bool pipe_flow;
    bool pipe_dns;
    bool pipe_http;
    bool pipe_tls;
    bool pipe_ssh;
    bool pipe_smtp;
    bool pipe_email;
    bool pipe_fileinfo;
    bool pipe_dhcp;
    bool pipe_stats;
    bool pipe_rdp;
    bool pipe_sip;
    bool pipe_ftp;
    bool pipe_ikev2;
    bool pipe_nfs;
    bool pipe_tftp;
    bool pipe_smb;
    bool pipe_dcerpc;
    bool pipe_mqtt;
    bool pipe_netflow;
    bool pipe_metadata;
    bool pipe_dnp3;
    bool pipe_anomaly;
    bool pipe_bluedot;

    /*
        bool pipe_alert;
        bool pipe_files;
        bool pipe_flow;
        bool pipe_http;
        bool pipe_smtp;
        bool pipe_ssh;
        bool pipe_tls;
        bool pipe_dns;
        bool pipe_fileinfo;
        bool pipe_dhcp;
        bool pipe_bluedot;
    */


};

typedef struct _MeerWaldo _MeerWaldo;
struct _MeerWaldo
{
    uint64_t position;
};

/* Counters */

typedef struct _MeerCounters _MeerCounters;
struct _MeerCounters
{

    int ClassCount;
    int ReferenceCount;			/* Legacy refererence system */
    int SIDMapCount;
    int OUICount;

    int fingerprint_network_count;

    uint32_t bluedot_skip_count;

#if defined(HAVE_LIBMYSQLCLIENT) || defined(HAVE_LIBPQ)

    uint64_t HealthCount;		/* Array count */

    uint64_t HealthCountT;
    uint64_t INSERTCount;
    uint64_t SELECTCount;
    uint64_t UPDATECount;

    uint64_t ClassCacheHitCount;
    uint64_t ClassCacheMissCount;

    uint64_t SigCacheHitCount;
    uint64_t SigCacheMissCount;

#endif

    uint64_t JSONPipeWrites;
    uint64_t JSONPipeMisses;

    uint64_t ExternalHitCount;
    uint64_t ExternalMissCount;

    uint_fast64_t total;

    uint_fast64_t alert;
    uint_fast64_t files;
    uint_fast64_t flow;
    uint_fast64_t dns;
    uint_fast64_t http;
    uint_fast64_t tls;
    uint_fast64_t ssh;
    uint_fast64_t smtp;
    uint_fast64_t email;
    uint_fast64_t fileinfo;
    uint_fast64_t dhcp;
    uint_fast64_t stats;
    uint_fast64_t rdp;
    uint_fast64_t sip;
    uint_fast64_t ftp;
    uint_fast64_t ikev2;
    uint_fast64_t nfs;
    uint_fast64_t tftp;
    uint_fast64_t smb;
    uint_fast64_t dcerpc;
    uint_fast64_t mqtt;
    uint_fast64_t netflow;
    uint_fast64_t metadata;
    uint_fast64_t dnp3;
    uint_fast64_t anomaly;
    uint_fast64_t unknown;
    uint_fast64_t bad;

    uint64_t DNSCount;
    uint64_t DNSCacheCount;
    uint64_t BluedotCount;

};


bool Decode_JSON( char * );
