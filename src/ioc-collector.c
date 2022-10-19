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

/* System for collecting potential IOCs and putting them in Zinc,  OpenSearch
   or Elasticsearch */

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#ifdef WITH_ELASTICSEARCH

#include <string.h>
#include <json-c/json.h>

#include "meer.h"
#include "meer-def.h"
#include "util.h"
#include "output.h"
#include "util-md5.h"

#include "ioc-collector.h"

extern struct _MeerConfig *MeerConfig;
extern struct _MeerOutput *MeerOutput;
extern struct _MeerCounters *MeerCounters;
extern struct _IOC_Ignore *IOC_Ignore;

/* Simple global cache system to skip repeat data */

char last_flow_id[MD5_SIZE] = { 0 };
char last_http_id[MD5_SIZE] = { 0 };
char last_user_agent_id[MD5_SIZE] = { 0 };
char last_ssh_id[MD5_SIZE] = { 0 };
char last_fileinfo_id[MD5_SIZE] = { 0 };
char last_tls_id[MD5_SIZE] = { 0 };
char last_dns_id[MD5_SIZE] = { 0 };
char last_smb_id[MD5_SIZE] = { 0 };
char last_ftp_id[MD5_SIZE] = { 0 };

/*******************************************************************/
/* IOC_Collector - Determines "what" we want to collect data from  */
/*******************************************************************/

void IOC_Collector( struct json_object *json_obj, const char *json_string, const char *event_type, const char *src_ip, const char *dest_ip, const char *flow_id )
{

    if ( !strcmp( event_type, "flow" ) && MeerConfig->ioc_routing_flow == true )
        {
            IOC_Flow( json_obj, src_ip, dest_ip, flow_id );
            return;
        }

    else if ( !strcmp( event_type, "http" ) && MeerConfig->ioc_routing_http == true )
        {
            IOC_HTTP( json_obj, src_ip, dest_ip, flow_id );
            return;
        }

    else if ( !strcmp( event_type, "ssh" ) && MeerConfig->ioc_routing_ssh == true )
        {
            IOC_SSH( json_obj, src_ip, dest_ip, flow_id );
            return;
        }

    else if ( !strcmp( event_type, "fileinfo" ) && MeerConfig->ioc_routing_fileinfo == true )
        {
            IOC_FileInfo( json_obj, src_ip, dest_ip, flow_id );
            return;
        }

    if ( !strcmp( event_type, "tls" ) && MeerConfig->ioc_routing_tls == true )
        {
            IOC_TLS( json_obj, src_ip, dest_ip, flow_id );
            return;
        }

    else if ( !strcmp( event_type, "dns" ) && MeerConfig->ioc_routing_dns == true )
        {
            IOC_DNS( json_obj, src_ip, dest_ip, flow_id );
            return;
        }

    else if ( !strcmp( event_type, "smb" ) && MeerConfig->ioc_routing_smb == true )
        {
            IOC_SMB( json_obj, src_ip, dest_ip, flow_id );
            return;
        }

    else if ( !strcmp( event_type, "ftp" ) && MeerConfig->ioc_routing_ftp == true )
        {
            IOC_FTP( json_obj, src_ip, dest_ip, flow_id );
            return;
        }

}

/********************************************************************/
/* IOC_Flow - Remove local IPs and collect IP addresses of interest */
/********************************************************************/

void IOC_Flow( struct json_object *json_obj, const char *src_ip, const char *dest_ip, const char *flow_id )
{

    char *tmp_type = NULL;
    char tmp_ip[64] = { 0 };
    char id_md5[MD5_SIZE] = { 0 };

    uint8_t i = 0;

    uint64_t bytes_toserver = 0;
    uint64_t bytes_toclient = 0;
    uint64_t age = 0;

    struct json_object *tmp = NULL;
    bool state_flag = false;

//    struct json_object *encode_json = NULL;
//    encode_json = json_object_new_object();

//    struct json_object *json_obj_flow = NULL;
//    struct json_object *json_obj_state = NULL;

    char timestamp[64] = { 0 };
    char proto[16] = { 0 };
    char app_proto[32] = { 0 };
    char state[16] = { 0 };
    char reason[16] = { 0 };
    bool alerted = false;
    char start[64] = { 0 };
    char end[64] = { 0 };
    char host[64] = { 0 };
    char src_dns[256] = { 0 }; 
    char dest_dns[256] = { 0 }; 

    MD5( (uint8_t*)src_ip, strlen(src_ip), id_md5, sizeof(id_md5) );

    if ( !strcmp( last_flow_id, id_md5 ) )
        {

            if ( MeerConfig->ioc_debug == true )
                {
                    Meer_Log(DEBUG, "[%s, line %d] SKIP FLOW %s", __FILE__, __LINE__, id_md5);
                }

            MeerCounters->ioc_skip++;

//            json_object_put(encode_json);
//            json_object_put(json_obj_flow);
//            json_object_put(json_obj_state);
            return;
        }

    MD5( (uint8_t*)dest_ip, strlen(dest_ip), id_md5, sizeof(id_md5) );

    if ( !strcmp( last_flow_id, id_md5 ) )
        {

            if ( MeerConfig->ioc_debug == true )
                {
                    Meer_Log(DEBUG, "[%s, line %d] SKIP FLOW %s", __FILE__, __LINE__, id_md5 );
                }

            MeerCounters->ioc_skip++;

//            json_object_put(encode_json);
//            json_object_put(json_obj_flow);
//            json_object_put(json_obj_state);
            return;
        }

    struct json_object *json_obj_flow = NULL;
    struct json_object *json_obj_state = NULL;

    if ( json_object_object_get_ex(json_obj, "flow", &tmp) )
        {

            json_obj_flow = json_tokener_parse(json_object_get_string(tmp));

            if ( json_obj_flow != NULL )
                {

                    json_obj_state = json_tokener_parse(json_object_get_string(json_obj_flow));

                    if ( json_obj_state != NULL )
                        {

                            if ( json_object_object_get_ex(json_obj_state, "state", &tmp) )
                                {

                                    // const char *state = json_object_get_string(tmp);

                                    /* This was so you can go off the flow type.  Not sure if it
                                       is useful */

                                    /* if ( !strcmp(state, "established" ) )
                                    	{  */

                                    state_flag = true;

                                    /* } */

                                }
                        }
                }
        }

    json_object_put(json_obj_flow);
    json_object_put(json_obj_state);

    /* State looks like something we're interested in */

    if ( state_flag == true )
        {

            for ( i = 0; i < 2; i++ )
                {

                    if ( i == 0 )
                        {
                            tmp_type = "src_ip";
                            strlcpy( tmp_ip, src_ip, sizeof(tmp_ip) );
                        }
                    else
                        {
                            tmp_type = "dest_ip";
                            strlcpy( tmp_ip, dest_ip, sizeof(tmp_ip) );
                        }

                    if ( IOC_In_Range( tmp_ip ) == false && ( Is_IP( tmp_ip, IPv4 ) ) )
                        {

			    if ( json_object_object_get_ex(json_obj, "src_dns", &tmp) )
			        {
			            strlcpy( src_dns, json_object_get_string(tmp), sizeof(src_dns) );
			        }

			    if ( json_object_object_get_ex(json_obj, "dest_dns", &tmp) )
			        {
			            strlcpy( dest_dns, json_object_get_string(tmp), sizeof(dest_dns) );
			        }

                            if ( json_object_object_get_ex(json_obj, "timestamp", &tmp) )
                                {
                                    strlcpy( timestamp, json_object_get_string(tmp), sizeof(timestamp) );
                                }

                            if ( json_object_object_get_ex(json_obj, "proto", &tmp) )
                                {
                                    strlcpy( proto, json_object_get_string(tmp), sizeof(proto) );
                                }

                            if ( json_object_object_get_ex(json_obj, "host", &tmp) )
                                {
                                    strlcpy( host, json_object_get_string(tmp), sizeof(host) );
                                }

                            /* Set a default value */

                            strlcpy(app_proto, "unknown", sizeof(app_proto));

                            if ( json_object_object_get_ex(json_obj, "app_proto", &tmp) )
                                {
                                    strlcpy( app_proto, json_object_get_string(tmp), sizeof(app_proto) );
                                }

                            if ( json_object_object_get_ex(json_obj_state, "bytes_toserver", &tmp) )
                                {
                                    bytes_toserver = json_object_get_int64(tmp);
                                }

                            if ( json_object_object_get_ex(json_obj_state, "bytes_toclient", &tmp) )
                                {
                                    bytes_toclient = json_object_get_int64(tmp);
                                }

                            if ( json_object_object_get_ex(json_obj_state, "age", &tmp) )
                                {
                                    age = json_object_get_int64(tmp);
                                }

                            if ( json_object_object_get_ex(json_obj_state, "state", &tmp) )
                                {
                                    strlcpy( state, json_object_get_string(tmp), sizeof(state) );
                                }

                            if ( json_object_object_get_ex(json_obj_state, "reason", &tmp) )
                                {
                                    strlcpy( reason, json_object_get_string(tmp), sizeof(reason) );
                                }

                            if ( json_object_object_get_ex(json_obj_state, "alerted", &tmp) )
                                {
                                    alerted = json_object_get_boolean(tmp);
                                }

                            if ( json_object_object_get_ex(json_obj_state, "start", &tmp) )
                                {
                                    strlcpy( start, json_object_get_string(tmp), sizeof(start) );
                                }

                            if ( json_object_object_get_ex(json_obj_state, "end", &tmp) )
                                {
                                    strlcpy( end, json_object_get_string(tmp), sizeof(end) );
                                }

                            /*************************************/
                            /* New object                        */
                            /*************************************/

                            struct json_object *encode_json = NULL;
                            encode_json = json_object_new_object();

                            json_object *jtype = json_object_new_string( "flow" );
                            json_object_object_add(encode_json,"type", jtype);

                            if ( timestamp[0] != '\0' )
                                {
                                    json_object *jtimestamp = json_object_new_string( timestamp );
                                    json_object_object_add(encode_json,"timestamp", jtimestamp);
                                }

                            json_object *jsrc_ip = json_object_new_string( src_ip );
                            json_object_object_add(encode_json,"src_ip", jsrc_ip);

                            json_object *jdest_ip = json_object_new_string( dest_ip );
                            json_object_object_add(encode_json,"dest_ip", jdest_ip);

                            json_object *jflow_id = json_object_new_string( flow_id );
                            json_object_object_add(encode_json,"flow_id", jflow_id);

                            json_object *jdirection = json_object_new_string( tmp_type );
                            json_object_object_add(encode_json,"direction", jdirection);

                            json_object *jip = json_object_new_string( tmp_ip );
                            json_object_object_add(encode_json,"ip_address", jip);

			    if ( src_dns[0] != '\0' )
				{
				json_object *jsrc_dns = json_object_new_string( src_dns );
				json_object_object_add(encode_json,"src_dns", jsrc_dns);
				}

			    if ( dest_dns[0] != '\0' )
				{
				json_object *jdest_dns = json_object_new_string( dest_dns );
				json_object_object_add(encode_json,"dest_dns", jdest_dns);
				}

                            if ( proto[0] != '\0' )
                                {
                                    json_object *jproto = json_object_new_string( proto );
                                    json_object_object_add(encode_json,"proto", jproto);
                                }

                            if ( app_proto[0] )
                                {
                                    json_object *japp_proto = json_object_new_string( app_proto );
                                    json_object_object_add(encode_json,"app_proto", japp_proto);
                                }

                            /* These can be zero */

                            json_object *jbytes_toserver = json_object_new_int64( bytes_toserver );
                            json_object_object_add(encode_json,"bytes_toserver", jbytes_toserver);

                            json_object *jbytes_toclient = json_object_new_int64( bytes_toclient );
                            json_object_object_add(encode_json,"bytes_toclient", jbytes_toclient);

                            json_object *jage = json_object_new_int64( age );
                            json_object_object_add(encode_json,"age", jage );

                            if ( state[0] != '\0' )
                                {
                                    json_object *japp_state = json_object_new_string( state );
                                    json_object_object_add(encode_json,"state", japp_state);
                                }

                            if ( reason[0] != '\0' )
                                {
                                    json_object *japp_reason = json_object_new_string( reason );
                                    json_object_object_add(encode_json,"reason", japp_reason);
                                }

                            json_object *japp_alerted = json_object_new_boolean( alerted );
                            json_object_object_add(encode_json,"alerted", japp_alerted);

                            if ( start[0] != '\0' )
                                {
                                    json_object *japp_start = json_object_new_string( start );
                                    json_object_object_add(encode_json,"start", japp_start);
                                }

                            if ( end[0] != '\0' )
                                {
                                    json_object *japp_end = json_object_new_string( end );
                                    json_object_object_add(encode_json,"end", japp_end);
                                }

                            if ( host[0] != '\0' )
                                {
                                    json_object *jhost = json_object_new_string( host );
                                    json_object_object_add(encode_json,"host", jhost);
                                }

                            if ( MeerConfig->description[0] != '\0' )
                                {
                                    json_object *jdesc = json_object_new_string( MeerConfig->description );
                                    json_object_object_add(encode_json,"description", jdesc);
                                }

                            /* Create new "id" based off the IP address */

                            MD5( (uint8_t*)tmp_ip, strlen(tmp_ip), id_md5, sizeof(id_md5) );

                            if ( MeerConfig->ioc_debug == true )
                                {
                                    Meer_Log(DEBUG, "[%s, line %d] INSERT FLOW %s: %s", __FILE__, __LINE__, id_md5, json_object_to_json_string(encode_json) );
                                }

                            MeerCounters->ioc++;
                            strlcpy(last_flow_id, id_md5, MD5_SIZE);
                            Output_Elasticsearch ( (char*)json_object_to_json_string(encode_json), "ioc", id_md5 );

                            json_object_put(encode_json);

                        }
                }
        }

//    json_object_put(encode_json);
//    json_object_put(json_obj_flow);
//    json_object_put(json_obj_state);

}

/**************************************/
/* IOC_FileInfo - Collect file hashes */
/**************************************/

void IOC_FileInfo( struct json_object *json_obj, const char *src_ip, const char *dest_ip, const char *flow_id )
{

    uint64_t size = 0;

    char app_proto[32] = { 0 };
    char timestamp[64] = { 0 };

    char md5[MD5_SIZE] = { 0 };
    char sha1[SHA1_SIZE] = { 0 };
    char sha256[SHA256_SIZE] = { 0 };
    char filename[8192] = { 0 };
    char magic[512] = { 0 };
    char host[64] = { 0 };

    char src_dns[256] = { 0 }; 
    char dest_dns[256] = { 0 }; 

    struct json_object *tmp = NULL;

//    struct json_object *encode_json = NULL;
//    encode_json = json_object_new_object();

    struct json_object *json_obj_fileinfo = NULL;

                            if ( json_object_object_get_ex(json_obj, "src_dns", &tmp) )
                                {
                                    strlcpy( src_dns, json_object_get_string(tmp), sizeof(src_dns) );
                                }

                            if ( json_object_object_get_ex(json_obj, "dest_dns", &tmp) )
                                {
                                    strlcpy( dest_dns, json_object_get_string(tmp), sizeof(dest_dns) );
                                }

    if ( json_object_object_get_ex(json_obj, "timestamp", &tmp) )
        {
            strlcpy( timestamp, json_object_get_string(tmp), sizeof(timestamp) );
        }

    if ( json_object_object_get_ex(json_obj, "app_proto", &tmp) )
        {
            strlcpy( app_proto, json_object_get_string(tmp), sizeof(app_proto) );
        }

    if ( json_object_object_get_ex(json_obj, "host", &tmp) )
        {
            strlcpy( host, json_object_get_string(tmp), sizeof(host) );
        }

    if ( json_object_object_get_ex(json_obj, "fileinfo", &tmp) )
        {

            json_obj_fileinfo = json_tokener_parse(json_object_get_string(tmp));

            if ( json_object_object_get_ex(json_obj_fileinfo, "md5", &tmp) )
                {
                    strlcpy(md5, json_object_get_string(tmp), sizeof(md5) );

                    if ( !strcmp(last_fileinfo_id, md5 ) )
                        {

                            if ( MeerConfig->ioc_debug == true )
                                {
                                    Meer_Log(DEBUG, "[%s, line %d] SKIP FILEINFO: %s", __FILE__, __LINE__, md5 );
                                }

                            MeerCounters->ioc_skip++;
                            //json_object_put(encode_json);
                            json_object_put(json_obj_fileinfo);
                            return;

                        }

                }

            if ( json_object_object_get_ex(json_obj_fileinfo, "sha1", &tmp) )
                {
                    strlcpy(sha1, json_object_get_string(tmp), sizeof(sha1) );
                }

            if ( json_object_object_get_ex(json_obj_fileinfo, "sha256", &tmp) )
                {
                    strlcpy(sha256, json_object_get_string(tmp), sizeof(sha256) );
                }

            if ( json_object_object_get_ex(json_obj_fileinfo, "filename", &tmp) )
                {
                    strlcpy(filename, json_object_get_string(tmp), sizeof(filename) );
                }

            if ( json_object_object_get_ex(json_obj_fileinfo, "magic", &tmp) )
                {
                    strlcpy(magic, json_object_get_string(tmp), sizeof(magic) );
                }

            if ( json_object_object_get_ex(json_obj_fileinfo, "size", &tmp) )
                {
                    size = json_object_get_int64(tmp);
                }

        }

    /*************************************/
    /* New JSON object                   */
    /*************************************/

    struct json_object *encode_json = NULL;
    encode_json = json_object_new_object();

    json_object *jtype = json_object_new_string( "fileinfo" );
    json_object_object_add(encode_json,"type", jtype);

    json_object *jsrc_ip = json_object_new_string( src_ip );
    json_object_object_add(encode_json,"src_ip", jsrc_ip);

    json_object *jdest_ip = json_object_new_string( dest_ip );
    json_object_object_add(encode_json,"dest_ip", jdest_ip);

                            if ( src_dns[0] != '\0' )
                                {
                                json_object *jsrc_dns = json_object_new_string( src_dns );
                                json_object_object_add(encode_json,"src_dns", jsrc_dns);
                                }

                            if ( dest_dns[0] != '\0' )
                                {
                                json_object *jdest_dns = json_object_new_string( dest_dns );
                                json_object_object_add(encode_json,"dest_dns", jdest_dns);
                                }

    if ( timestamp[0] != '\0' )
        {
            json_object *jtimestamp = json_object_new_string( timestamp );
            json_object_object_add(encode_json,"timestamp", jtimestamp);
        }

    if ( app_proto[0] != '\0' )
        {
            json_object *japp_proto = json_object_new_string( app_proto );
            json_object_object_add(encode_json,"app_proto", japp_proto);
        }

    if ( md5[0] != '\0' )
        {
            json_object *jmd5 = json_object_new_string( md5 );
            json_object_object_add(encode_json,"md5", jmd5);
        }

    if ( sha1[0] != '\0' )
        {
            json_object *jsha1 = json_object_new_string( sha1 );
            json_object_object_add(encode_json,"sha1", jsha1);
        }

    if ( sha256[0] != '\0' )
        {
            json_object *jsha256 = json_object_new_string( sha256 );
            json_object_object_add(encode_json,"sha256", jsha256);
        }

    if ( filename[0] != '\0' )
        {
            json_object *jfilename = json_object_new_string( filename );
            json_object_object_add(encode_json,"filename", jfilename);
        }

    if ( magic[0] != '\0' )
        {
            json_object *jmagic = json_object_new_string( magic );
            json_object_object_add(encode_json,"magic", jmagic);
        }

    /* Size can be zero */

    json_object *jsize = json_object_new_int64( size );
    json_object_object_add(encode_json,"size", jsize);

    json_object *jflow_id = json_object_new_string( flow_id );
    json_object_object_add(encode_json,"flow_id", jflow_id);

    if ( host[0] != '\0' )
        {
            json_object *jhost = json_object_new_string( host );
            json_object_object_add(encode_json,"host", jhost);
        }

    if ( MeerConfig->description[0] != '\0' )
        {
            json_object *jdesc = json_object_new_string( MeerConfig->description );
            json_object_object_add(encode_json,"description", jdesc);
        }

    if ( MeerConfig->ioc_debug == true )
        {
            Meer_Log(DEBUG, "[%s, line %d] INSERT FILEINFO: %s, %s", __FILE__, __LINE__, md5, json_object_to_json_string(encode_json) );
        }

    MeerCounters->ioc++;
    strlcpy(last_fileinfo_id, md5, MD5_SIZE);
    Output_Elasticsearch ( (char*)json_object_to_json_string(encode_json), "ioc", md5 );

    json_object_put(encode_json);
    json_object_put(json_obj_fileinfo);

}

/********************************************/
/* IOC_TLS - Collect SNI, expire dates, etc */
/********************************************/

void IOC_TLS( struct json_object *json_obj, const char *src_ip, const char *dest_ip, const char *flow_id )
{

    char timestamp[64] = { 0 };

    char id_md5[MD5_SIZE] = { 0 };

    char fingerprint[128] = { 0 };
    char subject[1024] = { 0 };
    char issuerdn[1024] = { 0 };
    char serial[512] = { 0 };
    char sni[512] = { 0 };
    char version[16] = { 0 };
    char notbefore[64]= { 0 };
    char notafter[64] = { 0 };
    char host[64] = { 0 };

    char src_dns[256] = { 0 }; 
    char dest_dns[256] = { 0 }; 

    char ja3[41] = { 0 };
    char ja3s[41] = { 0 };

    char id[68] = { 0 };

    struct json_object *tmp = NULL;
    struct json_object *json_obj_tls = NULL;
    struct json_object *json_obj_ja3 = NULL;
    struct json_object *json_obj_ja3s = NULL;

//   struct json_object *encode_json = NULL;
//   encode_json = json_object_new_object();

                            if ( json_object_object_get_ex(json_obj, "src_dns", &tmp) )
                                {
                                    strlcpy( src_dns, json_object_get_string(tmp), sizeof(src_dns) );
                                }

                            if ( json_object_object_get_ex(json_obj, "dest_dns", &tmp) )
                                {
                                    strlcpy( dest_dns, json_object_get_string(tmp), sizeof(dest_dns) );
                                }

    if ( json_object_object_get_ex(json_obj, "timestamp", &tmp) )
        {
            strlcpy( timestamp, json_object_get_string(tmp), sizeof(timestamp) );
        }

    if ( json_object_object_get_ex(json_obj, "host", &tmp) )
        {
            strlcpy( host, json_object_get_string(tmp), sizeof(host) );
        }

    if ( json_object_object_get_ex(json_obj, "tls", &tmp) )
        {

            json_obj_tls = json_tokener_parse(json_object_get_string(tmp));

            if ( json_object_object_get_ex(json_obj_tls, "fingerprint", &tmp) )
                {
                    strlcpy(fingerprint, json_object_get_string(tmp), sizeof(fingerprint) );
                }

            if ( json_object_object_get_ex(json_obj_tls, "subject", &tmp) )
                {
                    strlcpy(subject, json_object_get_string(tmp), sizeof(subject) );
                }

            if ( json_object_object_get_ex(json_obj_tls, "issuerdn", &tmp) )
                {
                    strlcpy(issuerdn, json_object_get_string(tmp), sizeof(issuerdn) );
                }

            if ( json_object_object_get_ex(json_obj_tls, "serial", &tmp) )
                {
                    strlcpy(serial, json_object_get_string(tmp), sizeof(serial) );
                }

            if ( json_object_object_get_ex(json_obj_tls, "sni", &tmp) )
                {
                    strlcpy(sni, json_object_get_string(tmp), sizeof(sni) );
                }

            if ( json_object_object_get_ex(json_obj_tls, "version", &tmp) )
                {
                    strlcpy(version, json_object_get_string(tmp), sizeof(version) );
                }

            if ( json_object_object_get_ex(json_obj_tls, "notbefore", &tmp) )
                {
                    strlcpy(notbefore, json_object_get_string(tmp), sizeof(notbefore) );
                }

            if ( json_object_object_get_ex(json_obj_tls, "notafter", &tmp) )
                {
                    strlcpy(notafter, json_object_get_string(tmp), sizeof(notafter) );
                }

            if ( json_object_object_get_ex(json_obj_tls, "ja3", &tmp) )
                {

                    json_obj_ja3 = json_tokener_parse(json_object_get_string(tmp));

                    if ( json_object_object_get_ex(json_obj_ja3, "hash", &tmp) )
                        {
                            strlcpy(ja3, json_object_get_string(tmp), sizeof(ja3) );
                        }

                }

            if ( json_object_object_get_ex(json_obj_tls, "ja3s", &tmp) )
                {

                    json_obj_ja3s = json_tokener_parse(json_object_get_string(tmp));

                    if ( json_object_object_get_ex(json_obj_ja3s, "hash", &tmp) )
                        {
                            strlcpy(ja3s, json_object_get_string(tmp), sizeof(ja3s) );
                        }
                }
        }

    /* If there is no JA3 or JA3S hash,  perhaps Suricata isn't setup right? */

    if ( ja3s[0] == '\0' && ja3[0] == '\0' )
        {
            Meer_Log(WARN, "[%s, line %d] No JA3 or JA3S hash located.  Are you sure Suricata is sending this data?", __FILE__, __LINE__);
//            json_object_put(encode_json);
            json_object_put(json_obj_ja3);
            json_object_put(json_obj_ja3s);
            json_object_put(json_obj_tls);
            return;
        }


    snprintf(id, sizeof(id), "%s:%s", ja3, ja3s);
    id[ sizeof(id) - 1] = '\0';

    MD5( (uint8_t*)id, strlen(id), id_md5, sizeof(id_md5) );

    if ( !strcmp(last_tls_id, id_md5 ) )
        {

	    MeerCounters->ioc_skip++; 

            if ( MeerConfig->ioc_debug == true )
                {
                    Meer_Log(DEBUG, "[%s, line %d] SKIP TLS: %s", __FILE__, __LINE__, id_md5);
                }

            json_object_put(json_obj_ja3);
            json_object_put(json_obj_ja3s);
            json_object_put(json_obj_tls);
            return;

        }


    /**********************************/
    /* New JSON object                */
    /**********************************/

    struct json_object *encode_json = NULL;
    encode_json = json_object_new_object();

    json_object *jtype = json_object_new_string( "tls" );
    json_object_object_add(encode_json,"type", jtype);

    json_object *jflow_id = json_object_new_string( flow_id );
    json_object_object_add(encode_json,"flow_id", jflow_id);

    json_object *jsrc_ip = json_object_new_string( src_ip );
    json_object_object_add(encode_json,"src_ip", jsrc_ip);

    json_object *jdest_ip = json_object_new_string( dest_ip );
    json_object_object_add(encode_json,"dest_ip", jdest_ip);

                            if ( src_dns[0] != '\0' )
                                {
                                json_object *jsrc_dns = json_object_new_string( src_dns );
                                json_object_object_add(encode_json,"src_dns", jsrc_dns);
                                }

                            if ( dest_dns[0] != '\0' )
                                {
                                json_object *jdest_dns = json_object_new_string( dest_dns );
                                json_object_object_add(encode_json,"dest_dns", jdest_dns);
                                }

    if ( timestamp[0] != '\0' )
        {
            json_object *jtimestamp = json_object_new_string( timestamp );
            json_object_object_add(encode_json,"timestamp", jtimestamp);
        }

    if ( fingerprint[0] != '\0' )
        {
            json_object *jfingerprint = json_object_new_string( fingerprint );
            json_object_object_add(encode_json,"fingerprint", jfingerprint);
        }

    if ( issuerdn[0] != '\0' )
        {
            json_object *jissuerdn = json_object_new_string( issuerdn );
            json_object_object_add(encode_json,"issuerdn", jissuerdn);
        }

    if ( subject[0] != '\0' )
        {
            json_object *jsubject = json_object_new_string( subject );
            json_object_object_add(encode_json,"subject", jsubject );
        }

    if ( serial[0] != '\0' )
        {
            json_object *jserial = json_object_new_string( serial );
            json_object_object_add(encode_json,"serial", jserial );
        }

    if ( sni[0] != '\0' )
        {
            json_object *jsni = json_object_new_string( sni );
            json_object_object_add(encode_json,"sni", jsni );
        }

    if ( version[0] != '\0' )
        {
            json_object *jversion = json_object_new_string( version );
            json_object_object_add(encode_json,"version", jversion );
        }

    if ( notbefore[0] != 0 )
        {
            json_object *jnotbefore = json_object_new_string( notbefore );
            json_object_object_add(encode_json,"notbefore", jnotbefore );
        }

    if ( notafter[0] != 0 )
        {
            json_object *jnotafter = json_object_new_string( notafter );
            json_object_object_add(encode_json,"notafter", jnotafter );
        }

    /* We've already tested for JA3/JA3S */

    json_object *jja3 = json_object_new_string( ja3 );
    json_object_object_add(encode_json,"ja3", jja3 );

    json_object *jja3s = json_object_new_string( ja3s );
    json_object_object_add(encode_json,"ja3s", jja3s );

    if ( host[0] != '\0' )
        {
            json_object *jhost = json_object_new_string( host );
            json_object_object_add(encode_json,"host", jhost);
        }

    if ( MeerConfig->description[0] != '\0' )
        {
            json_object *jdesc = json_object_new_string( MeerConfig->description );
            json_object_object_add(encode_json,"description", jdesc);
        }

//    snprintf(id, sizeof(id), "%s:%s", ja3, ja3s);
//    id[ sizeof(id) - 1] = '\0';

//    MD5( (uint8_t*)id, strlen(id), id_md5, sizeof(id_md5) );

    /* Is this a repeat log */

//    if ( strcmp(last_tls_id, id_md5 ) )
//        {

           if ( MeerConfig->ioc_debug == true )
               {
                   Meer_Log(DEBUG, "[%s, line %d] INSERT TLS: %s: %s", __FILE__, __LINE__, id_md5, json_object_to_json_string(encode_json) );
               }
//
    MeerCounters->ioc++;
    strlcpy(last_tls_id, id_md5, MD5_SIZE);
    Output_Elasticsearch ( (char*)json_object_to_json_string(encode_json), "ioc", id_md5 );
//        }
//    else
//        {

//            if ( MeerConfig->ioc_debug == true )
//                {
//                    Meer_Log(DEBUG, "[%s, line %d] SKIP: %s: %s", __FILE__, __LINE__, id_md5, json_object_to_json_string(encode_json) );
//                }

//            MeerCounters->ioc_skip++;
//        }

    json_object_put(encode_json);
    json_object_put(json_obj_ja3);
    json_object_put(json_obj_ja3s);
    json_object_put(json_obj_tls);

}

/*********************************************/
/* IOC_DNS - Collect "queries" (not answers) */
/*********************************************/

void IOC_DNS( struct json_object *json_obj, const char *src_ip, const char *dest_ip, const char *flow_id )
{

    char timestamp[64] = { 0 };
    char rrname[8192] = { 0 };
    char rrtype[16] = { 0 };
    char host[64] = { 0 };

    char src_dns[256] = { 0 }; 
    char dest_dns[256] = { 0 }; 

    char id_md5[MD5_SIZE] = { 0 };

    struct json_object *tmp = NULL;
    struct json_object *json_obj_dns = NULL;

//    struct json_object *encode_json = NULL;
//    encode_json = json_object_new_object();

                            if ( json_object_object_get_ex(json_obj, "src_dns", &tmp) )
                                {
                                    strlcpy( src_dns, json_object_get_string(tmp), sizeof(src_dns) );
                                }

                            if ( json_object_object_get_ex(json_obj, "dest_dns", &tmp) )
                                {
                                    strlcpy( dest_dns, json_object_get_string(tmp), sizeof(dest_dns) );
                                }

    if ( json_object_object_get_ex(json_obj, "timestamp", &tmp) )
        {
            strlcpy( timestamp, json_object_get_string(tmp), sizeof(timestamp) );
        }

    if ( json_object_object_get_ex(json_obj, "host", &tmp) )
        {
            strlcpy( host, json_object_get_string(tmp), sizeof(host) );
        }

    if ( json_object_object_get_ex(json_obj, "dns", &tmp) )
        {

            json_obj_dns = json_tokener_parse(json_object_get_string(tmp));

            if ( json_object_object_get_ex(json_obj_dns, "type", &tmp) )
                {

                    /* We only want to record the queries,  not the "answers" */

                    if ( !strcmp( json_object_get_string(tmp), "query" ) )
                        {

                            if ( json_object_object_get_ex(json_obj_dns, "rrname", &tmp) )
                                {
                                    strlcpy(rrname, json_object_get_string(tmp), sizeof( rrname ) );
                                    MD5( (uint8_t*)rrname, strlen(rrname), id_md5, sizeof(id_md5) );

                                    if ( !strcmp(last_dns_id, id_md5 ) )
                                        {

                                            if ( MeerConfig->ioc_debug == true )
                                                {
                                                    Meer_Log(DEBUG, "[%s, line %d] SKIP DNS: %s", __FILE__, __LINE__, id_md5 );
                                                }

                                            MeerCounters->ioc_skip++;

//                                            json_object_put(encode_json);
                                            json_object_put(json_obj_dns);
                                            return;


                                        }

                                    if ( json_object_object_get_ex(json_obj_dns, "rrtype", &tmp) )
                                        {
                                            strlcpy(rrtype, json_object_get_string(tmp), sizeof( rrtype ) );
                                        }

                                }
                            else
                                {

                                    /* It's not a "query", so skip it */

//                                    json_object_put(encode_json);
                                    json_object_put(json_obj_dns);
                                    return;

                                }

                        }
                    else
                        {

                            /* There's isn't a type! */

//                            json_object_put(encode_json);
                            json_object_put(json_obj_dns);
                            return;

                        }
                }

            /**************************************************/
            /* New JSON Object                                */
            /**************************************************/

            struct json_object *encode_json = NULL;
            encode_json = json_object_new_object();

            json_object *jtype = json_object_new_string( "dns" );
            json_object_object_add(encode_json,"type", jtype);

                            if ( src_dns[0] != '\0' )
                                {
                                json_object *jsrc_dns = json_object_new_string( src_dns );
                                json_object_object_add(encode_json,"src_dns", jsrc_dns);
                                }

                            if ( dest_dns[0] != '\0' )
                                {
                                json_object *jdest_dns = json_object_new_string( dest_dns );
                                json_object_object_add(encode_json,"dest_dns", jdest_dns);
                                }

            if ( timestamp[0] != '\0' )
                {
                    json_object *jtimestamp = json_object_new_string( timestamp );
                    json_object_object_add(encode_json,"timestamp", jtimestamp);
                }

            if ( src_ip[0] != '\0' )
                {
                    json_object *jsrc_ip = json_object_new_string( src_ip );
                    json_object_object_add(encode_json,"src_ip", jsrc_ip);
                }

            if ( dest_ip[0] != '\0' )
                {
                    json_object *jdest_ip = json_object_new_string( dest_ip );
                    json_object_object_add(encode_json,"dest_ip", jdest_ip);
                }


            json_object *jflow_id = json_object_new_string( flow_id );
            json_object_object_add(encode_json,"flow_id", jflow_id);

            if ( rrname[0] != '\0' )
                {
                    json_object *jrrname = json_object_new_string( rrname );
                    json_object_object_add(encode_json,"rrname", jrrname);
                }

            if ( rrtype[0] != '\0' )
                {
                    json_object *jrrtype = json_object_new_string( rrtype );
                    json_object_object_add(encode_json,"rrtype", jrrtype);
                }

            if ( host[0] != '\0' )
                {
                    json_object *jhost = json_object_new_string( host );
                    json_object_object_add(encode_json,"host", jhost);
                }

            if ( MeerConfig->description[0] != '\0' )
                {
                    json_object *jdesc = json_object_new_string( MeerConfig->description );
                    json_object_object_add(encode_json,"description", jdesc);
                }

            if ( MeerConfig->ioc_debug == true )
                {
                    Meer_Log(DEBUG, "[%s, line %d] INSERT DNS: %s: %s", __FILE__, __LINE__, id_md5, json_object_to_json_string(encode_json) );
                }

            MeerCounters->ioc++;
            strlcpy(last_dns_id, id_md5, MD5_SIZE);
            Output_Elasticsearch ( (char*)json_object_to_json_string(encode_json), "ioc", id_md5 );

            json_object_put(encode_json);

        }

//    json_object_put(encode_json);
    json_object_put(json_obj_dns);

}

/********************************************/
/* IOC_SSH - Collect SSH version / banners */
/********************************************/

void IOC_SSH( struct json_object *json_obj, const char *src_ip, const char *dest_ip, const char *flow_id )
{

    char timestamp[64] = { 0 };
    char host[64] = { 0 };
    char proto_version[64] = { 0 };
    char client_version[256] = { 0 };
    char server_version[256] = { 0 };

    char tmp_id[64] = { 0 };

    char src_dns[256] = { 0 }; 
    char dest_dns[256] = { 0 }; 

    uint16_t src_port = 0;
    uint16_t dest_port = 0;

    char id_md5[MD5_SIZE] = { 0 };

//    struct json_object *encode_json = NULL;
//    encode_json = json_object_new_object();

    struct json_object *tmp = NULL;
    struct json_object *json_obj_ssh = NULL;
    struct json_object *json_obj_ssh_client = NULL;
    struct json_object *json_obj_ssh_server = NULL;

                            if ( json_object_object_get_ex(json_obj, "src_dns", &tmp) )
                                {
                                    strlcpy( src_dns, json_object_get_string(tmp), sizeof(src_dns) );
                                }

                            if ( json_object_object_get_ex(json_obj, "dest_dns", &tmp) )
                                {
                                    strlcpy( dest_dns, json_object_get_string(tmp), sizeof(dest_dns) );
                                }

    if ( json_object_object_get_ex(json_obj, "timestamp", &tmp) )
        {
            strlcpy( timestamp, json_object_get_string(tmp), sizeof(timestamp) );
        }

    if ( json_object_object_get_ex(json_obj, "src_port", &tmp) )
        {
            src_port = json_object_get_int(tmp);
        }

    if ( json_object_object_get_ex(json_obj, "dest_port", &tmp) )
        {
            dest_port = json_object_get_int(tmp);
        }

    if ( json_object_object_get_ex(json_obj, "host", &tmp) )
        {
            strlcpy( host, json_object_get_string(tmp), sizeof(host) );
        }

    if ( json_object_object_get_ex(json_obj, "ssh", &tmp) )
        {

            json_obj_ssh = json_tokener_parse(json_object_get_string(tmp));

            if ( json_object_object_get_ex(json_obj_ssh, "client", &tmp) )
                {

                    json_obj_ssh_client = json_tokener_parse(json_object_get_string(tmp));

                    if ( json_object_object_get_ex(json_obj_ssh_client, "proto_version", &tmp) )
                        {
                            strlcpy(proto_version, json_object_get_string(tmp), sizeof( proto_version ) );
                        }

                    if ( json_object_object_get_ex(json_obj_ssh_client, "software_version", &tmp) )
                        {
                            strlcpy(client_version, json_object_get_string(tmp), sizeof( client_version ) );
                        }

                }


            if ( json_object_object_get_ex(json_obj_ssh, "server", &tmp) )
                {

                    json_obj_ssh_server = json_tokener_parse(json_object_get_string(tmp));

                    if ( json_object_object_get_ex(json_obj_ssh_client, "software_version", &tmp) )
                        {
                            strlcpy(server_version, json_object_get_string(tmp), sizeof( server_version ) );
                        }

                }

        }

    /*******************************************/
    /* New JSON object                         */
    /*******************************************/

    struct json_object *encode_json = NULL;
    encode_json = json_object_new_object();

    json_object *jtype = json_object_new_string( "ssh" );
    json_object_object_add(encode_json,"type", jtype);

    json_object *jsrc_ip = json_object_new_string( src_ip );
    json_object_object_add(encode_json,"src_ip", jsrc_ip);

    json_object *jdest_ip = json_object_new_string( dest_ip );
    json_object_object_add(encode_json,"dest_ip", jdest_ip);

    json_object *jflow_id = json_object_new_string( flow_id );
    json_object_object_add(encode_json,"flow_id", jflow_id);

                            if ( src_dns[0] != '\0' )
                                {
                                json_object *jsrc_dns = json_object_new_string( src_dns );
                                json_object_object_add(encode_json,"src_dns", jsrc_dns);
                                }

                            if ( dest_dns[0] != '\0' )
                                {
                                json_object *jdest_dns = json_object_new_string( dest_dns );
                                json_object_object_add(encode_json,"dest_dns", jdest_dns);
                                }

    if ( timestamp[0] != '\0' )
        {
            json_object *jtimestamp = json_object_new_string( timestamp );
            json_object_object_add(encode_json,"timestamp", jtimestamp);
        }

    if ( src_port != 0 )
        {
            json_object *jsrc_port = json_object_new_int( src_port );
            json_object_object_add(encode_json,"src_port", jsrc_port);
        }

    if ( dest_port != 0 )
        {
            json_object *jdest_port = json_object_new_int( dest_port );
            json_object_object_add(encode_json,"dest_port", jdest_port);
        }

    if ( host[0] != '\0' )
        {
            json_object *jhost = json_object_new_string( host );
            json_object_object_add(encode_json,"host", jhost);
        }

    if ( MeerConfig->description[0] != '\0' )
        {
            json_object *jdesc = json_object_new_string( MeerConfig->description );
            json_object_object_add(encode_json,"description", jdesc);
        }

    if ( proto_version[0] != '\0' )
        {
            json_object *jproto_version = json_object_new_string( proto_version );
            json_object_object_add(encode_json,"proto_version", jproto_version);
        }

    if ( server_version[0] != '\0' )
        {
            json_object *jserver_version = json_object_new_string( server_version );
            json_object_object_add(encode_json,"server_version", jserver_version);
        }

    if ( client_version[0] != '\0' )
        {
            json_object *jclient_version = json_object_new_string( client_version );
            json_object_object_add(encode_json,"client_version", jclient_version);
        }

    snprintf(tmp_id, sizeof(tmp_id), "%s:%d:%s:%s", dest_ip, dest_port, server_version, client_version);
    tmp_id[ sizeof( tmp_id ) - 1] = '\0';

    MD5( (uint8_t*)tmp_id, strlen(tmp_id), id_md5, sizeof(id_md5) );

    /* Is this a repeat log */

    if ( strcmp(last_ssh_id, id_md5 ) )
        {

            if ( MeerConfig->ioc_debug == true )
                {
                    Meer_Log(DEBUG, "[%s, line %d] INSERT SSH: %s: %s", __FILE__, __LINE__, id_md5, json_object_to_json_string(encode_json) );
                }

            MeerCounters->ioc++;
            strlcpy(last_ssh_id, id_md5, MD5_SIZE);
            Output_Elasticsearch ( (char*)json_object_to_json_string(encode_json), "ioc", id_md5 );
        }
    else
        {

            if ( MeerConfig->ioc_debug == true )
                {
                    Meer_Log(DEBUG, "[%s, line %d] SKIP SSH: %s: %s", __FILE__, __LINE__, id_md5, json_object_to_json_string(encode_json) );
                }

            MeerCounters->ioc_skip++;
        }

    json_object_put(encode_json);
    json_object_put(json_obj_ssh);
    json_object_put(json_obj_ssh_client);
    json_object_put(json_obj_ssh_server);

}

/**********************************************/
/* IOC_HTTP - Collects user agents, URLs, etc */
/**********************************************/

void IOC_HTTP( struct json_object *json_obj, const char *src_ip, const char *dest_ip, const char *flow_id )
{

    char timestamp[64] = { 0 };
    char host[64] = { 0 };

    char id_md5[MD5_SIZE] = { 0 };

    char http_user_agent[2048] = { 0 };
    char hostname[256] = { 0 };
    char url[10240] = { 0 };
    char full_url[256 + 10240] = { 0 };
    char method[16] = { 0 };

    char src_dns[256] = { 0 }; 
    char dest_dns[256] = { 0 }; 

    uint8_t status = 0;
    uint64_t length = 0;

    struct json_object *tmp = NULL;
    struct json_object *json_obj_http = NULL;

//    struct json_object *encode_json = NULL;
//    encode_json = json_object_new_object();

//    struct json_object *encode_json_user_agent = NULL;
//    encode_json_user_agent = json_object_new_object();

                            if ( json_object_object_get_ex(json_obj, "src_dns", &tmp) )
                                {
                                    strlcpy( src_dns, json_object_get_string(tmp), sizeof(src_dns) );
                                }

                            if ( json_object_object_get_ex(json_obj, "dest_dns", &tmp) )
                                {
                                    strlcpy( dest_dns, json_object_get_string(tmp), sizeof(dest_dns) );
                                }

    if ( json_object_object_get_ex(json_obj, "timestamp", &tmp) )
        {
            strlcpy( timestamp, json_object_get_string(tmp), sizeof(timestamp) );
        }

    if ( json_object_object_get_ex(json_obj, "host", &tmp) )
        {
            strlcpy( host, json_object_get_string(tmp), sizeof(host) );
        }

    if ( json_object_object_get_ex(json_obj, "http", &tmp) )
        {

            json_obj_http = json_tokener_parse(json_object_get_string(tmp));

            if ( json_object_object_get_ex(json_obj_http, "http_user_agent", &tmp) )
                {
                    strlcpy( http_user_agent, json_object_get_string(tmp), sizeof( http_user_agent ));
                }

            if ( json_object_object_get_ex(json_obj_http, "hostname", &tmp) )
                {
                    strlcpy( hostname, json_object_get_string(tmp), sizeof( hostname ));
                }

            if ( json_object_object_get_ex(json_obj_http, "url", &tmp) )
                {
                    strlcpy( url, json_object_get_string(tmp), sizeof( url ));
                }

            if ( json_object_object_get_ex(json_obj_http, "method", &tmp) )
                {
                    strlcpy( method, json_object_get_string(tmp), sizeof( method ));
                }

            if ( json_object_object_get_ex(json_obj_http, "status", &tmp) )
                {
                    status = json_object_get_int(tmp);
                }

            if ( json_object_object_get_ex(json_obj_http, "length", &tmp) )
                {
                    length = json_object_get_int(tmp);
                }

            snprintf(full_url, sizeof(full_url), "%s%s", hostname, url);
            full_url[ sizeof( full_url ) - 1 ] = '\0';

	    MD5( (uint8_t*)full_url, strlen(full_url), id_md5, sizeof(id_md5) );

            /****************************************/
            /* New HTTP JSON object                 */
            /****************************************/

            struct json_object *encode_json = NULL;
            encode_json = json_object_new_object();

            json_object *jtype = json_object_new_string( "http" );
            json_object_object_add(encode_json,"type", jtype);

            json_object *jsrc_ip = json_object_new_string( src_ip );
            json_object_object_add(encode_json,"src_ip", jsrc_ip);

            json_object *jdest_ip = json_object_new_string( dest_ip );
            json_object_object_add(encode_json,"dest_ip", jdest_ip);

            json_object *jflow_id = json_object_new_string( flow_id );
            json_object_object_add(encode_json,"flow_id", jflow_id);

                            if ( src_dns[0] != '\0' )
                                {
                                json_object *jsrc_dns = json_object_new_string( src_dns );
                                json_object_object_add(encode_json,"src_dns", jsrc_dns);
                                }

                            if ( dest_dns[0] != '\0' )
                                {
                                json_object *jdest_dns = json_object_new_string( dest_dns );
                                json_object_object_add(encode_json,"dest_dns", jdest_dns);
                                }

            if ( timestamp[0] != '\0' )
                {
                    json_object *jtimestamp = json_object_new_string( timestamp );
                    json_object_object_add(encode_json,"timestamp", jtimestamp);
                }

            if ( MeerConfig->description[0] != '\0' )
                {
                    json_object *jdesc = json_object_new_string( MeerConfig->description );
                    json_object_object_add(encode_json,"description", jdesc);
                }

            if ( host[0] != '\0' )
                {
                    json_object *jhost = json_object_new_string( host );
                    json_object_object_add(encode_json,"host", jhost);
                }

//            snprintf(full_url, sizeof(full_url), "%s%s", hostname, url);
//            full_url[ sizeof( full_url ) - 1 ] = '\0';

            json_object *jfull_url = json_object_new_string( full_url );
            json_object_object_add(encode_json,"url", jfull_url);

           if ( !strcmp(last_http_id, id_md5 ) )
                {
		
		MeerCounters->ioc_skip++;

                    if ( MeerConfig->ioc_debug == true )
                        {
                            Meer_Log(DEBUG, "[%s, line %d] HTTP URL SKIP: %s", __FILE__, __LINE__, id_md5 );
                        }


		json_object_put(json_obj_http);

		return;

		}


            /****************************************/
            /* New User Agent Object                */
            /****************************************/

            if ( http_user_agent[0] != '\0' )
                {
                    json_object *juser_agent = json_object_new_string( http_user_agent );
                    json_object_object_add(encode_json,"user_agent", juser_agent);
                }

            if ( method[0] != '\0' )
                {
                    json_object *jmethod = json_object_new_string( method );
                    json_object_object_add(encode_json,"method", jmethod);
                }

            json_object *jstatus = json_object_new_int( status );
            json_object_object_add(encode_json,"status", jstatus);

            json_object *jlength = json_object_new_int( length);
            json_object_object_add(encode_json,"length", jlength);

//            MD5( (uint8_t*)full_url, strlen(full_url), id_md5, sizeof(id_md5) );

            /* Is this a repeat log */

//            if ( strcmp(last_http_id, id_md5 ) )
//                {

                    if ( MeerConfig->ioc_debug == true )
                        {
                            Meer_Log(DEBUG, "[%s, line %d] INSERT HTTP URL: %s: %s", __FILE__, __LINE__, id_md5, json_object_to_json_string(encode_json) );
                        }

// HERE
                    MeerCounters->ioc++;
                    strlcpy(last_http_id, id_md5, MD5_SIZE);
                    Output_Elasticsearch ( (char*)json_object_to_json_string(encode_json), "ioc", id_md5 );
//                }
//            else
//                {

//                    if ( MeerConfig->ioc_debug == true )
//                        {
//                            Meer_Log(DEBUG, "[%s, line %d] SKIP: %s: %s", __FILE__, __LINE__, id_md5, json_object_to_json_string(encode_json) );
//                        }



//                    MeerCounters->ioc_skip++;
//                }

            json_object_put(encode_json);

	    /* Check User_agent */

	    MD5( (uint8_t*)http_user_agent, strlen(http_user_agent), id_md5, sizeof(id_md5) );

            if ( !strcmp(last_user_agent_id, id_md5 ) )
                {

		MeerCounters->ioc_skip++; 

                    if ( MeerConfig->ioc_debug == true )
                        {
                            Meer_Log(DEBUG, "[%s, line %d] SKIP HTTP USER_AGENT: %s", __FILE__, __LINE__, id_md5);
                        }

	    json_object_put(json_obj_http);

	    return;
	    } 


            /* New User Agent Object */

	    

            struct json_object *encode_json_user_agent = NULL;
            encode_json_user_agent = json_object_new_object();

            json_object *jtype_ua = json_object_new_string( "user_agent" );
            json_object_object_add(encode_json_user_agent,"type", jtype_ua);

                            if ( src_dns[0] != '\0' )
                                {
                                json_object *jsrc_dns = json_object_new_string( src_dns );
                                json_object_object_add(encode_json,"src_dns", jsrc_dns);
                                }

                            if ( dest_dns[0] != '\0' )
                                {
                                json_object *jdest_dns = json_object_new_string( dest_dns );
                                json_object_object_add(encode_json,"dest_dns", jdest_dns);
                                }

            if ( MeerConfig->description[0] != '\0' )
                {
                    json_object *jdesc_ua = json_object_new_string( MeerConfig->description );
                    json_object_object_add(encode_json_user_agent,"description", jdesc_ua);
                }

            if ( host[0] != '\0' )
                {
                    json_object *jhost_ua = json_object_new_string( host );
                    json_object_object_add(encode_json_user_agent,"host", jhost_ua);
                }

            if ( timestamp[0] != '\0' )
                {
                    json_object *jtimestamp_ua = json_object_new_string( timestamp );
                    json_object_object_add(encode_json_user_agent,"timestamp", jtimestamp_ua);
                }

            json_object *jsrc_ip_ua = json_object_new_string( src_ip );
            json_object_object_add(encode_json_user_agent,"src_ip", jsrc_ip_ua);

            json_object *jdest_ip_ua = json_object_new_string( dest_ip );
            json_object_object_add(encode_json_user_agent,"dest_ip", jdest_ip_ua);

            json_object *jflow_id_ua = json_object_new_string( flow_id );
            json_object_object_add(encode_json_user_agent,"flow_id", jflow_id_ua);

            if ( http_user_agent[0] != '\0' )
                {
                    json_object *juser_agent_ua = json_object_new_string( http_user_agent );
                    json_object_object_add(encode_json_user_agent,"user_agent", juser_agent_ua);
                }

//            MD5( (uint8_t*)http_user_agent, strlen(http_user_agent), id_md5, sizeof(id_md5) );

            /* Is this a repeat log */

/*            if ( strcmp(last_user_agent_id, id_md5 ) )
                {
*/
                  if ( MeerConfig->ioc_debug == true )
                        {
                            Meer_Log(DEBUG, "[%s, line %d] INSERT USER_AGENT: %s: %s", __FILE__, __LINE__, id_md5, json_object_to_json_string(encode_json_user_agent) );
                        }

                    MeerCounters->ioc++;
                    strlcpy(last_user_agent_id, id_md5, MD5_SIZE);
                    Output_Elasticsearch ( (char*)json_object_to_json_string(encode_json_user_agent), "ioc", id_md5 );
/*                }
            else
                {

                    if ( MeerConfig->ioc_debug == true )
                        {
                            Meer_Log(DEBUG, "[%s, line %d] SKIP: %s: %s", __FILE__, __LINE__, id_md5, json_object_to_json_string(encode_json_user_agent) );
                        }


                    MeerCounters->ioc_skip++;
                }
	*/

            json_object_put(encode_json_user_agent);

        }

//    json_object_put(encode_json);
//    json_object_put(encode_json_user_agent);
    json_object_put(json_obj_http);

}

/************************************************************************/
/* IOC_SMB - Grab data from SMB2_COMMAND_CREATE, SMB2_COMMAND_READ. and */
/* SMB2_COMMAND_WRITE.  SMB is used a lot in lateral movement.          */
/************************************************************************/

void IOC_SMB( struct json_object *json_obj, const char *src_ip, const char *dest_ip, const char *flow_id  )
{

    char timestamp[64] = { 0 };
    char host[64] = { 0 };

    char id_md5[MD5_SIZE] = { 0 };

    char smb_command[64] = { 0 };
    char smb_filename[10240] = { 0 };
 
    char src_dns[256] = { 0 }; 
    char dest_dns[256] = { 0 }; 

    char command_filename[64 + 10240 + 1] = { 0 };   /* SMB_COMMAND|/file/path */

    struct json_object *tmp = NULL;
    struct json_object *json_obj_smb = NULL;

//    struct json_object *encode_json = NULL;
//    encode_json = json_object_new_object();

                            if ( json_object_object_get_ex(json_obj, "src_dns", &tmp) )
                                {
                                    strlcpy( src_dns, json_object_get_string(tmp), sizeof(src_dns) );
                                }

                            if ( json_object_object_get_ex(json_obj, "dest_dns", &tmp) )
                                {
                                    strlcpy( dest_dns, json_object_get_string(tmp), sizeof(dest_dns) );
                                }

    if ( json_object_object_get_ex(json_obj, "timestamp", &tmp) )
        {
            strlcpy( timestamp, json_object_get_string(tmp), sizeof(timestamp) );
        }

    if ( json_object_object_get_ex(json_obj, "host", &tmp) )
        {
            strlcpy( host, json_object_get_string(tmp), sizeof(host) );
        }

    if ( json_object_object_get_ex(json_obj, "smb", &tmp) )
        {

            json_obj_smb = json_tokener_parse(json_object_get_string(tmp));

            if ( json_object_object_get_ex(json_obj_smb, "command", &tmp) )
                {
                    strlcpy( smb_command, json_object_get_string(tmp), sizeof( smb_command ));

                    if ( !strcmp(smb_command, "SMB2_COMMAND_CREATE" ) ||
                            !strcmp(smb_command, "SMB2_COMMAND_READ" ) ||
                            !strcmp(smb_command, "SMB2_COMMAND_WRITE" ) )
                        {

                            if ( json_object_object_get_ex(json_obj_smb, "filename", &tmp) )
                                {

                                    strlcpy(smb_filename, json_object_get_string(tmp), sizeof( smb_filename ) );

                                    snprintf(command_filename, sizeof(command_filename), "%s|%s", smb_command, smb_filename);
                                    command_filename[ sizeof(command_filename) - 1] = '\0';

                                    MD5( (uint8_t*)command_filename, strlen(command_filename), id_md5, sizeof(id_md5) );

                                    if ( !strcmp(last_smb_id, id_md5 ) )
                                        {

					MeerCounters->ioc_skip++; 

                                            if ( MeerConfig->ioc_debug == true )
                                                {
                                                    Meer_Log(DEBUG, "[%s, line %d] SKIP SMB: %s", __FILE__, __LINE__, id_md5 );
                                                }

					json_object_put(json_obj_smb);
					return;

					}

                                    /****************************************/
                                    /* New SMB JSON object                   */
                                    /****************************************/

                                    struct json_object *encode_json = NULL;
                                    encode_json = json_object_new_object();

                                    json_object *jtype = json_object_new_string( "smb" );
                                    json_object_object_add(encode_json,"type", jtype);

                                    json_object *jsrc_ip = json_object_new_string( src_ip );
                                    json_object_object_add(encode_json,"src_ip", jsrc_ip);

                                    json_object *jdest_ip = json_object_new_string( dest_ip );
                                    json_object_object_add(encode_json,"dest_ip", jdest_ip);

                                    json_object *jflow_id = json_object_new_string( flow_id );
                                    json_object_object_add(encode_json,"flow_id", jflow_id);

                            if ( src_dns[0] != '\0' )
                                {
                                json_object *jsrc_dns = json_object_new_string( src_dns );
                                json_object_object_add(encode_json,"src_dns", jsrc_dns);
                                }

                            if ( dest_dns[0] != '\0' )
                                {
                                json_object *jdest_dns = json_object_new_string( dest_dns );
                                json_object_object_add(encode_json,"dest_dns", jdest_dns);
                                }

                                    if ( timestamp[0] != '\0' )
                                        {
                                            json_object *jtimestamp = json_object_new_string( timestamp );
                                            json_object_object_add(encode_json,"timestamp", jtimestamp);
                                        }

                                    if ( MeerConfig->description[0] != '\0' )
                                        {
                                            json_object *jdesc = json_object_new_string( MeerConfig->description );
                                            json_object_object_add(encode_json,"description", jdesc);
                                        }

                                    if ( host[0] != '\0' )
                                        {
                                            json_object *jhost = json_object_new_string( host );
                                            json_object_object_add(encode_json,"host", jhost);
                                        }

                                    if ( smb_command[0] != '\0' )
                                        {
                                            json_object *jsmb_command = json_object_new_string( smb_command );
                                            json_object_object_add(encode_json,"command", jsmb_command);
                                        }

                                    if ( smb_filename[0] != '\0' )
                                        {
                                            json_object *jsmb_filename = json_object_new_string( smb_filename );
                                            json_object_object_add(encode_json,"filename", jsmb_filename);
                                        }

//                                    snprintf(command_filename, sizeof(command_filename), "%s|%s", smb_command, smb_filename);
//                                    command_filename[ sizeof(command_filename) - 1] = '\0';

//                                    MD5( (uint8_t*)command_filename, strlen(command_filename), id_md5, sizeof(id_md5) );

                                    if ( MeerConfig->ioc_debug == true )
                                        {
                                            Meer_Log(DEBUG, "[%s, line %d] INSERT SMB %s: %s", __FILE__, __LINE__, id_md5, json_object_to_json_string(encode_json) );
                                        }


                                    /* Is this a repeat log */

/*                                    if ( strcmp(last_smb_id, id_md5 ) )
                                        {

                                            if ( MeerConfig->ioc_debug == true )
                                                {
                                                    Meer_Log(DEBUG, "[%s, line %d] INSERT: %s: %s", __FILE__, __LINE__, id_md5, json_object_to_json_string(encode_json) );
                                                }
*/
                                            MeerCounters->ioc++;
                                            strlcpy(last_smb_id, id_md5, MD5_SIZE);
                                            Output_Elasticsearch ( (char*)json_object_to_json_string(encode_json), "ioc", id_md5 );

/*                                        }
                                    else
                                        {

                                            if ( MeerConfig->ioc_debug == true )
                                                {
                                                    Meer_Log(DEBUG, "[%s, line %d] SKIP: %s: %s", __FILE__, __LINE__, id_md5, json_object_to_json_string(encode_json) );
                                                }

                                            MeerCounters->ioc_skip++;
                                        }
*/

                                    json_object_put(encode_json);


                                }
                        }
                }
        }

//    json_object_put(encode_json);
    json_object_put(json_obj_smb);

}

/*****************************************************/
/* IOC_FTP - Grabs files sent, received and username */
/*****************************************************/

void IOC_FTP( struct json_object *json_obj, const char *src_ip, const char *dest_ip, const char *flow_id )
{

    char timestamp[64] = { 0 };
    char host[64] = { 0 };

    char id_md5[MD5_SIZE] = { 0 };

    char ftp_command[64] = { 0 };
    char ftp_command_data[10240] = { 0 };
    char ftp_plus_data[10240+64+1] = { 0 }; 		/* COMMAND|COMMAND_DATA */

    struct json_object *tmp = NULL;
    struct json_object *json_obj_ftp = NULL;

    char src_dns[256] = { 0 };
    char dest_dns[256] = { 0 }; 

//    struct json_object *encode_json = NULL;
//    encode_json = json_object_new_object();

                            if ( json_object_object_get_ex(json_obj, "src_dns", &tmp) )
                                {
                                    strlcpy( src_dns, json_object_get_string(tmp), sizeof(src_dns) );
                                }

                            if ( json_object_object_get_ex(json_obj, "dest_dns", &tmp) )
                                {
                                    strlcpy( dest_dns, json_object_get_string(tmp), sizeof(dest_dns) );
                                }

    if ( json_object_object_get_ex(json_obj, "timestamp", &tmp) )
        {
            strlcpy( timestamp, json_object_get_string(tmp), sizeof(timestamp) );
        }

    if ( json_object_object_get_ex(json_obj, "host", &tmp) )
        {
            strlcpy( host, json_object_get_string(tmp), sizeof(host) );
        }

    if ( json_object_object_get_ex(json_obj, "ftp", &tmp) )
        {

            json_obj_ftp = json_tokener_parse(json_object_get_string(tmp));

            if ( json_object_object_get_ex(json_obj_ftp, "command", &tmp) )
                {

                    strlcpy( ftp_command, json_object_get_string(tmp), sizeof(ftp_command) );

                    if ( !strcmp(ftp_command, "STOR" ) ||
                            !strcmp(ftp_command, "RETR" ) ||
                            !strcmp(ftp_command, "USER" ) )
                        {

                            if ( json_object_object_get_ex(json_obj_ftp, "command_data", &tmp) )
                                {

                                    strlcpy(ftp_command_data, json_object_get_string(tmp), sizeof( ftp_command_data ) );


                                    snprintf(ftp_plus_data, sizeof(ftp_plus_data), "%s|%s", ftp_command, ftp_command_data);
                                    ftp_plus_data[ sizeof(ftp_plus_data) - 1] = '\0';

                                    MD5( (uint8_t*)ftp_plus_data, strlen(ftp_plus_data), id_md5, sizeof(id_md5) );

                                    if ( !strcmp(last_ftp_id, id_md5 ) )
                                      {

					MeerCounters->ioc_skip++; 

                                            if ( MeerConfig->ioc_debug == true )
                                                {
                                                    Meer_Log(DEBUG, "[%s, line %d] SKIP FTP : %s", __FILE__, __LINE__, id_md5);
                                                }


					json_object_put(json_obj_ftp);
					return;

					}


                                    /****************************************/
                                    /* New FTP JSON object                  */
                                    /****************************************/

                                    struct json_object *encode_json = NULL;
                                    encode_json = json_object_new_object();

                                    json_object *jtype = json_object_new_string( "ftp" );
                                    json_object_object_add(encode_json,"type", jtype);

                                    json_object *jsrc_ip = json_object_new_string( src_ip );
                                    json_object_object_add(encode_json,"src_ip", jsrc_ip);

                                    json_object *jdest_ip = json_object_new_string( dest_ip );
                                    json_object_object_add(encode_json,"dest_ip", jdest_ip);

                                    json_object *jflow_id = json_object_new_string( flow_id );
                                    json_object_object_add(encode_json,"flow_id", jflow_id);

                            if ( src_dns[0] != '\0' )
                                {
                                json_object *jsrc_dns = json_object_new_string( src_dns );
                                json_object_object_add(encode_json,"src_dns", jsrc_dns);
                                }

                            if ( dest_dns[0] != '\0' )
                                {
                                json_object *jdest_dns = json_object_new_string( dest_dns );
                                json_object_object_add(encode_json,"dest_dns", jdest_dns);
                                }

                                    if ( timestamp[0] != '\0' )
                                        {
                                            json_object *jtimestamp = json_object_new_string( timestamp );
                                            json_object_object_add(encode_json,"timestamp", jtimestamp);
                                        }

                                    if ( MeerConfig->description[0] != '\0' )
                                        {
                                            json_object *jdesc = json_object_new_string( MeerConfig->description );
                                            json_object_object_add(encode_json,"description", jdesc);
                                        }

                                    if ( host[0] != '\0' )
                                        {
                                            json_object *jhost = json_object_new_string( host );
                                            json_object_object_add(encode_json,"host", jhost);
                                        }

                                    if ( ftp_command[0] != '\0' )
                                        {
                                            json_object *jftp_command = json_object_new_string( ftp_command );
                                            json_object_object_add(encode_json,"command", jftp_command);
                                        }

                                    if ( ftp_command_data[0] != '\0' )
                                        {
                                            json_object *jftp_command_data = json_object_new_string( ftp_command_data );
                                            json_object_object_add(encode_json,"command_data", jftp_command_data);
                                        }

//                                    snprintf(ftp_plus_data, sizeof(ftp_plus_data), "%s|%s", ftp_command, ftp_command_data);
//                                    ftp_plus_data[ sizeof(ftp_plus_data) - 1] = '\0';

//                                    MD5( (uint8_t*)ftp_plus_data, strlen(ftp_plus_data), id_md5, sizeof(id_md5) );

                                    /* Is this a repeat log */

/*                                    if ( strcmp(last_ftp_id, id_md5 ) )
                                        {
*/
                                            if ( MeerConfig->ioc_debug == true )
                                                {
                                                    Meer_Log(DEBUG, "[%s, line %d] INSERT FTP : %s: %s", __FILE__, __LINE__, id_md5, json_object_to_json_string(encode_json) );
                                                }


                                            MeerCounters->ioc++;
                                            strlcpy(last_ftp_id, id_md5, MD5_SIZE);
                                            Output_Elasticsearch ( (char*)json_object_to_json_string(encode_json), "ioc", id_md5 );
 /*                                       }
                                    else
                                        {

                                            if ( MeerConfig->ioc_debug == true )
                                                {
                                                    Meer_Log(DEBUG, "[%s, line %d] SKIP FTP : %s: %s", __FILE__, __LINE__, id_md5, json_object_to_json_string(encode_json) );
                                                }


                                            MeerCounters->ioc_skip++;
                                        }
*/

                                    json_object_put(encode_json);


                                }
                        }
                }
        }

//    json_object_put(encode_json);
    json_object_put(json_obj_ftp);


}

/***************************************************************/
/* IOC_In_Range - validate IP are within range of what we care */
/* about                                                       */
/***************************************************************/

bool IOC_In_Range( char *ip_address )
{

    uint16_t z = 0;
    bool valid_fingerprint_net = false;
    unsigned char ip[MAXIPBIT] = { 0 };

    IP2Bit(ip_address, ip);

    for ( z = 0; z < MeerCounters->ioc_ignore_count; z++ )
        {
            if ( Is_Inrange( ip, (unsigned char *)&IOC_Ignore[z].range, 1) )
                {
                    valid_fingerprint_net = true;
                    break;
                }
        }

    return( valid_fingerprint_net );
}

#endif

