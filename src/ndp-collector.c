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

/* System for collecting potential NDPs and putting them in Zinc,  OpenSearch
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

#include "ndp-collector.h"

extern struct _MeerConfig *MeerConfig;
extern struct _MeerOutput *MeerOutput;
extern struct _MeerCounters *MeerCounters;
extern struct _NDP_Ignore *NDP_Ignore;

/* Command Lists */

extern struct _NDP_SMB_Commands *NDP_SMB_Commands;
extern struct _NDP_FTP_Commands *NDP_FTP_Commands;


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
/* NDP_Collector - Determines "what" we want to collect data from  */
/*******************************************************************/

void NDP_Collector( struct json_object *json_obj, const char *json_string, const char *event_type, const char *src_ip, const char *dest_ip, const char *flow_id )
{

    /* SMB is used so heavy in lateral movement, we can log _all_ SMB commands/traffic
       here.  Basically, we can bypass IP checks for SMB data */

    if ( !strcmp( event_type, "smb" ) && MeerConfig->ndp_routing_smb == true && MeerConfig->ndp_smb_internal == true )
        {
            NDP_SMB( json_obj, src_ip, dest_ip, flow_id );
            return;
        }

    /* Make sure potential NDP's are being collected only from data sources (src/dest)
    that we care about! */

    if ( NDP_In_Range( (char*)src_ip ) == false ||  NDP_In_Range( (char*)dest_ip ) == false )
        {

            if ( !strcmp( event_type, "flow" ) && MeerConfig->ndp_routing_flow == true )
                {
                    NDP_Flow( json_obj, src_ip, dest_ip, flow_id );
                    return;
                }

            else if ( !strcmp( event_type, "http" ) && MeerConfig->ndp_routing_http == true )
                {
                    NDP_HTTP( json_obj, src_ip, dest_ip, flow_id );
                    return;
                }

            else if ( !strcmp( event_type, "ssh" ) && MeerConfig->ndp_routing_ssh == true )
                {
                    NDP_SSH( json_obj, src_ip, dest_ip, flow_id );
                    return;
                }

            else if ( !strcmp( event_type, "fileinfo" ) && MeerConfig->ndp_routing_fileinfo == true )
                {
                    NDP_FileInfo( json_obj, src_ip, dest_ip, flow_id );
                    return;
                }

            if ( !strcmp( event_type, "tls" ) && MeerConfig->ndp_routing_tls == true )
                {
                    NDP_TLS( json_obj, src_ip, dest_ip, flow_id );
                    return;
                }

            else if ( !strcmp( event_type, "dns" ) && MeerConfig->ndp_routing_dns == true )
                {
                    NDP_DNS( json_obj, src_ip, dest_ip, flow_id );
                    return;
                }

            else if ( !strcmp( event_type, "ftp" ) && MeerConfig->ndp_routing_ftp == true )
                {
                    NDP_FTP( json_obj, src_ip, dest_ip, flow_id );
                    return;
                }

            /* Note the "ndp_smb_internal == false" */

            else if ( !strcmp( event_type, "smb" ) && MeerConfig->ndp_routing_smb == true && MeerConfig->ndp_smb_internal == false )
                {
                    NDP_SMB( json_obj, src_ip, dest_ip, flow_id );
                    return;
                }

        }
}

/********************************************************************/
/* NDP_Flow - Remove local IPs and collect IP addresses of interest */
/********************************************************************/

void NDP_Flow( struct json_object *json_obj, const char *src_ip, const char *dest_ip, const char *flow_id )
{

    struct json_object *json_obj_flow = NULL;
    struct json_object *json_obj_state = NULL;

    char *tmp_type = NULL;
    char tmp_ip[64] = { 0 };
    char id_md5[MD5_SIZE] = { 0 };

    uint8_t i = 0;

    struct json_object *tmp = NULL;
    bool state_flag = false;

    MD5( (uint8_t*)src_ip, strlen(src_ip), id_md5, sizeof(id_md5) );

    if ( !strcmp( last_flow_id, id_md5 ) )
        {

            if ( MeerConfig->ndp_debug == true )
                {
                    Meer_Log(DEBUG, "[%s, line %d] SKIP FLOW %s", __FILE__, __LINE__, id_md5);
                }

            MeerCounters->ndp_skip++;
            return;
        }

    MD5( (uint8_t*)dest_ip, strlen(dest_ip), id_md5, sizeof(id_md5) );

    if ( !strcmp( last_flow_id, id_md5 ) )
        {

            if ( MeerConfig->ndp_debug == true )
                {
                    Meer_Log(DEBUG, "[%s, line %d] SKIP FLOW %s", __FILE__, __LINE__, id_md5 );
                }

            MeerCounters->ndp_skip++;
            return;
        }

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

                    if ( NDP_In_Range( tmp_ip ) == false && ( Is_IP( tmp_ip, IPv4 ) ) )
                        {


                            struct json_object *encode_json_flow = NULL;
                            encode_json_flow = json_object_new_object();

                            struct json_object *jgeoip_src = NULL;
                            jgeoip_src = json_object_new_object();

                            struct json_object *jgeoip_dest = NULL;
                            jgeoip_dest = json_object_new_object();

                            json_object *jtype = json_object_new_string( "flow" );
                            json_object_object_add(encode_json_flow,"type", jtype);

                            json_object *jflow_id = json_object_new_string( flow_id );
                            json_object_object_add(encode_json_flow,"flow_id", jflow_id);

                            json_object *jsrc_ip = json_object_new_string( src_ip );
                            json_object_object_add(encode_json_flow,"src_ip", jsrc_ip);

                            json_object *jdest_ip = json_object_new_string( dest_ip );
                            json_object_object_add(encode_json_flow,"dest_ip", jdest_ip);

                            if ( MeerConfig->description[0] != '\0' )
                                {
                                    json_object *jdesc = json_object_new_string( MeerConfig->description );
                                    json_object_object_add(encode_json_flow,"description", jdesc);
                                }

                            if ( json_object_object_get_ex(json_obj, "src_dns", &tmp) )
                                {
                                    json_object *jsrc_dns = json_object_new_string( json_object_get_string(tmp) );
                                    json_object_object_add(encode_json_flow,"src_dns", jsrc_dns);
                                }

                            if ( json_object_object_get_ex(json_obj, "dest_dns", &tmp) )
                                {
                                    json_object *jdest_dns = json_object_new_string( json_object_get_string(tmp) );
                                    json_object_object_add(encode_json_flow,"dest_dns", jdest_dns);
                                }

                            if ( json_object_object_get_ex(json_obj, "geoip_src", &tmp) )
                                {
                                    jgeoip_src = json_tokener_parse( json_object_get_string(tmp) );
                                    json_object_object_add(encode_json_flow,"geoip_src", jgeoip_src);
                                }

                            if ( json_object_object_get_ex(json_obj, "geoip_dest", &tmp) )
                                {
                                    jgeoip_dest = json_tokener_parse( json_object_get_string(tmp) );
                                    json_object_object_add(encode_json_flow,"geoip_dest", jgeoip_dest);
                                }

                            if ( json_object_object_get_ex(json_obj, "timestamp", &tmp) )
                                {
                                    json_object *jtimestamp = json_object_new_string( json_object_get_string(tmp) );
                                    json_object_object_add(encode_json_flow,"timestamp", jtimestamp);
                                }

                            if ( json_object_object_get_ex(json_obj, "proto", &tmp) )
                                {
                                    json_object *jproto = json_object_new_string( json_object_get_string(tmp) );
                                    json_object_object_add(encode_json_flow,"proto", jproto);
                                }

                            if ( json_object_object_get_ex(json_obj, "host", &tmp) )
                                {
                                    json_object *jhost = json_object_new_string( json_object_get_string(tmp) );
                                    json_object_object_add(encode_json_flow,"host", jhost);
                                }

                            /* Set a default value */

                            if ( json_object_object_get_ex(json_obj, "app_proto", &tmp) )
                                {
                                    json_object *japp_proto = json_object_new_string( json_object_get_string(tmp) );
                                    json_object_object_add(encode_json_flow,"app_proto", japp_proto);

                                }

                            if ( json_object_object_get_ex(json_obj_state, "bytes_toserver", &tmp) )
                                {

                                    json_object *jbytes_toserver = json_object_new_int64( json_object_get_int64(tmp) );
                                    json_object_object_add(encode_json_flow,"bytes_toserver", jbytes_toserver);
                                }

                            if ( json_object_object_get_ex(json_obj_state, "bytes_toclient", &tmp) )
                                {
                                    json_object *jbytes_toclient = json_object_new_int64( json_object_get_int64(tmp) );
                                    json_object_object_add(encode_json_flow,"bytes_toclient", jbytes_toclient);

                                }

                            if ( json_object_object_get_ex(json_obj_state, "age", &tmp) )
                                {
                                    json_object *jage = json_object_new_int64( json_object_get_int64(tmp) );
                                    json_object_object_add(encode_json_flow,"age", jage);

                                }

                            if ( json_object_object_get_ex(json_obj_state, "state", &tmp) )
                                {
                                    json_object *jstate = json_object_new_int64( json_object_get_int64(tmp) );
                                    json_object_object_add(encode_json_flow,"state", jstate);

                                }

                            if ( json_object_object_get_ex(json_obj_state, "reason", &tmp) )
                                {
                                    json_object *jreason = json_object_new_string( json_object_get_string(tmp) );
                                    json_object_object_add(encode_json_flow,"reason", jreason);
                                }

                            if ( json_object_object_get_ex(json_obj_state, "alerted", &tmp) )
                                {
                                    json_object *jalerted = json_object_new_boolean( json_object_get_boolean(tmp) );
                                    json_object_object_add(encode_json_flow,"alerted", jalerted);

                                }

                            if ( json_object_object_get_ex(json_obj_state, "start", &tmp) )
                                {
                                    json_object *jstart = json_object_new_string( json_object_get_string(tmp) );
                                    json_object_object_add(encode_json_flow,"start", jstart);

                                }

                            if ( json_object_object_get_ex(json_obj_state, "end", &tmp) )
                                {
                                    json_object *jend = json_object_new_string( json_object_get_string(tmp) );
                                    json_object_object_add(encode_json_flow,"end", jend);
                                }

                            /* Create new "id" based off the IP address */

                            MD5( (uint8_t*)tmp_ip, strlen(tmp_ip), id_md5, sizeof(id_md5) );

                            if ( MeerConfig->ndp_debug == true )
                                {
                                    Meer_Log(DEBUG, "[%s, line %d] INSERT FLOW %s: %s", __FILE__, __LINE__, id_md5, json_object_to_json_string(encode_json_flow) );
                                }

                            MeerCounters->ndp++;
                            strlcpy(last_flow_id, id_md5, MD5_SIZE);
                            Output_Elasticsearch ( (char*)json_object_to_json_string(encode_json_flow), "ndp", id_md5 );

                            json_object_put(encode_json_flow);

                        }
                }
        }

    json_object_put(json_obj_state);

}

/**************************************/
/* NDP_FileInfo - Collect file hashes */
/**************************************/

void NDP_FileInfo( struct json_object *json_obj, const char *src_ip, const char *dest_ip, const char *flow_id )
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

                            if ( MeerConfig->ndp_debug == true )
                                {
                                    Meer_Log(DEBUG, "[%s, line %d] SKIP FILEINFO: %s", __FILE__, __LINE__, md5 );
                                }

                            MeerCounters->ndp_skip++;
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

    struct json_object *encode_json_fileinfo = NULL;
    encode_json_fileinfo = json_object_new_object();

    json_object *jtype = json_object_new_string( "fileinfo" );
    json_object_object_add(encode_json_fileinfo,"type", jtype);

    json_object *jsrc_ip = json_object_new_string( src_ip );
    json_object_object_add(encode_json_fileinfo,"src_ip", jsrc_ip);

    json_object *jdest_ip = json_object_new_string( dest_ip );
    json_object_object_add(encode_json_fileinfo,"dest_ip", jdest_ip);

    if ( src_dns[0] != '\0' )
        {
            json_object *jsrc_dns = json_object_new_string( src_dns );
            json_object_object_add(encode_json_fileinfo,"src_dns", jsrc_dns);
        }

    if ( dest_dns[0] != '\0' )
        {
            json_object *jdest_dns = json_object_new_string( dest_dns );
            json_object_object_add(encode_json_fileinfo,"dest_dns", jdest_dns);
        }

    if ( timestamp[0] != '\0' )
        {
            json_object *jtimestamp = json_object_new_string( timestamp );
            json_object_object_add(encode_json_fileinfo,"timestamp", jtimestamp);
        }

    if ( app_proto[0] != '\0' )
        {
            json_object *japp_proto = json_object_new_string( app_proto );
            json_object_object_add(encode_json_fileinfo,"app_proto", japp_proto);
        }

    if ( md5[0] != '\0' )
        {
            json_object *jmd5 = json_object_new_string( md5 );
            json_object_object_add(encode_json_fileinfo,"md5", jmd5);
        }

    if ( sha1[0] != '\0' )
        {
            json_object *jsha1 = json_object_new_string( sha1 );
            json_object_object_add(encode_json_fileinfo,"sha1", jsha1);
        }

    if ( sha256[0] != '\0' )
        {
            json_object *jsha256 = json_object_new_string( sha256 );
            json_object_object_add(encode_json_fileinfo,"sha256", jsha256);
        }

    if ( filename[0] != '\0' )
        {
            json_object *jfilename = json_object_new_string( filename );
            json_object_object_add(encode_json_fileinfo,"filename", jfilename);
        }

    if ( magic[0] != '\0' )
        {
            json_object *jmagic = json_object_new_string( magic );
            json_object_object_add(encode_json_fileinfo,"magic", jmagic);
        }

    /* Size can be zero */

    json_object *jsize = json_object_new_int64( size );
    json_object_object_add(encode_json_fileinfo,"size", jsize);

    json_object *jflow_id = json_object_new_string( flow_id );
    json_object_object_add(encode_json_fileinfo,"flow_id", jflow_id);

    if ( host[0] != '\0' )
        {
            json_object *jhost = json_object_new_string( host );
            json_object_object_add(encode_json_fileinfo,"host", jhost);
        }

    if ( MeerConfig->description[0] != '\0' )
        {
            json_object *jdesc = json_object_new_string( MeerConfig->description );
            json_object_object_add(encode_json_fileinfo,"description", jdesc);
        }

    if ( MeerConfig->ndp_debug == true )
        {
            Meer_Log(DEBUG, "[%s, line %d] INSERT FILEINFO: %s, %s", __FILE__, __LINE__, md5, json_object_to_json_string(encode_json_fileinfo) );
        }

    MeerCounters->ndp++;
    strlcpy(last_fileinfo_id, md5, MD5_SIZE);
    Output_Elasticsearch ( (char*)json_object_to_json_string(encode_json_fileinfo), "ndp", md5 );

    json_object_put(encode_json_fileinfo);
    json_object_put(json_obj_fileinfo);

}

/********************************************/
/* NDP_TLS - Collect SNI, expire dates, etc */
/********************************************/

void NDP_TLS( struct json_object *json_obj, const char *src_ip, const char *dest_ip, const char *flow_id )
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

            MeerCounters->ndp_skip++;

            if ( MeerConfig->ndp_debug == true )
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

    struct json_object *encode_json_tls = NULL;
    encode_json_tls = json_object_new_object();

    json_object *jtype = json_object_new_string( "tls" );
    json_object_object_add(encode_json_tls,"type", jtype);

    json_object *jflow_id = json_object_new_string( flow_id );
    json_object_object_add(encode_json_tls,"flow_id", jflow_id);

    json_object *jsrc_ip = json_object_new_string( src_ip );
    json_object_object_add(encode_json_tls,"src_ip", jsrc_ip);

    json_object *jdest_ip = json_object_new_string( dest_ip );
    json_object_object_add(encode_json_tls,"dest_ip", jdest_ip);

    if ( src_dns[0] != '\0' )
        {
            json_object *jsrc_dns = json_object_new_string( src_dns );
            json_object_object_add(encode_json_tls,"src_dns", jsrc_dns);
        }

    if ( dest_dns[0] != '\0' )
        {
            json_object *jdest_dns = json_object_new_string( dest_dns );
            json_object_object_add(encode_json_tls,"dest_dns", jdest_dns);
        }

    if ( timestamp[0] != '\0' )
        {
            json_object *jtimestamp = json_object_new_string( timestamp );
            json_object_object_add(encode_json_tls,"timestamp", jtimestamp);
        }

    if ( fingerprint[0] != '\0' )
        {
            json_object *jfingerprint = json_object_new_string( fingerprint );
            json_object_object_add(encode_json_tls,"fingerprint", jfingerprint);
        }

    if ( issuerdn[0] != '\0' )
        {
            json_object *jissuerdn = json_object_new_string( issuerdn );
            json_object_object_add(encode_json_tls,"issuerdn", jissuerdn);
        }

    if ( subject[0] != '\0' )
        {
            json_object *jsubject = json_object_new_string( subject );
            json_object_object_add(encode_json_tls,"subject", jsubject );
        }

    if ( serial[0] != '\0' )
        {
            json_object *jserial = json_object_new_string( serial );
            json_object_object_add(encode_json_tls,"serial", jserial );
        }

    if ( sni[0] != '\0' )
        {
            json_object *jsni = json_object_new_string( sni );
            json_object_object_add(encode_json_tls,"sni", jsni );
        }

    if ( version[0] != '\0' )
        {
            json_object *jversion = json_object_new_string( version );
            json_object_object_add(encode_json_tls,"version", jversion );
        }

    if ( notbefore[0] != 0 )
        {
            json_object *jnotbefore = json_object_new_string( notbefore );
            json_object_object_add(encode_json_tls,"notbefore", jnotbefore );
        }

    if ( notafter[0] != 0 )
        {
            json_object *jnotafter = json_object_new_string( notafter );
            json_object_object_add(encode_json_tls,"notafter", jnotafter );
        }

    /* We've already tested for JA3/JA3S */

    json_object *jja3 = json_object_new_string( ja3 );
    json_object_object_add(encode_json_tls,"ja3", jja3 );

    json_object *jja3s = json_object_new_string( ja3s );
    json_object_object_add(encode_json_tls,"ja3s", jja3s );

    if ( host[0] != '\0' )
        {
            json_object *jhost = json_object_new_string( host );
            json_object_object_add(encode_json_tls,"host", jhost);
        }

    if ( MeerConfig->description[0] != '\0' )
        {
            json_object *jdesc = json_object_new_string( MeerConfig->description );
            json_object_object_add(encode_json_tls,"description", jdesc);
        }

    if ( MeerConfig->ndp_debug == true )
        {
            Meer_Log(DEBUG, "[%s, line %d] INSERT TLS: %s: %s", __FILE__, __LINE__, id_md5, json_object_to_json_string(encode_json_tls) );
        }

    MeerCounters->ndp++;
    strlcpy(last_tls_id, id_md5, MD5_SIZE);
    Output_Elasticsearch ( (char*)json_object_to_json_string(encode_json_tls), "ndp", id_md5 );

    json_object_put(encode_json_tls);
    json_object_put(json_obj_ja3);
    json_object_put(json_obj_ja3s);
    json_object_put(json_obj_tls);

}

/*********************************************/
/* NDP_DNS - Collect "queries" (not answers) */
/*********************************************/

void NDP_DNS( struct json_object *json_obj, const char *src_ip, const char *dest_ip, const char *flow_id )
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

                                            if ( MeerConfig->ndp_debug == true )
                                                {
                                                    Meer_Log(DEBUG, "[%s, line %d] SKIP DNS: %s", __FILE__, __LINE__, id_md5 );
                                                }

                                            MeerCounters->ndp_skip++;

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

                                    json_object_put(json_obj_dns);
                                    return;

                                }

                        }
                    else
                        {

                            /* There's isn't a type! */

                            json_object_put(json_obj_dns);
                            return;

                        }
                }

            /**************************************************/
            /* New JSON Object                                */
            /**************************************************/

            struct json_object *encode_json_dns = NULL;
            encode_json_dns = json_object_new_object();

            json_object *jtype = json_object_new_string( "dns" );
            json_object_object_add(encode_json_dns,"type", jtype);

            if ( src_dns[0] != '\0' )
                {
                    json_object *jsrc_dns = json_object_new_string( src_dns );
                    json_object_object_add(encode_json_dns,"src_dns", jsrc_dns);
                }

            if ( dest_dns[0] != '\0' )
                {
                    json_object *jdest_dns = json_object_new_string( dest_dns );
                    json_object_object_add(encode_json_dns,"dest_dns", jdest_dns);
                }

            if ( timestamp[0] != '\0' )
                {
                    json_object *jtimestamp = json_object_new_string( timestamp );
                    json_object_object_add(encode_json_dns,"timestamp", jtimestamp);
                }

            if ( src_ip[0] != '\0' )
                {
                    json_object *jsrc_ip = json_object_new_string( src_ip );
                    json_object_object_add(encode_json_dns,"src_ip", jsrc_ip);
                }

            if ( dest_ip[0] != '\0' )
                {
                    json_object *jdest_ip = json_object_new_string( dest_ip );
                    json_object_object_add(encode_json_dns,"dest_ip", jdest_ip);
                }


            json_object *jflow_id = json_object_new_string( flow_id );
            json_object_object_add(encode_json_dns,"flow_id", jflow_id);

            if ( rrname[0] != '\0' )
                {
                    json_object *jrrname = json_object_new_string( rrname );
                    json_object_object_add(encode_json_dns,"rrname", jrrname);
                }

            if ( rrtype[0] != '\0' )
                {
                    json_object *jrrtype = json_object_new_string( rrtype );
                    json_object_object_add(encode_json_dns,"rrtype", jrrtype);
                }

            if ( host[0] != '\0' )
                {
                    json_object *jhost = json_object_new_string( host );
                    json_object_object_add(encode_json_dns,"host", jhost);
                }

            if ( MeerConfig->description[0] != '\0' )
                {
                    json_object *jdesc = json_object_new_string( MeerConfig->description );
                    json_object_object_add(encode_json_dns,"description", jdesc);
                }

            if ( MeerConfig->ndp_debug == true )
                {
                    Meer_Log(DEBUG, "[%s, line %d] INSERT DNS: %s: %s", __FILE__, __LINE__, id_md5, json_object_to_json_string(encode_json_dns) );
                }

            MeerCounters->ndp++;
            strlcpy(last_dns_id, id_md5, MD5_SIZE);
            Output_Elasticsearch ( (char*)json_object_to_json_string(encode_json_dns), "ndp", id_md5 );

            json_object_put(encode_json_dns);

        }

    json_object_put(json_obj_dns);

}

/********************************************/
/* NDP_SSH - Collect SSH version / banners */
/********************************************/

void NDP_SSH( struct json_object *json_obj, const char *src_ip, const char *dest_ip, const char *flow_id )
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

    struct json_object *encode_json_ssh = NULL;
    encode_json_ssh = json_object_new_object();

    json_object *jtype = json_object_new_string( "ssh" );
    json_object_object_add(encode_json_ssh,"type", jtype);

    json_object *jsrc_ip = json_object_new_string( src_ip );
    json_object_object_add(encode_json_ssh,"src_ip", jsrc_ip);

    json_object *jdest_ip = json_object_new_string( dest_ip );
    json_object_object_add(encode_json_ssh,"dest_ip", jdest_ip);

    json_object *jflow_id = json_object_new_string( flow_id );
    json_object_object_add(encode_json_ssh,"flow_id", jflow_id);

    if ( src_dns[0] != '\0' )
        {
            json_object *jsrc_dns = json_object_new_string( src_dns );
            json_object_object_add(encode_json_ssh,"src_dns", jsrc_dns);
        }

    if ( dest_dns[0] != '\0' )
        {
            json_object *jdest_dns = json_object_new_string( dest_dns );
            json_object_object_add(encode_json_ssh,"dest_dns", jdest_dns);
        }

    if ( timestamp[0] != '\0' )
        {
            json_object *jtimestamp = json_object_new_string( timestamp );
            json_object_object_add(encode_json_ssh,"timestamp", jtimestamp);
        }

    if ( src_port != 0 )
        {
            json_object *jsrc_port = json_object_new_int( src_port );
            json_object_object_add(encode_json_ssh,"src_port", jsrc_port);
        }

    if ( dest_port != 0 )
        {
            json_object *jdest_port = json_object_new_int( dest_port );
            json_object_object_add(encode_json_ssh,"dest_port", jdest_port);
        }

    if ( host[0] != '\0' )
        {
            json_object *jhost = json_object_new_string( host );
            json_object_object_add(encode_json_ssh,"host", jhost);
        }

    if ( MeerConfig->description[0] != '\0' )
        {
            json_object *jdesc = json_object_new_string( MeerConfig->description );
            json_object_object_add(encode_json_ssh,"description", jdesc);
        }

    if ( proto_version[0] != '\0' )
        {
            json_object *jproto_version = json_object_new_string( proto_version );
            json_object_object_add(encode_json_ssh,"proto_version", jproto_version);
        }

    if ( server_version[0] != '\0' )
        {
            json_object *jserver_version = json_object_new_string( server_version );
            json_object_object_add(encode_json_ssh,"server_version", jserver_version);
        }

    if ( client_version[0] != '\0' )
        {
            json_object *jclient_version = json_object_new_string( client_version );
            json_object_object_add(encode_json_ssh,"client_version", jclient_version);
        }

    snprintf(tmp_id, sizeof(tmp_id), "%s:%d:%s:%s", dest_ip, dest_port, server_version, client_version);
    tmp_id[ sizeof( tmp_id ) - 1] = '\0';

    MD5( (uint8_t*)tmp_id, strlen(tmp_id), id_md5, sizeof(id_md5) );

    /* Is this a repeat log */

    if ( strcmp(last_ssh_id, id_md5 ) )
        {

            if ( MeerConfig->ndp_debug == true )
                {
                    Meer_Log(DEBUG, "[%s, line %d] INSERT SSH: %s: %s", __FILE__, __LINE__, id_md5, json_object_to_json_string(encode_json_ssh) );
                }

            MeerCounters->ndp++;
            strlcpy(last_ssh_id, id_md5, MD5_SIZE);
            Output_Elasticsearch ( (char*)json_object_to_json_string(encode_json_ssh), "ndp", id_md5 );
        }
    else
        {

            if ( MeerConfig->ndp_debug == true )
                {
                    Meer_Log(DEBUG, "[%s, line %d] SKIP SSH: %s: %s", __FILE__, __LINE__, id_md5, json_object_to_json_string(encode_json_ssh) );
                }

            MeerCounters->ndp_skip++;
        }

    json_object_put(encode_json_ssh);
    json_object_put(json_obj_ssh);
    json_object_put(json_obj_ssh_client);
    json_object_put(json_obj_ssh_server);

}

/**********************************************/
/* NDP_HTTP - Collects user agents, URLs, etc */
/**********************************************/

void NDP_HTTP( struct json_object *json_obj, const char *src_ip, const char *dest_ip, const char *flow_id )
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

            if ( !strcmp(last_http_id, id_md5 ) )
                {

                    MeerCounters->ndp_skip++;

                    if ( MeerConfig->ndp_debug == true )
                        {
                            Meer_Log(DEBUG, "[%s, line %d] HTTP URL SKIP: %s", __FILE__, __LINE__, id_md5 );
                        }


                    json_object_put(json_obj_http);

                    return;

                }

            /****************************************/
            /* New HTTP JSON object                 */
            /****************************************/

            struct json_object *encode_json_http = NULL;
            encode_json_http = json_object_new_object();

            json_object *jtype = json_object_new_string( "http" );
            json_object_object_add(encode_json_http,"type", jtype);

            json_object *jsrc_ip = json_object_new_string( src_ip );
            json_object_object_add(encode_json_http,"src_ip", jsrc_ip);

            json_object *jdest_ip = json_object_new_string( dest_ip );
            json_object_object_add(encode_json_http,"dest_ip", jdest_ip);

            json_object *jflow_id = json_object_new_string( flow_id );
            json_object_object_add(encode_json_http,"flow_id", jflow_id);

            if ( src_dns[0] != '\0' )
                {
                    json_object *jsrc_dns = json_object_new_string( src_dns );
                    json_object_object_add(encode_json_http,"src_dns", jsrc_dns);
                }

            if ( dest_dns[0] != '\0' )
                {
                    json_object *jdest_dns = json_object_new_string( dest_dns );
                    json_object_object_add(encode_json_http,"dest_dns", jdest_dns);
                }

            if ( timestamp[0] != '\0' )
                {
                    json_object *jtimestamp = json_object_new_string( timestamp );
                    json_object_object_add(encode_json_http,"timestamp", jtimestamp);
                }

            if ( MeerConfig->description[0] != '\0' )
                {
                    json_object *jdesc = json_object_new_string( MeerConfig->description );
                    json_object_object_add(encode_json_http,"description", jdesc);
                }

            if ( host[0] != '\0' )
                {
                    json_object *jhost = json_object_new_string( host );
                    json_object_object_add(encode_json_http,"host", jhost);
                }

            json_object *jfull_url = json_object_new_string( full_url );
            json_object_object_add(encode_json_http,"url", jfull_url);

            if ( http_user_agent[0] != '\0' )
                {
                    json_object *juser_agent = json_object_new_string( http_user_agent );
                    json_object_object_add(encode_json_http,"user_agent", juser_agent);
                }

            if ( method[0] != '\0' )
                {
                    json_object *jmethod = json_object_new_string( method );
                    json_object_object_add(encode_json_http,"method", jmethod);
                }

            json_object *jstatus = json_object_new_int( status );
            json_object_object_add(encode_json_http,"status", jstatus);

            json_object *jlength = json_object_new_int( length);
            json_object_object_add(encode_json_http,"length", jlength);

            if ( MeerConfig->ndp_debug == true )
                {
                    Meer_Log(DEBUG, "[%s, line %d] INSERT HTTP URL: %s: %s", __FILE__, __LINE__, id_md5, json_object_to_json_string(encode_json_http) );
                }


            MeerCounters->ndp++;
            strlcpy(last_http_id, id_md5, MD5_SIZE);
            Output_Elasticsearch ( (char*)json_object_to_json_string(encode_json_http), "ndp", id_md5 );

            json_object_put(encode_json_http);

            /* Check User_agent */

            MD5( (uint8_t*)http_user_agent, strlen(http_user_agent), id_md5, sizeof(id_md5) );

            if ( !strcmp(last_user_agent_id, id_md5 ) )
                {

                    MeerCounters->ndp_skip++;

                    if ( MeerConfig->ndp_debug == true )
                        {
                            Meer_Log(DEBUG, "[%s, line %d] SKIP HTTP USER_AGENT: %s", __FILE__, __LINE__, id_md5);
                        }

                    json_object_put(json_obj_http);

                    return;
                }

            /****************************************/
            /* New User Agent Object                */
            /****************************************/

            struct json_object *encode_json_user_agent = NULL;
            encode_json_user_agent = json_object_new_object();

            json_object *jtype_ua = json_object_new_string( "user_agent" );
            json_object_object_add(encode_json_user_agent,"type", jtype_ua);

            if ( src_dns[0] != '\0' )
                {
                    json_object *jsrc_dns = json_object_new_string( src_dns );
                    json_object_object_add(encode_json_user_agent,"src_dns", jsrc_dns);
                }

            if ( dest_dns[0] != '\0' )
                {
                    json_object *jdest_dns = json_object_new_string( dest_dns );
                    json_object_object_add(encode_json_user_agent,"dest_dns", jdest_dns);
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

            if ( MeerConfig->ndp_debug == true )
                {
                    Meer_Log(DEBUG, "[%s, line %d] INSERT USER_AGENT: %s: %s", __FILE__, __LINE__, id_md5, json_object_to_json_string(encode_json_user_agent) );
                }

            MeerCounters->ndp++;
            strlcpy(last_user_agent_id, id_md5, MD5_SIZE);
            Output_Elasticsearch ( (char*)json_object_to_json_string(encode_json_user_agent), "ndp", id_md5 );

            json_object_put(encode_json_user_agent);

        }

    json_object_put(json_obj_http);

}

/************************************************************************/
/* NDP_SMB - Grab data from SMB2_COMMAND_CREATE, SMB2_COMMAND_READ. and */
/* SMB2_COMMAND_WRITE.  SMB is used a lot in lateral movement.          */
/************************************************************************/

void NDP_SMB( struct json_object *json_obj, const char *src_ip, const char *dest_ip, const char *flow_id  )
{

    char timestamp[64] = { 0 };
    char host[64] = { 0 };

    char id_md5[MD5_SIZE] = { 0 };
    bool flag = false;
    uint8_t i = 0;

    char smb_command[64] = { 0 };
    char smb_filename[10240] = { 0 };

    char src_dns[256] = { 0 };
    char dest_dns[256] = { 0 };

    char command_filename[64 + 10240 + 1] = { 0 };   /* SMB_COMMAND|/file/path */

    struct json_object *tmp = NULL;
    struct json_object *json_obj_smb = NULL;

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

                    /* Is the a SMB command we care about? */

                    for ( i = 0; i < MeerCounters->SMB_Command_Count; i++ )
                        {
                            if ( !strcmp( smb_command, NDP_SMB_Commands[i].command) )
                                {
                                    flag = true;
                                    continue;
                                }
                        }

                    if ( flag == true )
                        {

                            if ( json_object_object_get_ex(json_obj_smb, "filename", &tmp) )
                                {

                                    strlcpy(smb_filename, json_object_get_string(tmp), sizeof( smb_filename ) );

                                    snprintf(command_filename, sizeof(command_filename), "%s|%s", smb_command, smb_filename);
                                    command_filename[ sizeof(command_filename) - 1] = '\0';

                                    MD5( (uint8_t*)command_filename, strlen(command_filename), id_md5, sizeof(id_md5) );

                                    if ( !strcmp(last_smb_id, id_md5 ) )
                                        {

                                            MeerCounters->ndp_skip++;

                                            if ( MeerConfig->ndp_debug == true )
                                                {
                                                    Meer_Log(DEBUG, "[%s, line %d] SKIP SMB: %s", __FILE__, __LINE__, id_md5 );
                                                }

                                            json_object_put(json_obj_smb);
                                            return;

                                        }

                                    /****************************************/
                                    /* New SMB JSON object                   */
                                    /****************************************/

                                    struct json_object *encode_json_smb = NULL;
                                    encode_json_smb = json_object_new_object();

                                    json_object *jtype = json_object_new_string( "smb" );
                                    json_object_object_add(encode_json_smb,"type", jtype);

                                    json_object *jsrc_ip = json_object_new_string( src_ip );
                                    json_object_object_add(encode_json_smb,"src_ip", jsrc_ip);

                                    json_object *jdest_ip = json_object_new_string( dest_ip );
                                    json_object_object_add(encode_json_smb,"dest_ip", jdest_ip);

                                    json_object *jflow_id = json_object_new_string( flow_id );
                                    json_object_object_add(encode_json_smb,"flow_id", jflow_id);

                                    if ( src_dns[0] != '\0' )
                                        {
                                            json_object *jsrc_dns = json_object_new_string( src_dns );
                                            json_object_object_add(encode_json_smb,"src_dns", jsrc_dns);
                                        }

                                    if ( dest_dns[0] != '\0' )
                                        {
                                            json_object *jdest_dns = json_object_new_string( dest_dns );
                                            json_object_object_add(encode_json_smb,"dest_dns", jdest_dns);
                                        }

                                    if ( timestamp[0] != '\0' )
                                        {
                                            json_object *jtimestamp = json_object_new_string( timestamp );
                                            json_object_object_add(encode_json_smb,"timestamp", jtimestamp);
                                        }

                                    if ( MeerConfig->description[0] != '\0' )
                                        {
                                            json_object *jdesc = json_object_new_string( MeerConfig->description );
                                            json_object_object_add(encode_json_smb,"description", jdesc);
                                        }

                                    if ( host[0] != '\0' )
                                        {
                                            json_object *jhost = json_object_new_string( host );
                                            json_object_object_add(encode_json_smb,"host", jhost);
                                        }

                                    if ( smb_command[0] != '\0' )
                                        {
                                            json_object *jsmb_command = json_object_new_string( smb_command );
                                            json_object_object_add(encode_json_smb,"command", jsmb_command);
                                        }

                                    if ( smb_filename[0] != '\0' )
                                        {
                                            json_object *jsmb_filename = json_object_new_string( smb_filename );
                                            json_object_object_add(encode_json_smb,"filename", jsmb_filename);
                                        }

                                    if ( MeerConfig->ndp_debug == true )
                                        {
                                            Meer_Log(DEBUG, "[%s, line %d] INSERT SMB %s: %s", __FILE__, __LINE__, id_md5, json_object_to_json_string(encode_json_smb) );
                                        }


                                    MeerCounters->ndp++;
                                    strlcpy(last_smb_id, id_md5, MD5_SIZE);
                                    Output_Elasticsearch ( (char*)json_object_to_json_string(encode_json_smb), "ndp", id_md5 );

                                    json_object_put(encode_json_smb);


                                }
                        }
                }
        }

    json_object_put(json_obj_smb);

}

/*****************************************************/
/* NDP_FTP - Grabs files sent, received and username */
/*****************************************************/

void NDP_FTP( struct json_object *json_obj, const char *src_ip, const char *dest_ip, const char *flow_id )
{

    char timestamp[64] = { 0 };
    char host[64] = { 0 };

    bool flag = false;
    uint8_t i = 0;

    char id_md5[MD5_SIZE] = { 0 };

    char ftp_command[64] = { 0 };
    char ftp_command_data[10240] = { 0 };
    char ftp_plus_data[10240+64+1] = { 0 }; 		/* COMMAND|COMMAND_DATA */

    struct json_object *tmp = NULL;
    struct json_object *json_obj_ftp = NULL;

    char src_dns[256] = { 0 };
    char dest_dns[256] = { 0 };

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

                    /* Is the a FTP command we care about? */

                    for ( i = 0; i < MeerCounters->FTP_Command_Count; i++ )
                        {
                            if ( !strcmp( ftp_command, NDP_FTP_Commands[i].command) )
                                {
                                    flag = true;
                                    continue;
                                }
                        }

                    if ( flag == true )
                        {

                            if ( json_object_object_get_ex(json_obj_ftp, "command_data", &tmp) )
                                {

                                    strlcpy(ftp_command_data, json_object_get_string(tmp), sizeof( ftp_command_data ) );


                                    snprintf(ftp_plus_data, sizeof(ftp_plus_data), "%s|%s", ftp_command, ftp_command_data);
                                    ftp_plus_data[ sizeof(ftp_plus_data) - 1] = '\0';

                                    MD5( (uint8_t*)ftp_plus_data, strlen(ftp_plus_data), id_md5, sizeof(id_md5) );

                                    if ( !strcmp(last_ftp_id, id_md5 ) )
                                        {

                                            MeerCounters->ndp_skip++;

                                            if ( MeerConfig->ndp_debug == true )
                                                {
                                                    Meer_Log(DEBUG, "[%s, line %d] SKIP FTP : %s", __FILE__, __LINE__, id_md5);
                                                }


                                            json_object_put(json_obj_ftp);
                                            return;

                                        }


                                    /****************************************/
                                    /* New FTP JSON object                  */
                                    /****************************************/

                                    struct json_object *encode_json_ftp = NULL;
                                    encode_json_ftp = json_object_new_object();

                                    json_object *jtype = json_object_new_string( "ftp" );
                                    json_object_object_add(encode_json_ftp,"type", jtype);

                                    json_object *jsrc_ip = json_object_new_string( src_ip );
                                    json_object_object_add(encode_json_ftp,"src_ip", jsrc_ip);

                                    json_object *jdest_ip = json_object_new_string( dest_ip );
                                    json_object_object_add(encode_json_ftp,"dest_ip", jdest_ip);

                                    json_object *jflow_id = json_object_new_string( flow_id );
                                    json_object_object_add(encode_json_ftp,"flow_id", jflow_id);

                                    if ( src_dns[0] != '\0' )
                                        {
                                            json_object *jsrc_dns = json_object_new_string( src_dns );
                                            json_object_object_add(encode_json_ftp,"src_dns", jsrc_dns);
                                        }

                                    if ( dest_dns[0] != '\0' )
                                        {
                                            json_object *jdest_dns = json_object_new_string( dest_dns );
                                            json_object_object_add(encode_json_ftp,"dest_dns", jdest_dns);
                                        }

                                    if ( timestamp[0] != '\0' )
                                        {
                                            json_object *jtimestamp = json_object_new_string( timestamp );
                                            json_object_object_add(encode_json_ftp,"timestamp", jtimestamp);
                                        }

                                    if ( MeerConfig->description[0] != '\0' )
                                        {
                                            json_object *jdesc = json_object_new_string( MeerConfig->description );
                                            json_object_object_add(encode_json_ftp,"description", jdesc);
                                        }

                                    if ( host[0] != '\0' )
                                        {
                                            json_object *jhost = json_object_new_string( host );
                                            json_object_object_add(encode_json_ftp,"host", jhost);
                                        }

                                    if ( ftp_command[0] != '\0' )
                                        {
                                            json_object *jftp_command = json_object_new_string( ftp_command );
                                            json_object_object_add(encode_json_ftp,"command", jftp_command);
                                        }

                                    if ( ftp_command_data[0] != '\0' )
                                        {
                                            json_object *jftp_command_data = json_object_new_string( ftp_command_data );
                                            json_object_object_add(encode_json_ftp,"command_data", jftp_command_data);
                                        }

                                    if ( MeerConfig->ndp_debug == true )
                                        {
                                            Meer_Log(DEBUG, "[%s, line %d] INSERT FTP : %s: %s", __FILE__, __LINE__, id_md5, json_object_to_json_string(encode_json_ftp) );
                                        }


                                    MeerCounters->ndp++;
                                    strlcpy(last_ftp_id, id_md5, MD5_SIZE);
                                    Output_Elasticsearch ( (char*)json_object_to_json_string(encode_json_ftp), "ndp", id_md5 );

                                    json_object_put(encode_json_ftp);


                                }
                        }
                }
        }

    json_object_put(json_obj_ftp);

}

/***************************************************************/
/* NDP_In_Range - validate IP are within range of what we care */
/* about                                                       */
/***************************************************************/

bool NDP_In_Range( char *ip_address )
{

    uint16_t z = 0;
    bool valid_fingerprint_net = false;
    unsigned char ip[MAXIPBIT] = { 0 };

    IP2Bit(ip_address, ip);

    for ( z = 0; z < MeerCounters->ndp_ignore_count; z++ )
        {
            if ( Is_Inrange( ip, (unsigned char *)&NDP_Ignore[z].range, 1) )
                {
                    valid_fingerprint_net = true;
                    break;
                }
        }

    return( valid_fingerprint_net );
}

#endif

