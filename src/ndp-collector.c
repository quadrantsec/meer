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

    char geoip_src[2048] = { 0 };
    char geoip_dest[2048] = { 0 };

    uint8_t i = 0;

    struct json_object *tmp = NULL;
    bool state_flag = false;

    char *new_json_string = malloc(MeerConfig->payload_buffer_size);

    if ( new_json_string == NULL )
        {
            Meer_Log(ERROR, "[%s, line %d] Fatal Error: Can't allocate memory! Abort!\n", __FILE__, __LINE__);
        }

    memset(new_json_string, 0, sizeof(MeerConfig->payload_buffer_size *sizeof(char) ) );

    char *geoip_tmp = malloc(MeerConfig->payload_buffer_size);

    if ( geoip_tmp == NULL )
        {
            Meer_Log(ERROR, "[%s, line %d] Fatal Error: Can't allocate memory! Abort!\n", __FILE__, __LINE__);
        }

    memset(geoip_tmp, 0, sizeof(MeerConfig->payload_buffer_size *sizeof(char) ) );

    MD5( (uint8_t*)src_ip, strlen(src_ip), id_md5, sizeof(id_md5) );

    if ( !strcmp( last_flow_id, id_md5 ) )
        {

            if ( MeerConfig->ndp_debug == true )
                {
                    Meer_Log(DEBUG, "[%s, line %d] SKIP FLOW %s", __FILE__, __LINE__, id_md5);
                }

            free(new_json_string);
            free(geoip_tmp);

            json_object_put(json_obj_flow);
            json_object_put(json_obj_state);

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

            free(new_json_string);
            free(geoip_tmp);

            json_object_put(json_obj_flow);
            json_object_put(json_obj_state);

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

                            if ( MeerConfig->dns == true )
                                {

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
                                }

#ifdef HAVE_LIBMAXMINDDB

                            if ( MeerConfig->geoip == true )
                                {
                                    if ( json_object_object_get_ex(json_obj, "geoip_src", &tmp) )
                                        {
                                            strlcpy(geoip_src,  (char*)json_object_get_string(tmp), sizeof(geoip_src));
                                        }

                                    if ( json_object_object_get_ex(json_obj, "geoip_dest", &tmp) )
                                        {
                                            strlcpy(geoip_dest,  (char*)json_object_get_string(tmp), sizeof(geoip_dest));
                                        }
                                }

#endif


                            if ( json_object_object_get_ex(json_obj, "timestamp", &tmp) )
                                {
                                    json_object *jtimestamp = json_object_new_string( json_object_get_string(tmp) );
                                    json_object_object_add(encode_json_flow,"timestamp", jtimestamp);
                                }

                            if ( json_object_object_get_ex(json_obj, "community_id", &tmp) )
                                {
                                    json_object *jcommunity_id = json_object_new_string( json_object_get_string(tmp) );
                                    json_object_object_add(encode_json_flow,"community_id", jcommunity_id);
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

                            /* Tried to do this properly with json-c, but kept leading to memory leaks.... and
                               if json_object_put() the object,  it would lead to faults! So, we are back to
                               string manipulation */

                            strlcpy(new_json_string, (char*)json_object_to_json_string(encode_json_flow), MeerConfig->payload_buffer_size );

                            if ( geoip_src[0] != '\0' )
                                {
                                    new_json_string[ strlen(new_json_string) - 2 ] = '\0';
                                    snprintf(geoip_tmp, MeerConfig->payload_buffer_size, "%s, \"geoip_src\": %s", new_json_string, geoip_src);

                                    geoip_tmp[ MeerConfig->payload_buffer_size - 1] = '\0';

                                    strlcpy(new_json_string, geoip_tmp, MeerConfig->payload_buffer_size);
                                    strlcat(new_json_string, " }", MeerConfig->payload_buffer_size);
                                }

                            if ( geoip_dest[0] != '\0' )
                                {
                                    new_json_string[ strlen(new_json_string) - 2 ] = '\0';
                                    snprintf(geoip_tmp, MeerConfig->payload_buffer_size, "%s, \"geoip_dest\": %s", new_json_string, geoip_dest);

                                    geoip_tmp[ MeerConfig->payload_buffer_size - 1] = '\0';

                                    strlcpy(new_json_string, geoip_tmp, MeerConfig->payload_buffer_size);
                                    strlcat(new_json_string, " }", MeerConfig->payload_buffer_size);
                                }

                            /* Create new "id" based off the IP address */

                            MD5( (uint8_t*)tmp_ip, strlen(tmp_ip), id_md5, sizeof(id_md5) );

                            if ( MeerConfig->ndp_debug == true )
                                {
                                    Meer_Log(DEBUG, "[%s, line %d] INSERT FLOW %s: %s", __FILE__, __LINE__, id_md5, json_object_to_json_string(encode_json_flow) );
                                }

                            MeerCounters->ndp++;
                            strlcpy(last_flow_id, id_md5, MD5_SIZE);
                            Output_Elasticsearch ( new_json_string, "ndp", id_md5 );

                            json_object_put(encode_json_flow);

                        }
                }
        }

    free(new_json_string);
    free(geoip_tmp);

    json_object_put(json_obj_state);

}

/**************************************/
/* NDP_FileInfo - Collect file hashes */
/**************************************/

void NDP_FileInfo( struct json_object *json_obj, const char *src_ip, const char *dest_ip, const char *flow_id )
{

    uint64_t size = 0;

    char md5[MD5_SIZE] = { 0 };

    char geoip_src[2048] = { 0 };
    char geoip_dest[2048] = { 0 };

    struct json_object *tmp = NULL;

    struct json_object *json_obj_fileinfo = NULL;

    struct json_object *encode_json_fileinfo = NULL;
    encode_json_fileinfo = json_object_new_object();

    char *new_json_string = malloc(MeerConfig->payload_buffer_size);

    if ( new_json_string == NULL )
        {
            Meer_Log(ERROR, "[%s, line %d] Fatal Error: Can't allocate memory! Abort!\n", __FILE__, __LINE__);
        }

    memset(new_json_string, 0, sizeof(MeerConfig->payload_buffer_size *sizeof(char) ) );

    char *geoip_tmp = malloc(MeerConfig->payload_buffer_size);

    if ( geoip_tmp == NULL )
        {
            Meer_Log(ERROR, "[%s, line %d] Fatal Error: Can't allocate memory! Abort!\n", __FILE__, __LINE__);
        }

    memset(geoip_tmp, 0, sizeof(MeerConfig->payload_buffer_size *sizeof(char) ) );

    json_object *jtype = json_object_new_string( "fileinfo" );
    json_object_object_add(encode_json_fileinfo,"type", jtype);

    json_object *jsrc_ip = json_object_new_string( src_ip );
    json_object_object_add(encode_json_fileinfo,"src_ip", jsrc_ip);

    json_object *jdest_ip = json_object_new_string( dest_ip );
    json_object_object_add(encode_json_fileinfo,"dest_ip", jdest_ip);

    json_object *jflow_id = json_object_new_string( flow_id );
    json_object_object_add(encode_json_fileinfo,"flow_id", jflow_id );

#ifdef HAVE_LIBMAXMINDDB

    if ( MeerConfig->geoip == true )
        {

            if ( json_object_object_get_ex(json_obj, "geoip_src", &tmp) )
                {
                    strlcpy(geoip_src,  (char*)json_object_to_json_string(tmp), sizeof(geoip_src));
                }

            if ( json_object_object_get_ex(json_obj, "geoip_dest", &tmp) )
                {
                    strlcpy(geoip_dest,  (char*)json_object_to_json_string(tmp), sizeof(geoip_dest));
                }

        }
#endif

    if ( MeerConfig->dns == true )
        {

            if ( json_object_object_get_ex(json_obj, "src_dns", &tmp) )
                {
                    json_object *jsrc_dns = json_object_new_string( json_object_get_string(tmp) );
                    json_object_object_add(encode_json_fileinfo,"src_dns", jsrc_dns);
                }

            if ( json_object_object_get_ex(json_obj, "dest_dns", &tmp) )
                {
                    json_object *jdest_dns = json_object_new_string( json_object_get_string(tmp) );
                    json_object_object_add(encode_json_fileinfo,"dest_dns", jdest_dns);
                }
        }

    if ( MeerConfig->description[0] != '\0' )
        {
            json_object *jdesc = json_object_new_string( MeerConfig->description );
            json_object_object_add(encode_json_fileinfo,"description", jdesc);
        }

    if ( json_object_object_get_ex(json_obj, "timestamp", &tmp) )
        {
            json_object *jtimestamp = json_object_new_string( json_object_get_string(tmp) );
            json_object_object_add(encode_json_fileinfo,"timestamp", jtimestamp);
        }

    if ( json_object_object_get_ex(json_obj, "community_id", &tmp) )
        {
            json_object *jcommunity_id = json_object_new_string( json_object_get_string(tmp) );
            json_object_object_add(encode_json_fileinfo,"community_id", jcommunity_id);
        }


    if ( json_object_object_get_ex(json_obj, "app_proto", &tmp) )
        {
            json_object *japp_proto = json_object_new_string( json_object_get_string(tmp) );
            json_object_object_add(encode_json_fileinfo,"app_proto", japp_proto);
        }

    if ( json_object_object_get_ex(json_obj, "host", &tmp) )
        {
            json_object *jhost = json_object_new_string( json_object_get_string(tmp) );
            json_object_object_add(encode_json_fileinfo,"host", jhost);
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

                            free(geoip_tmp);
                            free(new_json_string);

                            json_object_put(encode_json_fileinfo);
                            json_object_put(json_obj_fileinfo);

                            return;

                        }

                }

            if ( json_object_object_get_ex(json_obj_fileinfo, "sha1", &tmp) )
                {
                    json_object *jsha1 = json_object_new_string( json_object_get_string(tmp) );
                    json_object_object_add(encode_json_fileinfo,"sha1", jsha1);
                }

            if ( json_object_object_get_ex(json_obj_fileinfo, "sha256", &tmp) )
                {
                    json_object *jsha256 = json_object_new_string( json_object_get_string(tmp) );
                    json_object_object_add(encode_json_fileinfo,"sha256", jsha256);

                }

            if ( json_object_object_get_ex(json_obj_fileinfo, "filename", &tmp) )
                {
                    json_object *jfilename = json_object_new_string( json_object_get_string(tmp) );
                    json_object_object_add(encode_json_fileinfo,"filename", jfilename);
                }

            if ( json_object_object_get_ex(json_obj_fileinfo, "magic", &tmp) )
                {
                    json_object *jmagic = json_object_new_string( json_object_get_string(tmp) );
                    json_object_object_add(encode_json_fileinfo,"magic", jmagic);
                }

            if ( json_object_object_get_ex(json_obj_fileinfo, "size", &tmp) )
                {

                    json_object *jsize = json_object_new_int( json_object_get_int(tmp) );
                    json_object_object_add(encode_json_fileinfo,"size", jsize);

                }
        }

    /* Tried to do this properly with json-c, but kept leading to memory leaks.... and
           if json_object_put() the object,  it would lead to faults! So, we are back to
           string manipulation */


    strlcpy(new_json_string, (char*)json_object_to_json_string(encode_json_fileinfo), MeerConfig->payload_buffer_size );

    if ( geoip_src[0] != '\0' )
        {
            new_json_string[ strlen(new_json_string) - 2 ] = '\0';
            snprintf(geoip_tmp, MeerConfig->payload_buffer_size, "%s, \"geoip_src\": %s", new_json_string, geoip_src);

            geoip_tmp[ MeerConfig->payload_buffer_size - 1] = '\0';

            strlcpy(new_json_string, geoip_tmp, MeerConfig->payload_buffer_size);
            strlcat(new_json_string, " }", MeerConfig->payload_buffer_size);
        }

    if ( geoip_dest[0] != '\0' )
        {
            new_json_string[ strlen(new_json_string) - 2 ] = '\0';
            snprintf(geoip_tmp, MeerConfig->payload_buffer_size, "%s, \"geoip_dest\": %s", new_json_string, geoip_dest);

            geoip_tmp[ MeerConfig->payload_buffer_size - 1] = '\0';

            strlcpy(new_json_string, geoip_tmp, MeerConfig->payload_buffer_size);
            strlcat(new_json_string, " }", MeerConfig->payload_buffer_size);
        }


    if ( MeerConfig->ndp_debug == true )
        {
            Meer_Log(DEBUG, "[%s, line %d] INSERT FILEINFO: %s, %s", __FILE__, __LINE__, md5, json_object_to_json_string(encode_json_fileinfo) );
        }

    MeerCounters->ndp++;
    strlcpy(last_fileinfo_id, md5, MD5_SIZE);
    Output_Elasticsearch ( new_json_string, "ndp", md5 );

    free(geoip_tmp);
    free(new_json_string);

    json_object_put(encode_json_fileinfo);
    json_object_put(json_obj_fileinfo);

}

/********************************************/
/* NDP_TLS - Collect SNI, expire dates, etc */
/********************************************/

void NDP_TLS( struct json_object *json_obj, const char *src_ip, const char *dest_ip, const char *flow_id )
{

    char id_md5[MD5_SIZE] = { 0 };

    char ja3[41] = { 0 };
    char ja3s[41] = { 0 };

    char id[68] = { 0 };

    char geoip_src[2048] = { 0 };
    char geoip_dest[2048] = { 0 };

    struct json_object *tmp = NULL;
    struct json_object *json_obj_tls = NULL;
    struct json_object *json_obj_ja3 = NULL;
    struct json_object *json_obj_ja3s = NULL;

    struct json_object *encode_json_tls = NULL;
    encode_json_tls = json_object_new_object();

    char *new_json_string = malloc(MeerConfig->payload_buffer_size);

    if ( new_json_string == NULL )
        {
            Meer_Log(ERROR, "[%s, line %d] Fatal Error: Can't allocate memory! Abort!\n", __FILE__, __LINE__);
        }

    memset(new_json_string, 0, sizeof(MeerConfig->payload_buffer_size *sizeof(char) ) );

    char *geoip_tmp = malloc(MeerConfig->payload_buffer_size);

    if ( geoip_tmp == NULL )
        {
            Meer_Log(ERROR, "[%s, line %d] Fatal Error: Can't allocate memory! Abort!\n", __FILE__, __LINE__);
        }

    memset(geoip_tmp, 0, sizeof(MeerConfig->payload_buffer_size *sizeof(char) ) );

    json_object *jtype = json_object_new_string( "tls" );
    json_object_object_add(encode_json_tls,"type", jtype);

    json_object *jflow_id = json_object_new_string( flow_id );
    json_object_object_add(encode_json_tls,"flow_id", jflow_id);

    json_object *jsrc_ip = json_object_new_string( src_ip );
    json_object_object_add(encode_json_tls,"src_ip", jsrc_ip);

    json_object *jdest_ip = json_object_new_string( dest_ip );
    json_object_object_add(encode_json_tls,"dest_ip", jdest_ip);

#ifdef HAVE_LIBMAXMINDDB

    if ( MeerConfig->geoip == true )
        {

            if ( json_object_object_get_ex(json_obj, "geoip_src", &tmp) )
                {
                    strlcpy(geoip_src,  (char*)json_object_to_json_string(tmp), sizeof(geoip_src));
                }

            if ( json_object_object_get_ex(json_obj, "geoip_dest", &tmp) )
                {
                    strlcpy(geoip_dest,  (char*)json_object_to_json_string(tmp), sizeof(geoip_dest));
                }

        }
#endif

    if  ( MeerConfig->dns == true )
        {
            if ( json_object_object_get_ex(json_obj, "src_dns", &tmp) )
                {
                    json_object *jsrc_dns = json_object_new_string( json_object_get_string(tmp) );
                    json_object_object_add(encode_json_tls,"src_dns", jsrc_dns);
                }

            if ( json_object_object_get_ex(json_obj, "dest_dns", &tmp) )
                {
                    json_object *jdest_dns = json_object_new_string( json_object_get_string(tmp) );
                    json_object_object_add(encode_json_tls,"dest_dns", jdest_dns);
                }
        }

    if ( MeerConfig->description[0] != '\0' )
        {
            json_object *jdesc = json_object_new_string( MeerConfig->description );
            json_object_object_add(encode_json_tls,"description", jdesc);
        }

    if ( json_object_object_get_ex(json_obj, "timestamp", &tmp) )
        {
            json_object *jtimestamp = json_object_new_string( json_object_get_string(tmp) );
            json_object_object_add(encode_json_tls,"timestamp", jtimestamp);
        }

    if ( json_object_object_get_ex(json_obj, "community_id", &tmp) )
        {
            json_object *jcommunity_id = json_object_new_string( json_object_get_string(tmp) );
            json_object_object_add(encode_json_tls,"community_id", jcommunity_id);
        }

    if ( json_object_object_get_ex(json_obj, "host", &tmp) )
        {
            json_object *jhost = json_object_new_string( json_object_get_string(tmp) );
            json_object_object_add(encode_json_tls,"host", jhost);
        }

    if ( json_object_object_get_ex(json_obj, "tls", &tmp) )
        {

            json_obj_tls = json_tokener_parse(json_object_get_string(tmp));

            if ( json_object_object_get_ex(json_obj_tls, "fingerprint", &tmp) )
                {
                    json_object *jfingerprint = json_object_new_string( json_object_get_string(tmp) );
                    json_object_object_add(encode_json_tls,"fingerprint", jfingerprint);
                }

            if ( json_object_object_get_ex(json_obj_tls, "subject", &tmp) )
                {
                    json_object *jsubject = json_object_new_string( json_object_get_string(tmp) );
                    json_object_object_add(encode_json_tls,"subject", jsubject);

                }

            if ( json_object_object_get_ex(json_obj_tls, "issuerdn", &tmp) )
                {
                    json_object *jissuerdn = json_object_new_string( json_object_get_string(tmp) );
                    json_object_object_add(encode_json_tls,"issuerdn", jissuerdn);

                }

            if ( json_object_object_get_ex(json_obj_tls, "serial", &tmp) )
                {
                    json_object *jserial = json_object_new_string( json_object_get_string(tmp) );
                    json_object_object_add(encode_json_tls,"serial", jserial);
                }

            if ( json_object_object_get_ex(json_obj_tls, "sni", &tmp) )
                {
                    json_object *jsni = json_object_new_string( json_object_get_string(tmp) );
                    json_object_object_add(encode_json_tls,"sni", jsni);

                }

            if ( json_object_object_get_ex(json_obj_tls, "version", &tmp) )
                {
                    json_object *jversion = json_object_new_string( json_object_get_string(tmp) );
                    json_object_object_add(encode_json_tls,"version", jversion);
                }

            if ( json_object_object_get_ex(json_obj_tls, "notbefore", &tmp) )
                {
                    json_object *jnotbefore = json_object_new_string( json_object_get_string(tmp) );
                    json_object_object_add(encode_json_tls,"notbefore", jnotbefore);
                }

            if ( json_object_object_get_ex(json_obj_tls, "notafter", &tmp) )
                {
                    json_object *jnotafter = json_object_new_string( json_object_get_string(tmp) );
                    json_object_object_add(encode_json_tls,"notafter", jnotafter);

                }

            if ( json_object_object_get_ex(json_obj_tls, "ja3", &tmp) )
                {

                    json_obj_ja3 = json_tokener_parse(json_object_get_string(tmp));

                    if ( json_object_object_get_ex(json_obj_ja3, "hash", &tmp) )
                        {
                            strlcpy(ja3, json_object_get_string(tmp), sizeof(ja3) );
                            json_object *jja3 = json_object_new_string( json_object_get_string(tmp) );
                            json_object_object_add(encode_json_tls,"ja3", jja3);
                        }

                }

            if ( json_object_object_get_ex(json_obj_tls, "ja3s", &tmp) )
                {

                    json_obj_ja3s = json_tokener_parse(json_object_get_string(tmp));

                    if ( json_object_object_get_ex(json_obj_ja3s, "hash", &tmp) )
                        {
                            strlcpy(ja3s, json_object_get_string(tmp), sizeof(ja3s) );
                            json_object *jja3s = json_object_new_string( json_object_get_string(tmp) );
                            json_object_object_add(encode_json_tls,"ja3s", jja3s);
                        }
                }
        }

    /* If there is no JA3 or JA3S hash,  perhaps Suricata isn't setup right? */

    if ( ja3s[0] == '\0' && ja3[0] == '\0' )
        {
            Meer_Log(WARN, "[%s, line %d] No JA3 or JA3S hash located.  Are you sure Suricata is sending this data?", __FILE__, __LINE__);

            free(geoip_tmp);
            free(new_json_string);

            json_object_put(json_obj_ja3);
            json_object_put(json_obj_ja3s);
            json_object_put(json_obj_tls);
            json_object_put(encode_json_tls);

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

            free(geoip_tmp);
            free(new_json_string);

            json_object_put(json_obj_ja3);
            json_object_put(json_obj_ja3s);
            json_object_put(json_obj_tls);
            json_object_put(encode_json_tls);

            return;

        }

    /* Tried to do this properly with json-c, but kept leading to memory leaks.... and
           if json_object_put() the object,  it would lead to faults! So, we are back to
           string manipulation */


    strlcpy(new_json_string, (char*)json_object_to_json_string(encode_json_tls), MeerConfig->payload_buffer_size );

    if ( geoip_src[0] != '\0' )
        {
            new_json_string[ strlen(new_json_string) - 2 ] = '\0';
            snprintf(geoip_tmp, MeerConfig->payload_buffer_size, "%s, \"geoip_src\": %s", new_json_string, geoip_src);

            geoip_tmp[ MeerConfig->payload_buffer_size - 1] = '\0';

            strlcpy(new_json_string, geoip_tmp, MeerConfig->payload_buffer_size);
            strlcat(new_json_string, " }", MeerConfig->payload_buffer_size);
        }

    if ( geoip_dest[0] != '\0' )
        {
            new_json_string[ strlen(new_json_string) - 2 ] = '\0';
            snprintf(geoip_tmp, MeerConfig->payload_buffer_size, "%s, \"geoip_dest\": %s", new_json_string, geoip_dest);

            geoip_tmp[ MeerConfig->payload_buffer_size - 1] = '\0';

            strlcpy(new_json_string, geoip_tmp, MeerConfig->payload_buffer_size);
            strlcat(new_json_string, " }", MeerConfig->payload_buffer_size);
        }

    if ( MeerConfig->ndp_debug == true )
        {
            Meer_Log(DEBUG, "[%s, line %d] INSERT TLS: %s: %s", __FILE__, __LINE__, id_md5, json_object_to_json_string(encode_json_tls) );
        }

    MeerCounters->ndp++;
    strlcpy(last_tls_id, id_md5, MD5_SIZE);
    Output_Elasticsearch ( new_json_string, "ndp", id_md5 );

    free(geoip_tmp);
    free(new_json_string);

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

    char rrname[8192] = { 0 };

    char id_md5[MD5_SIZE] = { 0 };

    char geoip_src[2048] = { 0 };
    char geoip_dest[2048] = { 0 };

    struct json_object *tmp = NULL;
    struct json_object *json_obj_dns = NULL;

    struct json_object *encode_json_dns = NULL;
    encode_json_dns = json_object_new_object();

    char *new_json_string = malloc(MeerConfig->payload_buffer_size);

    if ( new_json_string == NULL )
        {
            Meer_Log(ERROR, "[%s, line %d] Fatal Error: Can't allocate memory! Abort!\n", __FILE__, __LINE__);
        }

    memset(new_json_string, 0, sizeof(MeerConfig->payload_buffer_size *sizeof(char) ) );

    char *geoip_tmp = malloc(MeerConfig->payload_buffer_size);

    if ( geoip_tmp == NULL )
        {
            Meer_Log(ERROR, "[%s, line %d] Fatal Error: Can't allocate memory! Abort!\n", __FILE__, __LINE__);
        }

    memset(geoip_tmp, 0, sizeof(MeerConfig->payload_buffer_size *sizeof(char) ) );

    json_object *jtype = json_object_new_string( "dns" );
    json_object_object_add(encode_json_dns,"type", jtype);

    json_object *jsrc_ip = json_object_new_string( src_ip );
    json_object_object_add(encode_json_dns,"src_ip", jsrc_ip);

    json_object *jdest_ip = json_object_new_string( dest_ip );
    json_object_object_add(encode_json_dns,"dest_ip", jdest_ip);

    json_object *jflow_id = json_object_new_string( flow_id );
    json_object_object_add(encode_json_dns,"flow_id", jflow_id);

    if ( MeerConfig->description[0] != '\0' )
        {
            json_object *jdesc = json_object_new_string( MeerConfig->description );
            json_object_object_add(encode_json_dns,"description", jdesc);
        }

#ifdef HAVE_LIBMAXMINDDB

    if ( MeerConfig->geoip == true )
        {

            if ( json_object_object_get_ex(json_obj, "geoip_src", &tmp) )
                {
                    strlcpy(geoip_src,  (char*)json_object_to_json_string(tmp), sizeof(geoip_src));
                }

            if ( json_object_object_get_ex(json_obj, "geoip_dest", &tmp) )
                {
                    strlcpy(geoip_src,  (char*)json_object_to_json_string(tmp), sizeof(geoip_src));
                }

        }

#endif


    if ( MeerConfig->dns == true )
        {

            if ( json_object_object_get_ex(json_obj, "src_dns", &tmp) )
                {
                    json_object *jsrc_dns = json_object_new_string( json_object_get_string(tmp) );
                    json_object_object_add(encode_json_dns,"src_dns", jsrc_dns);
                }

            if ( json_object_object_get_ex(json_obj, "dest_dns", &tmp) )
                {
                    json_object *jdest_dns = json_object_new_string( json_object_get_string(tmp) );
                    json_object_object_add(encode_json_dns,"dest_dns", jdest_dns);

                }

        }

    if ( json_object_object_get_ex(json_obj, "timestamp", &tmp) )
        {
            json_object *jtimestamp = json_object_new_string( json_object_get_string(tmp) );
            json_object_object_add(encode_json_dns,"timestamp", jtimestamp);

        }

    if ( json_object_object_get_ex(json_obj, "community_id", &tmp) )
        {
            json_object *jcommunity_id = json_object_new_string( json_object_get_string(tmp) );
            json_object_object_add(encode_json_dns,"community_id", jcommunity_id);
        }

    if ( json_object_object_get_ex(json_obj, "host", &tmp) )
        {
            json_object *jhost = json_object_new_string( json_object_get_string(tmp) );
            json_object_object_add(encode_json_dns,"host", jhost);

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

                                            free(geoip_tmp);
                                            free(new_json_string);

                                            json_object_put(encode_json_dns);
                                            json_object_put(json_obj_dns);
                                            return;

                                        }

                                    json_object *jrrname = json_object_new_string( json_object_get_string(tmp) );
                                    json_object_object_add(encode_json_dns,"rrname", jrrname);


                                    if ( json_object_object_get_ex(json_obj_dns, "rrtype", &tmp) )
                                        {
                                            json_object *jrrtype = json_object_new_string( json_object_get_string(tmp) );
                                            json_object_object_add(encode_json_dns,"rrtype", jrrtype);
                                        }

                                }
                            else
                                {

                                    /* It's not a "query", so skip it */

                                    free(geoip_tmp);
                                    free(new_json_string);

                                    json_object_put(encode_json_dns);
                                    json_object_put(json_obj_dns);
                                    return;

                                }

                        }
                    else
                        {

                            /* There's isn't a type! */

                            free(geoip_tmp);
                            free(new_json_string);

                            json_object_put(encode_json_dns);
                            json_object_put(json_obj_dns);
                            return;

                        }
                }

            /* Tried to do this properly with json-c, but kept leading to memory leaks.... and
               if json_object_put() the object,  it would lead to faults! So, we are back to
               string manipulation */

            strlcpy(new_json_string, (char*)json_object_to_json_string(encode_json_dns), MeerConfig->payload_buffer_size );

            if ( geoip_src[0] != '\0' )
                {
                    new_json_string[ strlen(new_json_string) - 2 ] = '\0';

                    snprintf(geoip_tmp, MeerConfig->payload_buffer_size, "%s, \"geoip_src\": %s", new_json_string, geoip_src);

                    geoip_tmp[ MeerConfig->payload_buffer_size - 1] = '\0';

                    strlcpy(new_json_string, geoip_tmp, MeerConfig->payload_buffer_size);
                    strlcat(new_json_string, " }", MeerConfig->payload_buffer_size);
                }

            if ( geoip_dest[0] != '\0' )
                {
                    new_json_string[ strlen(new_json_string) - 2 ] = '\0';

                    snprintf(geoip_tmp, MeerConfig->payload_buffer_size, "%s, \"geoip_dest\": %s", new_json_string, geoip_dest);

                    geoip_tmp[ MeerConfig->payload_buffer_size - 1] = '\0';

                    strlcpy(new_json_string, geoip_tmp, MeerConfig->payload_buffer_size);
                    strlcat(new_json_string, " }", MeerConfig->payload_buffer_size);
                }


            if ( MeerConfig->ndp_debug == true )
                {
                    Meer_Log(DEBUG, "[%s, line %d] INSERT DNS: %s: %s", __FILE__, __LINE__, id_md5, json_object_to_json_string(encode_json_dns) );
                }

            MeerCounters->ndp++;
            strlcpy(last_dns_id, id_md5, MD5_SIZE);
            Output_Elasticsearch ( new_json_string, "ndp", id_md5 );

        }

    free(geoip_tmp);
    free(new_json_string);

    json_object_put(encode_json_dns);
    json_object_put(json_obj_dns);


}

/********************************************/
/* NDP_SSH - Collect SSH version / banners */
/********************************************/

void NDP_SSH( struct json_object *json_obj, const char *src_ip, const char *dest_ip, const char *flow_id )
{

    char timestamp[64] = { 0 };
    char client_version[256] = { 0 };
    char server_version[256] = { 0 };

    char tmp_id[64] = { 0 };
    uint16_t dest_port = 0;

    char geoip_src[2048] = { 0 };
    char geoip_dest[2048] = { 0 };

    char id_md5[MD5_SIZE] = { 0 };

    struct json_object *tmp = NULL;
    struct json_object *json_obj_ssh = NULL;
    struct json_object *json_obj_ssh_client = NULL;
    struct json_object *json_obj_ssh_server = NULL;

    struct json_object *encode_json_ssh = NULL;
    encode_json_ssh = json_object_new_object();

    char *new_json_string = malloc(MeerConfig->payload_buffer_size);

    if ( new_json_string == NULL )
        {
            Meer_Log(ERROR, "[%s, line %d] Fatal Error: Can't allocate memory! Abort!\n", __FILE__, __LINE__);
        }

    memset(new_json_string, 0, sizeof(MeerConfig->payload_buffer_size *sizeof(char) ) );

    char *geoip_tmp = malloc(MeerConfig->payload_buffer_size);

    if ( geoip_tmp == NULL )
        {
            Meer_Log(ERROR, "[%s, line %d] Fatal Error: Can't allocate memory! Abort!\n", __FILE__, __LINE__);
        }

    memset(geoip_tmp, 0, sizeof(MeerConfig->payload_buffer_size *sizeof(char) ) );

    json_object *jtype = json_object_new_string( "ssh" );
    json_object_object_add(encode_json_ssh,"type", jtype);

    json_object *jsrc_ip = json_object_new_string( src_ip );
    json_object_object_add(encode_json_ssh,"src_ip", jsrc_ip);

    json_object *jdest_ip = json_object_new_string( dest_ip );
    json_object_object_add(encode_json_ssh,"dest_ip", jdest_ip);

    json_object *jflow_id = json_object_new_string( flow_id );
    json_object_object_add(encode_json_ssh,"flow_id", jflow_id);

    if ( MeerConfig->description[0] != '\0' )
        {
            json_object *jdesc = json_object_new_string( MeerConfig->description );
            json_object_object_add(encode_json_ssh,"description", jdesc);
        }

#ifdef HAVE_LIBMAXMINDDB

    if ( MeerConfig->geoip == true )
        {

            if ( json_object_object_get_ex(json_obj, "geoip_src", &tmp) )
                {
                    strlcpy(geoip_src,  (char*)json_object_to_json_string(tmp), sizeof(geoip_src));
                }

            if ( json_object_object_get_ex(json_obj, "geoip_dest", &tmp) )
                {
                    strlcpy(geoip_dest,  (char*)json_object_to_json_string(tmp), sizeof(geoip_dest));
                }

        }
#endif

    if ( MeerConfig->dns == true )
        {

            if ( json_object_object_get_ex(json_obj, "src_dns", &tmp) )
                {
                    json_object *jsrc_dns = json_object_new_string( json_object_to_json_string( tmp ));
                    json_object_object_add(encode_json_ssh,"src_dns", jsrc_dns);
                }

            if ( json_object_object_get_ex(json_obj, "dest_dns", &tmp) )
                {
                    json_object *jdest_dns = json_object_new_string( json_object_to_json_string( tmp ));
                    json_object_object_add(encode_json_ssh,"src_dest", jdest_dns);
                }
        }

    if ( json_object_object_get_ex(json_obj, "timestamp", &tmp) )
        {
            json_object *jtimestamp = json_object_new_string( json_object_to_json_string( tmp ));
            json_object_object_add(encode_json_ssh,"timestamp", jtimestamp);
        }

    if ( json_object_object_get_ex(json_obj, "community_id", &tmp) )
        {
            json_object *jcommunity_id = json_object_new_string( json_object_get_string(tmp) );
            json_object_object_add(encode_json_ssh,"community_id", jcommunity_id);
        }

    if ( json_object_object_get_ex(json_obj, "src_port", &tmp) )
        {
            json_object *jsrc_port = json_object_new_int( json_object_get_int(tmp) );
            json_object_object_add(encode_json_ssh,"src_port", jsrc_port);
        }

    if ( json_object_object_get_ex(json_obj, "dest_port", &tmp) )
        {
            dest_port = json_object_get_int(tmp);
            json_object *jdest_port = json_object_new_int( dest_port );
            json_object_object_add(encode_json_ssh,"dest_port", jdest_port);
        }

    if ( json_object_object_get_ex(json_obj, "host", &tmp) )
        {
            json_object *jhost = json_object_new_string( json_object_to_json_string( tmp ));
            json_object_object_add(encode_json_ssh,"host", jhost);
        }

    if ( json_object_object_get_ex(json_obj, "ssh", &tmp) )
        {

            json_obj_ssh = json_tokener_parse(json_object_get_string(tmp));

            if ( json_object_object_get_ex(json_obj_ssh, "client", &tmp) )
                {

                    json_obj_ssh_client = json_tokener_parse(json_object_get_string(tmp));

                    if ( json_object_object_get_ex(json_obj_ssh_client, "proto_version", &tmp) )
                        {

                            json_object *jproto_version = json_object_new_string( json_object_to_json_string( tmp ));
                            json_object_object_add(encode_json_ssh,"client_proto_version", jproto_version);
                        }

                    if ( json_object_object_get_ex(json_obj_ssh_client, "software_version", &tmp) )
                        {
                            strlcpy( client_version, json_object_to_json_string( tmp ), sizeof( client_version ));
                            json_object *jsoftware_version = json_object_new_string( client_version );
                            json_object_object_add(encode_json_ssh,"client_software_version", jsoftware_version);
                        }

                }


            if ( json_object_object_get_ex(json_obj_ssh, "server", &tmp) )
                {

                    json_obj_ssh_server = json_tokener_parse(json_object_get_string(tmp));

                    if ( json_object_object_get_ex(json_obj_ssh_client, "software_version", &tmp) )
                        {
                            strlcpy(server_version, json_object_to_json_string( tmp ), sizeof(server_version));
                            json_object *jserver_software_version = json_object_new_string( server_version );
                            json_object_object_add(encode_json_ssh,"server_software_version", jserver_software_version);
                        }

                }

        }

    /* Tried to do this properly with json-c, but kept leading to memory leaks.... and
       if json_object_put() the object,  it would lead to faults! So, we are back to
       string manipulation */


    strlcpy(new_json_string, (char*)json_object_to_json_string(encode_json_ssh), MeerConfig->payload_buffer_size );

    if ( geoip_src[0] != '\0' )
        {
            new_json_string[ strlen(new_json_string) - 2 ] = '\0';
            snprintf(geoip_tmp, MeerConfig->payload_buffer_size, "%s, \"geoip_src\": %s", new_json_string, geoip_src);

            geoip_tmp[ MeerConfig->payload_buffer_size - 1] = '\0';

            strlcpy(new_json_string, geoip_tmp, MeerConfig->payload_buffer_size);
            strlcat(new_json_string, " }", MeerConfig->payload_buffer_size);
        }

    if ( geoip_dest[0] != '\0' )
        {
            new_json_string[ strlen(new_json_string) - 2 ] = '\0';
            snprintf(geoip_tmp, MeerConfig->payload_buffer_size, "%s, \"geoip_dest\": %s", new_json_string, geoip_dest);

            geoip_tmp[ MeerConfig->payload_buffer_size - 1] = '\0';

            strlcpy(new_json_string, geoip_tmp, MeerConfig->payload_buffer_size);
            strlcat(new_json_string, " }", MeerConfig->payload_buffer_size);
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
            Output_Elasticsearch ( new_json_string, "ndp", id_md5 );
        }
    else
        {

            if ( MeerConfig->ndp_debug == true )
                {
                    Meer_Log(DEBUG, "[%s, line %d] SKIP SSH: %s: %s", __FILE__, __LINE__, id_md5, json_object_to_json_string(encode_json_ssh) );
                }

            MeerCounters->ndp_skip++;
        }

    free(geoip_tmp);
    free(new_json_string);

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

    char id_md5[MD5_SIZE] = { 0 };

    char http_user_agent[2048] = { 0 };
    char hostname[256] = { 0 };
    char url[10240] = { 0 };
    char full_url[256 + 10240] = { 0 };

    char geoip_src[2048] = { 0 };
    char geoip_dest[2048] = { 0 };

    struct json_object *tmp = NULL;
    struct json_object *json_obj_http = NULL;

    char *new_json_string = malloc(MeerConfig->payload_buffer_size);

    if ( new_json_string == NULL )
        {
            Meer_Log(ERROR, "[%s, line %d] Fatal Error: Can't allocate memory! Abort!\n", __FILE__, __LINE__);
        }

    memset(new_json_string, 0, sizeof(MeerConfig->payload_buffer_size *sizeof(char) ) );

    char *geoip_tmp = malloc(MeerConfig->payload_buffer_size);

    if ( geoip_tmp == NULL )
        {
            Meer_Log(ERROR, "[%s, line %d] Fatal Error: Can't allocate memory! Abort!\n", __FILE__, __LINE__);
        }

    memset(geoip_tmp, 0, sizeof(MeerConfig->payload_buffer_size *sizeof(char) ) );

    struct json_object *encode_json_http = NULL;
    encode_json_http = json_object_new_object();

    struct json_object *encode_json_user_agent = NULL;
    encode_json_user_agent = json_object_new_object();

    json_object *jtype = json_object_new_string( "http" );
    json_object_object_add(encode_json_http,"type", jtype);

    json_object *jtype_ua = json_object_new_string( "user_agent" );
    json_object_object_add(encode_json_user_agent,"type", jtype_ua);

    json_object *jsrc_ip = json_object_new_string( src_ip );
    json_object_object_add(encode_json_http,"src_ip", jsrc_ip);
    json_object_object_add(encode_json_user_agent,"src_ip", jsrc_ip);

    json_object *jdest_ip = json_object_new_string( dest_ip );
    json_object_object_add(encode_json_http,"dest_ip", jdest_ip);
    json_object_object_add(encode_json_user_agent,"dest_ip", jdest_ip);

    json_object *jflow_id = json_object_new_string( flow_id );
    json_object_object_add(encode_json_http,"flow_id", jflow_id);
    json_object_object_add(encode_json_user_agent,"flow_id", jflow_id);

    if ( MeerConfig->description[0] != '\0' )
        {
            json_object *jdesc = json_object_new_string( MeerConfig->description );
            json_object_object_add(encode_json_http,"description", jdesc);
            json_object_object_add(encode_json_user_agent,"description", jdesc);
        }

#ifdef HAVE_LIBMAXMINDDB

    if ( MeerConfig->geoip == true )
        {

            if ( json_object_object_get_ex(json_obj, "geoip_src", &tmp) )
                {
                    strlcpy(geoip_src,  (char*)json_object_to_json_string(tmp), sizeof(geoip_src));
                }

            if ( json_object_object_get_ex(json_obj, "geoip_dest", &tmp) )
                {
                    strlcpy(geoip_dest,  (char*)json_object_to_json_string(tmp), sizeof(geoip_dest));
                }

        }
#endif

    if ( MeerConfig->dns == true )
        {

            if ( json_object_object_get_ex(json_obj, "src_dns", &tmp) )
                {
                    json_object *jsrc_dns = json_object_new_string( json_object_to_json_string( tmp ));
                    json_object_object_add(encode_json_http,"src_dns", jsrc_dns);
                    json_object_object_add(encode_json_user_agent,"src_dns", jsrc_dns);
                }

            if ( json_object_object_get_ex(json_obj, "dest_dns", &tmp) )
                {
                    json_object *jdest_dns = json_object_new_string( json_object_to_json_string( tmp ));
                    json_object_object_add(encode_json_http,"dest_dns", jdest_dns);
                    json_object_object_add(encode_json_user_agent,"dest_dns", jdest_dns);
                }

        }

    if ( json_object_object_get_ex(json_obj, "timestamp", &tmp) )
        {
            json_object *jtimestamp = json_object_new_string( json_object_to_json_string( tmp ));
            json_object_object_add(encode_json_http,"timestamp", jtimestamp);
            json_object_object_add(encode_json_user_agent,"timestamp", jtimestamp);
        }

    if ( json_object_object_get_ex(json_obj, "community_id", &tmp) )
        {
            json_object *jcommunity_id = json_object_new_string( json_object_get_string(tmp) );
            json_object_object_add(encode_json_user_agent,"community_id", jcommunity_id);
        }

    if ( json_object_object_get_ex(json_obj, "host", &tmp) )
        {
            json_object *jhost = json_object_new_string( json_object_to_json_string( tmp ));
            json_object_object_add(encode_json_http,"host", jhost);
            json_object_object_add(encode_json_user_agent,"host", jhost);
        }

    if ( json_object_object_get_ex(json_obj, "http", &tmp) )
        {

            json_obj_http = json_tokener_parse(json_object_get_string(tmp));

            if ( json_object_object_get_ex(json_obj_http, "http_user_agent", &tmp) )
                {
                    strlcpy( http_user_agent, json_object_get_string(tmp), sizeof( http_user_agent ));

                    json_object *jhttp_user_agent = json_object_new_string( http_user_agent );
                    json_object_object_add(encode_json_http,"http_user_agent", jhttp_user_agent);
                    json_object_object_add(encode_json_user_agent,"user_agent", jhttp_user_agent);

                }

            if ( json_object_object_get_ex(json_obj_http, "hostname", &tmp) )
                {
                    strlcpy( hostname, json_object_get_string(tmp), sizeof( hostname ));

                    json_object *jhostname = json_object_new_string( hostname );
                    json_object_object_add(encode_json_http,"hostname", jhostname);
                }

            if ( json_object_object_get_ex(json_obj_http, "url", &tmp) )
                {
                    strlcpy( url, json_object_get_string(tmp), sizeof( url ));

                    json_object *jurl = json_object_new_string( url );
                    json_object_object_add(encode_json_http,"url", jurl);
                }

            if ( json_object_object_get_ex(json_obj_http, "method", &tmp) )
                {
                    json_object *jmethod = json_object_new_string( json_object_get_string(tmp) );
                    json_object_object_add(encode_json_http,"method", jmethod);
                }

            if ( json_object_object_get_ex(json_obj_http, "status", &tmp) )
                {
                    json_object *jstatus = json_object_new_int( json_object_get_int(tmp) );
                    json_object_object_add(encode_json_http,"status", jstatus);
                }

            if ( json_object_object_get_ex(json_obj_http, "length", &tmp) )
                {
                    json_object *jlength = json_object_new_int( json_object_get_int(tmp) );
                    json_object_object_add(encode_json_http,"length", jlength);
                }

            snprintf(full_url, sizeof(full_url), "%s%s", hostname, url);
            full_url[ sizeof( full_url ) - 1 ] = '\0';

            MD5( (uint8_t*)full_url, strlen(full_url), id_md5, sizeof(id_md5) );

            if ( strcmp(last_http_id, id_md5 ) )
                {

                    if ( MeerConfig->ndp_debug == true )
                        {
                            Meer_Log(DEBUG, "[%s, line %d] INSERT HTTP URL: %s: %s", __FILE__, __LINE__, id_md5, json_object_to_json_string(encode_json_http) );
                        }

                    /* Tried to do this properly with json-c, but kept leading to memory leaks.... and
                           if json_object_put() the object,  it would lead to faults! So, we are back to
                           string manipulation */

                    strlcpy(new_json_string, (char*)json_object_to_json_string(encode_json_http), MeerConfig->payload_buffer_size );

                    if ( geoip_src[0] != '\0' )
                        {
                            new_json_string[ strlen(new_json_string) - 2 ] = '\0';
                            snprintf(geoip_tmp, MeerConfig->payload_buffer_size, "%s, \"geoip_src\": %s", new_json_string, geoip_src);

                            geoip_tmp[ MeerConfig->payload_buffer_size - 1] = '\0';

                            strlcpy(new_json_string, geoip_tmp, MeerConfig->payload_buffer_size);
                            strlcat(new_json_string, " }", MeerConfig->payload_buffer_size);
                        }

                    if ( geoip_dest[0] != '\0' )
                        {
                            new_json_string[ strlen(new_json_string) - 2 ] = '\0';
                            snprintf(geoip_tmp, MeerConfig->payload_buffer_size, "%s, \"geoip_dest\": %s", new_json_string, geoip_dest);

                            geoip_tmp[ MeerConfig->payload_buffer_size - 1] = '\0';

                            strlcpy(new_json_string, geoip_tmp, MeerConfig->payload_buffer_size);
                            strlcat(new_json_string, " }", MeerConfig->payload_buffer_size);
                        }

                    MeerCounters->ndp++;
                    strlcpy(last_http_id, id_md5, MD5_SIZE);
                    Output_Elasticsearch ( new_json_string, "ndp", id_md5 );

                }
            else
                {

                    MeerCounters->ndp_skip++;

                    if ( MeerConfig->ndp_debug == true )
                        {
                            Meer_Log(DEBUG, "[%s, line %d] HTTP URL SKIP: %s", __FILE__, __LINE__, id_md5 );
                        }
                }

            /* Check User_agent */

            MD5( (uint8_t*)http_user_agent, strlen(http_user_agent), id_md5, sizeof(id_md5) );

            if ( !strcmp(last_user_agent_id, id_md5 ) )
                {

                    MeerCounters->ndp_skip++;

                    if ( MeerConfig->ndp_debug == true )
                        {
                            Meer_Log(DEBUG, "[%s, line %d] SKIP HTTP USER_AGENT: %s", __FILE__, __LINE__, id_md5);
                        }

                    free(geoip_tmp);
                    free(new_json_string);

                    json_object_put(json_obj_http);

                    json_object_put(encode_json_http);
//                    json_object_put(encode_json_user_agent);

                    return;
                }

            strlcpy(new_json_string, (char*)json_object_to_json_string(encode_json_user_agent), MeerConfig->payload_buffer_size );

            if ( geoip_src[0] != '\0' )
                {
                    new_json_string[ strlen(new_json_string) - 2 ] = '\0';
                    snprintf(geoip_tmp, MeerConfig->payload_buffer_size, "%s, \"geoip_src\": %s", new_json_string, geoip_src);

                    geoip_tmp[ MeerConfig->payload_buffer_size - 1] = '\0';

                    strlcpy(new_json_string, geoip_tmp, MeerConfig->payload_buffer_size);
                    strlcat(new_json_string, " }", MeerConfig->payload_buffer_size);
                }

            if ( geoip_dest[0] != '\0' )
                {
                    new_json_string[ strlen(new_json_string) - 2 ] = '\0';
                    snprintf(geoip_tmp, MeerConfig->payload_buffer_size, "%s, \"geoip_dest\": %s", new_json_string, geoip_dest);

                    geoip_tmp[ MeerConfig->payload_buffer_size - 1] = '\0';

                    strlcpy(new_json_string, geoip_tmp, MeerConfig->payload_buffer_size);
                    strlcat(new_json_string, " }", MeerConfig->payload_buffer_size);
                }


            MeerCounters->ndp++;
            strlcpy(last_user_agent_id, id_md5, MD5_SIZE);
            Output_Elasticsearch ( new_json_string, "ndp", id_md5 );
        }

    free(geoip_tmp);
    free(new_json_string);

    json_object_put(encode_json_http);
//    json_object_put(encode_json_user_agent);
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

    char geoip_src[2048] = { 0 };
    char geoip_dest[2048] = { 0 };

    char id_md5[MD5_SIZE] = { 0 };
    bool flag = false;
    uint8_t i = 0;

    char smb_command[64] = { 0 };
    char smb_filename[10240] = { 0 };

    char command_filename[64 + 10240 + 1] = { 0 };   /* SMB_COMMAND|/file/path */

    char *new_json_string = malloc(MeerConfig->payload_buffer_size);

    if ( new_json_string == NULL )
        {
            Meer_Log(ERROR, "[%s, line %d] Fatal Error: Can't allocate memory! Abort!\n", __FILE__, __LINE__);
        }

    memset(new_json_string, 0, sizeof(MeerConfig->payload_buffer_size *sizeof(char) ) );

    char *geoip_tmp = malloc(MeerConfig->payload_buffer_size);

    if ( geoip_tmp == NULL )
        {
            Meer_Log(ERROR, "[%s, line %d] Fatal Error: Can't allocate memory! Abort!\n", __FILE__, __LINE__);
        }

    memset(geoip_tmp, 0, sizeof(MeerConfig->payload_buffer_size *sizeof(char) ) );

    struct json_object *tmp = NULL;
    struct json_object *json_obj_smb = NULL;

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

    if ( MeerConfig->description[0] != '\0' )
        {
            json_object *jdesc = json_object_new_string( MeerConfig->description );
            json_object_object_add(encode_json_smb,"description", jdesc);
        }

#ifdef HAVE_LIBMAXMINDDB

    if ( MeerConfig->geoip == true )
        {

            if ( json_object_object_get_ex(json_obj, "geoip_src", &tmp) )
                {
                    strlcpy(geoip_src, (char*)json_object_to_json_string(tmp), sizeof(geoip_src));
                }

            if ( json_object_object_get_ex(json_obj, "geoip_dest", &tmp) )
                {
                    strlcpy(geoip_dest, (char*)json_object_to_json_string(tmp), sizeof(geoip_dest));
                }

        }
#endif

    if ( MeerConfig->dns == true )
        {

            if ( json_object_object_get_ex(json_obj, "src_dns", &tmp) )
                {
                    json_object *jsrc_dns = json_object_new_string( json_object_to_json_string( tmp ));
                    json_object_object_add(encode_json_smb,"src_dns", jsrc_dns);
                }

            if ( json_object_object_get_ex(json_obj, "dest_dns", &tmp) )
                {
                    json_object *jdest_dns = json_object_new_string( json_object_to_json_string( tmp ));
                    json_object_object_add(encode_json_smb,"dest_dns", jdest_dns);
                }

        }

    if ( json_object_object_get_ex(json_obj, "timestamp", &tmp) )
        {
            json_object *jtimestamp = json_object_new_string( json_object_to_json_string( tmp ));
            json_object_object_add(encode_json_smb,"timestamp", jtimestamp);
        }

    if ( json_object_object_get_ex(json_obj, "community_id", &tmp) )
        {
            json_object *jcommunity_id = json_object_new_string( json_object_get_string(tmp) );
            json_object_object_add(encode_json_smb,"community_id", jcommunity_id);
        }

    if ( json_object_object_get_ex(json_obj, "host", &tmp) )
        {
            json_object *jhost = json_object_new_string( json_object_to_json_string( tmp ));
            json_object_object_add(encode_json_smb,"host", jhost);
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

                                            free(geoip_tmp);
                                            free(new_json_string);

                                            json_object_put(encode_json_smb);
                                            json_object_put(json_obj_smb);

                                            return;

                                        }

                                    json_object *jsmb_command = json_object_new_string( smb_command );
                                    json_object_object_add(encode_json_smb,"command", jsmb_command);

                                    json_object *jsmb_filename = json_object_new_string( smb_filename );
                                    json_object_object_add(encode_json_smb,"filename", jsmb_filename);

                                    /* Tried to do this properly with json-c, but kept leading to memory leaks.... and
                                                   if json_object_put() the object,  it would lead to faults! So, we are back to
                                                   string manipulation */


                                    strlcpy(new_json_string, (char*)json_object_to_json_string(encode_json_smb), MeerConfig->payload_buffer_size );

                                    if ( geoip_src[0] != '\0' )
                                        {
                                            new_json_string[ strlen(new_json_string) - 2 ] = '\0';
                                            snprintf(geoip_tmp, MeerConfig->payload_buffer_size, "%s, \"geoip_src\": %s", new_json_string, geoip_src);

                                            geoip_tmp[ MeerConfig->payload_buffer_size - 1] = '\0';

                                            strlcpy(new_json_string, geoip_tmp, MeerConfig->payload_buffer_size);
                                            strlcat(new_json_string, " }", MeerConfig->payload_buffer_size);
                                        }

                                    if ( geoip_dest[0] != '\0' )
                                        {
                                            new_json_string[ strlen(new_json_string) - 2 ] = '\0';
                                            snprintf(geoip_tmp, MeerConfig->payload_buffer_size, "%s, \"geoip_dest\": %s", new_json_string, geoip_dest);

                                            geoip_tmp[ MeerConfig->payload_buffer_size - 1] = '\0';

                                            strlcpy(new_json_string, geoip_tmp, MeerConfig->payload_buffer_size);
                                            strlcat(new_json_string, " }", MeerConfig->payload_buffer_size);
                                        }

                                    if ( MeerConfig->ndp_debug == true )
                                        {
                                            Meer_Log(DEBUG, "[%s, line %d] INSERT SMB %s: %s", __FILE__, __LINE__, id_md5, json_object_to_json_string(encode_json_smb) );
                                        }

                                    MeerCounters->ndp++;
                                    strlcpy(last_smb_id, id_md5, MD5_SIZE);
                                    Output_Elasticsearch ( new_json_string, "ndp", id_md5 );

                                }
                        }
                }
        }

    free(geoip_tmp);
    free(new_json_string);

    json_object_put(encode_json_smb);
    json_object_put(json_obj_smb);

}

/*****************************************************/
/* NDP_FTP - Grabs files sent, received and username */
/*****************************************************/

void NDP_FTP( struct json_object *json_obj, const char *src_ip, const char *dest_ip, const char *flow_id )
{

    bool flag = false;
    uint8_t i = 0;

    char id_md5[MD5_SIZE] = { 0 };

    char ftp_command[64] = { 0 };
    char ftp_command_data[10240] = { 0 };
    char ftp_plus_data[10240+64+1] = { 0 }; 		/* COMMAND|COMMAND_DATA */

    char geoip_src[2048] = { 0 };
    char geoip_dest[2048] = { 0 };

    struct json_object *tmp = NULL;
    struct json_object *json_obj_ftp = NULL;

    struct json_object *encode_json_ftp = NULL;
    encode_json_ftp = json_object_new_object();

    char *new_json_string = malloc(MeerConfig->payload_buffer_size);

    if ( new_json_string == NULL )
        {
            Meer_Log(ERROR, "[%s, line %d] Fatal Error: Can't allocate memory! Abort!\n", __FILE__, __LINE__);
        }

    memset(new_json_string, 0, sizeof(MeerConfig->payload_buffer_size *sizeof(char) ) );

    char *geoip_tmp = malloc(MeerConfig->payload_buffer_size);

    if ( geoip_tmp == NULL )
        {
            Meer_Log(ERROR, "[%s, line %d] Fatal Error: Can't allocate memory! Abort!\n", __FILE__, __LINE__);
        }

    memset(geoip_tmp, 0, sizeof(MeerConfig->payload_buffer_size *sizeof(char) ) );



    json_object *jtype = json_object_new_string( "ftp" );
    json_object_object_add(encode_json_ftp,"type", jtype);

    json_object *jsrc_ip = json_object_new_string( src_ip );
    json_object_object_add(encode_json_ftp,"src_ip", jsrc_ip);

    json_object *jdest_ip = json_object_new_string( dest_ip );
    json_object_object_add(encode_json_ftp,"dest_ip", jdest_ip);

    json_object *jflow_id = json_object_new_string( flow_id );
    json_object_object_add(encode_json_ftp,"flow_id", jflow_id);

#ifdef HAVE_LIBMAXMINDDB

    if ( MeerConfig->geoip == true )
        {

            if ( json_object_object_get_ex(json_obj, "geoip_src", &tmp) )
                {
                    strlcpy(geoip_src,  (char*)json_object_to_json_string(tmp), sizeof(geoip_src));
                }

            if ( json_object_object_get_ex(json_obj, "geoip_dest", &tmp) )
                {
                    strlcpy(geoip_dest, json_object_to_json_string(tmp), sizeof(geoip_dest));
                }
        }
#endif

    if ( MeerConfig->dns == true )
        {

            if ( json_object_object_get_ex(json_obj, "src_dns", &tmp) )
                {
                    json_object *jsrc_dns = json_object_new_string( json_object_get_string(tmp) );
                    json_object_object_add(encode_json_ftp,"src_dns", jsrc_dns);
                }

            if ( json_object_object_get_ex(json_obj, "dest_dns", &tmp) )
                {
                    json_object *jdest_dns = json_object_new_string( json_object_get_string(tmp) );
                    json_object_object_add(encode_json_ftp,"dest_dns", jdest_dns);
                }
        }

    if ( MeerConfig->description[0] != '\0' )
        {
            json_object *jdesc = json_object_new_string( MeerConfig->description );
            json_object_object_add(encode_json_ftp,"description", jdesc);
        }

    if ( json_object_object_get_ex(json_obj, "timestamp", &tmp) )
        {
            json_object *jtimestamp = json_object_new_string( json_object_get_string(tmp) );
            json_object_object_add(encode_json_ftp,"timestamp", jtimestamp);
        }

    if ( json_object_object_get_ex(json_obj, "community_id", &tmp) )
        {
            json_object *jcommunity_id = json_object_new_string( json_object_get_string(tmp) );
            json_object_object_add(encode_json_ftp,"community_id", jcommunity_id);
        }

    if ( json_object_object_get_ex(json_obj, "host", &tmp) )
        {
            json_object *jhost = json_object_new_string( json_object_get_string(tmp) );
            json_object_object_add(encode_json_ftp,"host", jhost);
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

                                            free(geoip_tmp);
                                            free(new_json_string);

                                            json_object_put(encode_json_ftp);
                                            json_object_put(json_obj_ftp);
                                            return;

                                        }

                                    json_object *jftp_command = json_object_new_string( ftp_command );
                                    json_object_object_add(encode_json_ftp,"command", jftp_command);

                                    json_object *jftp_command_data = json_object_new_string( ftp_command_data );
                                    json_object_object_add(encode_json_ftp,"command_data", jftp_command_data);

                                    /* Tried to do this properly with json-c, but kept leading to memory leaks.... and
                                                   if json_object_put() the object,  it would lead to faults! So, we are back to
                                                   string manipulation */

                                    strlcpy(new_json_string, (char*)json_object_to_json_string(encode_json_ftp), MeerConfig->payload_buffer_size );

                                    if ( geoip_src[0] != '\0' )
                                        {
                                            new_json_string[ strlen(new_json_string) - 2 ] = '\0';
                                            snprintf(geoip_tmp, MeerConfig->payload_buffer_size, "%s, \"geoip_src\": %s", new_json_string, geoip_src);

                                            geoip_tmp[ MeerConfig->payload_buffer_size - 1] = '\0';

                                            strlcpy(new_json_string, geoip_tmp, MeerConfig->payload_buffer_size);
                                            strlcat(new_json_string, " }", MeerConfig->payload_buffer_size);
                                        }

                                    if ( geoip_dest[0] != '\0' )
                                        {
                                            new_json_string[ strlen(new_json_string) - 2 ] = '\0';
                                            snprintf(geoip_tmp, MeerConfig->payload_buffer_size, "%s, \"geoip_dest\": %s", new_json_string, geoip_dest);

                                            geoip_tmp[ MeerConfig->payload_buffer_size - 1] = '\0';

                                            strlcpy(new_json_string, geoip_tmp, MeerConfig->payload_buffer_size);
                                            strlcat(new_json_string, " }", MeerConfig->payload_buffer_size);
                                        }


                                    if ( MeerConfig->ndp_debug == true )
                                        {
                                            Meer_Log(DEBUG, "[%s, line %d] INSERT FTP : %s: %s", __FILE__, __LINE__, id_md5, json_object_to_json_string(encode_json_ftp) );
                                        }


                                    MeerCounters->ndp++;
                                    strlcpy(last_ftp_id, id_md5, MD5_SIZE);
                                    Output_Elasticsearch ( new_json_string, "ndp", id_md5 );

                                }
                        }
                }
        }

    free(geoip_tmp);
    free(new_json_string);

    json_object_put(encode_json_ftp);
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

