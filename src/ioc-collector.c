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

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#include <string.h>
#include <json-c/json.h>

#include "meer.h"
#include "meer-def.h"
#include "util.h"
#include "output.h"

#include "ioc-collector.h"

extern struct _MeerConfig *MeerConfig;
extern struct _MeerOutput *MeerOutput;
extern struct _MeerCounters *MeerCounters;
extern struct _IOC_Ignore *IOC_Ignore;


bool IOC_Collector( struct json_object *json_obj, const char *json_string, const char *event_type )
{

// DEBUG: Add "host" to JSON!

    if ( !strcmp( event_type, "flow" ) )
        {
            IOC_Flow( json_obj );
        }

    else if ( !strcmp( event_type, "fileinfo" ) )
        {
            IOC_FileInfo( json_obj );
        }

    else if ( !strcmp( event_type, "tls" ) )
        {
            IOC_TLS( json_obj );
        }

    else if ( !strcmp( event_type, "dns" ) )
        {
            IOC_DNS( json_obj );
        }

    return(false);

}

bool IOC_Flow( struct json_object *json_obj )
{

    char *tmp_type = NULL;
    char tmp_ip[64] = { 0 };
    char src_ip[64] = { 0 };
    char dest_ip[64] = { 0 };

    uint8_t i = 0;

    uint64_t bytes_toserver = 0;
    uint64_t bytes_toclient = 0;
    uint64_t age = 0;


    struct json_object *tmp = NULL;
    bool state_flag = false;

    struct json_object *encode_json = NULL;
    encode_json = json_object_new_object();

    struct json_object *json_obj_flow = NULL;
    struct json_object *json_obj_state = NULL;

    uint16_t z = 0;

    char timestamp[64] = { 0 };
    char proto[16] = { 0 };
    char app_proto[32] = { 0 };
    char state[16] = { 0 };
    char reason[16] = { 0 };
    bool alerted = false;
    char start[64] = { 0 };
    char end[64] = { 0 };

    uint64_t flow_id = 0;

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

                                    const char *state = json_object_get_string(tmp);

//				if ( !strcmp(state, "established" ) )
//					{
                                    state_flag = true;
//					}

                                }
                        }
                }

        }

    /* State looks like something we're interested in */

    if ( state_flag == true )
        {

            json_object_object_get_ex(json_obj, "src_ip", &tmp);
            strlcpy( src_ip, json_object_get_string(tmp), sizeof(src_ip) );

            json_object_object_get_ex(json_obj, "dest_ip", &tmp);
            strlcpy( dest_ip, json_object_get_string(tmp), sizeof(dest_ip) );


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

//	        json_object_object_get_ex(json_obj, "src_ip", &tmp);
//	        strlcpy( src_ip, json_object_get_string(tmp), sizeof(src_ip) );

                    if ( IOC_In_Range( tmp_ip ) == false && ( Is_IP( tmp_ip, IPv4 ) ) )
                        {

                            json_object_object_get_ex(json_obj, "timestamp", &tmp);
                            strlcpy( timestamp, json_object_get_string(tmp), sizeof(timestamp) );

                            json_object_object_get_ex(json_obj, "flow_id", &tmp);
                            flow_id = json_object_get_int64(tmp);

                            json_object_object_get_ex(json_obj, "proto", &tmp);
                            strlcpy( proto, json_object_get_string(tmp), sizeof(proto) );

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

                            /* Add to object */

                            json_object *jtimestamp = json_object_new_string( timestamp );
                            json_object_object_add(encode_json,"timestamp", jtimestamp);

                            json_object *jsrc_ip = json_object_new_string( src_ip );
                            json_object_object_add(encode_json,"src_ip", jsrc_ip);

                            json_object *jdest_ip = json_object_new_string( dest_ip );
                            json_object_object_add(encode_json,"dest_ip", jdest_ip);

                            json_object *jflow_id = json_object_new_int64( flow_id );
                            json_object_object_add(encode_json,"flow_id", jflow_id);

                            json_object *jtype = json_object_new_string( "ip" );
                            json_object_object_add(encode_json,"type", jtype);

                            json_object *jdirection = json_object_new_string( tmp_type );
                            json_object_object_add(encode_json,"direction", jdirection);

                            json_object *jip = json_object_new_string( tmp_ip );
                            json_object_object_add(encode_json,"ip_address", jip);

                            json_object *jproto = json_object_new_string( proto );
                            json_object_object_add(encode_json,"proto", jproto);

                            json_object *japp_proto = json_object_new_string( app_proto );
                            json_object_object_add(encode_json,"app_proto", japp_proto);

                            json_object *jbytes_toserver = json_object_new_int64( bytes_toserver );
                            json_object_object_add(encode_json,"bytes_toserver", jbytes_toserver);

                            json_object *jbytes_toclient = json_object_new_int64( bytes_toclient );
                            json_object_object_add(encode_json,"bytes_toclient", jbytes_toclient);

                            json_object *jage = json_object_new_int64( age );
                            json_object_object_add(encode_json,"age", jage );

                            json_object *japp_state = json_object_new_string( state );
                            json_object_object_add(encode_json,"state", japp_state);

                            json_object *japp_reason = json_object_new_string( reason );
                            json_object_object_add(encode_json,"reason", japp_reason);

                            json_object *japp_alerted = json_object_new_boolean( alerted );
                            json_object_object_add(encode_json,"alerted", japp_alerted);

                            json_object *japp_start = json_object_new_string( start );
                            json_object_object_add(encode_json,"start", japp_start);

                            json_object *japp_end = json_object_new_string( end );
                            json_object_object_add(encode_json,"end", japp_end);

                            Output_Elasticsearch ( (char*)json_object_to_json_string(encode_json), "ioc", tmp_ip );

                        }

                }
        }

    json_object_put(encode_json);
    json_object_put(json_obj_flow);
    json_object_put(json_obj_state); 

}

bool IOC_FileInfo( struct json_object *json_obj )
{

    uint64_t flow_id = 0;
    uint64_t size = 0;

    char app_proto[32] = { 0 };
    char timestamp[64] = { 0 };
    char src_ip[64] = { 0 };
    char dest_ip[64] = { 0 };

    char md5[33] = { 0 };
    char sha1[41] = { 0 };
    char sha256[65] = { 0 };
    char filename[8192] = { 0 };
    char magic[512] = { 0 };

    struct json_object *tmp = NULL;

    struct json_object *encode_json = NULL;
    encode_json = json_object_new_object();

    struct json_object *json_obj_fileinfo = NULL;

    json_object_object_get_ex(json_obj, "timestamp", &tmp);
    strlcpy( timestamp, json_object_get_string(tmp), sizeof(timestamp) );

    json_object_object_get_ex(json_obj, "src_ip", &tmp);
    strlcpy( src_ip, json_object_get_string(tmp), sizeof(src_ip) );

    json_object_object_get_ex(json_obj, "dest_ip", &tmp);
    strlcpy( dest_ip, json_object_get_string(tmp), sizeof(dest_ip) );

    json_object_object_get_ex(json_obj, "app_proto", &tmp);
    strlcpy( app_proto, json_object_get_string(tmp), sizeof(app_proto) );

    json_object_object_get_ex(json_obj, "flow_id", &tmp);
    flow_id = json_object_get_int64(tmp);

    if ( json_object_object_get_ex(json_obj, "fileinfo", &tmp) )
        {

            json_obj_fileinfo = json_tokener_parse(json_object_get_string(tmp));

            if ( json_object_object_get_ex(json_obj_fileinfo, "md5", &tmp) )
                {
                    strlcpy(md5, json_object_get_string(tmp), sizeof(md5) );
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

    /*************/

    json_object *jtype = json_object_new_string( "hash" );
    json_object_object_add(encode_json,"type", jtype);

    json_object *jtimestamp = json_object_new_string( timestamp );
    json_object_object_add(encode_json,"timestamp", jtimestamp);

    json_object *japp_proto = json_object_new_string( app_proto );
    json_object_object_add(encode_json,"app_proto", japp_proto);

    json_object *jsrc_ip = json_object_new_string( src_ip );
    json_object_object_add(encode_json,"src_ip", jsrc_ip);

    json_object *jdest_ip = json_object_new_string( dest_ip );
    json_object_object_add(encode_json,"dest_ip", jdest_ip);

    json_object *jmd5 = json_object_new_string( md5 );
    json_object_object_add(encode_json,"md5", jmd5);

    json_object *jsha1 = json_object_new_string( sha1 );
    json_object_object_add(encode_json,"sha1", jsha1);

    json_object *jsha256 = json_object_new_string( sha256 );
    json_object_object_add(encode_json,"sha256", jsha256);

    json_object *jfilename = json_object_new_string( filename );
    json_object_object_add(encode_json,"filename", jfilename);

    json_object *jmagic = json_object_new_string( magic );
    json_object_object_add(encode_json,"magic", jmagic);

    json_object *jsize = json_object_new_int64( size );
    json_object_object_add(encode_json,"size", jsize);

    json_object *jflow_id = json_object_new_int64( flow_id );
    json_object_object_add(encode_json,"flow_id", jflow_id);

    Output_Elasticsearch ( (char*)json_object_to_json_string(encode_json), "ioc", md5 );


    json_object_put(encode_json);
    json_object_put(json_obj_fileinfo);

}

bool IOC_TLS( struct json_object *json_obj )
{

    char timestamp[64] = { 0 };
    char src_ip[64] = { 0 };
    char dest_ip[64] = { 0 };

    char fingerprint[128] = { 0 };
    char subject[1024] = { 0 };
    char issuerdn[1024] = { 0 };
    char serial[512] = { 0 };
    char sni[512] = { 0 };
    char version[16] = { 0 };
    char notbefore[64]= { 0 };
    char notafter[64] = { 0 };

    char ja3[34] = { 0 };
    char ja3s[34] = { 0 };

    char id[68] = { 0 };

    uint64_t flow_id = 0;

    struct json_object *tmp = NULL;
    struct json_object *json_obj_tls = NULL;
    struct json_object *json_obj_ja3 = NULL;
    struct json_object *json_obj_ja3s = NULL;

    struct json_object *encode_json = NULL;
    encode_json = json_object_new_object();

    json_object_object_get_ex(json_obj, "timestamp", &tmp);
    strlcpy( timestamp, json_object_get_string(tmp), sizeof(timestamp) );

    json_object_object_get_ex(json_obj, "src_ip", &tmp);
    strlcpy( src_ip, json_object_get_string(tmp), sizeof(src_ip) );

    json_object_object_get_ex(json_obj, "dest_ip", &tmp);
    strlcpy( dest_ip, json_object_get_string(tmp), sizeof(dest_ip) );

    json_object_object_get_ex(json_obj, "flow_id", &tmp);
    flow_id = json_object_get_int64(tmp);

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


    /* New JSON object */

    json_object *jtimestamp = json_object_new_string( timestamp );
    json_object_object_add(encode_json,"timestamp", jtimestamp);

    json_object *jflow_id = json_object_new_int64( flow_id );
    json_object_object_add(encode_json,"flow_id", jflow_id);

    json_object *jsrc_ip = json_object_new_string( src_ip );
    json_object_object_add(encode_json,"src_ip", jsrc_ip);

    json_object *jdest_ip = json_object_new_string( dest_ip );
    json_object_object_add(encode_json,"dest_ip", jdest_ip);

    json_object *jtype = json_object_new_string( "tls" );
    json_object_object_add(encode_json,"type", jtype);

    json_object *jfingerprint = json_object_new_string( fingerprint );
    json_object_object_add(encode_json,"fingerprint", jfingerprint);

    json_object *jissuerdn = json_object_new_string( issuerdn );
    json_object_object_add(encode_json,"issuerdn", jissuerdn);

    json_object *jsubject = json_object_new_string( subject );
    json_object_object_add(encode_json,"subject", jsubject );

    json_object *jserial = json_object_new_string( serial );
    json_object_object_add(encode_json,"serial", jserial );

    json_object *jsni = json_object_new_string( sni );
    json_object_object_add(encode_json,"sni", jsni );

    json_object *jversion = json_object_new_string( version );
    json_object_object_add(encode_json,"version", jversion );

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

    json_object *jja3 = json_object_new_string( ja3 );
    json_object_object_add(encode_json,"ja3", jja3 );

    json_object *jja3s = json_object_new_string( ja3s );
    json_object_object_add(encode_json,"ja3s", jja3s );

    json_object_object_get_ex(json_obj, "flow_id", &tmp);
    flow_id = json_object_get_int64(tmp);

    snprintf(id, sizeof(id), "%s:%s", ja3, ja3s);
    id[ sizeof(id) - 1] = '\0';

    Output_Elasticsearch ( (char*)json_object_to_json_string(encode_json), "ioc", id );

    json_object_put(encode_json);
    json_object_put(json_obj_ja3);
    json_object_put(json_obj_ja3s);
    json_object_put(json_obj_tls);

}

bool IOC_DNS( struct json_object *json_obj )
{

    char timestamp[64] = { 0 };
    char src_ip[64] = { 0 };
    char dest_ip[64] = { 0 };
    uint64_t flow_id = 0;
    char rrname[8192] = { 0 };
    char rrtype[16] = { 0 };

    struct json_object *tmp = NULL;
    struct json_object *json_obj_dns = NULL;

    struct json_object *encode_json = NULL;
    encode_json = json_object_new_object();

    json_object_object_get_ex(json_obj, "timestamp", &tmp);
    strlcpy( timestamp, json_object_get_string(tmp), sizeof(timestamp) );

    json_object_object_get_ex(json_obj, "src_ip", &tmp);
    strlcpy( src_ip, json_object_get_string(tmp), sizeof(src_ip) );

    json_object_object_get_ex(json_obj, "dest_ip", &tmp);
    strlcpy( dest_ip, json_object_get_string(tmp), sizeof(dest_ip) );

    json_object_object_get_ex(json_obj, "flow_id", &tmp);
    flow_id = json_object_get_int64(tmp);

    /* New JSON object */

    if ( json_object_object_get_ex(json_obj, "dns", &tmp) )
        {

            json_obj_dns = json_tokener_parse(json_object_get_string(tmp));

            if ( json_object_object_get_ex(json_obj_dns, "type", &tmp) )
                {

                    /* We only want to record the queries,  not the "answers" */

                    if ( !strcmp( json_object_get_string(tmp), "query" ) )
                        {

                            json_object_object_get_ex(json_obj_dns, "rrname", &tmp);
                            strlcpy(rrname, json_object_get_string(tmp), sizeof( rrname ) );

                            json_object_object_get_ex(json_obj_dns, "rrtype", &tmp);
                            strlcpy(rrtype, json_object_get_string(tmp), sizeof( rrtype ) );

                        }
                    else
                        {

                            /* It's not a "query", so skip it */

			    json_object_put(encode_json);
			    json_object_put(json_obj_dns);
                            return(false);

                        }

                    json_object *jtimestamp = json_object_new_string( timestamp );
                    json_object_object_add(encode_json,"timestamp", jtimestamp);

                    json_object *jsrc_ip = json_object_new_string( src_ip );
                    json_object_object_add(encode_json,"src_ip", jsrc_ip);

                    json_object *jdest_ip = json_object_new_string( dest_ip );
                    json_object_object_add(encode_json,"dest_ip", jdest_ip);

                    json_object *jtype = json_object_new_string( "dns" );
                    json_object_object_add(encode_json,"type", jtype);

                    json_object *jflow_id = json_object_new_int64( flow_id );
                    json_object_object_add(encode_json,"flow_id", jflow_id);

                    json_object *jrrname = json_object_new_string( rrname );
                    json_object_object_add(encode_json,"rrname", jrrname);

                    json_object *jrrtype = json_object_new_string( rrtype );
                    json_object_object_add(encode_json,"rrtype", jrrtype);

                    Output_Elasticsearch ( (char*)json_object_to_json_string(encode_json), "ioc", rrname);

                }
        }

    json_object_put(encode_json);
    json_object_put(json_obj_dns);

}


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

