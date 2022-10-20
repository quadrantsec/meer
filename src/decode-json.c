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

/* EVE JSON decode */

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#ifdef HAVE_LIBJSON_C
#include <json-c/json.h>
#endif

#ifndef HAVE_LIBJSON_C
libjson-c is required for Meer to function!
#endif

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <stdbool.h>
#include <string.h>

#include "decode-json.h"
#include "decode-output-json-client-stats.h"

#include "output-plugins/pipe.h"
#include "output-plugins/file.h"

#include "meer.h"
#include "meer-def.h"
#include "util.h"
#include "output.h"
#include "get-dns.h"
#include "get-oui.h"
#include "counters.h"
#include "calculate-stats.h"
#include "ioc-collector.h"

#ifdef HAVE_LIBMAXMINDDB
#include "get-geoip.h"
#endif

#ifdef HAVE_LIBHIREDIS
#include "get-fingerprint.h"
#include "output-plugins/redis.h"
#endif

extern struct _Classifications *MeerClass;
extern struct _MeerOutput *MeerOutput;
extern struct _MeerCounters *MeerCounters;
extern struct _MeerConfig *MeerConfig;
extern struct _MeerHealth *MeerHealth;

bool Decode_JSON( char *json_string )
{

    struct json_object *json_obj = NULL;
    struct json_object *tmp = NULL;

    char event_type[32] = { 0 };
    char flow_id[32] = { 0 };
    char src_ip[64] = { 0 };
    char dest_ip[64] = { 0 };

    char fixed_ip[64] = { 0 };

    /* Remove \n from string */

    json_string[ strlen(json_string) - 1 ] = '\0';

    char *new_json_string = malloc( MeerConfig->payload_buffer_size );

    if ( new_json_string == NULL )
        {
            fprintf(stderr, "[%s, line %d] Fatal Error:  Can't allocate memory! Abort!\n", __FILE__, __LINE__);
            exit(-1);
        }

    memset(new_json_string, 0, MeerConfig->payload_buffer_size);

    /* We should have gotten a valid string! */

    if ( json_string == NULL )
        {
            MeerCounters->bad++;
            json_object_put(json_obj);
            free(new_json_string);
            return(false);
        }

    json_obj = json_tokener_parse(json_string);

    if ( json_obj == NULL )
        {
            MeerCounters->bad++;
            Meer_Log(WARN, "[%s, line %d] Unable t json_tokener_parse: %s", __FILE__, __LINE__, json_string);
            json_object_put(json_obj);
            free(new_json_string);
            return(false);
        }

    /* Let's add our "description" */

    json_object *jdescription  = json_object_new_string( MeerConfig->description );
    json_object_object_add(json_obj,"sensor_description", jdescription );

    /* Let's add our "sensor_type",  if it has been set */

    if ( MeerConfig->sensor_type[0] != '\0' )
        {
            json_object *jsensor_type  = json_object_new_string( MeerConfig->sensor_type );
            json_object_object_add(json_obj,"sensor_type", jsensor_type );
        }

    /* Go ahead and get the "event_type".  All JSON should have one */

    if (json_object_object_get_ex(json_obj, "event_type", &tmp))
        {
            strlcpy(event_type, json_object_get_string(tmp), sizeof( event_type ) );
        }
    else
        {
            MeerCounters->bad++;
            json_object_put(json_obj);
            free(new_json_string);
            return(false);
        }

    /* Certain logs do not contact flow_id, src_ip, dest_ip, etc.  For example, the
     * event_type "stats" doesn't have any of this data.  We want the validation checks
     * for types that don't have this data. */

    if ( strcmp(event_type, "stats" ) )
        {

            if (json_object_object_get_ex(json_obj, "flow_id", &tmp))
                {
                    strlcpy( flow_id, json_object_get_string(tmp), sizeof( flow_id ) );
                }
            else
                {
                    MeerCounters->bad++;
                    json_object_put(json_obj);
                    free(new_json_string);
                    return(false);
                }

            /* More sanity checks on src_ip/dest_ip - Some applications screw this up (*cough* Microsoft). */

            if (json_object_object_get_ex(json_obj, "src_ip", &tmp))
                {
                    strlcpy( src_ip, json_object_get_string(tmp), sizeof(src_ip) );
                }
            else
                {
                    Meer_Log(WARN, "[%s, line %d] No 'src_ip' address could be found.  Skipping.....", __FILE__, __LINE__ );
                    MeerCounters->bad++;
                    json_object_put(json_obj);
                    free(new_json_string);
                    return(false);
                }

            if (json_object_object_get_ex(json_obj, "dest_ip", &tmp))
                {
                    strlcpy( dest_ip, json_object_get_string(tmp), sizeof(dest_ip) );
                }
            else
                {
                    Meer_Log(WARN, "[%s, line %d] No 'dest_ip' address could be found.  Skipping.....", __FILE__, __LINE__ );
                    MeerCounters->bad++;
                    json_object_put(json_obj);
                    free(new_json_string);
                    return(false);
                }


            /* Validate src_ip address */

            if ( !Is_IP(src_ip, IPv4) && !Is_IP(src_ip, IPv6 ) )
                {
                    Meer_Log(WARN, "[%s, line %d] Invalid 'src_ip' found in flow_id %s. Attempting to 'fix'.", __FILE__, __LINE__, flow_id);

                    /* Store the "original" IP address */

                    json_object *jsrc_ip_orig = json_object_new_string(src_ip);
                    json_object_object_add(json_obj,"original_src_ip", jsrc_ip_orig);

                    if ( Try_And_Fix_IP( src_ip, fixed_ip, sizeof( fixed_ip)) == true )
                        {

                            /* Copy over the "fixed" value */

                            json_object *jsrc_ip = json_object_new_string( fixed_ip );
                            json_object_object_add(json_obj,"src_ip", jsrc_ip);

                            strlcpy( new_json_string, json_object_to_json_string(json_obj), MeerConfig->payload_buffer_size);
                            json_string = new_json_string;

                            Meer_Log(WARN, "[%s, line %d] Successfully 'fixed' bad src_ip '%s' to '%s'.", __FILE__, __LINE__, src_ip, fixed_ip );
                            strlcpy( src_ip, fixed_ip, sizeof( src_ip ) );

                        }
                    else
                        {

                            /* Over write the src_ip with the BAD_IP value */

                            json_object *jsrc_ip = json_object_new_string(BAD_IP);
                            json_object_object_add(json_obj,"src_ip", jsrc_ip);

                            strlcpy( new_json_string, json_object_to_json_string(json_obj), MeerConfig->payload_buffer_size);
                            json_string = new_json_string;

                            Meer_Log(WARN, "[%s, line %d] Was unsuccessful in fixing src_ip '%s'. Replaced with '%s'.", __FILE__, __LINE__, src_ip, BAD_IP);

                            strlcpy( src_ip, BAD_IP, sizeof( src_ip ) );

                        }
                }

            /* Validate dest_ip address */

            if ( !Is_IP(dest_ip, IPv4) && !Is_IP(dest_ip, IPv6 ) )
                {
                    Meer_Log(WARN, "[%s, line %d] Invalid 'dest_ip' found in flow_id %s. Attempting to 'fix'.", __FILE__, __LINE__, flow_id);

                    /* Store the "original" IP address */

                    json_object *jdest_ip_orig = json_object_new_string(dest_ip);
                    json_object_object_add(json_obj,"original_dest_ip", jdest_ip_orig);


                    if ( Try_And_Fix_IP( dest_ip, fixed_ip, sizeof( fixed_ip)) == true )
                        {

                            /* Copy over the "fixed" value */

                            json_object *jdest_ip = json_object_new_string( fixed_ip );
                            json_object_object_add(json_obj,"dest_ip", jdest_ip);

                            strlcpy( new_json_string, json_object_to_json_string(json_obj), MeerConfig->payload_buffer_size);
                            json_string = new_json_string;

                            Meer_Log(WARN, "[%s, line %d] Successfully 'fixed' bad dest_ip '%s' to '%s'.", __FILE__, __LINE__, dest_ip, fixed_ip );
                            strlcpy( dest_ip, fixed_ip, sizeof( dest_ip ) );

                        }
                    else
                        {

                            /* Over write the dest_ip with the BAD_IP value */

                            json_object *jdest_ip = json_object_new_string(BAD_IP);
                            json_object_object_add(json_obj,"dest_ip", jdest_ip);

                            strlcpy( new_json_string, json_object_to_json_string(json_obj), MeerConfig->payload_buffer_size);
                            json_string = new_json_string;

                            Meer_Log(WARN, "[%s, line %d] Was unsuccessful in fixing dest_ip '%s'. Replaced with '%s'.", __FILE__, __LINE__, dest_ip, BAD_IP);

                            strlcpy( dest_ip, BAD_IP, sizeof( dest_ip ) );

                        }
                }

        } /* End of validation and exclusion */


    /* if "caclulate_stats" is true,  we want to do add some keys and do some math! */

    if ( !strcmp(event_type, "stats" ) )
        {

            if ( MeerConfig->calculate_stats == true )
                {
                    Calculate_Stats( json_obj, new_json_string );
                    json_string = new_json_string;
                }

        }

#ifdef HAVE_LIBHIREDIS

    /* We do "fingerprint" checks early on because we might want to switch the
       "event_type". */

    if ( !strcmp(event_type, "alert") && MeerConfig->fingerprint == true && MeerOutput->redis_enabled == true )
        {

            if ( Is_Fingerprint( json_obj ) == true )
                {

                    /* If it's a "fingerprint" add it to our database.  First,  is our "fingerprint"
                     * in range? */

                    if ( Fingerprint_In_Range( src_ip ) == false )
                        {
                            json_object_put(json_obj);
                            free(new_json_string);
                            return(false);
                        }

                    /* Switch event_type from "alert" to "fingerprint" */

                    json_object *jevent_type = json_object_new_string("fingerprint");
                    json_object_object_add(json_obj,"event_type", jevent_type);

                    strlcpy(event_type, "fingerprint", 12);

                    /* Add fingerprint data to Redis for future events */

                    if ( Fingerprint_JSON_IP_Redis( json_obj ) == false ) 	/* Add "fingerprint|ip|{IP}" key */
                        {
                            Meer_Log(WARN, "[%s, line %d] Couldn't write Redis 'fingerprint|ip' key! Skipping!", __FILE__, __LINE__);
                            json_object_put(json_obj);
                            free(new_json_string);
                            return(false);
                        }

                    if ( Fingerprint_JSON_Event_Redis( json_obj, new_json_string, MeerConfig->payload_buffer_size ) == false )
                        {
                            Meer_Log(WARN, "[%s, line %d] Couldn't write Redis 'fingerprint|event' key! Skipping!", __FILE__, __LINE__);
                            json_object_put(json_obj);
                            free(new_json_string);
                            return(false);
                        }

                    json_string = new_json_string;	/* Make "new" JSON the "fingerprint" one!
							   For later user in "output" */

                }
            else
                {

                    /* Add "fingerprint" data to the alert,  if available */

                    Get_Fingerprint( json_obj, new_json_string, MeerConfig->payload_buffer_size, json_string );
                    json_string = new_json_string;

                }

        }

    /* Write out DHCP data for fingerprinting */

    if ( !strcmp(event_type, "dhcp") && MeerConfig->fingerprint == true && MeerOutput->redis_enabled == true )
        {

            /* Only write DHCP if Meer is a "fingerprint" writer */

            if ( MeerConfig->fingerprint_writer == true )
                {
                    Fingerprint_DHCP ( json_obj, json_string );
                }
        }

#endif

    /* Do we want to add DNS to the JSON? */

    if ( MeerConfig->dns == true && Is_DNS_Event_Type( event_type ) == true )
        {
            Get_DNS( json_obj, new_json_string );
            json_string = new_json_string;
        }

    /* Add OUI / Mac data */

    if ( MeerConfig->oui == true && !strcmp( event_type, "dhcp"  ) )
        {
            Get_OUI( json_obj, new_json_string );
            json_string = new_json_string;
        }

    Counters( event_type );

#ifdef HAVE_LIBMAXMINDDB

    /* Add GeoIP information */

    if ( MeerConfig->geoip == true )
        {
            Get_GeoIP( json_obj, json_string, new_json_string );
            json_string = new_json_string;
        }

#endif

    if ( MeerOutput->pipe_enabled == true )
        {
            Output_Pipe( json_string, event_type );
        }

    if ( MeerOutput->external_enabled == true )
        {
            Output_External( json_string, json_obj, event_type );
        }


    if ( MeerOutput->file_enabled == true )
        {
            Output_File( json_string, event_type );
        }

#ifdef HAVE_LIBHIREDIS

    if ( MeerOutput->redis_enabled == true )
        {
            Output_Redis( json_string, event_type );
        }

#endif

#ifdef WITH_ELASTICSEARCH

    if ( MeerOutput->elasticsearch_enabled == true )
        {
            Output_Elasticsearch( json_string, event_type, NULL );
        }

#endif

#ifdef WITH_BLUEDOT

    if ( ( MeerOutput->bluedot_flag = true && !strcmp( event_type, "alert" ) ) )
        {
            Output_Bluedot( json_obj );
        }

#endif

#ifdef HAVE_LIBHIREDIS

    /* Process client stats data from Sagan */

    if ( ( !strcmp(event_type, "client_stats") || !strcmp(event_type, "client_stats") )  && MeerConfig->client_stats == true )
        {
            Decode_Output_JSON_Client_Stats( json_obj, json_string );
        }

#endif

#ifdef WITH_ELASTICSEARCH

    if ( MeerConfig->ioc_collector == true )
        {

            IOC_Collector( json_obj, json_string, event_type, src_ip, dest_ip, flow_id );

        }

#endif

    /* Delete json-c _root_ objects */

    json_object_put(json_obj);
    free(new_json_string);

    return 0;
}
