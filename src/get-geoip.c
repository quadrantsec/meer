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

#include <stdio.h>
#include <string.h>
#include <json-c/json.h>

#include "meer-def.h"
#include "meer.h"

#include "geoip.h"

extern struct _MeerCounters *MeerCounters;
extern struct _MeerConfig *MeerConfig;


#ifdef HAVE_LIBMAXMINDDB

void Get_GeoIP( struct json_object *json_obj, const char *json_string, char *str, size_t size )
{

    struct json_object *tmp = NULL;

    char *tmp_geoip = malloc((MeerConfig->payload_buffer_size)*sizeof(char));

    if ( tmp_geoip == NULL )
        {
            fprintf(stderr, "[%s, line %d] Fatal Error: Can't allocate memory! Abort!\n", __FILE__, __LINE__);
            exit(-1);
        }

    char *new_json_string = malloc((MeerConfig->payload_buffer_size)*sizeof(char));

    if ( new_json_string == NULL )
        {
            fprintf(stderr, "[%s, line %d] Fatal Error: Can't allocate memory! Abort!\n", __FILE__, __LINE__);
            exit(-1);
        }

//    char tmp_geoip[PACKET_BUFFER_SIZE_DEFAULT] = { 0 };
//    char new_json_string[PACKET_BUFFER_SIZE_DEFAULT] = { 0 };

//    char *return_ptr = NULL;

    char src_ip[64] = { 0 };
    char dest_ip[64] = { 0 };

    char geoip_src_json[1024] = { 0 };
    char geoip_dest_json[1024] = { 0 };

    if (json_object_object_get_ex(json_obj, "src_ip", &tmp))
        {
            strlcpy(src_ip, json_object_get_string(tmp), sizeof( src_ip ));
        }

    if (json_object_object_get_ex(json_obj, "dest_ip", &tmp))
        {
            strlcpy(dest_ip, json_object_get_string(tmp), sizeof( dest_ip ));
        }


    strlcpy( new_json_string, json_string, MeerConfig->payload_buffer_size);

    /*************************************************/
    /* Add any GeoIP data for the source/destination */
    /*************************************************/

    if ( src_ip[0] != '\0' && dest_ip[0] != '\0' )
        {

            struct _GeoIP *GeoIP;

            struct json_object *jobj_geoip;
            jobj_geoip = json_object_new_object();

            GeoIP = malloc(sizeof(_GeoIP));

            if ( GeoIP == NULL )
                {
                    Meer_Log(ERROR, "[%s, line %d] Failed to allocate memory for _GeoIP. Abort!", __FILE__, __LINE__);
                }

            memset(GeoIP, 0, sizeof(_GeoIP));

            /*******************/
            /* Get src_ip data */
            /*******************/

            GeoIP_Lookup( src_ip,  GeoIP );

            if ( GeoIP->country[0] != '\0' )
                {

                    json_object *jgeoip_country = json_object_new_string( GeoIP->country );
                    json_object_object_add(jobj_geoip,"country", jgeoip_country);

                    if ( GeoIP->city[0] != '\0' )
                        {
                            json_object *jgeoip_city = json_object_new_string( GeoIP->city );
                            json_object_object_add(jobj_geoip,"city", jgeoip_city);
                        }

                    if ( GeoIP->subdivision[0] != '\0' )
                        {
                            json_object *jgeoip_subdivision = json_object_new_string( GeoIP->subdivision );
                            json_object_object_add(jobj_geoip,"subdivision", jgeoip_subdivision);
                        }

                    if ( GeoIP->postal[0] != '\0' )
                        {
                            json_object *jgeoip_postal = json_object_new_string( GeoIP->postal );
                            json_object_object_add(jobj_geoip,"postal", jgeoip_postal);
                        }

                    if ( GeoIP->timezone[0] != '\0' )
                        {
                            json_object *jgeoip_timezone = json_object_new_string( GeoIP->timezone );
                            json_object_object_add(jobj_geoip,"timezone", jgeoip_timezone);
                        }

                    if ( GeoIP->longitude[0] != '\0' )
                        {
                            json_object *jgeoip_longitude = json_object_new_string( GeoIP->longitude );
                            json_object_object_add(jobj_geoip,"longitude", jgeoip_longitude);
                        }

                    if ( GeoIP->latitude[0] != '\0' )
                        {
                            json_object *jgeoip_latitude = json_object_new_string( GeoIP->latitude );
                            json_object_object_add(jobj_geoip,"latitude", jgeoip_latitude);
                        }

                    snprintf(geoip_src_json, sizeof(geoip_src_json), "%s", json_object_to_json_string(jobj_geoip));
                    geoip_src_json[ sizeof(geoip_src_json) - 1 ] = '\0';

                }

            /*****************************************/
            /* Get dest_ip GeoIP information (reset) */
            /*****************************************/

            memset(GeoIP, 0, sizeof(_GeoIP));

            GeoIP_Lookup( dest_ip,  GeoIP );

            if ( GeoIP->country[0] != '\0' )
                {

                    json_object *jgeoip_country = json_object_new_string( GeoIP->country );
                    json_object_object_add(jobj_geoip,"country", jgeoip_country);

                    if ( GeoIP->city[0] != '\0' )
                        {
                            json_object *jgeoip_city = json_object_new_string( GeoIP->city );
                            json_object_object_add(jobj_geoip,"city", jgeoip_city);
                        }

                    if ( GeoIP->subdivision[0] != '\0' )
                        {
                            json_object *jgeoip_subdivision = json_object_new_string( GeoIP->subdivision );
                            json_object_object_add(jobj_geoip,"subdivision", jgeoip_subdivision);
                        }

                    if ( GeoIP->postal[0] != '\0' )
                        {
                            json_object *jgeoip_postal = json_object_new_string( GeoIP->postal );
                            json_object_object_add(jobj_geoip,"postal", jgeoip_postal);
                        }

                    if ( GeoIP->timezone[0] != '\0' )
                        {
                            json_object *jgeoip_timezone = json_object_new_string( GeoIP->timezone );
                            json_object_object_add(jobj_geoip,"timezone", jgeoip_timezone);
                        }

                    if ( GeoIP->longitude[0] != '\0' )
                        {
                            json_object *jgeoip_longitude = json_object_new_string( GeoIP->longitude );
                            json_object_object_add(jobj_geoip,"longitude", jgeoip_longitude);
                        }

                    if ( GeoIP->latitude[0] != '\0' )
                        {
                            json_object *jgeoip_latitude = json_object_new_string( GeoIP->latitude );
                            json_object_object_add(jobj_geoip,"latitude", jgeoip_latitude);
                        }

                    snprintf(geoip_dest_json, sizeof(geoip_dest_json), "%s", json_object_to_json_string(jobj_geoip));
                    geoip_dest_json[ sizeof(geoip_dest_json) - 1 ] = '\0';
                }

            json_object_put(jobj_geoip);
//            json_object_put(tmp);
            free(GeoIP);
        }

    if ( geoip_src_json[0] != '\0' )
        {

            new_json_string[ strlen(new_json_string) -2 ] = '\0';
            snprintf(tmp_geoip, sizeof(tmp_geoip), "%s, \"geoip_src\": %s", new_json_string, geoip_src_json);

            strlcpy(new_json_string, tmp_geoip, MeerConfig->payload_buffer_size);
            strlcat(new_json_string, " }", MeerConfig->payload_buffer_size);

        }

    if ( geoip_dest_json[0] != '\0' )
        {

            new_json_string[ strlen(new_json_string) -2 ] = '\0';

            snprintf(tmp_geoip, sizeof(tmp_geoip), "%s, \"geoip_dest\": %s", new_json_string, geoip_dest_json);

            strlcpy(new_json_string, tmp_geoip, MeerConfig->payload_buffer_size);
            strlcat(new_json_string, " }", MeerConfig->payload_buffer_size);

        }

//    json_object_put(tmp);

    snprintf(str, size, "%s", new_json_string);

    free(tmp_geoip);
    free(new_json_string);


}

#endif
