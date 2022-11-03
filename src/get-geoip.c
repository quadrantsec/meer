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

#include <stdio.h>
#include <string.h>
#include <json-c/json.h>

#include "meer-def.h"
#include "meer.h"

#include "geoip.h"

extern struct _MeerCounters *MeerCounters;
extern struct _MeerConfig *MeerConfig;

#ifdef HAVE_LIBMAXMINDDB

void Get_GeoIP( struct json_object *json_obj, char *str, const char *src_ip, const char *dest_ip )
{

//    struct json_object *jobj_geoip_src = NULL;
//    jobj_geoip_src = json_object_new_object();

//    struct json_object *jobj_geoip_dest = NULL;
//    jobj_geoip_dest = json_object_new_object();

    /*************************************************/
    /* Add any GeoIP data for the source/destination */
    /*************************************************/

    struct _GeoIP *GeoIP;
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

            struct json_object *jobj_geoip_src = NULL;
            jobj_geoip_src = json_object_new_object();

            json_object *jgeoip_country = json_object_new_string( GeoIP->country );
            json_object_object_add(jobj_geoip_src,"country", jgeoip_country);

            if ( GeoIP->city[0] != '\0' )
                {
                    json_object *jgeoip_city = json_object_new_string( GeoIP->city );
                    json_object_object_add(jobj_geoip_src,"city", jgeoip_city);
                }

            if ( GeoIP->subdivision[0] != '\0' )
                {
                    json_object *jgeoip_subdivision = json_object_new_string( GeoIP->subdivision );
                    json_object_object_add(jobj_geoip_src,"subdivision", jgeoip_subdivision);
                }

            if ( GeoIP->postal[0] != '\0' )
                {
                    json_object *jgeoip_postal = json_object_new_string( GeoIP->postal );
                    json_object_object_add(jobj_geoip_src,"postal", jgeoip_postal);
                }

            if ( GeoIP->timezone[0] != '\0' )
                {
                    json_object *jgeoip_timezone = json_object_new_string( GeoIP->timezone );
                    json_object_object_add(jobj_geoip_src,"timezone", jgeoip_timezone);
                }

            if ( GeoIP->longitude[0] != '\0' )
                {
                    json_object *jgeoip_longitude = json_object_new_string( GeoIP->longitude );
                    json_object_object_add(jobj_geoip_src,"longitude", jgeoip_longitude);
                }

            if ( GeoIP->latitude[0] != '\0' )
                {
                    json_object *jgeoip_latitude = json_object_new_string( GeoIP->latitude );
                    json_object_object_add(jobj_geoip_src,"latitude", jgeoip_latitude);
                }

            json_object_object_add(json_obj, "geoip_src", jobj_geoip_src);

        }

    /*****************************************/
    /* Get dest_ip GeoIP information (reset) */
    /*****************************************/

    memset(GeoIP, 0, sizeof(_GeoIP));

    GeoIP_Lookup( dest_ip,  GeoIP );

    if ( GeoIP->country[0] != '\0' )
        {

            struct json_object *jobj_geoip_dest = NULL;
            jobj_geoip_dest = json_object_new_object();

            json_object *jgeoip_country = json_object_new_string( GeoIP->country );
            json_object_object_add(jobj_geoip_dest,"country", jgeoip_country);

            if ( GeoIP->city[0] != '\0' )
                {
                    json_object *jgeoip_city = json_object_new_string( GeoIP->city );
                    json_object_object_add(jobj_geoip_dest,"city", jgeoip_city);
                }

            if ( GeoIP->subdivision[0] != '\0' )
                {
                    json_object *jgeoip_subdivision = json_object_new_string( GeoIP->subdivision );
                    json_object_object_add(jobj_geoip_dest,"subdivision", jgeoip_subdivision);
                }

            if ( GeoIP->postal[0] != '\0' )
                {
                    json_object *jgeoip_postal = json_object_new_string( GeoIP->postal );
                    json_object_object_add(jobj_geoip_dest,"postal", jgeoip_postal);
                }

            if ( GeoIP->timezone[0] != '\0' )
                {
                    json_object *jgeoip_timezone = json_object_new_string( GeoIP->timezone );
                    json_object_object_add(jobj_geoip_dest,"timezone", jgeoip_timezone);
                }

            if ( GeoIP->longitude[0] != '\0' )
                {
                    json_object *jgeoip_longitude = json_object_new_string( GeoIP->longitude );
                    json_object_object_add(jobj_geoip_dest,"longitude", jgeoip_longitude);
                }

            if ( GeoIP->latitude[0] != '\0' )
                {
                    json_object *jgeoip_latitude = json_object_new_string( GeoIP->latitude );
                    json_object_object_add(jobj_geoip_dest,"latitude", jgeoip_latitude);
                }

            json_object_object_add(json_obj, "geoip_dest", jobj_geoip_dest);

        }

    snprintf(str, MeerConfig->payload_buffer_size, "%s", (char*)json_object_to_json_string(json_obj) );
    free(GeoIP);

}

#endif
