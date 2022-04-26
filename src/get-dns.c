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


#include <json-c/json.h>

#include <stdio.h>
#include <string.h>

#include "meer-def.h"
#include "meer.h"
#include "util-dns.h"

extern struct _MeerConfig *MeerConfig;
extern struct _MeerCounters *MeerCounters;

/******************************************************************/
/* Get_DNS() - looks up and adds DNS PTR records to a JSON object */
/******************************************************************/

void Get_DNS( struct json_object *json_obj, const char *json_string, char *str )
{

    struct json_object *json_obj_new = NULL;
    struct json_object *tmp = NULL;

    char src_ip[64] = { 0 };
    char dest_ip[64] = { 0 };

    char src_dns[256] = { 0 };
    char dest_dns[256] = { 0 };

    json_obj_new = json_tokener_parse(json_string);

    if ( json_obj_new == NULL )
        {
            Meer_Log(WARN, "Unable t json_tokener_parse: %s", json_string);
            snprintf(str, MeerConfig->payload_buffer_size, "%s", json_string);
            str[ MeerConfig->payload_buffer_size - 1 ] = '\0';
            return;
        }

    json_object_object_get_ex(json_obj, "src_ip", &tmp);
    strlcpy( src_ip, json_object_get_string(tmp), sizeof(src_ip) );

    json_object_object_get_ex(json_obj, "dest_ip", &tmp);
    strlcpy( dest_ip, json_object_get_string(tmp), sizeof(dest_ip) );

    DNS_Lookup_Reverse( src_ip, src_dns, sizeof( src_dns ) );

    if ( src_dns[0] != '\0' )
        {
            json_object *jsrc_dns = json_object_new_string(src_dns);
            json_object_object_add(json_obj_new,"src_dns", jsrc_dns);
        }

    DNS_Lookup_Reverse( dest_ip, dest_dns, sizeof( dest_dns ) );

    if ( dest_dns[0] != '\0' )
        {
            json_object *jdest_dns = json_object_new_string(dest_dns);
            json_object_object_add(json_obj_new,"dest_dns", jdest_dns);
        }

    snprintf(str, MeerConfig->payload_buffer_size, "%s", (char*)json_object_to_json_string(json_obj_new) );

    json_object_put(json_obj_new);

}

/****************************************************************************/
/* Is_DNS_Event_Type() - Used to determine if an "event_type" need  to have */
/* DNS PTR records added or not.                                            */
/****************************************************************************/

bool Is_DNS_Event_Type( const char *event_type )
{

    uint8_t i = 0;

    /* If it's 'all' we always return true */

    if ( MeerConfig->dns_lookup_types[0][0] == 'a' && MeerConfig->dns_lookup_types[0][1] == 'l' &&
            MeerConfig->dns_lookup_types[0][2] == 'l' )
        {
            return(true);
        }

    /* Lookup event_type and decide DNS PTR is needed */

    for ( i = 0; i < MeerConfig->dns_lookup_types_count; i++ )
        {

            if ( !strcmp( event_type, MeerConfig->dns_lookup_types[i] ) )
                {
                    return(true);
                }

        }

    return(false);
}

