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


#include <json-c/json.h>

#include <stdio.h>

#include "meer-def.h"
#include "meer.h"

#include "util-dns.h"


extern struct _MeerConfig *MeerConfig;
extern struct _MeerCounters *MeerCounters;

char *Get_DNS( struct json_object *json_obj )
{

    struct json_object *tmp = NULL;

    char src_ip[64] = { 0 };
    char dest_ip[64] = { 0 };

    char src_dns[256] = { 0 };
    char dest_dns[256] = { 0 };


    if (json_object_object_get_ex(json_obj, "src_ip", &tmp))
        {
            strlcpy( src_ip, json_object_get_string(tmp), sizeof(src_ip) );
        }

    if (json_object_object_get_ex(json_obj, "dest_ip", &tmp))
        {
            strlcpy( dest_ip, json_object_get_string(tmp), sizeof(dest_ip) );
        }

    DNS_Lookup_Reverse( src_ip, src_dns, sizeof( src_dns) );

    if ( src_dns[0] != '\0' )
        {
            json_object *jsrc_dns = json_object_new_string(src_dns);
            json_object_object_add(json_obj,"src_dns", jsrc_dns);
        }

    DNS_Lookup_Reverse( dest_ip, dest_dns, sizeof( dest_dns ) );

    if ( dest_dns[0] != '\0' )
        {
            json_object *jdest_dns = json_object_new_string(dest_dns);
            json_object_object_add(json_obj,"dest_dns", jdest_dns);
        }

    return ( (char*)json_object_to_json_string(json_obj) );


}

