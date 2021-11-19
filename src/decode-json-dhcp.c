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

/* Decode Suricata "dhcp" */

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

#include "util.h"
#include "meer.h"
#include "meer-def.h"

#include "decode-json-dhcp.h"

extern struct _MeerCounters *MeerCounters;
extern struct _MeerConfig *MeerConfig;

void Decode_JSON_DHCP( struct json_object *json_obj, char *json_string, struct _DecodeDHCP *DecodeDHCP )
{

    struct json_object *tmp = NULL;
    struct json_object *json_obj_dhcp = NULL;
    struct json_object *tmp_dhcp = NULL;

    char *dhcp = NULL;

    DecodeDHCP->timestamp = NULL;
    DecodeDHCP->flowid = NULL;
    DecodeDHCP->in_iface = NULL;
    DecodeDHCP->src_ip = NULL;
    DecodeDHCP->src_port = NULL;
    DecodeDHCP->dest_ip = NULL;
    DecodeDHCP->dest_port = NULL;
    DecodeDHCP->proto = NULL;

    if (json_object_object_get_ex(json_obj, "timestamp", &tmp))
        {
            DecodeDHCP->timestamp = (char *)json_object_get_string(tmp);
        }

    if (json_object_object_get_ex(json_obj, "flow_id", &tmp))
        {
            DecodeDHCP->flowid = (char *)json_object_get_string(tmp);
        }

    if (json_object_object_get_ex(json_obj, "in_iface", &tmp))
        {
            DecodeDHCP->in_iface = (char *)json_object_get_string(tmp);
        }

    if (json_object_object_get_ex(json_obj, "src_ip", &tmp))
        {
            DecodeDHCP->src_ip = (char *)json_object_get_string(tmp);
        }

    if (json_object_object_get_ex(json_obj, "src_port", &tmp))
        {
            DecodeDHCP->src_port = (char *)json_object_get_string(tmp);
        }

    if (json_object_object_get_ex(json_obj, "dest_ip", &tmp))
        {
            DecodeDHCP->dest_ip = (char *)json_object_get_string(tmp);
        }

    if (json_object_object_get_ex(json_obj, "dest_port", &tmp))
        {
            DecodeDHCP->dest_port = (char *)json_object_get_string(tmp);
        }

    if (json_object_object_get_ex(json_obj, "proto", &tmp))
        {
            DecodeDHCP->proto = (char *)json_object_get_string(tmp);
        }

    if (json_object_object_get_ex(json_obj, "dhcp", &tmp))
        {

            dhcp = (char *)json_object_get_string(tmp);

            if ( Validate_JSON_String( dhcp ) == 0 )
                {

                    json_obj_dhcp = json_tokener_parse(dhcp);

                    if (json_object_object_get_ex(json_obj_dhcp, "type", &tmp_dhcp))
                        {
                            strlcpy(DecodeDHCP->dhcp_type, (char *)json_object_get_string(tmp_dhcp), sizeof(DecodeDHCP->dhcp_type));
                        }

                    if (json_object_object_get_ex(json_obj_dhcp, "id", &tmp_dhcp))
                        {
                            strlcpy(DecodeDHCP->dhcp_id, (char *)json_object_get_string(tmp_dhcp), sizeof(DecodeDHCP->dhcp_id));
                        }

                    if (json_object_object_get_ex(json_obj_dhcp, "client_mac", &tmp_dhcp))
                        {
                            strlcpy(DecodeDHCP->dhcp_client_mac, (char *)json_object_get_string(tmp_dhcp), sizeof(DecodeDHCP->dhcp_client_mac));
                        }

                    if (json_object_object_get_ex(json_obj_dhcp, "assigned_ip", &tmp_dhcp))
                        {

                            char *assigned_ip = (char *)json_object_get_string(tmp_dhcp);

                            /* 0.0.0.0 is no good, try to avoid it */

                            if ( !strcmp(assigned_ip, "0.0.0.0" ) && strcmp(DecodeDHCP->dest_ip, "255.255.255.255") )
                                {
                                    assigned_ip =  DecodeDHCP->dest_ip;
                                }

                            strlcpy(DecodeDHCP->dhcp_assigned_ip, assigned_ip, sizeof(DecodeDHCP->dhcp_assigned_ip));
                        }

                }

        }

    if ( dhcp == NULL )
        {
            Meer_Log(WARN, "[%s, line %d] Got event_type: dhcp log without dhcp json: %s", __FILE__, __LINE__, json_string);
        }

    json_object_put(json_obj_dhcp);

}
