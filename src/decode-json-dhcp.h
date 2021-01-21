/*
** Copyright (C) 2018-2020 Quadrant Information Security <quadrantsec.com>
** Copyright (C) 2018-2020 Champ Clark III <cclark@quadrantsec.com>
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

#ifdef HAVE_LIBJSON_C
#include <json-c/json.h>
#endif

#ifndef HAVE_LIBJSON_C
libjson-c is required for Meer to function!
#endif

#include "meer-def.h"

typedef struct _DecodeDHCP _DecodeDHCP;
struct _DecodeDHCP
{

char *timestamp;
char *flowid;
char *in_iface;
char *src_ip;
char *src_port;
char *dest_ip;
char *dest_port;
char *proto;

char dhcp_type[16];
    char dhcp_id[32];
    char dhcp_client_mac[20];
    char dhcp_assigned_ip[MAXIP];
    char dhcp_oui[128];

};


void Decode_JSON_DHCP( struct json_object *json_obj, char *json_string, struct _DecodeDHCP *DecodeDHCP );

