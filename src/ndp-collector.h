/*                                                                                                                     ** Copyright (C) 2018-2023 Quadrant Information Security <quadrantsec.com>                                             ** Copyright (C) 2018-2023 Champ Clark III <cclark@quadrantsec.com>                                                    **                                                                                                                     ** This program is free software; you can redistribute it and/or modify
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

typedef struct _NDP_SMB_Commands _NDP_SMB_Commands;
struct _NDP_SMB_Commands
{
    char command[32];
};

typedef struct _NDP_FTP_Commands _NDP_FTP_Commands;
struct _NDP_FTP_Commands
{
    char command[5];
};


bool NDP_In_Range( char *ip_address );
void NDP_Collector( struct json_object *json_obj, const char *json_string, const char *event_type, const char *src_ip, const char *dest_ip, const char *flow_id );
void NDP_Flow( struct json_object *json_obj, const char *src_ip, const char *dest_ip, const char *flow_id );
void NDP_FileInfo( struct json_object *json_obj, const char *src_ip, const char *dest_ip, const char *flow_id );
void NDP_TLS( struct json_object *json_obj, const char *src_ip, const char *dest_ip, const char *flow_id );
void NDP_DNS( struct json_object *json_obj, const char *src_ip, const char *dest_ip, const char *flow_id );
void NDP_SSH( struct json_object *json_obj, const char *src_ip, const char *dest_ip, const char *flow_id );
void NDP_HTTP( struct json_object *json_obj, const char *src_ip, const char *dest_ip, const char *flow_id );
void NDP_SMB( struct json_object *json_obj, const char *src_ip, const char *dest_ip, const char *flow_id );
void NDP_FTP( struct json_object *json_obj, const char *src_ip, const char *dest_ip, const char *flow_id );








