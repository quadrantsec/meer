/*                                                                                                                     ** Copyright (C) 2018-2022 Quadrant Information Security <quadrantsec.com>                                             ** Copyright (C) 2018-2022 Champ Clark III <cclark@quadrantsec.com>                                                    **                                                                                                                     ** This program is free software; you can redistribute it and/or modify
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

bool IOC_In_Range( char *ip_address );
void IOC_Collector( struct json_object *json_obj, const char *json_string, const char *event_type );
void IOC_Flow( struct json_object *json_obj );
void IOC_FileInfo( struct json_object *json_obj );
void IOC_TLS( struct json_object *json_obj );
void IOC_DNS( struct json_object *json_obj );
void IOC_SSH( struct json_object *json_obj );
void IOC_HTTP( struct json_object *json_obj );
void IOC_SMB( struct json_object *json_obj );
void IOC_FTP( struct json_object *json_obj );







