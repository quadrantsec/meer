/*
** Copyright (C) 2018-2023 Quadrant Information Security <quadrantsec.com>
** Copyright (C) 2018-2023 Champ Clark III <cclark@quadrantsec.com>
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


void Fingerprint_DHCP ( struct json_object *json_obj, const char *json_string );
bool Fingerprint_In_Range( char *ip_address );
bool Is_Fingerprint( struct json_object *json_obj );
bool Fingerprint_JSON_IP_Redis ( struct json_object *json_obj );
bool Fingerprint_JSON_Event_Redis ( struct json_object *json_obj, char *str, size_t size );
void Get_Fingerprint( struct json_object *json_obj, char *str, size_t size, const char *json_string );

