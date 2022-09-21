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

#include <json-c/json.h>

void Init_Output( void );
bool Output_Pipe ( const char *json_string, const char *event_type );
bool Output_External ( const char *json_string, struct json_object *json_obj, const char *event_type );
void Output_Bluedot ( struct json_object *json_obj );
bool Output_Elasticsearch ( const char *json_string, const char *event_type, const char *id );
bool Output_Do_Elasticsearch ( const char *json_string, const char *event_type, const char *id );
bool Output_File ( const char *json_string, const char *event_type );
bool Output_Redis( const char *json_string, const char *event_type );
