/*
** Copyright (C) 2018-2021 Quadrant Information Security <quadrantsec.com>                          ** Copyright (C) 2018-2021 Champ Clark III <cclark@quadrantsec.com>
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

void Redis_Init ( void );
void Redis_Connect( void );
void Redis_Reader ( char *redis_command, char *str, size_t size );
bool Redis_Writer ( const char *command, const char *key, const char *value, int expire );
void JSON_To_Redis ( const char *json_string, const char *key );

