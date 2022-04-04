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

typedef struct _FingerprintData _FingerprintData;
struct _FingerprintData
{

    char os[32];
    char type[8];
    char source[32];
    uint32_t expire;

};

void Fingerprint_DHCP ( struct json_object *json_obj, const char *json_string );
bool Is_Fingerprint( struct json_object *json_obj, struct _FingerprintData *FingerprintData );
void Get_Fingerprint( struct json_object *json_obj, const char *json_string, char *str );
void Fingerprint_JSON_Redis( struct json_object *json_obj, struct _FingerprintData *FingerprintData, char *str);
