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
** GNU General Public License for more details.                                                                        **
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

typedef struct _GeoIP _GeoIP;
struct _GeoIP
{

    uint_fast8_t results;

    char city[32];
    char country[32];
    char subdivision[3];
    char postal[16];
    char timezone[32];
    char latitude[16];
    char longitude[16];

};


void Open_GeoIP_Database( void );
void GeoIP_Lookup( const char *ip_address, struct _GeoIP *GeoIP );

