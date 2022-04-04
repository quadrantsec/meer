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

#include <stdio.h>
#include <ctype.h>

#include "util-http.h"

char rfc3986[256] = { 0 };
char html5[256] = { 0 };

/* Yanked from https://stackoverflow.com/questions/5842471/c-url-encoding */

void url_encoder_rfc_tables_init(void)
{

    int i;

    for (i = 0; i < 256; i++)
        {

            rfc3986[i] = isalnum( i) || i == '~' || i == '-' || i == '.' || i == '_' ? i : 0;
            html5[i] = isalnum( i) || i == '*' || i == '-' || i == '.' || i == '_' ? i : (i == ' ') ? '+' : 0;
        }
}

char *url_encode( char *table, unsigned char *s, char *enc)
{

    for (; *s; s++)
        {

            if (table[*s]) sprintf( enc, "%c", table[*s]);
            else sprintf( enc, "%%%02X", *s);
            while (*++enc);
        }

    return( enc);
}

