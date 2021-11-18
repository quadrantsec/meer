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

#include <stdbool.h>
#include "meer-def.h"

typedef struct _Fingerprint_Networks _Fingerprint_Networks;
struct _Fingerprint_Networks
{

    struct
    {
        unsigned char ipbits[MAXIPBIT];
        unsigned char maskbits[MAXIPBIT];
    } range;

};


void Drop_Priv(void);
bool Check_Endian(void);
char *Hexify(char *xdata, int length);
bool Validate_JSON_String( const char *buf );
bool IP2Bit(char *ipaddr, unsigned char *out);
bool Mask2Bit(int mask, unsigned char *out);
void Remove_Spaces(char *s);
void Remove_Return(char *s);
uint64_t Current_Epoch( void );
bool Is_IPv6 (char *ipaddr);
double CalcPct(uint64_t cnt, uint64_t total);
double CalcPct_Down(uint64_t cnt, uint64_t total);


bool Is_IP (char *ipaddr, int ver );
int File_Check (char *filename);
bool Is_Inrange ( unsigned char *ip, unsigned char *tests, int count);
void To_UpperC(char *const s);
uint32_t Djb2_Hash(char *str);
void Convert_ISO8601_For_SQL( char *time, char *str, size_t size );
bool Is_Notroutable ( unsigned char *ip );
bool Try_And_Fix_IP ( char *orig_ip, char *str, size_t size );
//void Replace_String(const char *in_str, char *orig, char *rep, char *str, size_t size);

