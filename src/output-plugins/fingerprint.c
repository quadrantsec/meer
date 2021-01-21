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

#ifdef HAVE_LIBHIREDIS

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdbool.h>

#include "meer.h"
#include "meer-def.h"
#include "util.h"

#include "decode-json-alert.h"
#include "decode-json-dhcp.h"

#include "fingerprints.h"
#include "output-plugins/fingerprint.h"
#include "output-plugins/sql.h"
#include "output-plugins/redis.h"

struct _MeerOutput *MeerOutput;
struct _MeerCounters *MeerCounters;
struct _MeerConfig *MeerConfig;

struct _Fingerprint_Networks *Fingerprint_Networks;

void Output_Fingerprint_IP ( struct _DecodeAlert *DecodeAlert, char *fingerprint_IP_JSON )
{

    char key[512] = { 0 };
    snprintf(key, sizeof(key), "%s|ip|%s", FINGERPRINT_REDIS_KEY, DecodeAlert->src_ip);
    Redis_Writer( "SET", key, fingerprint_IP_JSON, FINGERPRINT_IP_REDIS_EXPIRE);

}

void Output_Fingerprint_EVENT( struct _DecodeAlert *DecodeAlert, struct _FingerprintData *FingerprintData, char *fingerprint_EVENT_JSON )
{

    char key[512] = { 0 };

    snprintf(key, sizeof(key), "%s|event|%s|%" PRIu64 "", FINGERPRINT_REDIS_KEY, DecodeAlert->src_ip, DecodeAlert->alert_signature_id);
    Redis_Writer( "SET", key, fingerprint_EVENT_JSON, FingerprintData->expire );

    if ( MeerConfig->fingerprint_log[0] != '\0' )
        {
            fprintf(MeerConfig->fingerprint_log_fd, "%s\n", fingerprint_EVENT_JSON);
            fflush(MeerConfig->fingerprint_log_fd);
        }

}

void Output_Fingerprint_DHCP ( struct _DecodeDHCP *DecodeDHCP, char *fingerprint_DHCP_JSON )
{

    char key[512] = { 0 };
    snprintf(key, sizeof(key), "%s|dhcp|%s", FINGERPRINT_REDIS_KEY, DecodeDHCP->dhcp_assigned_ip);
    Redis_Writer( "SET", key, fingerprint_DHCP_JSON, FINGERPRINT_DHCP_REDIS_EXPIRE );

}

#endif
