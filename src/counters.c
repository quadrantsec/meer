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

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "meer.h"
#include "meer-def.h"
#include "counters.h"

extern struct _MeerCounters *MeerCounters;

void Counters ( const char *event_type )
{

    MeerCounters->total++;

    if ( !strcmp(event_type, "alert" ) )
        {
            MeerCounters->alert++;
            return;
        }

    else if ( !strcmp(event_type, "files" ) )
        {
            MeerCounters->files++;
            return;
        }

    else if ( !strcmp(event_type, "flow" ) )
        {
            MeerCounters->flow++;
            return;
        }

    else if ( !strcmp(event_type, "dns" ) )
        {
            MeerCounters->dns++;
            return;
        }

    else if ( !strcmp(event_type, "http" ) )
        {
            MeerCounters->http++;
            return;
        }

    else if ( !strcmp(event_type, "tls" ) )
        {
            MeerCounters->tls++;
            return;
        }

    else if ( !strcmp(event_type, "ssh" ) )
        {
            MeerCounters->ssh++;
            return;
        }

    else if ( !strcmp(event_type, "smtp" ) )
        {
            MeerCounters->smtp++;
            return;
        }

    else if ( !strcmp(event_type, "email" ) )
        {
            MeerCounters->email++;
            return;
        }

    else if ( !strcmp(event_type, "fileinfo" ) )
        {
            MeerCounters->fileinfo++;
            return;
        }

    else if ( !strcmp(event_type, "dhcp" ) )
        {
            MeerCounters->dhcp++;
            return;
        }

    else if ( !strcmp(event_type, "stats" ) )
        {
            MeerCounters->stats++;
            return;
        }

    else if ( !strcmp(event_type, "rdp" ) )
        {
            MeerCounters->rdp++;
            return;
        }

    else if ( !strcmp(event_type, "sip" ) )
        {
            MeerCounters->sip++;
            return;
        }

    else if ( !strcmp(event_type, "ftp" ) || !strcmp(event_type, "ftp_data" ) )
        {
            MeerCounters->ftp++;
            return;
        }

    else if ( !strcmp(event_type, "ikev2" ) )
        {
            MeerCounters->ikev2++;
            return;
        }

    else if ( !strcmp(event_type, "nfs" ) )
        {
            MeerCounters->nfs++;
            return;
        }

    else if ( !strcmp(event_type, "tftp" ) )
        {
            MeerCounters->tftp++;
            return;
        }

    else if ( !strcmp(event_type, "smb" ) )
        {
            MeerCounters->smb++;
            return;
        }

    else if ( !strcmp(event_type, "dcerpc" ) )
        {
            MeerCounters->dcerpc++;
            return;
        }

    else if ( !strcmp(event_type, "mqtt" ) )
        {
            MeerCounters->mqtt++;
            return;
        }

    else if ( !strcmp(event_type, "netflow" ) )
        {
            MeerCounters->netflow++;
            return;
        }

    else if ( !strcmp(event_type, "metadata" ) )
        {
            MeerCounters->metadata++;
            return;
        }

    else if ( !strcmp(event_type, "dnp3" ) )
        {
            MeerCounters->dnp3++;
            return;
        }

    else if ( !strcmp(event_type, "anomaly" ) )
        {
            MeerCounters->anomaly++;
            return;
        }

    else if ( !strcmp(event_type, "fingerprint" ) )
        {
            MeerCounters->fingerprint++;
            return;
        }

    else if ( !strcmp(event_type, "client_stats" ) )
        {
            MeerCounters->client_stats++;
            return;
        }

    MeerCounters->unknown++;
    Meer_Log(WARN, "[%s, line %d] Unknown event_type '%s'. Skipping....", __FILE__, __LINE__, event_type);

}
