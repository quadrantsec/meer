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

/* Display statistics */

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#include <stdio.h>

#include "meer.h"
#include "meer-def.h"
#include "stats.h"
#include "util.h"


extern struct _MeerCounters *MeerCounters;
extern struct _MeerWaldo *MeerWaldo;
extern struct _MeerConfig *MeerConfig;
extern struct _MeerOutput *MeerOutput;

void Statistics( void )
{

    /* Idea:  Add "JSON per/sec"? */

    Meer_Log(NORMAL, "");
    Meer_Log(NORMAL, "--[ Meer Statistics ]---------------------------------------");
    Meer_Log(NORMAL, "");
    Meer_Log(NORMAL, " - Decoded Statistics:");
    Meer_Log(NORMAL, "");
    Meer_Log(NORMAL, " Total         : %" PRIu64 "", MeerCounters->total);
    Meer_Log(NORMAL, " Bad           : %" PRIu64 " (%.3f%%)", MeerCounters->bad, CalcPct( MeerCounters->bad, MeerCounters->total ) );
    Meer_Log(NORMAL, "");
    Meer_Log(NORMAL, " alert         : %" PRIu64 " (%.3f%%)", MeerCounters->alert, CalcPct( MeerCounters->alert, MeerCounters->total ) );
    Meer_Log(NORMAL, " files         : %" PRIu64 " (%.3f%%)", MeerCounters->files, CalcPct( MeerCounters->files, MeerCounters->total ) );
    Meer_Log(NORMAL, " flow          : %" PRIu64 " (%.3f%%)", MeerCounters->flow, CalcPct( MeerCounters->flow, MeerCounters->total ) );
    Meer_Log(NORMAL, " dns           : %" PRIu64 " (%.3f%%)", MeerCounters->dns, CalcPct( MeerCounters->dns, MeerCounters->total ) );
    Meer_Log(NORMAL, " http          : %" PRIu64 " (%.3f%%)", MeerCounters->http, CalcPct( MeerCounters->http, MeerCounters->total ) );
    Meer_Log(NORMAL, " tls           : %" PRIu64 " (%.3f%%)", MeerCounters->tls, CalcPct( MeerCounters->tls, MeerCounters->total ) );
    Meer_Log(NORMAL, " ssh           : %" PRIu64 " (%.3f%%)", MeerCounters->ssh, CalcPct( MeerCounters->ssh, MeerCounters->total ) );
    Meer_Log(NORMAL, " smtp          : %" PRIu64 " (%.3f%%)", MeerCounters->smtp, CalcPct( MeerCounters->smtp, MeerCounters->total ) );
    Meer_Log(NORMAL, " email         : %" PRIu64 " (%.3f%%)", MeerCounters->email, CalcPct( MeerCounters->email, MeerCounters->total ) );
    Meer_Log(NORMAL, " fileinfo      : %" PRIu64 " (%.3f%%)", MeerCounters->fileinfo, CalcPct( MeerCounters->fileinfo, MeerCounters->total ) );
    Meer_Log(NORMAL, " dhcp          : %" PRIu64 " (%.3f%%)", MeerCounters->dhcp, CalcPct( MeerCounters->dhcp, MeerCounters->total ) );
    Meer_Log(NORMAL, " stats         : %" PRIu64 " (%.3f%%)", MeerCounters->stats, CalcPct( MeerCounters->stats, MeerCounters->total ) );
    Meer_Log(NORMAL, " rdp           : %" PRIu64 " (%.3f%%)", MeerCounters->rdp, CalcPct( MeerCounters->rdp, MeerCounters->total ) );
    Meer_Log(NORMAL, " sip           : %" PRIu64 " (%.3f%%)", MeerCounters->sip, CalcPct( MeerCounters->sip, MeerCounters->total ) );
    Meer_Log(NORMAL, " ftp           : %" PRIu64 " (%.3f%%)", MeerCounters->ftp, CalcPct( MeerCounters->ftp, MeerCounters->total ) );
    Meer_Log(NORMAL, " ikev2         : %" PRIu64 " (%.3f%%)", MeerCounters->ikev2, CalcPct( MeerCounters->ikev2, MeerCounters->total ) );
    Meer_Log(NORMAL, " nfs           : %" PRIu64 " (%.3f%%)", MeerCounters->nfs, CalcPct( MeerCounters->nfs, MeerCounters->total ) );
    Meer_Log(NORMAL, " tftp          : %" PRIu64 " (%.3f%%)", MeerCounters->tftp, CalcPct( MeerCounters->tftp, MeerCounters->total ) );
    Meer_Log(NORMAL, " smb           : %" PRIu64 " (%.3f%%)", MeerCounters->smb, CalcPct( MeerCounters->smb, MeerCounters->total ) );
    Meer_Log(NORMAL, " dcerpc        : %" PRIu64 " (%.3f%%)", MeerCounters->dcerpc, CalcPct( MeerCounters->dcerpc, MeerCounters->total ) );
    Meer_Log(NORMAL, " mqtt          : %" PRIu64 " (%.3f%%)", MeerCounters->mqtt, CalcPct( MeerCounters->mqtt, MeerCounters->total ) );
    Meer_Log(NORMAL, " netflow       : %" PRIu64 " (%.3f%%)", MeerCounters->netflow, CalcPct( MeerCounters->netflow, MeerCounters->total ) );
    Meer_Log(NORMAL, " metadata      : %" PRIu64 " (%.3f%%)", MeerCounters->metadata, CalcPct( MeerCounters->metadata, MeerCounters->total ) );
    Meer_Log(NORMAL, " dnp3          : %" PRIu64 " (%.3f%%)", MeerCounters->dnp3, CalcPct( MeerCounters->dnp3, MeerCounters->total ) );
    Meer_Log(NORMAL, " anomaly       : %" PRIu64 " (%.3f%%)", MeerCounters->anomaly, CalcPct( MeerCounters->anomaly, MeerCounters->total ) );
    Meer_Log(NORMAL, " client_stats  : %" PRIu64 " (%.3f%%)", MeerCounters->client_stats, CalcPct( MeerCounters->client_stats, MeerCounters->total ) );

    Meer_Log(NORMAL, "");
    Meer_Log(NORMAL, " Waldo Postion : %" PRIu64 "", MeerWaldo->position);
//    Meer_Log(NORMAL, " JSON          : %" PRIu64 "", MeerCounters->JSONCount);
//    Meer_Log(NORMAL, " Invalid JSON  : %" PRIu64 " (%.3f%%)", MeerCounters->bad, CalcPct(MeerCounters->JSONCount,MeerCounters->bad));

#ifdef BLUEDOT
    Meer_Log(NORMAL, " Bluedot       : %" PRIu64 "", MeerCounters->bluedot);
#endif


    Meer_Log(NORMAL, "");

    if ( MeerConfig->dns == true )
        {

            Meer_Log(NORMAL, " - DNS Statistics:");
            Meer_Log(NORMAL, "");
            Meer_Log(NORMAL, " DNS Lookups   : %"PRIu64 "", MeerCounters->DNSCount);
            Meer_Log(NORMAL, " DNS Cache Hits: %"PRIu64 " (%.3f%%)", MeerCounters->DNSCacheCount, CalcPct(MeerCounters->DNSCacheCount,MeerCounters->DNSCount));
            Meer_Log(NORMAL, "");

        }

#if defined(HAVE_LIBMYSQLCLIENT) || defined(HAVE_LIBPQ)

    if ( MeerOutput->sql_enabled == true )
        {

            Meer_Log(NORMAL, " - MySQL/MariaDB Statistics:");
            Meer_Log(NORMAL, "");
            Meer_Log(NORMAL, " Health Checks          : %"PRIu64 "", MeerCounters->HealthCountT);
            Meer_Log(NORMAL, " INSERT                 : %"PRIu64 "", MeerCounters->INSERTCount);
            Meer_Log(NORMAL, " SELECT                 : %"PRIu64 "", MeerCounters->SELECTCount);
            Meer_Log(NORMAL, " UPDATE                 : %"PRIu64 "", MeerCounters->UPDATECount);
            Meer_Log(NORMAL, " Class Cache Misses     : %"PRIu64 "", MeerCounters->ClassCacheMissCount);
            Meer_Log(NORMAL, " Class Cache Hits       : %"PRIu64 " (%.3f%%)", MeerCounters->ClassCacheHitCount, CalcPct(MeerCounters->ClassCacheHitCount, MeerCounters->ClassCacheMissCount));
            Meer_Log(NORMAL, " Signature Cache Misses : %"PRIu64 "", MeerCounters->ClassCacheMissCount);
            Meer_Log(NORMAL, " Signature Cache Hits   : %"PRIu64 " (%.3f%%)", MeerCounters->ClassCacheHitCount, CalcPct(MeerCounters->ClassCacheHitCount, MeerCounters->ClassCacheMissCount));
            Meer_Log(NORMAL, "");

        }

    if ( MeerOutput->pipe_enabled == true )
        {

            Meer_Log(NORMAL, " - Pipe Statistics:");
            Meer_Log(NORMAL, "");
            Meer_Log(NORMAL, " JSON writes        : %"PRIu64 "", MeerCounters->JSONPipeWrites);
            Meer_Log(NORMAL, " JSON misses/errors : %"PRIu64 " (%.3f%%)", MeerCounters->JSONPipeMisses, CalcPct(MeerCounters->JSONPipeWrites, MeerCounters->JSONPipeMisses));

        }

    if ( MeerOutput->external_enabled == true )
        {

            Meer_Log(NORMAL, " - External Statistics:");
            Meer_Log(NORMAL, "");
            Meer_Log(NORMAL, " Success       : %"PRIu64 "", MeerCounters->ExternalHitCount);
            Meer_Log(NORMAL, " Failures      : %"PRIu64 "", MeerCounters->ExternalMissCount);

        }


    Meer_Log(NORMAL, "");

#endif

}
