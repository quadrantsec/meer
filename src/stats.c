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


struct _MeerCounters *MeerCounters;
struct _MeerWaldo *MeerWaldo;
struct _MeerConfig *MeerConfig;
struct _MeerOutput *MeerOutput;

void Statistics( void )
{

    Meer_Log(NORMAL, "");
    Meer_Log(NORMAL, "--[ Meer Statistics ]---------------------------------------");
    Meer_Log(NORMAL, "");
    Meer_Log(NORMAL, " - Decoded Statistics:");
    Meer_Log(NORMAL, "");
    Meer_Log(NORMAL, " Waldo Postion : %" PRIu64 "", MeerWaldo->position);
    Meer_Log(NORMAL, " JSON          : %" PRIu64 "", MeerCounters->JSONCount);
    Meer_Log(NORMAL, " Invalid JSON  : %" PRIu64 " (%.3f%%)", MeerCounters->InvalidJSONCount, CalcPct(MeerCounters->JSONCount,MeerCounters->InvalidJSONCount));
    Meer_Log(NORMAL, " Flow          : %" PRIu64 "", MeerCounters->FlowCount);
    Meer_Log(NORMAL, " HTTP          : %" PRIu64 "", MeerCounters->HTTPCount);
    Meer_Log(NORMAL, " TLS           : %" PRIu64 "", MeerCounters->TLSCount);
    Meer_Log(NORMAL, " SSH           : %" PRIu64 "", MeerCounters->SSHCount);
    Meer_Log(NORMAL, " SMTP          : %" PRIu64 "", MeerCounters->SMTPCount);
    Meer_Log(NORMAL, " Email         : %" PRIu64 "", MeerCounters->EmailCount);
    Meer_Log(NORMAL, " Metadata      : %" PRIu64 "", MeerCounters->MetadataCount);

#ifdef BLUEDOT
    Meer_Log(NORMAL, " Bluedot       : %" PRIu64 "", MeerCounters->BluedotCount);
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
