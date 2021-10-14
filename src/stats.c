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

    // DO JSON PER SEC!

    Meer_Log(NORMAL, "");
    Meer_Log(NORMAL, "--[ Meer Statistics ]---------------------------------------");
    Meer_Log(NORMAL, "");
    Meer_Log(NORMAL, " - Decoded Statistics:");
    Meer_Log(NORMAL, "");
    Meer_Log(NORMAL, " Total         : %" PRIu64 "", MeerCounters->total);
    Meer_Log(NORMAL, " Bad           : %" PRIu64 " (%.3f%%)", MeerCounters->bad, CalcPct( MeerCounters->total, MeerCounters->bad ) );
    Meer_Log(NORMAL, "");
    Meer_Log(NORMAL, " alert         : %" PRIu64 " (%.3f%%)", MeerCounters->alert, CalcPct( MeerCounters->total, MeerCounters->alert ) );
    Meer_Log(NORMAL, " files         : %" PRIu64 " (%.3f%%)", MeerCounters->files, CalcPct( MeerCounters->total, MeerCounters->files ) );
    Meer_Log(NORMAL, " flow          : %" PRIu64 " (%.3f%%)", MeerCounters->flow, CalcPct( MeerCounters->total, MeerCounters->flow ) );
    Meer_Log(NORMAL, " dns           : %" PRIu64 " (%.3f%%)", MeerCounters->dns, CalcPct( MeerCounters->total, MeerCounters->dns ) );
    Meer_Log(NORMAL, " http          : %" PRIu64 " (%.3f%%)", MeerCounters->http, CalcPct( MeerCounters->total, MeerCounters->http ) );
    Meer_Log(NORMAL, " tls           : %" PRIu64 " (%.3f%%)", MeerCounters->tls, CalcPct( MeerCounters->total, MeerCounters->tls ) );
    Meer_Log(NORMAL, " ssh           : %" PRIu64 " (%.3f%%)", MeerCounters->ssh, CalcPct( MeerCounters->total, MeerCounters->ssh ) );
    Meer_Log(NORMAL, " smtp          : %" PRIu64 " (%.3f%%)", MeerCounters->smtp, CalcPct( MeerCounters->total, MeerCounters->smtp ) );
    Meer_Log(NORMAL, " email         : %" PRIu64 " (%.3f%%)", MeerCounters->email, CalcPct( MeerCounters->total, MeerCounters->email ) );
    Meer_Log(NORMAL, " fileinfo      : %" PRIu64 " (%.3f%%)", MeerCounters->fileinfo, CalcPct( MeerCounters->total, MeerCounters->fileinfo ) );
    Meer_Log(NORMAL, " dhcp          : %" PRIu64 " (%.3f%%)", MeerCounters->dhcp, CalcPct( MeerCounters->total, MeerCounters->dhcp ) );
    Meer_Log(NORMAL, " stats         : %" PRIu64 " (%.3f%%)", MeerCounters->stats, CalcPct( MeerCounters->total, MeerCounters->stats ) );
    Meer_Log(NORMAL, " rdp           : %" PRIu64 " (%.3f%%)", MeerCounters->rdp, CalcPct( MeerCounters->total, MeerCounters->rdp ) );
    Meer_Log(NORMAL, " sip           : %" PRIu64 " (%.3f%%)", MeerCounters->sip, CalcPct( MeerCounters->total, MeerCounters->sip ) );
    Meer_Log(NORMAL, " ftp           : %" PRIu64 " (%.3f%%)", MeerCounters->ftp, CalcPct( MeerCounters->total, MeerCounters->ftp ) );
    Meer_Log(NORMAL, " ikev2         : %" PRIu64 " (%.3f%%)", MeerCounters->ikev2, CalcPct( MeerCounters->total, MeerCounters->ikev2 ) );
    Meer_Log(NORMAL, " nfs           : %" PRIu64 " (%.3f%%)", MeerCounters->nfs, CalcPct( MeerCounters->total, MeerCounters->nfs ) );
    Meer_Log(NORMAL, " tftp          : %" PRIu64 " (%.3f%%)", MeerCounters->tftp, CalcPct( MeerCounters->total, MeerCounters->tftp ) );
    Meer_Log(NORMAL, " smb           : %" PRIu64 " (%.3f%%)", MeerCounters->smb, CalcPct( MeerCounters->total, MeerCounters->smb ) );
    Meer_Log(NORMAL, " dcerpc        : %" PRIu64 " (%.3f%%)", MeerCounters->dcerpc, CalcPct( MeerCounters->total, MeerCounters->dcerpc ) );
    Meer_Log(NORMAL, " mqtt          : %" PRIu64 " (%.3f%%)", MeerCounters->mqtt, CalcPct( MeerCounters->total, MeerCounters->mqtt ) );
    Meer_Log(NORMAL, " netflow       : %" PRIu64 " (%.3f%%)", MeerCounters->netflow, CalcPct( MeerCounters->total, MeerCounters->netflow ) );
    Meer_Log(NORMAL, " metadata      : %" PRIu64 " (%.3f%%)", MeerCounters->metadata, CalcPct( MeerCounters->total, MeerCounters->metadata ) );
    Meer_Log(NORMAL, " dnp3          : %" PRIu64 " (%.3f%%)", MeerCounters->dnp3, CalcPct( MeerCounters->total, MeerCounters->dnp3 ) );
    Meer_Log(NORMAL, " anomaly       : %" PRIu64 " (%.3f%%)", MeerCounters->anomaly, CalcPct( MeerCounters->total, MeerCounters->anomaly ) );



    //Meer_Log(NORMAL, " Waldo Postion : %" PRIu64 "", MeerWaldo->position);
    //Meer_Log(NORMAL, " JSON          : %" PRIu64 "", MeerCounters->JSONCount);
    //Meer_Log(NORMAL, " Invalid JSON  : %" PRIu64 " (%.3f%%)", MeerCounters->InvalidJSONCount, CalcPct(MeerCounters->JSONCount,MeerCounters->InvalidJSONCount));
    //Meer_Log(NORMAL, " Flow          : %" PRIu64 "", MeerCounters->FlowCount);
    //Meer_Log(NORMAL, " HTTP          : %" PRIu64 "", MeerCounters->HTTPCount);
    //Meer_Log(NORMAL, " TLS           : %" PRIu64 "", MeerCounters->TLSCount);
    //Meer_Log(NORMAL, " SSH           : %" PRIu64 "", MeerCounters->SSHCount);
    //Meer_Log(NORMAL, " SMTP          : %" PRIu64 "", MeerCounters->SMTPCount);
    //Meer_Log(NORMAL, " Email         : %" PRIu64 "", MeerCounters->EmailCount);
    //Meer_Log(NORMAL, " Metadata      : %" PRIu64 "", MeerCounters->MetadataCount);

#ifdef BLUEDOT
    Meer_Log(NORMAL, " Bluedot       : %" PRIu64 "", MeerCounters->bluedot);
#endif


    Meer_Log(NORMAL, "");

    if ( MeerConfig->dns == true )
        {

            Meer_Log(NORMAL, " - DNS Statistics:");
            Meer_Log(NORMAL, "");
            Meer_Log(NORMAL, " DNS Lookups   : %"PRIu64 "", MeerCounters->DNSCount);
            Meer_Log(NORMAL, " DNS Cache Hits: %"PRIu64 " (%.3f%%)", MeerCounters->DNSCacheCount, CalcPct_Down(MeerCounters->DNSCacheCount,MeerCounters->DNSCount));
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
