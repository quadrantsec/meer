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

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>


#include "meer-def.h"
#include "meer.h"

#include "util-dns.h"


extern struct _MeerConfig *MeerConfig;
extern struct _MeerCounters *MeerCounters;

struct _DnsCache *DnsCache;

uint32_t DnsCacheCount = 0;


void DNS_Lookup_Reverse( char *host, char *str, size_t size )
{


    struct sockaddr_in ipaddr;
    time_t t;
    struct tm *run;
    char utime_string[20] = { 0 };
    int i = 0;

    t = time(NULL);
    run=localtime(&t);
    strftime(utime_string, sizeof(utime_string), "%s",  run);
    uint64_t utime = atol(utime_string);


    char host_r[NI_MAXHOST] = { 0 };

    for (i=0; i<DnsCacheCount; i++)
        {

            /* If we have a fresh copy,  return whats in memory */

            if ( !strcmp(host, DnsCache[i].ipaddress ) )
                {

                    if ( ( utime - DnsCache[i].lookup_time ) < MeerConfig->dns_cache )
                        {

                            MeerCounters->DNSCacheCount++;

                            snprintf(str, size, "%s", DnsCache[i].reverse);
                            return;

                        }
                    else
                        {

                            /* Re-look it up and return it if cache is stale */

                            memset(&ipaddr, 0, sizeof(struct sockaddr_in));

                            ipaddr.sin_family = AF_INET;
                            ipaddr.sin_port = htons(0);

                            inet_pton(AF_INET, host, &ipaddr.sin_addr);

                            (void)getnameinfo((struct sockaddr *)&ipaddr, sizeof(struct sockaddr_in), host_r, sizeof(host_r), NULL, 0, NI_NAMEREQD);

                            strlcpy(DnsCache[i].reverse, host_r, sizeof(DnsCache[i].reverse));
                            DnsCache[i].lookup_time = utime;

                            MeerCounters->DNSCount++;

                            snprintf(str, size, "%s", DnsCache[i].reverse);
                            return;
                        }

                }

        }

    memset(&ipaddr, 0, sizeof(struct sockaddr_in));

    ipaddr.sin_family = AF_INET;
    ipaddr.sin_port = htons(0);

    inet_pton(AF_INET, host, &ipaddr.sin_addr);

    (void)getnameinfo((struct sockaddr *)&ipaddr, sizeof(struct sockaddr_in), host_r, sizeof(host_r), NULL, 0, NI_NAMEREQD);

    /* Insert DNS into cache */

    DnsCache = (_DnsCache *) realloc(DnsCache, (DnsCacheCount+1) * sizeof(_DnsCache));

    strlcpy(DnsCache[DnsCacheCount].ipaddress, host, sizeof(DnsCache[DnsCacheCount].ipaddress));
    strlcpy(DnsCache[DnsCacheCount].reverse, host_r, sizeof(DnsCache[DnsCacheCount].reverse));
    DnsCache[DnsCacheCount].lookup_time = utime;

    DnsCacheCount++;
    MeerCounters->DNSCount++;

    snprintf(str, size, "%s", host_r);

}

int DNS_Lookup_Forward( const char *host, char *str, size_t size )
{

    char ipstr[INET6_ADDRSTRLEN] = { 0 };

    struct addrinfo hints = {0}, *res = NULL;
    int status;
    void *addr;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;     /* AF_INET or AF_INET6 to force version */
    hints.ai_socktype = SOCK_STREAM;

    if ((status = getaddrinfo(host, NULL, &hints, &res)) != 0)
        {

            Meer_Log(WARN, "%s: %s", gai_strerror(status), host);
            return -1;

        }

    if (res->ai_family == AF_INET)   /* IPv4 */
        {

            struct sockaddr_in *ipv4 = (struct sockaddr_in *)res->ai_addr;
            addr = &(ipv4->sin_addr);

        }
    else     /* IPv6 */
        {

            struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)res->ai_addr;
            addr = &(ipv6->sin6_addr);

        }

    inet_ntop(res->ai_family, addr, ipstr, sizeof ipstr);
    freeaddrinfo(res);

    snprintf(str, size, "%s", ipstr);
    return 0;
}

