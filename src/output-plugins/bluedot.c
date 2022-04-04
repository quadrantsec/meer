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

/*
 *   bluedot:
 *
 *       enabled: yes
 *       source: "Honeypot Network"
 *       host: "your.host.here"
 *       uri: "/insert.php?apikey=abc123"
 *       skip_networks: "12.159.2.0/24, 199.188.171.0/27"
 *       debug: no
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#ifdef WITH_BLUEDOT

#include <stdio.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include <strings.h>
#include <unistd.h>
#include <string.h>

#include "decode-json-alert.h"

#include "meer.h"
#include "meer-def.h"
#include "util.h"
#include "util-http.h"

#include "output-plugins/bluedot.h"

extern struct _MeerOutput *MeerOutput;
extern struct _MeerCounters *MeerCounters;
extern struct _Bluedot_Skip *Bluedot_Skip;

extern char rfc3986[256];
extern char html5[256];

#define MAX_BUFFER   2048
#define	MAX_COMMENTS 1024
#define	MAX_SOURCE   1024

bool Bluedot( struct _DecodeAlert *DecodeAlert )
{

    char buff[2048] = { 0 };
    char url_encoded[MAX_BUFFER*3] = { 0 };

    struct json_object *json_obj = NULL;
    struct json_object *tmp = NULL;

    const char *bluedot = NULL;

    char ip[MAXIP] = { 0 };
    unsigned char ip_convert[MAXIPBIT] = { 0 };

    char source_encoded[MAX_SOURCE] = { 0 };
    char comments_encoded[MAX_SOURCE*3] = { 0 };

    int sockfd;
    struct sockaddr_in servaddr;
    uint_fast16_t i = 0;

    json_obj = json_tokener_parse(DecodeAlert->alert_metadata);

    /* Which IP are we adding to Bluedot? */

    if (json_object_object_get_ex(json_obj, "bluedot", &tmp))
        {
            bluedot = (char *)json_object_get_string(tmp);

            if ( strstr( bluedot, "by_source" ) )
                {
                    strlcpy(ip, DecodeAlert->src_ip, sizeof(ip));
                }

            else if ( strstr ( bluedot, "by_destination" ) )
                {
                    strlcpy(ip, DecodeAlert->dest_ip, sizeof(ip));
                }

        }

    /* Didn't find either.  Warn the user but continue on */

    if ( ip[0] == '\0' )
        {
            Meer_Log(WARN, "No 'by_source' or 'by_destination' not found in signature!");
            return(0);
        }

    IP2Bit( ip, ip_convert );

    /* Is the IP address "routable?" */

    if ( Is_Notroutable(ip_convert) )
        {

            if ( MeerOutput->bluedot_debug == true )
                {
                    Meer_Log(DEBUG, "[%s, line %d] %s is RFC1918, link local or invalid.", __FILE__, __LINE__, ip);
                }

            return(false);
        }

    /* Is the IP within the "skip_networks"?  Is so,  skip it! */

    for ( i = 0; i < MeerCounters->bluedot_skip_count; i++ )
        {

            if ( Is_Inrange(ip_convert, (unsigned char *)&Bluedot_Skip[i].range, 1) )
                {

                    if ( MeerOutput->bluedot_debug == true )
                        {
                            Meer_Log(DEBUG, "IP address %s is in the 'skip_network' range.  Skipping!", ip);
                        }

                    return(false);
                }

        }


    /* Encode the unknown sources like comments, and "source" */

    url_encode( rfc3986, MeerOutput->bluedot_source, source_encoded);
    url_encode( rfc3986, DecodeAlert->alert_signature, comments_encoded);

    snprintf(buff, sizeof(buff), "GET %s&ip=%s&code=4&source=%s&comments=%s HTTP/1.1\r\nHost: %s\r\nUser-Agent: Meer\r\nConnection: close\r\n\r\n", MeerOutput->bluedot_uri, ip, source_encoded, comments_encoded, MeerOutput->bluedot_host);
    buff[ sizeof(buff) - 1 ] = '\0';

    sockfd = socket(AF_INET, SOCK_STREAM, 0);

    if (sockfd == -1)
        {
            Meer_Log(WARN, "[%s, %d] Unable to create socket for Bluedot request!", __FILE__, __LINE__);
            return(false);
        }

    bzero(&servaddr, sizeof(servaddr));

    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = inet_addr( MeerOutput->bluedot_ip );
    servaddr.sin_port = htons(80);

    if ( MeerOutput->bluedot_debug == true )
        {
            Meer_Log(DEBUG, "------------------------------------------------------");
            Meer_Log(DEBUG, "Sending: %s", buff);
        }

    if (connect(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) != 0)
        {
            Meer_Log(WARN, "[%s, %d] Unabled to connect to server!", __FILE__, __LINE__);
            return(false);
        }


    /* Send request */

    write(sockfd, buff, sizeof(buff));

    /* Get response */

    bzero(buff, sizeof(buff));
    read(sockfd, buff, sizeof(buff));

    /* Close the socket! */

    close(sockfd);

    if ( MeerOutput->bluedot_debug == true )
        {
            printf("Response:\n%s", buff);
        }

    json_object_put(json_obj);

    return(true);
}


#endif
