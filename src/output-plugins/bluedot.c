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
 *     enabled: yes
 *     debug: yes
 *     url: "https://bluedot.quadrantsec.com/insert.php?apikey=KEYHERE"
 *     insecure: true                                      # Only applied when https is used.
 *     source: "Field Sensors"
 *     skip_networks: "10.0.0.0/8,192.168.0.0/16,172.16.0.0/12,12.159.2.0/24,199.188.171.0/27"
 *
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

#include <json-c/json.h>
#include <curl/curl.h>

#include "meer.h"
#include "meer-def.h"
#include "util.h"
#include "bluedot.h"

extern struct _MeerOutput *MeerOutput;
extern struct _MeerCounters *MeerCounters;
extern struct _Bluedot_Skip *Bluedot_Skip;


CURL *curl;
struct curl_slist *headers = NULL;

void Bluedot_Init( void )
{

    curl_global_init(CURL_GLOBAL_ALL);
    curl = curl_easy_init();

    if ( MeerOutput->bluedot_insecure == true )
        {

            curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, false);
            curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, false);
            curl_easy_setopt(curl, CURLOPT_SSL_VERIFYSTATUS, false);

        }

    if ( MeerOutput->bluedot_debug == true )
        {
            curl_easy_setopt(curl, CURLOPT_VERBOSE, 1);
        }


    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1);    /* Will send SIGALRM if not set */

    headers = curl_slist_append (headers, MEER_USER_AGENT);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);


}

void Bluedot ( const char *metadata, struct json_object *json_obj )
{

    char ip[MAXIP] = { 0 };
    char buff[8192] = { 0 };
    unsigned char ip_convert[MAXIPBIT] = { 0 };

    const char *bluedot = NULL;
    const char *alert = NULL;
    const char *signature = NULL;

    struct json_object *json_obj_metadata = NULL;
    struct json_object *json_obj_alert = NULL;

    struct json_object *tmp = NULL;

    uint32_t i = 0;

    CURLcode res;

    char *source_encoded = NULL;
    char *comments_encoded = NULL;

    json_obj_metadata = json_tokener_parse(metadata);

    if (json_object_object_get_ex(json_obj_metadata, "bluedot", &tmp))
        {
            bluedot = (char *)json_object_get_string(tmp);

            if ( strstr( bluedot, "by_source" ) )
                {
                    json_object_object_get_ex(json_obj, "src_ip", &tmp);
                    strlcpy(ip, json_object_get_string(tmp), MAXIP);
                }

            else if ( strstr ( bluedot, "by_destination" ) )
                {
                    json_object_object_get_ex(json_obj, "dest_ip", &tmp);
                    strlcpy(ip, json_object_get_string(tmp), MAXIP);
                }

        }

    /* This should never, ever happen */

    if ( ip[0] == '\0' )
        {
            Meer_Log(WARN, "No 'by_source' or 'by_destination' not found in signature!");
            json_object_put(json_obj_metadata);
            return;
        }

    json_object_object_get_ex(json_obj, "alert", &tmp);
    alert = json_object_get_string(tmp);

    if ( alert == NULL )
        {
            Meer_Log(WARN, "No 'alert' data found!");
            json_object_put(json_obj_metadata);
//	    json_object_put(json_obj_alert);
            return;
        }

    json_obj_alert = json_tokener_parse(alert);

    json_object_object_get_ex(json_obj_alert, "signature", &tmp);
    signature = json_object_get_string(tmp);

    if ( signature == NULL )
        {
            Meer_Log(WARN, "No 'signature' data found!");
            json_object_put(json_obj_metadata);
            json_object_put(json_obj_alert);
            return;
        }

    IP2Bit( ip, ip_convert );

    /* Is the IP address "routable?" */

    if ( Is_Notroutable(ip_convert) )
        {

            if ( MeerOutput->bluedot_debug == true )
                {
                    Meer_Log(DEBUG, "[%s, line %d] %s is RFC1918, link local or invalid.", __FILE__, __LINE__, ip);
                }

            json_object_put(json_obj_metadata);
            return;
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

                    json_object_put(json_obj_metadata);
                    return;
                }

        }

    /* We need to encode some data */

    comments_encoded = curl_easy_escape(curl, signature, strlen(signature));
    source_encoded = curl_easy_escape(curl, MeerOutput->bluedot_source, strlen(MeerOutput->bluedot_source));

    snprintf(buff, sizeof(buff), "%s&ip=%s&code=4&comments=%s&source=%s", MeerOutput->bluedot_url,ip, comments_encoded, source_encoded);

    buff[ sizeof(buff) - 1 ] = '\0';

    curl_easy_setopt(curl, CURLOPT_URL, buff);
    res = curl_easy_perform(curl);

    if(res != CURLE_OK)
    {
        Meer_Log(WARN, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
    }

    json_object_put(json_obj_metadata);
    json_object_put(json_obj_alert);

}

#endif
