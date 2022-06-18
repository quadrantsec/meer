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

/* caclulate-stats.c - Suricata only accumulates stat entries.  This is fine
   for tools like RRDTool and LibreNMS but it doesn't work well if you want 
   to pull data for specific dates.  This code leaves the "stats" in tact and
   creates a new "calculated" key/value which is the sum totals in between 
   times! */

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#include <json-c/json.h>

#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <stdbool.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>


#include "meer-def.h"
#include "meer.h"
#include "calculate-stats.h"
#include "waldo.h"


extern struct _MeerConfig *MeerConfig;
extern struct _MeerWaldo *MeerWaldo;


void Calculate_Stats( struct json_object *json_obj, char *str )
{

    char *stats = NULL;
    char *capture = NULL;
    char *decoder = NULL;

    int64_t kernel_packets = 0;
    int64_t kernel_drops = 0;
    int64_t errors = 0;

    int64_t pkts = 0;
    int64_t bytes = 0;
    int64_t invalid = 0;
    int64_t ipv4 = 0;
    int64_t ipv6 = 0;
    int64_t tcp = 0;
    int64_t udp = 0;

    struct json_object *tmp = NULL;
    struct json_object *json_obj_stats = NULL;
    struct json_object *json_obj_kernel = NULL;
    struct json_object *json_obj_decoder = NULL;

    struct json_object *json_obj_calculated = NULL;
    json_obj_calculated = json_object_new_object();

    char *new_json_string = malloc ( MeerConfig->payload_buffer_size );
    char *fjson = malloc ( MeerConfig->payload_buffer_size );

    /***********************************/
    /* Get stats.capture.kernel stats! */
    /***********************************/

    if (json_object_object_get_ex(json_obj, "stats", &tmp))
        {
            stats = (char *)json_object_get_string(tmp);
        }
    else
        {
            Meer_Log(WARN, "Got an event_type of 'stats' without a 'stats' key/value!");

            free(fjson);
            free(new_json_string);

            json_object_put(json_obj_stats);
            json_object_put(json_obj_kernel);
            json_object_put(json_obj_decoder);
            json_object_put(json_obj_calculated);

            return;
        }

    json_obj_stats = json_tokener_parse(stats);

    if (json_object_object_get_ex(json_obj_stats, "capture", &tmp))
        {
            capture = (char *)json_object_get_string(tmp);
        }
    else
        {
            Meer_Log(WARN, "Got an event_type of 'stats' without a 'capture' key/value!");

            free(fjson);
            free(new_json_string);

            json_object_put(json_obj_stats);
            json_object_put(json_obj_kernel);
            json_object_put(json_obj_decoder);
            json_object_put(json_obj_calculated);

            return;
        }

    json_obj_kernel = json_tokener_parse(capture);

    if (json_object_object_get_ex(json_obj_kernel, "kernel_packets", &tmp))
        {
            kernel_packets = json_object_get_int64(tmp);
        }
    else
        {
            Meer_Log(WARN, "Got an event_type of 'stats' without a 'kernel_packets' key/value!");

            free(fjson);
            free(new_json_string);

            json_object_put(json_obj_stats);
            json_object_put(json_obj_kernel);
            json_object_put(json_obj_decoder);
            json_object_put(json_obj_calculated);

            return;
        }

    if (json_object_object_get_ex(json_obj_kernel, "kernel_drops", &tmp))
        {
            kernel_drops = json_object_get_int64(tmp);
        }
    else
        {
            Meer_Log(WARN, "Got an event_type of 'stats' without a 'kernel_drops' key/value!");

            free(fjson);
            free(new_json_string);

            json_object_put(json_obj_stats);
            json_object_put(json_obj_kernel);
            json_object_put(json_obj_decoder);
            json_object_put(json_obj_calculated);

            return;
        }

    if (json_object_object_get_ex(json_obj_kernel, "errors", &tmp))
        {
            errors = json_object_get_int64(tmp);
        }
    else
        {
            Meer_Log(WARN, "Got an event_type of 'stats' without a 'errors' key/value!");

            free(fjson);
            free(new_json_string);

            json_object_put(json_obj_stats);
            json_object_put(json_obj_kernel);
            json_object_put(json_obj_decoder);
            json_object_put(json_obj_calculated);

            return;
        }

    if (json_object_object_get_ex(json_obj_stats, "decoder", &tmp))
        {
            decoder = (char *)json_object_get_string(tmp);
        }
    else
        {
            Meer_Log(WARN, "Got an event_type of 'stats' without a 'decoder' key/value!");

            free(fjson);
            free(new_json_string);

            json_object_put(json_obj_stats);
            json_object_put(json_obj_kernel);
            json_object_put(json_obj_decoder);
            json_object_put(json_obj_calculated);

            return;
        }

    json_obj_decoder = json_tokener_parse(decoder);

    if (json_object_object_get_ex(json_obj_decoder, "pkts", &tmp))
        {
            pkts = json_object_get_int64(tmp);
        }
    else
        {
            Meer_Log(WARN, "Got an event_type of 'decoder' without a 'pkts' key/value!");

            free(fjson);
            free(new_json_string);

            json_object_put(json_obj_stats);
            json_object_put(json_obj_kernel);
            json_object_put(json_obj_decoder);
            json_object_put(json_obj_calculated);

            return;
        }

    if (json_object_object_get_ex(json_obj_decoder, "bytes", &tmp))
        {
            bytes = json_object_get_int64(tmp);
        }
    else
        {
            Meer_Log(WARN, "Got an event_type of 'decoder' without a 'bytes' key/value!");

            free(fjson);
            free(new_json_string);

            json_object_put(json_obj_stats);
            json_object_put(json_obj_kernel);
            json_object_put(json_obj_decoder);
            json_object_put(json_obj_calculated);

            return;
        }

    if (json_object_object_get_ex(json_obj_decoder, "invalid", &tmp))
        {
            invalid = json_object_get_int64(tmp);
        }
    else
        {
            Meer_Log(WARN, "Got an event_type of 'decoder' without a 'invalid' key/value!");

            free(fjson);
            free(new_json_string);

            json_object_put(json_obj_stats);
            json_object_put(json_obj_kernel);
            json_object_put(json_obj_decoder);
            json_object_put(json_obj_calculated);

            return;
        }

    if (json_object_object_get_ex(json_obj_decoder, "ipv4", &tmp))
        {
            ipv4 = json_object_get_int64(tmp);
        }
    else
        {
            Meer_Log(WARN, "Got an event_type of 'decoder' without a 'ipv4' key/value!");

            free(fjson);
            free(new_json_string);

            json_object_put(json_obj_stats);
            json_object_put(json_obj_kernel);
            json_object_put(json_obj_decoder);
            json_object_put(json_obj_calculated);

            return;
        }

    if (json_object_object_get_ex(json_obj_decoder, "ipv6", &tmp))
        {
            ipv6 = json_object_get_int64(tmp);
        }
    else
        {
            Meer_Log(WARN, "Got an event_type of 'decoder' without a 'ipv6' key/value!");

            free(fjson);
            free(new_json_string);

            json_object_put(json_obj_stats);
            json_object_put(json_obj_kernel);
            json_object_put(json_obj_decoder);
            json_object_put(json_obj_calculated);

            return;
        }

    if (json_object_object_get_ex(json_obj_decoder, "tcp", &tmp))
        {
            tcp = json_object_get_int64(tmp);
        }
    else
        {
            Meer_Log(WARN, "Got an event_type of 'decoder' without a 'tcp' key/value!");

            free(fjson);
            free(new_json_string);

            json_object_put(json_obj_stats);
            json_object_put(json_obj_kernel);
            json_object_put(json_obj_decoder);
            json_object_put(json_obj_calculated);

            return;
        }

    if (json_object_object_get_ex(json_obj_decoder, "udp", &tmp))
        {
            udp = json_object_get_int64(tmp);
        }
    else
        {
            Meer_Log(WARN, "Got an event_type of 'decoder' without a 'udp' key/value!");

            free(fjson);
            free(new_json_string);

            json_object_put(json_obj_stats);
            json_object_put(json_obj_kernel);
            json_object_put(json_obj_decoder);
            json_object_put(json_obj_calculated);

            return;
        }

    if ( MeerWaldo->old_kernel_packets < kernel_packets )
        {

            json_object *jkernel_packets = json_object_new_int64( kernel_packets - MeerWaldo->old_kernel_packets );
            json_object_object_add(json_obj_calculated,"kernel_packets", jkernel_packets);

            json_object *jkernel_drops = json_object_new_int64( kernel_drops - MeerWaldo->old_kernel_drops );
            json_object_object_add(json_obj_calculated,"kernel_drops", jkernel_drops);

            json_object *jerrors = json_object_new_int64( errors - MeerWaldo->old_errors );
            json_object_object_add(json_obj_calculated,"errors", jerrors);

            json_object *jpkts = json_object_new_int64( pkts - MeerWaldo->old_pkts );
            json_object_object_add(json_obj_calculated,"pkts", jpkts);

            json_object *jbytes = json_object_new_int64( bytes - MeerWaldo->old_bytes );
            json_object_object_add(json_obj_calculated,"bytes", jbytes);

            json_object *jinvalid = json_object_new_int64( invalid - MeerWaldo->old_invalid );
            json_object_object_add(json_obj_calculated,"invalid", jinvalid);

            json_object *jipv4 = json_object_new_int64( ipv4 - MeerWaldo->old_ipv4 );
            json_object_object_add(json_obj_calculated,"ipv4", jipv4);

            json_object *jipv6 = json_object_new_int64( ipv6 - MeerWaldo->old_ipv6 );
            json_object_object_add(json_obj_calculated,"ipv6", jipv6);

            json_object *jtcp = json_object_new_int64( tcp - MeerWaldo->old_tcp );
            json_object_object_add(json_obj_calculated,"tcp", jtcp);

            json_object *judp = json_object_new_int64( udp - MeerWaldo->old_udp );
            json_object_object_add(json_obj_calculated,"udp", judp);

        }
    else
        {

            json_object *jkernel_packets = json_object_new_int64( kernel_packets );
            json_object_object_add(json_obj_calculated,"kernel_packets", jkernel_packets);

            json_object *jkernel_drops = json_object_new_int64( kernel_drops );
            json_object_object_add(json_obj_calculated,"kernel_drops", jkernel_drops);

            json_object *jerrors = json_object_new_int64( errors );
            json_object_object_add(json_obj_calculated,"errors", jerrors);

            json_object *jpkts = json_object_new_int64( pkts - MeerWaldo->old_pkts );
            json_object_object_add(json_obj_calculated,"pkts", jpkts);

            json_object *jbytes = json_object_new_int64( bytes );
            json_object_object_add(json_obj_calculated,"bytes", jbytes);

            json_object *jinvalid = json_object_new_int64( invalid );
            json_object_object_add(json_obj_calculated,"invalid", jinvalid);

            json_object *jipv4 = json_object_new_int64( ipv4 );
            json_object_object_add(json_obj_calculated,"ipv4", jipv4);

            json_object *jipv6 = json_object_new_int64( ipv6 );
            json_object_object_add(json_obj_calculated,"ipv6", jipv6);

            json_object *jtcp = json_object_new_int64( tcp );
            json_object_object_add(json_obj_calculated,"tcp", jtcp);

            json_object *judp = json_object_new_int64( udp );
            json_object_object_add(json_obj_calculated,"udp", judp);

        }


    /* Append new "calcualated" key/value to the end of the new "stats" string */

    snprintf(new_json_string, MeerConfig->payload_buffer_size, "%s", json_object_get_string( json_obj ) );
    new_json_string[ strlen(new_json_string) -2 ] = '\0';
    snprintf(fjson, MeerConfig->payload_buffer_size, "%s, \"calculated\": %s", new_json_string, json_object_get_string( json_obj_calculated ) );
    fjson[ MeerConfig->payload_buffer_size - 1] = '\0';
    strlcat(fjson, " }", MeerConfig->payload_buffer_size);

    /* Record "stats" for the next cycle */

    MeerWaldo->old_kernel_packets = kernel_packets;
    MeerWaldo->old_kernel_drops = kernel_drops;
    MeerWaldo->old_errors = errors;
    MeerWaldo->old_pkts = pkts;
    MeerWaldo->old_bytes = bytes;
    MeerWaldo->old_invalid = invalid;
    MeerWaldo->old_ipv4 = ipv4;
    MeerWaldo->old_ipv6 = ipv6;
    MeerWaldo->old_tcp = tcp;
    MeerWaldo->old_udp = udp;

    /* Don't need json objects anymore, so free these */

    json_object_put(json_obj_stats);
    json_object_put(json_obj_kernel);
    json_object_put(json_obj_decoder);
    json_object_put(json_obj_calculated);

    /* Copy our string to return */

    snprintf(str, MeerConfig->payload_buffer_size, "%s", fjson);

    /* Free last memory buffers for building new "stats" json string */

    free(fjson);
    free(new_json_string);

}
