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
#include <string.h>
#include <json-c/json.h>

#include "meer-def.h"
#include "meer.h"
#include "oui.h"

#include "get-oui.h"

extern struct _MeerConfig *MeerConfig;
extern struct _MeerCounters *MeerCounters;

void Get_OUI( struct json_object *json_obj, char *str )
{

    struct json_object *tmp = NULL;

    char mac[20] = { 0 };

    if ( json_object_object_get_ex(json_obj, "dhcp", &tmp) )
        {

            struct json_object *json_obj_dhcp = NULL;

            json_obj_dhcp = json_tokener_parse(json_object_get_string(tmp));

            /* Got a good MAC!  Let look it up! */

            if ( json_object_object_get_ex(json_obj_dhcp, "client_mac", &tmp) )
                {

                    strlcpy( mac, json_object_get_string(tmp), sizeof(mac) );

                    char vendor[128] = { 0 };

                    OUI_Lookup ( mac, vendor, sizeof(vendor) );

                    if ( vendor[0] != '\0' )
                        {
                            json_object *jvendor = json_object_new_string(vendor);
                            json_object_object_add(json_obj_dhcp,"vendor", jvendor);
                        }
                    else
                        {

                            /* No vender found.  Clean up and return orig JSON string */

                            json_object_put(json_obj_dhcp);
                            snprintf(str, MeerConfig->payload_buffer_size, "%s\n", json_object_to_json_string(json_obj));
                            return;
                        }


                    /* We got a vendor,  we need to rebuild the JSON */

                    struct json_object *jobj_obj_new;
                    jobj_obj_new = json_object_new_object();

                    char *new_json_string = malloc((MeerConfig->payload_buffer_size)*sizeof(char));

                    if ( new_json_string == NULL )
                        {
                            fprintf(stderr, "[%s, line %d] Fatal Error:  Can't allocate memory! Abort!\n", __FILE__, __LINE__);
                            exit(-1);
                        }

                    char *final_json = malloc((MeerConfig->payload_buffer_size)*sizeof(char));

                    if ( final_json == NULL )
                        {
                            fprintf(stderr, "[%s, line %d] Fatal Error:  Can't allocate memory! Abort!\n", __FILE__, __LINE__);
                            exit(-1);
                        }

                    const char *timestamp = NULL;
                    uint64_t flow_id = 0;
                    const char *in_iface = NULL;
                    const char *event_type = NULL;
                    const char *src_ip = NULL;
                    uint16_t src_port = 0;
                    const char *dest_ip = NULL;
                    uint16_t dest_port = 0;
                    const char *proto = NULL;
                    const char *host = NULL;

                    if ( json_object_object_get_ex(json_obj, "timestamp", &tmp) )
                        {
                            timestamp = json_object_get_string(tmp);
                            json_object *jtimestamp = json_object_new_string( timestamp );
                            json_object_object_add(jobj_obj_new,"timestamp", jtimestamp);

                        }

                    if ( json_object_object_get_ex(json_obj, "flow_id", &tmp) )
                        {
                            flow_id = json_object_get_int64(tmp);
                            json_object *jflow_id = json_object_new_int64( flow_id );
                            json_object_object_add(jobj_obj_new,"flow_id", jflow_id);
                        }

                    if ( json_object_object_get_ex(json_obj, "in_iface", &tmp) )
                        {
                            in_iface = json_object_get_string(tmp);
                            json_object *jin_iface = json_object_new_string( in_iface );
                            json_object_object_add(jobj_obj_new,"in_iface", jin_iface);
                        }

                    if ( json_object_object_get_ex(json_obj, "event_type", &tmp) )
                        {
                            event_type = json_object_get_string(tmp);
                            json_object *jevent_type = json_object_new_string( event_type );
                            json_object_object_add(jobj_obj_new,"event_type", jevent_type);
                        }

                    if ( json_object_object_get_ex(json_obj, "src_ip", &tmp) )
                        {
                            src_ip = json_object_get_string(tmp);
                            json_object *jsrc_ip = json_object_new_string( src_ip );
                            json_object_object_add(jobj_obj_new,"src_ip", jsrc_ip);
                        }

                    if ( json_object_object_get_ex(json_obj, "src_port", &tmp) )
                        {
                            src_port = json_object_get_int(tmp);
                            json_object *jsrc_port = json_object_new_int( src_port );
                            json_object_object_add(jobj_obj_new,"src_port", jsrc_port);
                        }

                    if ( json_object_object_get_ex(json_obj, "dest_ip", &tmp) )
                        {
                            dest_ip = json_object_get_string(tmp);
                            json_object *jdest_ip = json_object_new_string( dest_ip );
                            json_object_object_add(jobj_obj_new,"dest_ip", jdest_ip);
                        }

                    if ( json_object_object_get_ex(json_obj, "dest_port", &tmp) )
                        {
                            dest_port = json_object_get_int(tmp);
                            json_object *jdest_port = json_object_new_int( dest_port );
                            json_object_object_add(jobj_obj_new,"dest_port", jdest_port);
                        }

                    if ( json_object_object_get_ex(json_obj, "proto", &tmp) )
                        {
                            proto = json_object_get_string(tmp);
                            json_object *jproto = json_object_new_string( proto );
                            json_object_object_add(jobj_obj_new,"proto", jproto);

                        }

                    if ( json_object_object_get_ex(json_obj, "host", &tmp) )
                        {
                            host = json_object_get_string(tmp);
                            json_object *jhost = json_object_new_string( host );
                            json_object_object_add(jobj_obj_new,"host", jhost);
                        }


                    /* Tie everything back together */

                    strlcpy(new_json_string, json_object_to_json_string(jobj_obj_new), MeerConfig->payload_buffer_size);
                    new_json_string[ strlen(new_json_string) -2 ] = '\0';

                    snprintf(final_json, MeerConfig->payload_buffer_size, "%s, \"dhcp\": %s }", new_json_string, json_object_to_json_string(json_obj_dhcp) );
                    final_json[ sizeof(final_json) - 1] = '\0';

                    json_object_put(jobj_obj_new);
                    json_object_put(json_obj_dhcp);

                    snprintf(str, MeerConfig->payload_buffer_size, "%s\n", final_json);

                    free( new_json_string );
                    free( final_json );
                    return;

                }

        }

    snprintf(str, MeerConfig->payload_buffer_size, "%s", (char*)json_object_to_json_string(json_obj) );

}

