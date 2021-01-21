#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>
#include <stdbool.h>
#include <time.h>
#include <string.h>
#include <unistd.h>

#include "decode-json-alert.h"
#include "decode-json-dhcp.h"
#include "fingerprints.h"

#include "meer.h"
#include "meer-def.h"
#include "util.h"
#include "output.h"
#include "references.h"
#include "sid-map.h"
#include "oui.h"
#include "config-yaml.h"

struct _MeerConfig *MeerConfig;

#ifdef HAVE_LIBHIREDIS

void Parse_Fingerprint ( struct _DecodeAlert *DecodeAlert, struct _FingerprintData *FingerprintData )
{

    struct json_object *json_obj = NULL;
    struct json_object *tmp = NULL;

    char *fingerprint_d_os = NULL;
    char *fingerprint_d_type = NULL;
    char *fingerprint_d_expire = NULL;
    char *fingerprint_d_source = NULL;

    char *fingerprint_os = "unknown";
    char *fingerprint_source = "unknown";
    char *fingerprint_expire = NULL;

    char *ptr1 = NULL;

    FingerprintData->expire = FINGERPRINT_REDIS_EXPIRE;

    if ( DecodeAlert->alert_metadata[0] != '\0' )
        {

            json_obj = json_tokener_parse(DecodeAlert->alert_metadata);

            if ( json_object_object_get_ex(json_obj, "fingerprint_os", &tmp))
                {

                    FingerprintData->ret = true;

                    fingerprint_d_os =  (char *)json_object_get_string(tmp);

                    strtok_r(fingerprint_d_os, "\"", &ptr1);

                    if ( ptr1 == NULL )
                        {
                            Meer_Log(WARN, "[%s, line %d] Failure to decode fingerprint_os from %s", __FILE__, __LINE__, fingerprint_d_os);
                        }

                    fingerprint_os = strtok_r(NULL, "\"", &ptr1);

                    if ( fingerprint_os == NULL )
                        {
                            Meer_Log(WARN, "[%s, line %d] Failure to decode fingerprint_os from %s", __FILE__, __LINE__, fingerprint_d_os);
                        }

                    strlcpy(FingerprintData->os, fingerprint_os, sizeof(FingerprintData->os));
                }

            if ( json_object_object_get_ex(json_obj, "fingerprint_source", &tmp))
                {

                    FingerprintData->ret = true;

                    fingerprint_d_source =  (char *)json_object_get_string(tmp);

                    strtok_r(fingerprint_d_source, "\"", &ptr1);

                    if ( ptr1 == NULL )
                        {
                            Meer_Log(WARN, "[%s, line %d] Failure to decode fingerprint_source from %s", __FILE__, __LINE__, fingerprint_d_source);
                        }

                    fingerprint_source = strtok_r(NULL, "\"", &ptr1);

                    if ( fingerprint_source == NULL )
                        {
                            Meer_Log(WARN, "[%s, line %d] Failure to decode fingerprint_os from %s", __FILE__, __LINE__, fingerprint_d_source);
                        }

                    strlcpy(FingerprintData->source, fingerprint_source, sizeof(FingerprintData->source));
                }


            if ( json_object_object_get_ex(json_obj, "fingerprint_expire", &tmp))
                {

                    FingerprintData->ret = true;

                    fingerprint_d_expire =  (char *)json_object_get_string(tmp);

                    strtok_r(fingerprint_d_expire, "\"", &ptr1);

                    if ( ptr1 == NULL )
                        {
                            Meer_Log(WARN, "[%s, line %d] Failure to decode fingerprint_expire from %s", __FILE__, __LINE__, fingerprint_d_expire);
                        }

                    fingerprint_expire = strtok_r(NULL, "\"", &ptr1);

                    if ( fingerprint_expire == NULL )
                        {
                            Meer_Log(WARN, "[%s, line %d] Failure to decode fingerprint_expire from %s", __FILE__, __LINE__, fingerprint_d_expire);
                        }

                    FingerprintData->expire = atoi( fingerprint_expire );
                }

            if ( json_object_object_get_ex(json_obj, "fingerprint_type", &tmp))
                {

                    FingerprintData->ret = true;

                    fingerprint_d_type =  (char *)json_object_get_string(tmp);

                    if ( strcasestr( fingerprint_d_type, "client") )
                        {
                            strlcpy(FingerprintData->type, "client", sizeof(FingerprintData->type));
                        }

                    else if ( strcasestr( fingerprint_d_type, "server") )
                        {
                            strlcpy(FingerprintData->type, "server", sizeof(FingerprintData->type));
                        }
                }
        }

    json_object_put(json_obj);

}

void Fingerprint_IP_JSON ( struct _DecodeAlert *DecodeAlert, char *str, size_t size )
{

    struct json_object *encode_json = NULL;
    encode_json = json_object_new_object();

    json_object *jtimestamp = json_object_new_string( DecodeAlert->timestamp );
    json_object_object_add(encode_json,"timestamp", jtimestamp);

    if ( DecodeAlert->src_ip != NULL )
        {
            json_object *jip = json_object_new_string( DecodeAlert->src_ip );
            json_object_object_add(encode_json,"ip", jip);
        }

    snprintf(str, size, "%s", json_object_to_json_string(encode_json));

    json_object_put(encode_json);

}


void Fingerprint_EVENT_JSON ( struct _DecodeAlert *DecodeAlert, struct _FingerprintData *FingerprintData, char *str, size_t size )
{

    struct json_object *encode_json = NULL;
    encode_json = json_object_new_object();

    struct json_object *encode_json_fp = NULL;
    encode_json_fp = json_object_new_object();

    struct json_object *encode_json_http = NULL;
    encode_json_http = json_object_new_object();

    char tmp_string[PACKET_BUFFER_SIZE_DEFAULT] = { 0 };
    char tmp_string2[PACKET_BUFFER_SIZE_DEFAULT] = { 0 };

    char http[PACKET_BUFFER_SIZE_DEFAULT] = { 0 };
    char fp[PACKET_BUFFER_SIZE_DEFAULT] = { 0 };

    char dns[255] = { 0 };

    json_object_object_add(encode_json, "event_type", json_object_new_string("fingerprint"));

    if ( DecodeAlert->timestamp != NULL )
        {
            json_object_object_add(encode_json, "timestamp", json_object_new_string( DecodeAlert->timestamp ));
        }

    if ( MeerConfig->dns && DecodeAlert->src_ip != NULL )
        {
            DNS_Lookup( DecodeAlert->src_ip, dns, sizeof(dns));
            json_object_object_add(encode_json,"dns", json_object_new_string( dns ));
        }

    if ( DecodeAlert->host != NULL )
        {
            json_object_object_add(encode_json, "host", json_object_new_string( DecodeAlert->host ));
        }

    if ( DecodeAlert->flowid != NULL )
        {
            json_object_object_add(encode_json, "flow_id", json_object_new_int64( atol( DecodeAlert->flowid )));
        }

    if ( DecodeAlert->in_iface != NULL )
        {
            json_object_object_add(encode_json, "in_iface", json_object_new_string( DecodeAlert->in_iface ));
        }

    if ( DecodeAlert->src_ip != NULL )
        {
            json_object_object_add(encode_json, "src_ip", json_object_new_string( DecodeAlert->src_ip ));
        }

    if ( DecodeAlert->src_port != NULL )
        {
            json_object_object_add(encode_json, "src_port", json_object_new_int( atoi ( DecodeAlert->src_port )));
        }

    if ( DecodeAlert->dest_ip != NULL )
        {
            json_object_object_add(encode_json, "dest_ip", json_object_new_string( DecodeAlert->dest_ip ));
        }

    if ( DecodeAlert->dest_port != NULL )
        {
            json_object_object_add(encode_json, "dest_port", json_object_new_int( atoi ( DecodeAlert->dest_port )));

        }

    if ( DecodeAlert->proto != NULL )
        {
            json_object_object_add(encode_json, "proto", json_object_new_string( DecodeAlert->proto ));

        }

    if ( DecodeAlert->program != NULL )
        {
            json_object_object_add(encode_json, "program", json_object_new_string( DecodeAlert->program ));
        }

    json_object_object_add(encode_json_fp, "signature_id", json_object_new_int64( DecodeAlert->alert_signature_id ));
    json_object_object_add(encode_json_fp, "rev", json_object_new_int64( DecodeAlert->alert_rev ));

    if ( DecodeAlert->alert_signature[0] != '\0' )
        {
            json_object_object_add(encode_json_fp, "signature", json_object_new_string( DecodeAlert->alert_signature ));

        }

    if ( FingerprintData->os[0] != '\0' )
        {
            json_object_object_add(encode_json_fp, "os", json_object_new_string( FingerprintData->os ));
        }

    if ( FingerprintData->source[0] != '\0' )
        {
            json_object_object_add(encode_json_fp, "source", json_object_new_string( FingerprintData->source ));
        }

    if ( FingerprintData->type[0] != '\0' )
        {
            json_object_object_add(encode_json_fp, "client_server", json_object_new_string( FingerprintData->type ));
        }

    if ( DecodeAlert->app_proto[0] != '\0' )
        {
            json_object_object_add(encode_json_fp, "app_proto", json_object_new_string( DecodeAlert->app_proto ));

        }

    if ( DecodeAlert->payload[0] != '\0' )
        {
            json_object_object_add(encode_json_fp, "payload", json_object_new_string( DecodeAlert->payload ));
        }

    if ( !strcmp(DecodeAlert->app_proto, "http") )
        {

            if ( DecodeAlert->http_user_agent[0] != '\0' )
                {

                    json_object_object_add(encode_json_http, "http_user_agent", json_object_new_string( DecodeAlert->http_user_agent ));


                }

            if ( DecodeAlert->http_xff[0] != '\0' )
                {
                    json_object_object_add(encode_json_http, "xff", json_object_new_string( DecodeAlert->http_xff ));
                }

            strlcpy(http, json_object_to_json_string_ext(encode_json_http, JSON_C_TO_STRING_PLAIN), sizeof(http));

        }


    strlcpy(fp, json_object_to_json_string_ext(encode_json_fp, JSON_C_TO_STRING_PLAIN), sizeof(fp));

    /* Merge fingerprint JSON, http JSON in EVE */

    snprintf(tmp_string, sizeof(tmp_string), "%s", json_object_to_json_string_ext(encode_json, JSON_C_TO_STRING_PLAIN));
    tmp_string[ strlen(tmp_string) - 1 ] = ',';
    snprintf(tmp_string2, sizeof(tmp_string2), "%s \"fingerprint\": %s}", tmp_string, fp);
    strlcpy(tmp_string, tmp_string2, sizeof(tmp_string));

    if ( http[0] != '\0' )
        {
            tmp_string[ strlen(tmp_string) - 1 ] = ',';
            snprintf(tmp_string2, sizeof(tmp_string2), "%s \"http\": %s}", tmp_string, http);
        }

    snprintf(str, size, "%s", tmp_string2);

    json_object_put(encode_json);
    json_object_put(encode_json_fp);
    json_object_put(encode_json_http);

}

void Fingerprint_DHCP_JSON ( struct _DecodeDHCP *DecodeDHCP, char *str, size_t size )
{

    struct json_object *encode_json = NULL;
    encode_json = json_object_new_object();

    char oui_data[128] = { 0 };

    json_object_object_add(encode_json, "timestamp", json_object_new_string( DecodeDHCP->timestamp ));

    if ( DecodeDHCP->dhcp_assigned_ip[0] != '\0' )
        {
            json_object_object_add(encode_json, "assigned_ip", json_object_new_string( DecodeDHCP->dhcp_assigned_ip ));
        }

    if ( DecodeDHCP->dhcp_client_mac[0] != '\0' )
        {
            json_object_object_add(encode_json, "client_mac", json_object_new_string( DecodeDHCP->dhcp_client_mac ));
        }

    if ( MeerConfig->oui == true )
        {
            OUI_Lookup( DecodeDHCP->dhcp_client_mac, oui_data, sizeof(oui_data) );
            json_object_object_add(encode_json, "vendor", json_object_new_string( oui_data ));
        }

    snprintf(str, size, "%s", json_object_to_json_string_ext(encode_json, JSON_C_TO_STRING_PLAIN));

    json_object_put(encode_json);

}


#endif
