
#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#ifdef WITH_ELASTICSEARCH

#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <sys/types.h>
#include <stdlib.h>

#include <curl/curl.h>

#include "meer-def.h"
#include "meer.h"
#include "util.h"

#include "output-plugins/elasticsearch.h"

struct _MeerConfig *MeerConfig;
struct _MeerOutput *MeerOutput;

CURL *curl;
const char *response=NULL;

uint16_t elasticsearch_batch_count = 0;
//char elasticsearch_batch[MAX_ELASTICSEARCH_BATCH][1024 + PACKET_BUFFER_SIZE_DEFAULT];
//char elasticsearch_batch_index[MAX_ELASTICSEARCH_BATCH][512] = {{ 0 }};

char big_batch[PACKET_BUFFER_SIZE_DEFAULT * 1000] = { 0 };

/****************************************************************************
 * write_callback_func() - Callback for data received via libcurl
 ****************************************************************************/

size_t static write_callback_func(void *buffer, size_t size, size_t nmemb, void *userp)
{
    char **response_ptr =  (char**)userp;
    *response_ptr = strndup(buffer, (size_t)(size *nmemb));     /* Return the string */
}


void Elasticsearch_Init( void )
{

    struct curl_slist *headers = NULL;

    curl_global_init(CURL_GLOBAL_ALL);
    curl = curl_easy_init();

    if ( curl )
        {

            curl = curl_easy_init();

            if ( MeerOutput->elasticsearch_insecure == true )
                {

                    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, false); /* Need to be an option */
                    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, false);
                    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYSTATUS, false);

                }

            if ( MeerOutput->elasticsearch_username[0] != '\0' && MeerOutput->elasticsearch_password[0] != '\0' )
                {

                    curl_easy_setopt(curl, CURLOPT_USERNAME, MeerOutput->elasticsearch_username);
                    curl_easy_setopt(curl, CURLOPT_PASSWORD, MeerOutput->elasticsearch_password);

                }

            curl_easy_setopt(curl, CURLOPT_VERBOSE, 1);
            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback_func);
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
            curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1);    /* WIll send SIGALRM if not set */

            headers = curl_slist_append(headers, "Content-Type: application/x-ndjson");
            headers = curl_slist_append (headers, MEER_USER_AGENT);

            curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

        }
    else
        {

            Meer_Log(ERROR, "[%s, line %d] Failed to initialize libcurl.", __FILE__, __LINE__ );

        }

}


void Elasticsearch ( const char *json_string, const char *event_type )
{

    CURLcode res;

    uint16_t i = 0;

//    char big_batch[PACKET_BUFFER_SIZE_DEFAULT * 1000] = { 0 };
    char tmp[PACKET_BUFFER_SIZE_DEFAULT] = { 0 };

//char str[PACKET_BUFFER_SIZE_DEFAULT + 1024] = { 0 };
    char index_name[512] = { 0 };

    /* Get what the current index should be */

    Elasticsearch_Get_Index(index_name, sizeof(index_name), event_type);

    snprintf(tmp, sizeof(tmp), "{\"index\":{\"_index\":\"%s\"}}\n%s\n", index_name, json_string);
//snprintf(str, sizeof(str), "{\"index\":{\"_index\":\"%s\"}}\n%s\n", index_name, json_string);

//    snprintf(elasticsearch_batch[elasticsearch_batch_count], sizeof(elasticsearch_batch[elasticsearch_batch_count]), "{\"index\":{\"_index\":\"%s\"}}\n%s\n", index_name, json_string);

    strlcat(big_batch, tmp, sizeof(big_batch) );
    elasticsearch_batch_count++;

    if ( elasticsearch_batch_count == MeerOutput->elasticsearch_batch )
        {

            printf("WROTE BATCH\n");

//            for ( i = 0; i < MeerOutput->elasticsearch_batch; i++ )
//	    {

            curl_easy_setopt(curl, CURLOPT_URL, MeerOutput->elasticsearch_url);
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, big_batch);

            res = curl_easy_perform(curl);

            /*
            if(res != CURLE_OK)
            	{
                 	 fprintf(stderr, "curl_easy_perform() failed: %s\n",
                     curl_easy_strerror(res));
            	}
            	*/

            if ( response != NULL )
                {
                    printf("%s\n", response);
                }

//		}

//           elasticsearch_batch_count = 0;

            elasticsearch_batch_count = 0;
            big_batch[0] = '\0';
        }

}

void Elasticsearch_Get_Index ( char *str, size_t size, const char *event_type )
{

    char tmp[512] = { 0 };
    char index[512] = { 0 };
    uint16_t i = 0;
    uint16_t a = 0;
    uint8_t pos=0;

    time_t t = time(NULL);
    struct tm tm = *localtime(&t);
    //printf("now: %d-%02d-%02d %02d:%02d:%02d\n", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);

    // suricata_$EVENTTYPE_$YEAR$MONTH$DAY
//      suricata_alert_

    for (i = 0; i < strlen(MeerOutput->elasticsearch_index); i++ )
        {


            /* $EVENTTYPE */

            if ( MeerOutput->elasticsearch_index[i] == '$' &&
                    MeerOutput->elasticsearch_index[i+1] == 'E' &&
                    MeerOutput->elasticsearch_index[i+2] == 'V' &&
                    MeerOutput->elasticsearch_index[i+3] == 'E' &&
                    MeerOutput->elasticsearch_index[i+4] == 'N' &&
                    MeerOutput->elasticsearch_index[i+5] == 'T' &&
                    MeerOutput->elasticsearch_index[i+6] == 'T' &&
                    MeerOutput->elasticsearch_index[i+7] == 'Y' &&
                    MeerOutput->elasticsearch_index[i+8] == 'P' &&
                    MeerOutput->elasticsearch_index[i+9] == 'E' )
                {
                    for ( a = 0; a < strlen(event_type); a++ )
                        {
                            index[pos] = event_type[a];
                            pos++;
                        }
                    i = i+10;
                }

            /* $YEAR */

            if ( MeerOutput->elasticsearch_index[i] == '$' &&
                    MeerOutput->elasticsearch_index[i+1] == 'Y' &&
                    MeerOutput->elasticsearch_index[i+2] == 'E' &&
                    MeerOutput->elasticsearch_index[i+3] == 'A' &&
                    MeerOutput->elasticsearch_index[i+4] == 'R' )
                {

                    snprintf(tmp, sizeof(tmp), "%d", tm.tm_year + 1900);

                    for ( a = 0; a < strlen(tmp); a++ )
                        {
                            index[pos] = tmp[a];
                            pos++;
                        }

                    i = i+5;
                }

            /* $MONTH */

            if ( MeerOutput->elasticsearch_index[i] == '$' &&
                    MeerOutput->elasticsearch_index[i+1] == 'M' &&
                    MeerOutput->elasticsearch_index[i+2] == 'O' &&
                    MeerOutput->elasticsearch_index[i+3] == 'N' &&
                    MeerOutput->elasticsearch_index[i+4] == 'T' &&
                    MeerOutput->elasticsearch_index[i+5] == 'H' )
                {

                    snprintf(tmp, sizeof(tmp), "%02d", tm.tm_mon + 1);

                    for ( a = 0; a < strlen(tmp); a++ )
                        {
                            index[pos] = tmp[a];
                            pos++;
                        }

                    i = i+6;

                }

            /* $DAY */

            if ( MeerOutput->elasticsearch_index[i] == '$' &&
                    MeerOutput->elasticsearch_index[i+1] == 'D' &&
                    MeerOutput->elasticsearch_index[i+2] == 'A' &&
                    MeerOutput->elasticsearch_index[i+3] == 'Y' )
                {

                    snprintf(tmp, sizeof(tmp), "%02d", tm.tm_mday);

                    for ( a = 0; a < strlen(tmp); a++ )
                        {
                            index[pos] = tmp[a];
                            pos++;
                        }

                    i = i+4;

                }




            index[pos]  = MeerOutput->elasticsearch_index[i];
            pos++;

        }

    snprintf(str, size, "%s", index);


}



#endif



