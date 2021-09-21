/*
** Copyright (C) 2018-2020 Quadrant Information Security <quadrantsec.com>
** Copyright (C) 2018-2020 Champ Clark III <cclark@quadrantsec.com>
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

/* TODO */

/* Add in routing for different "types" (flow, alert, etc) from the config.
   */

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#ifdef WITH_ELASTICSEARCH

#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
#include <json-c/json.h>
#include <pthread.h>

#include <curl/curl.h>

#include "meer-def.h"
#include "meer.h"
#include "util.h"
#include "lockfile.h"

#include "output-plugins/elasticsearch.h"

struct _MeerConfig *MeerConfig;
struct _MeerOutput *MeerOutput;

bool elasticsearch_death = false;

CURL *curl;

uint16_t elasticsearch_batch_count = 0;
char big_batch[PACKET_BUFFER_SIZE_DEFAULT * 1000];
char big_batch_THREAD[PACKET_BUFFER_SIZE_DEFAULT * 1000];

pthread_cond_t MeerElasticWork;
pthread_mutex_t MeerElasticMutex;

extern uint_fast16_t elastic_proc_msgslot;
extern uint_fast16_t elastic_proc_running;

static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
    size_t realsize = size * nmemb;
    struct MemoryStruct *mem = (struct MemoryStruct *)userp;

    char *ptr = realloc(mem->memory, mem->size + realsize + 1);

    if(!ptr)
        {
            /* out of memory! */
            printf("not enough memory (realloc returned NULL)\n");
            return 0;
        }

    mem->memory = ptr;
    memcpy(&(mem->memory[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->memory[mem->size] = 0;

    return realsize;
}

void Elasticsearch_Init( void )
{

    uint8_t i=0;
    int rc=0;

    pthread_t elasticsearch_id[MeerOutput->elasticsearch_threads];
    pthread_attr_t thread_elasticsearch_attr;
    pthread_attr_init(&thread_elasticsearch_attr);
    pthread_attr_setdetachstate(&thread_elasticsearch_attr,  PTHREAD_CREATE_DETACHED);

    Meer_Log(NORMAL, "");
    Meer_Log(NORMAL, "Spawning %d Elasticsearch threads.", MeerOutput->elasticsearch_threads);

    for (i = 0; i < MeerOutput->elasticsearch_threads; i++)
        {

            rc = pthread_create ( &elasticsearch_id[i], &thread_elasticsearch_attr, (void *)Elasticsearch, NULL );

            if ( rc != 0 )
                {

                    Remove_Lock_File();
                    Meer_Log(ERROR, "Could not pthread_create() for I/O processors [error: %d]", rc);
                }
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

/*************************************/
/* Elasticsearch threaded operation! */
/*************************************/

void Elasticsearch( void )
{

    char big_batch_LOCAL[PACKET_BUFFER_SIZE_DEFAULT] = { 0 };

    uint16_t i = 0;

    char tmp[PACKET_BUFFER_SIZE_DEFAULT] = { 0 };
    char index_name[512] = { 0 };

    struct MemoryStruct chunk;    /* Large JSON returns from Elastic */

    CURL *curl_LOCAL;
    CURLcode res;

    struct curl_slist *headers = NULL;
    curl_global_init(CURL_GLOBAL_ALL);

    curl_LOCAL = curl_easy_init();

    if ( curl_LOCAL )
        {

            curl_LOCAL = curl_easy_init();

            if ( MeerOutput->elasticsearch_insecure == true )
                {

                    curl_easy_setopt(curl_LOCAL, CURLOPT_SSL_VERIFYPEER, false);
                    curl_easy_setopt(curl_LOCAL, CURLOPT_SSL_VERIFYHOST, false);
                    curl_easy_setopt(curl_LOCAL, CURLOPT_SSL_VERIFYSTATUS, false);

                }

            if ( MeerOutput->elasticsearch_username[0] != '\0' && MeerOutput->elasticsearch_password[0] != '\0' )
                {

                    curl_easy_setopt(curl_LOCAL, CURLOPT_USERNAME, MeerOutput->elasticsearch_username);
                    curl_easy_setopt(curl_LOCAL, CURLOPT_PASSWORD, MeerOutput->elasticsearch_password);

                }

            /* Put libcurl in "debug" it we're in "debug" mode! */

            if ( MeerOutput->elasticsearch_debug == true )
                {
                    curl_easy_setopt(curl_LOCAL, CURLOPT_VERBOSE, 1);
                }

            curl_easy_setopt(curl_LOCAL, CURLOPT_NOSIGNAL, 1);    /* Will send SIGALRM if not set */

            headers = curl_slist_append(headers, "Content-Type: application/x-ndjson");
            headers = curl_slist_append (headers, MEER_USER_AGENT);

            curl_easy_setopt(curl_LOCAL, CURLOPT_HTTPHEADER, headers);

            curl_easy_setopt(curl_LOCAL, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
            curl_easy_setopt(curl_LOCAL, CURLOPT_WRITEDATA, (void *)&chunk);

            curl_easy_setopt(curl_LOCAL, CURLOPT_URL, MeerOutput->elasticsearch_url);


        }
    else
        {

            Meer_Log(ERROR, "[%s, line %d] Failed to initialize libcurl.", __FILE__, __LINE__ );

        }


    while ( elasticsearch_death == false )
        {

            pthread_mutex_lock(&MeerElasticMutex);

            while ( elastic_proc_msgslot == 0 ) pthread_cond_wait(&MeerElasticWork, &MeerElasticMutex);

            /* Copy the latest batch! */

            elastic_proc_msgslot--;
            strlcpy(big_batch_LOCAL, big_batch_THREAD, sizeof(big_batch_LOCAL));

            pthread_mutex_unlock(&MeerElasticMutex);

            struct json_object *json_obj = NULL;
            struct json_object *json_tmp = NULL;

            chunk.memory = malloc(1);   /* will be grown as needed by the realloc above */
            chunk.size = 0;             /* no data at this point */

            curl_easy_setopt(curl_LOCAL, CURLOPT_POSTFIELDS, big_batch_LOCAL);

            res = curl_easy_perform(curl_LOCAL);

            while (res != CURLE_OK && res != CURLE_WRITE_ERROR )
                {

                    Meer_Log(WARN, "[%s, line %d] Couldn't connect to the Elasticsearch server [%s]. Sleeping for 5 seconds.....", __FILE__, __LINE__, curl_easy_strerror(res));

                    sleep(5);
                    res = curl_easy_perform(curl_LOCAL);

                }

            /* If we got data back from Elasticsearch,  let's parse if for errors */

            if ( chunk.memory != NULL )
                {

                    if ( MeerOutput->elasticsearch_debug == true )
                        {
                            Meer_Log(DEBUG, "[%s, line %d] Response from Elasticsearch: %s", __FILE__, __LINE__, chunk.memory);
                        }

                    json_obj = json_tokener_parse(chunk.memory);

                    if (json_object_object_get_ex(json_obj, "errors", &json_tmp))
                        {

                            if ( strcmp((char *)json_object_get_string(json_tmp), "false" ) )
                                {

                                    Meer_Log(WARN, "[%s, line %d] Failure inserting into Elasticsearch! Result codes: %s", __FILE__, __LINE__, chunk.memory);
                                }

                        }

                }
            else
                {

                    Meer_Log(WARN, "[%s, line %d] Got NULL back from Elasticsearch.  Failed to insert batch.", __FILE__, __LINE__, chunk.memory);

                }


            json_object_put(json_obj);
            free(chunk.memory);

            __atomic_sub_fetch(&elastic_proc_running, 1, __ATOMIC_SEQ_CST);

        }

    /* Clean up thread! */

    curl_easy_cleanup(curl_LOCAL);

    pthread_exit(NULL);

}


#endif



