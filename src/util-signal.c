/*
** Copyright (C) 2018-2023 Quadrant Information Security <quadrantsec.com>
** Copyright (C) 2018-2023 Champ Clark III <cclark@quadrantsec.com>
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
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <sys/mman.h>
#include <json-c/json.h>

#include "meer.h"
#include "meer-def.h"
#include "config-yaml.h"
#include "lockfile.h"
#include "stats.h"
#include "waldo.h"
#include "config-yaml.h"

#if defined(WITH_BLUEDOT) || defined(WITH_ELASTICSEARCH)
#include <curl/curl.h>
#endif

#ifdef WITH_ELASTICSEARCH
#include <output-plugins/elasticsearch.h>
bool elasticsearch_death = false;
uint8_t elasticsearch_death_count = 0;
extern uint_fast16_t elastic_proc_running;
extern char *big_batch;
extern char *big_batch_THREAD;
#endif

#ifdef HAVE_LIBHIREDIS
#include <output-plugins/redis.h>
#endif

#ifdef WITH_BLUEDOT
#include <output-plugins/bluedot.h>
extern CURL *curl_bluedot;
#endif

extern struct _MeerWaldo *MeerWaldo;
extern struct _MeerConfig *MeerConfig;
extern struct _MeerOutput *MeerOutput;
extern struct _MeerInput *MeerInput;

void Signal_Handler(int sig_num)
{

    Meer_Log(NORMAL, "Got signal %d!", sig_num);

    switch( sig_num )
        {

        /* exit */

        case SIGQUIT:
        case SIGINT:
        case SIGTERM:
//        case SIGSEGV:
//        case SIGABRT:

            if ( MeerOutput->pipe_enabled == true )
                {
                    close(MeerOutput->pipe_fd);
                }

#ifdef HAVE_LIBHIREDIS

            if ( MeerOutput->redis_enabled == true )
                {
                    Redis_Close();
                }

#endif


#ifdef WITH_ELASTICSEARCH

            if ( MeerOutput->elasticsearch_enabled == true )
                {

                    elasticsearch_death = true;
                    elasticsearch_death_count = 0;

                    while ( elastic_proc_running != 0 )
                        {
                            Meer_Log(NORMAL, "Waiting on %d Elasticseach thread to shutdown.", elastic_proc_running);
                            sleep(1);

                            if ( elasticsearch_death_count == 15 )
                                {
                                    Meer_Log(WARN, "Timemout reached!  Forcing shutdown.");
                                    break;
                                }

                            elasticsearch_death_count++;

                        }

                    if ( elastic_proc_running == 0 )
                        {
                            free( big_batch );
                            free( big_batch_THREAD);
                        }

                }

#endif

            /* Some gymnastics to cleanup libcurl */

#if defined(WITH_BLUEDOT) || defined(WITH_ELASTICSEARCH)

            bool clean_up = false;

#ifdef WITH_BLUEDOT

            if ( MeerOutput->bluedot_flag == true )
                {
                    curl_global_cleanup();
                    clean_up = true;
                }

#endif

#ifdef WITH_ELASTICSEARCH

            if ( MeerOutput->elasticsearch_enabled == true && clean_up == false )
                {
                    curl_global_cleanup();
                }
#endif

#endif

            if ( MeerOutput->file_enabled == true )
                {
                    fflush(MeerOutput->file_fd);
                    fclose(MeerOutput->file_fd);
                }



            Remove_Lock_File();

            Statistics();


            if ( MeerInput->type == YAML_INPUT_FILE )
                {
                    fsync(MeerInput->waldo_fd);
                    close(MeerInput->waldo_fd);
                    Waldo_Close();
                }

            Meer_Log(NORMAL, "Shutdown complete.");

            fclose(MeerConfig->meer_log_fd);
            fflush(stdout);

            exit(0);

        /* Signals to ignore */

        case 17:                /* Child process has exited. */
        case 28:                /* Terminal 'resize'/alarm. */

            break;

        case SIGUSR1:

            Statistics();
            break;

        case SIGUSR2:

            Statistics();
            break;

        case SIGPIPE:
            Meer_Log(NORMAL, "[Received signal %d [SIGPIPE]. Possible incomplete JSON?", sig_num);
            break;


        default:
            Meer_Log(NORMAL, "[Received signal %d. Meer doesn't know how to deal with.", sig_num);
        }

}



