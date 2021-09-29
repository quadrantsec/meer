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
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <sys/mman.h>

#include "meer.h"
#include "meer-def.h"
#include "config-yaml.h"
#include "decode-json-alert.h"
#include "lockfile.h"
#include "stats.h"

#include "output-plugins/sql.h"

#ifdef HAVE_LIBMYSQLCLIENT
#include "output-plugins/mysql.h"
#endif

#ifdef HAVE_LIBPQ
#include "output-plugins/postgresql.h"
#endif

#ifdef WITH_ELASTICSEARCH
#include <output-plugins/elasticsearch.h>
#include <curl/curl.h>

extern bool elasticsearch_death;
extern uint_fast16_t elastic_proc_running;
#endif

struct _MeerWaldo *MeerWaldo;
struct _MeerConfig *MeerConfig;
struct _MeerOutput *MeerOutput;

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

#if defined(HAVE_LIBMYSQLCLIENT) || defined(HAVE_LIBPQ)

            close(MeerConfig->waldo_fd);

            if ( MeerOutput->sql_enabled == true )
                {

#ifdef HAVE_LIBMYSQLCLIENT

                    if ( MeerOutput->sql_driver == DB_MYSQL )
                        {

                            /* If we're in the middle of a transaction,  commit/rollback */

                            if ( MeerOutput->sql_transaction == true )
                                {
                                    MySQL_DB_Query("COMMIT");
                                    MySQL_DB_Query("ROLLBACK");
                                }

                            MeerOutput->sql_last_cid++;
                            SQL_Record_Last_CID();
                            sleep(1);
                            mysql_close(MeerOutput->mysql_dbh);
                        }


#endif

#ifdef HAVE_LIBPQ

                    if ( MeerOutput->sql_driver == DB_POSTGRESQL )
                        {

                            /* If we're in the middle of a transaction,  commit/rollback */

                            if ( MeerOutput->sql_transaction == true )
                                {
                                    PG_DB_Query("COMMIT");
                                    PG_DB_Query("ROLLBACK");
                                }

                            MeerOutput->sql_last_cid++;
                            SQL_Record_Last_CID();
                            sleep(1);
                            PQfinish(MeerOutput->psql);
                        }

#endif

                }

#endif

#ifdef WITH_ELASTICSEARCH

            if ( MeerOutput->elasticsearch_flag == true )
                {

                    elasticsearch_death = true;

                    while ( elastic_proc_running != 0 )
                        {
                            Meer_Log(NORMAL, "Waiting on %d Elasticseach thread to shutdown.", elastic_proc_running);
                            sleep(1);

                            curl_global_cleanup();
                        }

                }

#endif


            Remove_Lock_File();

            Statistics();

            if ( MeerOutput->sql_enabled == true )
                {
                    Meer_Log(NORMAL, "Last CID is : %" PRIu64 ".", MeerOutput->sql_last_cid);
                }

            if ( MeerConfig->fingerprint == true && MeerConfig->fingerprint_log[0] != '\0' )
                {
                    fflush(MeerConfig->fingerprint_log_fd);
                    fclose(MeerConfig->fingerprint_log_fd);
                }


            fsync(MeerConfig->waldo_fd);
            close(MeerConfig->waldo_fd);

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

        case SIGPIPE:
            Meer_Log(NORMAL, "[Received signal %d [SIGPIPE]. Possible incomplete JSON?]", sig_num);
            break;


        default:
            Meer_Log(NORMAL, "[Received signal %d. Meer doesn't know how to deal with]", sig_num);
        }

}



