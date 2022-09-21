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

/* Main Meer function */

/*
 * Notes:  Fix validation in yaml (make sure the module is enabled)
 *         Sanity checks (external_match == NULL, dont run, etc)
 *	   port the "stat" code to Sagan for external calls.
 *	   documentation!
 */


#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <getopt.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <sys/mman.h>

#include "meer-def.h"
#include "meer.h"

#include "util.h"
#include "util-signal.h"
#include "config-yaml.h"
#include "lockfile.h"
#include "output.h"
#include "usage.h"
#include "oui.h"
#include "daemonize.h"

#include "input-plugins/file.h"

#ifdef HAVE_LIBMAXMINDDB
#include "geoip.h"
#endif

struct _MeerConfig *MeerConfig = NULL;
struct _MeerOutput *MeerOutput = NULL;
struct _MeerInput *MeerInput = NULL;
struct _MeerWaldo *MeerWaldo = NULL;
struct _MeerCounters *MeerCounters = NULL;
struct _Classifications *MeerClass = NULL;
struct _References *MeerReferences = NULL;

int main (int argc, char *argv[])
{

    signal(SIGINT,  &Signal_Handler);
    signal(SIGQUIT,  &Signal_Handler);
    signal(SIGTERM,  &Signal_Handler);
    signal(SIGPIPE, &Signal_Handler);
//    signal(SIGSEGV,  &Signal_Handler);
    signal(SIGABRT,  &Signal_Handler);
//    signal(SIGHUP,  &Signal_Handler);		/* DEBUG: Need SIGHUP handler */
    signal(SIGUSR1,  &Signal_Handler);

    /* MOST configuration options should happen in the meer.yaml.  Barnyard2's
       "command line" verses "barnyard2.conf" gets really annoying.  Meer is
       trying to avoid that.  Hence,  very few command line options! */

    const struct option long_options[] =
    {
        { "help",         no_argument,          NULL,   'h' },
        { "quiet",        no_argument,          NULL,   'q' },
        { "daemon",       no_argument,          NULL,   'D' },
//        { "credits",      no_argument,          NULL,   'C' },
        { "config",       required_argument,    NULL,   'c' },
        {0, 0, 0, 0}
    };

    static const char *short_options =
        "c:hDq";

    signed char c;
    int option_index = 0;

//    int fd_int;
//    FILE *fd_file;

//    struct stat st;

//    bool skip_flag = 0;
//    bool wait_flag = false;

//    uint64_t linecount = 0;
//    uint64_t old_size = 0;

//    FILE *meer_log_fd_test;

    MeerConfig = (struct _MeerConfig *) malloc(sizeof(_MeerConfig));

    if ( MeerConfig == NULL )
        {
            Meer_Log(ERROR, "[%s, line %d] Failed to allocate memory for _MeerConfig. Abort!", __FILE__, __LINE__);
        }

    memset(MeerConfig, 0, sizeof(_MeerConfig));

    strlcpy(MeerConfig->yaml_file, DEFAULT_CONFIG, sizeof(MeerConfig->yaml_file));
    MeerConfig->daemonize = false;
    MeerConfig->quiet = false;

    while ((c = getopt_long(argc, argv, short_options, long_options, &option_index)) != -1)
        {

            switch(c)
                {

                case 'c':
                    strlcpy(MeerConfig->yaml_file,optarg,sizeof(MeerConfig->yaml_file) - 1);
                    break;

                case 'h':
                    Usage();
                    exit(0);
                    break;

                case 'D':
                    MeerConfig->daemonize = true;
                    break;

                case 'q':
                    MeerConfig->quiet = true;
                    break;

                default:
                    fprintf(stderr, "\nInvalid argument! See below for command line switches.\n");
                    Usage();
                    exit(0);
                    break;

                }

        }

    MeerCounters = (struct _MeerCounters *) malloc(sizeof(_MeerCounters));

    if ( MeerCounters == NULL )
        {
            Meer_Log(ERROR, "[%s, line %d] Failed to allocate memory for _MeerCounters. Abort!", __FILE__, __LINE__);
        }

    memset(MeerCounters, 0, sizeof(_MeerCounters));

    Load_YAML_Config(MeerConfig->yaml_file);

    if (( MeerConfig->meer_log_fd = fopen(MeerConfig->meer_log, "a" )) == NULL )
        {
            Meer_Log(ERROR, "Cannot open Meer log file %s! [%s]. Abort!", MeerConfig->meer_log, strerror(errno));
        }

    MeerConfig->meer_log_on = true;

    /* Daemonize early on */

    if ( MeerConfig->daemonize == true )
        {
            Daemonize();
        }

    Meer_Log(NORMAL, "");
    Meer_Log(NORMAL, " @@@@@@@@@@  @@@@@@@@ @@@@@@@@ @@@@@@@    Meer version %s", VERSION);
    Meer_Log(NORMAL, " @@! @@! @@! @@!      @@!      @@!  @@@   Quadrant Information Security");
    Meer_Log(NORMAL, " @!! !!@ @!@ @!!!:!   @!!!:!   @!@!!@a    https://quadrantsec.com");
    Meer_Log(NORMAL, " !!:     !!: !!:      !!:      !!: :!a    Copyright (C) 2018-2022");
    Meer_Log(NORMAL, "  :      :   : :: ::  : :: ::   :   : :");
    Meer_Log(NORMAL, "");

    Meer_Log(NORMAL, "Meer's PID is %d", getpid() );
    Meer_Log(NORMAL, "Meer's buffer size is %" PRIu64 " bytes.", MeerConfig->payload_buffer_size);
    Drop_Priv();
    CheckLockFile();

    if ( MeerConfig->oui == true )
        {
            Load_OUI();
        }

    Meer_Log(NORMAL, "");
    Meer_Log(NORMAL, "Fingerprint support    : %s", MeerConfig->fingerprint ? "enabled" : "disabled" );
    Meer_Log(NORMAL, "- Fingerprint reader   : %s", MeerConfig->fingerprint_reader ? "enabled" : "disabled" );
    Meer_Log(NORMAL, "- Fingerprint writer   : %s", MeerConfig->fingerprint_writer ? "enabled" : "disabled" );
    Meer_Log(NORMAL, "");

    if ( MeerConfig->calculate_stats == true )
        {

            Meer_Log(NORMAL, "Calculate stats        : %s", MeerConfig->calculate_stats ? "enabled" : "disabled" );
            Meer_Log(NORMAL, "");
        }

#ifdef HAVE_LIBMAXMINDDB

    Meer_Log(NORMAL, "GeoIP support          : %s", MeerConfig->geoip ? "enabled" : "disabled" );

    if ( MeerConfig->geoip == true )
        {
            Meer_Log(NORMAL, "GeoIP database         : %s", MeerConfig->geoip_database );

            Open_GeoIP_Database();


        }

    Meer_Log(NORMAL, "");



#endif

    Init_Output();

    if (  MeerInput->type == YAML_INPUT_FILE )
        {
            Input_File();
        }

    else if ( MeerInput->type == YAML_INPUT_PIPE )
        {
            /* DO PIPE */
        }

    else if ( MeerInput->type == YAML_INPUT_REDIS )
        {
            /* DO REDIS */
        }

}
