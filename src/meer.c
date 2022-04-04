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

#include "meer-def.h"
#include "meer.h"

#include "util.h"
#include "util-signal.h"
#include "config-yaml.h"
#include "lockfile.h"
#include "waldo.h"
#include "output.h"
#include "usage.h"
#include "oui.h"

#ifdef HAVE_LIBMAXMINDDB
#include "geoip.h"
#endif

struct _MeerConfig *MeerConfig = NULL;
struct _MeerOutput *MeerOutput = NULL;
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

    int fd_int;
    FILE *fd_file;

    struct stat st;

    bool skip_flag = 0;
    bool wait_flag = false;

    uint64_t linecount = 0;
    uint64_t old_size = 0;

    FILE *meer_log_fd_test;

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

    char *buf = malloc(MeerConfig->payload_buffer_size);

    if ( buf == NULL )
        {
            fprintf(stderr, "[%s, line %d] Fatal Error:  Can't allocate memory for buf! Abort!\n", __FILE__, __LINE__);
            exit(-1);
        }

    memset(buf, 0, MeerConfig->payload_buffer_size);

    if (( MeerConfig->meer_log_fd = fopen(MeerConfig->meer_log, "a" )) == NULL )
        {
            Meer_Log(ERROR, "Cannot open Meer log file %s! [%s]. Abort!", MeerConfig->meer_log, strerror(errno));
        }

    MeerConfig->meer_log_on = true;

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

#ifdef HAVE_LIBMAXMINDDB

    Meer_Log(NORMAL, "GeoIP support          : %s", MeerConfig->geoip ? "enabled" : "disabled" );

    if ( MeerConfig->geoip == true )
        {
            Meer_Log(NORMAL, "GeoIP database         : %s", MeerConfig->geoip_database );

            Open_GeoIP_Database();


        }

    Meer_Log(NORMAL, "");



#endif

    Init_Waldo();

    Init_Output();

    /* Open the follow_file or wait for the file to be created! */

    while (( fd_file = fopen(MeerConfig->follow_file, "r" )) == NULL )
        {

            if ( wait_flag == false )
                {
                    Meer_Log(NORMAL, "Waiting on %s spool file [%s].....", MeerConfig->follow_file, strerror(errno));
                    wait_flag = true;
                }
            sleep(1);
        }

    fd_int = fileno(fd_file);

    Meer_Log(NORMAL, "Successfully opened %s.", MeerConfig->follow_file);

    /* Become a daemon if requested */

    if ( MeerConfig->daemonize == true )
        {

            Meer_Log(NORMAL, "Becoming a daemon!");

            pid_t pid = 0;
            pid = fork();

            if ( pid == 0 )
                {

                    /* Child */

                    if ( setsid() == -1 )
                        {
                            Meer_Log(ERROR, "[%s, line %d] Failed creating new session while daemonizing", __FILE__, __LINE__);
                            exit(1);
                        }

                    pid = fork();

                    if ( pid == 0 )
                        {

                            /* Grandchild, the actual daemon */

                            if ( chdir("/") == -1 )
                                {
                                    Meer_Log(ERROR, "[%s, line %d] Failed changing directory to / after daemonizing [errno %d]", __FILE__, __LINE__, errno);
                                    exit(1);
                                }

                            /* Close and re-open stdin, stdout, and stderr, so as to
                               to release anyone waiting on them. */

                            close(0);
                            close(1);
                            close(2);

                            if ( open("/dev/null", O_RDONLY) == -1 )
                                {
                                    Meer_Log(ERROR, "[%s, line %d] Failed reopening stdin after daemonizing [errno %d]", __FILE__, __LINE__, errno);
                                }

                            if ( open("/dev/null", O_WRONLY) == -1 )
                                {
                                    Meer_Log(ERROR, "[%s, line %d] Failed reopening stdout after daemonizing [errno %d]", __FILE__, __LINE__, errno);
                                }

                            if ( open("/dev/null", O_RDWR) == -1 )
                                {
                                    Meer_Log(ERROR, "[%s, line %d] Failed reopening stderr after daemonizing [errno %d]", __FILE__, __LINE__, errno);
                                }

                        }
                    else if ( pid < 0 )
                        {

                            Meer_Log(ERROR, "[%s, line %d] Failed second fork while daemonizing", __FILE__, __LINE__);
                            exit(1);

                        }
                    else
                        {

                            exit(0);
                        }

                }
            else if ( pid < 0 )
                {

                    Meer_Log(ERROR, "[%s, line %d] Failed first fork while daemonizing", __FILE__, __LINE__);
                    exit(1);

                }
            else
                {

                    /* Wait for child to exit */
                    waitpid(pid, NULL, 0);
                    exit(0);
                }
        }



    if ( MeerWaldo->position != 0 )
        {

            Meer_Log(NORMAL, "Skipping to record %" PRIu64 " in %s", MeerWaldo->position, MeerConfig->follow_file);

            while( (fgets(buf, MeerConfig->payload_buffer_size, fd_file) != NULL ) && linecount < MeerWaldo->position )
                {

                    linecount++;
                }

            /* If our Waldo is > than our line count,  the file was likely truncated while Meer was
               "offline".  Reset the Waldo,  and inform the user.  On restart, we'll treat the spool
               as a new file. */

            if ( MeerWaldo->position > linecount )
                {

                    Meer_Log(WARN, "Spool might have been truncated!  Resetting Waldo to zero and aborting.");
                    MeerWaldo->position = 0;
                    Signal_Handler(SIGTERM);

                }

            Meer_Log(NORMAL, "Reached target record of %" PRIu64 ".  Processing new records.", MeerWaldo->position);


        }
    else
        {

            Meer_Log(NORMAL, "Ingesting data. Working........");

        }

    while(fgets(buf, MeerConfig->payload_buffer_size, fd_file) != NULL)
        {

            if ( Validate_JSON_String( buf ) == 0 )
                {
                    Decode_JSON( buf );
                }

            MeerWaldo->position++;

        }

    Meer_Log(NORMAL, "Read in %" PRIu64 " lines",MeerWaldo->position);

    if (fstat(fd_int, &st))
        {
            Meer_Log(ERROR, "Cannot 'stat' spool file '%s' [%s]  Abort!", MeerConfig->follow_file, strerror(errno));
        }

    old_size = (uint64_t) st.st_size;

    Meer_Log(NORMAL, "Waiting for new data......");

    while(1)
        {

            /* If the spool file disappears, then we wait to see if a new one
               shows up.  Suricata might be rotating the alert.json file.  We use to
               try and "stat" the file but that didn't work.  We use fopen as a "test"
               instead. 2020/10/27 - Champ */

            if (( meer_log_fd_test = fopen(MeerConfig->follow_file, "r" )) == NULL )
                {

                    fclose(fd_file);

                    old_size = 0;
                    linecount = 0;

                    MeerWaldo->position = 0;

                    Meer_Log(NORMAL, "Follow JSON File '%s' disappeared [%s].", MeerConfig->follow_file, strerror(errno) );
                    Meer_Log(NORMAL, "Waiting for new spool file....");

                    while (( fd_file = fopen(MeerConfig->follow_file, "r" )) == NULL )
                        {
                            sleep(1);
                        }

                    fd_int = fileno(fd_file);

                    Meer_Log(NORMAL, "Sucessfully re-opened %s. Waiting for new data.", MeerConfig->follow_file);

                }
            else
                {

                    /* Test succeeded.  Close test file */

                    fclose(meer_log_fd_test);

                }

            /* Check spool file.  If it's grown,  read in the new data.  For some reason,  around Debian 10
               the call for fgets() stop functioning.  We've replaced that with a read() and parsing of the
               read_buf. */

            if (fstat(fd_int, &st))
                {
                    Meer_Log(ERROR, "Cannot 'stat' spool file '%s' [%s]  Abort!", MeerConfig->follow_file, strerror(errno));
                }

            if ( (uint64_t) st.st_size > old_size )
                {

                    /* Clear any previous EOF */

                    clearerr( fd_file );

                    while(fgets(buf, MeerConfig->payload_buffer_size, fd_file) != NULL)
                        {

                            skip_flag = Validate_JSON_String( buf );

                            if ( skip_flag == 0 )
                                {
                                    Decode_JSON( buf);
                                }

                            MeerWaldo->position++;

                        }

                    old_size = (uint64_t) st.st_size;

                }

            /* If the spool file has _shunk_,  it's been truncated.  We need to
                   re-open it! */

            else if ( (uint64_t) st.st_size < old_size )
                {
                    Meer_Log(NORMAL, "Spool file Truncated! Re-opening '%s'!", MeerConfig->follow_file );

                    fclose(fd_file);

                    if (( fd_file = fopen(MeerConfig->follow_file, "r" )) == NULL )
                        {
                            Meer_Log(ERROR, "Cannot re-open %s. [%s]", MeerConfig->follow_file, strerror(errno) );
                        }

                    fd_int = fileno(fd_file);

                    old_size = 0;
                    linecount = 0;

                    MeerWaldo->position = 0;

                }

            sleep(1);
        }


    free(buf);
    return(0);

}
