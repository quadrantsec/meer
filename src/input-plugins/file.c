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
#include "waldo.h"
#include "output.h"

#include "input-plugins/file.h"

extern struct _MeerConfig *MeerConfig;
extern struct _MeerInput *MeerInput;
extern struct _MeerWaldo *MeerWaldo;


void Input_File()
{


    int fd_int;
    FILE *fd_file;

    struct stat st;

    bool skip_flag = 0;
    bool wait_flag = false;

    uint64_t linecount = 0;
    uint64_t old_size = 0;

    FILE *meer_log_fd_test;

    char *buf = malloc(MeerConfig->payload_buffer_size);
    if ( buf == NULL )
        {
            fprintf(stderr, "[%s, line %d] Fatal Error:  Can't allocate memory for buf! Abort!\n", __FILE__, __LINE__);
            exit(-1);
        }

    Meer_Log(NORMAL, "--[ File input information ]--------------------------------------");
    Meer_Log(NORMAL, "");

    Init_Waldo();


    /* Open the follow_file or wait for the file to be created! */

    while (( fd_file = fopen(MeerInput->follow_file, "r" )) == NULL )
        {

            if ( wait_flag == false )
                {
                    Meer_Log(NORMAL, "Waiting on %s spool file [%s].....", MeerInput->follow_file, strerror(errno));
                    wait_flag = true;
                }
            sleep(1);
        }

    fd_int = fileno(fd_file);

    Meer_Log(NORMAL, "Successfully opened %s.", MeerInput->follow_file);

    if ( MeerWaldo->position != 0 )
        {

            Meer_Log(NORMAL, "Skipping to record %" PRIu64 " in %s", MeerWaldo->position, MeerInput->follow_file);

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
                    Waldo_Sync();
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
            Waldo_Sync();

        }

    Meer_Log(NORMAL, "Read in %" PRIu64 " lines",MeerWaldo->position);

    if (fstat(fd_int, &st))
        {
            Meer_Log(ERROR, "Cannot 'stat' spool file '%s' [%s]  Abort!", MeerInput->follow_file, strerror(errno));
        }

    old_size = (uint64_t) st.st_size;

    Meer_Log(NORMAL, "Waiting for new data......");

    while(1)
        {

            /* If the spool file disappears, then we wait to see if a new one
               shows up.  Suricata might be rotating the alert.json file.  We use to
               try and "stat" the file but that didn't work.  We use fopen as a "test"
               instead. 2020/10/27 - Champ */

            if (( meer_log_fd_test = fopen(MeerInput->follow_file, "r" )) == NULL )
                {

                    fclose(fd_file);

                    old_size = 0;
                    linecount = 0;

                    MeerWaldo->position = 0;

                    Meer_Log(NORMAL, "Follow JSON File '%s' disappeared [%s].", MeerInput->follow_file, strerror(errno) );
                    Meer_Log(NORMAL, "Waiting for new spool file....");

                    while (( fd_file = fopen(MeerInput->follow_file, "r" )) == NULL )
                        {
                            sleep(1);
                        }

                    fd_int = fileno(fd_file);

                    Meer_Log(NORMAL, "Sucessfully re-opened %s. Waiting for new data.", MeerInput->follow_file);

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
                    Meer_Log(ERROR, "Cannot 'stat' spool file '%s' [%s]  Abort!", MeerInput->follow_file, strerror(errno));
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
                    Meer_Log(NORMAL, "Spool file Truncated! Re-opening '%s'!", MeerInput->follow_file );

                    fclose(fd_file);

                    if (( fd_file = fopen(MeerInput->follow_file, "r" )) == NULL )
                        {
                            Meer_Log(ERROR, "Cannot re-open %s. [%s]", MeerInput->follow_file, strerror(errno) );
                        }

                    fd_int = fileno(fd_file);

                    old_size = 0;
                    linecount = 0;

                    MeerWaldo->position = 0;

                }

            sleep(1);
        }


    free(buf);
    return;

}
