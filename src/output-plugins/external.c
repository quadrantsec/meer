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

/*
 * This calls an external program
 */

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "meer.h"
#include "meer-def.h"
#include "util.h"

extern struct _MeerOutput *MeerOutput;
extern struct _MeerCounters *MeerCounters;
extern struct _MeerConfig *MeerConfig;

bool External( const char *json_string )
{

    int in[2];
    int out[2];
    int pid;
    int n;

    char *buf = malloc((MeerConfig->payload_buffer_size)*sizeof(char));

    if ( buf == NULL )
        {
            fprintf(stderr, "[%s, line %d] Fatal Error: Can't allocate memory! Abort!\n", __FILE__, __LINE__);
            exit(-1);
        }


    if( File_Check( MeerOutput->external_program ) != 1 )
        {

            Meer_Log(WARN, "Warning! The external program '%s' does not exsist!", MeerOutput->external_program);
            MeerCounters->ExternalMissCount++;
            free(buf);
            return(1);

        }

    if ( pipe(in) < 0 )
        {
            Meer_Log(WARN, "[%s, line %d] Cannot create input pipe!", __FILE__, __LINE__);
            MeerCounters->ExternalMissCount++;
            free(buf);
            return(1);
        }


    if ( pipe(out) < 0 )
        {
            Meer_Log(WARN, "[%s, line %d] Cannot create output pipe!", __FILE__, __LINE__);
            MeerCounters->ExternalMissCount++;
            free(buf);
            return(1);
        }

    pid=fork();
    if ( pid < 0 )
        {
            Meer_Log(WARN, "[%s, line %d] Cannot create external program process", __FILE__, __LINE__);
            MeerCounters->ExternalMissCount++;
            free(buf);
            return(1);
        }
    else if ( pid == 0 )
        {
            /* Causes problems with alert.log */


            close(0);
            close(1);
            close(2);

            dup2(in[0],0);
            dup2(out[1],1);
            dup2(out[1],2);

            close(in[1]);
            close(out[0]);

            execl(MeerOutput->external_program, MeerOutput->external_program, NULL, (char *)NULL);

            Meer_Log(WARN, "[%s, line %d] Cannot execute %s", __FILE__, __LINE__, MeerOutput->external_program);
            MeerCounters->ExternalMissCount++;
        }

    close(in[0]);
    close(out[1]);

    /* Write to child input */

    n = write(in[1], json_string, strlen(json_string));
    n = write(in[1], "\n", 1);		/* Take on \n */
    close(in[1]);

    n = read(out[0], buf, sizeof(buf));
    close(out[0]);
    buf[n] = 0;

    waitpid(pid, NULL, 0);

    if ( MeerOutput->external_debug )
        {
            Meer_Log(DEBUG, "DEBUG: Executed '%s'", MeerOutput->external_program);
        }

    MeerCounters->ExternalHitCount++;

    free(buf);
    return(0);

}
