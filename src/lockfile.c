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

/* Lock file routines */

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <pthread.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <string.h>

#include "meer.h"
#include "meer-def.h"
#include "lockfile.h"

extern struct _MeerConfig *MeerConfig;

void CheckLockFile ( void )
{

    char buf[10];
    FILE *lck;
    int pid;
    struct stat lckcheck;

    /* Check for lockfile first */

    if (stat(MeerConfig->lock_file, &lckcheck) == 0 )
        {

            /* Lock file is present,  open for read */

            if (( lck = fopen(MeerConfig->lock_file, "r" )) == NULL )
                {
                    Meer_Log(ERROR, "[%s, line %d] Lock file '%s' is present but can't be read [%s]", __FILE__, __LINE__, MeerConfig->lock_file, strerror(errno));
                }
            else
                {
                    if (!fgets(buf, sizeof(buf), lck))
                        {
                            Meer_Log(ERROR, "[%s, line %d] Lock file (%s) is open for reading, but can't read contents.", __FILE__, __LINE__, MeerConfig->lock_file);
                        }

                    fclose(lck);
                    pid = atoi(buf);

                    if ( pid == 0 )
                        {
                            Meer_Log(ERROR, "[%s, line %d] Lock file read but pid value is zero. Aborting.....", __FILE__, __LINE__);
                        }

                    /* Check to see if process is running.  We use kill with 0 signal
                     * to determine this.  We check this return value.  Signal 0
                     * won't affect running processes */

                    if ( kill(pid, 0) != -1 )
                        {
                            Meer_Log(ERROR, "[%s, line %d] It appears that Meer is already running (pid: %d).", __FILE__, __LINE__, pid);
                        }
                    else
                        {

                            Meer_Log(NORMAL, "Lock file is present,  but Meer isn't at pid %d (Removing stale %s file)", pid, MeerConfig->lock_file);

                            if (unlink(MeerConfig->lock_file))
                                {
                                    Meer_Log(ERROR, "Unable to unlink %s.", MeerConfig->lock_file);
                                }
                        }
                }
        }
    else
        {

            /* No lock file present, so create it */

            if (( lck = fopen(MeerConfig->lock_file, "w" )) == NULL )
                {
                    Meer_Log(ERROR, "[%s, line %d] Cannot create lock file (%s - %s)", __FILE__, __LINE__, MeerConfig->lock_file, strerror(errno));
                }
            else
                {
                    fprintf(lck, "%d", getpid() );
                    fflush(lck);
                    fclose(lck);
                }
        }
}

void Remove_Lock_File ( void )
{

    struct stat lckcheck;

    if ( (stat(MeerConfig->lock_file, &lckcheck) == 0) && unlink(MeerConfig->lock_file) != 0 )
        {
            Meer_Log(ERROR, "[%s, line %d] Cannot remove lock file (%s - %s)", __FILE__, __LINE__, MeerConfig->lock_file, strerror(errno));
        }
}

