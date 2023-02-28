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

#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <wait.h>


#include "meer-def.h"
#include "meer.h"

extern struct _MeerConfig *MeerConfig;

void Daemonize()
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

