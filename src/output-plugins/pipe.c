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

/****************************************************************************
 * This takes input data (JSON) and writes it out to a named pipe/FIFO
 ****************************************************************************/

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include "meer.h"
#include "meer-def.h"
#include "pipe.h"

extern struct _MeerOutput *MeerOutput;
extern struct _MeerCounters *MeerCounters;

void Pipe_Write ( const char *json_string )
{
    uint32_t ret = 0;

    ret = write(MeerOutput->pipe_fd, json_string, strlen(json_string));

    if ( ret < 0 )
        {
            Meer_Log(WARN, "Could not write pipe. Error: %s", strerror(errno));
            return;
        }

    MeerCounters->JSONPipeWrites++;

}
