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
#include <string.h>
#include <stdlib.h>

#include "meer.h"
#include "meer-def.h"
#include "util.h"
#include "references.h"

struct _References *MeerReferences;
struct _MeerCounters *MeerCounters;
struct _MeerOutput *MeerOutput;

void Load_References( void )
{

    int linecount = 0;

    char buf[1024] = { 0 };

    char *ptr1 = NULL;
    char *ptr2 = NULL;
    char *ptr3 = NULL;

    FILE *reference_fd;

    MeerCounters->ReferenceCount = 0;

    if (( reference_fd = fopen(MeerOutput->sql_reference_file, "r" )) == NULL )
        {
            Meer_Log(ERROR, "[%s, line %d] Cannot open '%s'", __FILE__,  __LINE__, MeerOutput->sql_reference_file);
        }

    while(fgets(buf, sizeof(buf), reference_fd) != NULL)
        {

            linecount++;

            if (buf[0] == '#' || buf[0] == 10 || buf[0] == ';' || buf[0] == 32)
                {
                    continue;
                }

            MeerReferences = (_References *) realloc(MeerReferences, (MeerCounters->ReferenceCount+1) * sizeof(_References));

            if ( MeerReferences == NULL )
                {
                    Meer_Log(ERROR, "[%s, line %d] Failed to reallocate memory for _References. Abort!", __FILE__, __LINE__);


                }

            Remove_Return(buf);

            strtok_r(buf, ":", &ptr1);

            ptr2 = strtok_r(NULL, ",", &ptr1);
            ptr3 = strtok_r(NULL, ",", &ptr1);

            if ( ptr2 == NULL || ptr3 == NULL )
                {
                    Meer_Log(ERROR, "[%s, line %d] Reference file appears to be incomplete. Abort!", __FILE__, __LINE__);
                }

            Remove_Spaces(ptr2);


            strlcpy(MeerReferences[MeerCounters->ReferenceCount].refid, ptr2, sizeof(MeerReferences[MeerCounters->ReferenceCount].refid));
            strlcpy(MeerReferences[MeerCounters->ReferenceCount].refurl, ptr2, sizeof(MeerReferences[MeerCounters->ReferenceCount].refurl));

            MeerCounters->ReferenceCount++;

        }

    Meer_Log(NORMAL, "References file loaded [%s].", MeerOutput->sql_reference_file);
    fclose(reference_fd);

}

