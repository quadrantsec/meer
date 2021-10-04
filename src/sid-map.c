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
#include "sid-map.h"
#include "references.h"

struct _SID_Map *SID_Map = NULL;

extern struct _MeerCounters *MeerCounters;
extern struct _MeerOutput *MeerOutput;
extern struct _References *MeerReferences;

void Load_SID_Map ( void )
{

    int linecount = 0;
    int i = 0;
    bool flag = 0;

    char buf[4096] = { 0 };

    char *sid_ptr = NULL;
    char *ref_ptr = NULL;
    char *msg_ptr = NULL;
    char *type = NULL;
    char *location = NULL;

    FILE *sid_map_fd;

    MeerCounters->SIDMapCount = 0;

    if (( sid_map_fd = fopen(MeerOutput->sql_sid_map_file, "r" )) == NULL )
        {
            Meer_Log(ERROR, "[%s, line %d] Cannot open '%s'", __FILE__,  __LINE__, MeerOutput->sql_sid_map_file);
        }

    while(fgets(buf, sizeof(buf), sid_map_fd) != NULL)
        {

            linecount++;

            if (buf[0] == '#' || buf[0] == 10 || buf[0] == ';' || buf[0] == 32)
                {
                    continue;
                }

            Remove_Return(buf);

            sid_ptr = strtok(buf, "||");

            if ( sid_ptr == NULL )
                {
                    Meer_Log(ERROR, "[%s, line %d] SID not found in %s. Abort!", __FILE__, __LINE__, MeerOutput->sql_sid_map_file);
                }

            Remove_Spaces(sid_ptr);

            msg_ptr = strtok(NULL, "||");

            if ( msg_ptr == NULL )
                {
                    Meer_Log(ERROR, "[%s, line %d] 'msg' not found in %s. Abort!", __FILE__, __LINE__, MeerOutput->sql_sid_map_file);
                }

            ref_ptr = strtok(NULL, "||");

            while (ref_ptr != NULL )
                {

                    SID_Map = (_SID_Map *) realloc(SID_Map, (MeerCounters->SIDMapCount+1) * sizeof(_SID_Map));

                    if ( SID_Map == NULL )
                        {
                            Meer_Log(ERROR, "[%s, line %d] Failed to reallocate memory for _SID_Map. Abort!", __FILE__, __LINE__);

                        }

                    Remove_Spaces(ref_ptr);

                    strlcpy(SID_Map[MeerCounters->SIDMapCount].msg, msg_ptr, sizeof(SID_Map[MeerCounters->SIDMapCount].msg));
                    SID_Map[MeerCounters->SIDMapCount].sid = atol(sid_ptr);

                    type = strtok_r(ref_ptr, ",", &location);

                    if ( type == NULL )
                        {
                            Meer_Log(ERROR, "[%s, line %d] 'type' not found in %s. Abort!", __FILE__, __LINE__, MeerOutput->sql_sid_map_file);
                        }

                    flag = 0;

                    for ( i = 0; i < MeerCounters->ReferenceCount; i++ )
                        {

                            if ( !strcmp(MeerReferences[i].refid, type ) )
                                {
                                    flag =1;
                                }
                        }

                    if ( flag == 0 )
                        {
                            Meer_Log(WARN, "Reference '%s' for siganture id %" PRIu64 " is unknown.",
                                     type, SID_Map[MeerCounters->SIDMapCount].sid);
                        }


                    if ( location == NULL )
                        {
                            Meer_Log(ERROR, "[%s, line %d] 'location' not found in %s. Abort!", __FILE__, __LINE__, MeerOutput->sql_sid_map_file);
                        }

                    strlcpy(SID_Map[MeerCounters->SIDMapCount].type, type, sizeof(SID_Map[MeerCounters->SIDMapCount].type));

                    strlcpy(SID_Map[MeerCounters->SIDMapCount].location, location, sizeof(SID_Map[MeerCounters->SIDMapCount].location));
                    ref_ptr = strtok(NULL, "||");

                    MeerCounters->SIDMapCount++;

                }

        }

    Meer_Log(NORMAL, "SID map file loaded [%s].", MeerOutput->sql_sid_map_file);
    fclose(sid_map_fd);

}

