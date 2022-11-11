/*
** Copyright (C) 2018-2022 Quadrant Information Security <quadrantsec.com>
** Copyright (C) 2018-2022 Champ Clark III <cclark@quadrantsec.com>
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License Version 2 as                                                   ** published by the Free Software Foundation.  You may not use, modify or
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

/* --file command line for normal and gzip files */

#include <stdio.h>
#include <glob.h>
#include <sys/stat.h>
#include <string.h>
#include <errno.h>

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#ifdef HAVE_LIBZ
#include <zlib.h>
#endif

#include "meer.h"
#include "meer-def.h"
#include "util.h"

#include "input-plugins/commandline.h"

extern struct _MeerConfig *MeerConfig;

void Command_Line()
{

    glob_t globbuf = {0};

    Meer_Log(NORMAL, "--[ Command line - file input information ]--------------------------------------");
    Meer_Log(NORMAL, "");

    glob(MeerConfig->command_line, GLOB_DOOFFS, NULL, &globbuf);

    for (size_t z = 0; z != globbuf.gl_pathc; ++z)
        {

            if ( globbuf.gl_pathv[z][ strlen(globbuf.gl_pathv[z]) - 3 ] == '.' &&
                    globbuf.gl_pathv[z][ strlen(globbuf.gl_pathv[z]) - 2 ] == 'g' &&
                    globbuf.gl_pathv[z][ strlen(globbuf.gl_pathv[z]) - 1 ] == 'z' )
                {
#ifdef HAVE_LIBZ
                    GZIP_Input( globbuf.gl_pathv[z] );
#endif

#ifndef HAVE_LIBZ
                    Meer_Log(WARN, "[%s, line %d] Meer lacks gzip/libz support. Skipping %s.", __FILE__, __LINE__, globbuf.gl_pathv[z]);
#endif
                }
            else
                {
                    Read_File( globbuf.gl_pathv[z] );
                }
        }

    Meer_Log(NORMAL, "Done processing all files.");

}

#ifdef HAVE_LIBZ

void GZIP_Input( const char *filename )
{

    uint64_t linecount = 0;

    gzFile fd;

    if (( fd = gzopen(filename, "rb")) == NULL )
        {
            Meer_Log(ERROR, "[%s, line %d] Cannot open %s! [%s]", __FILE__, __LINE__, filename, strerror(errno));
        }

    Meer_Log(NORMAL, "Successfully opened GZIP file %s....  processing.....", filename);

    char *buf = malloc(MeerConfig->payload_buffer_size);

    if ( buf == NULL )
        {
            fprintf(stderr, "[%s, line %d] Fatal Error:  Can't allocate memory for buf! Abort!\n", __FILE__, __LINE__);
            exit(-1);
        }


    while(gzgets(fd, buf, MeerConfig->payload_buffer_size) != NULL)
        {

            if ( Validate_JSON_String( buf ) == 0 )
                {
                    Decode_JSON( buf );
                }

            linecount++;

        }

    Meer_Log(NORMAL, "Done with %s.  Processed %"PRIu64 " lines", filename, linecount);

    free(buf);

    gzclose(fd);
}

#endif


void Read_File( const char *filename )
{

    FILE *fd_file;

    struct stat st;

    bool skip_flag = 0;
    bool wait_flag = false;

    uint64_t linecount = 0;

    /* DEBUG:  This never gets hit!??! */

    if ( ( fd_file = fopen("whatever", "r" )) == NULL  )
        {
            Meer_Log(ERROR, "[%s, line %d] Cannot open %s [%s]", __FILE__, __LINE__, filename, strerror(errno));
        }

    char *buf = malloc(MeerConfig->payload_buffer_size);

    if ( buf == NULL )
        {
            fprintf(stderr, "[%s, line %d] Fatal Error:  Can't allocate memory for buf! Abort!\n", __FILE__, __LINE__);
            exit(-1);
        }

    Meer_Log(NORMAL, "Processing %s......", filename);

    while(fgets(buf, MeerConfig->payload_buffer_size, fd_file) != NULL)
        {

            if ( Validate_JSON_String( buf ) == 0 )
                {
                    Decode_JSON( buf );
                }

            linecount++;

        }

    Meer_Log(NORMAL, "Done with %s.  Processed %"PRIu64 " lines", filename, linecount);

    free(buf);
    fclose(fd_file);

}
