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

/* MySQL/MariaDB specific routines */

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#ifdef HAVE_LIBMYSQLCLIENT

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>

#include "meer.h"
#include "meer-def.h"
#include "lockfile.h"
#include "config-yaml.h"
#include "decode-json-alert.h"
#include "output-plugins/sql.h"
#include "output-plugins/mysql.h"

struct _MeerConfig *MeerConfig;
struct _MeerOutput *MeerOutput;

void MySQL_Connect( void )
{

    MeerOutput->mysql_dbh = mysql_init(NULL);

    if ( MeerOutput->mysql_dbh == NULL )
        {
            Remove_Lock_File();
            Meer_Log(ERROR, "[%s, line %d] Error initializing MySQL", __FILE__, __LINE__);
        }

    if (!mysql_real_connect(MeerOutput->mysql_dbh, MeerOutput->sql_server,
                            MeerOutput->sql_username, MeerOutput->sql_password, MeerOutput->sql_database,
                            MeerOutput->sql_port, NULL, 0 ))
        {

            Meer_Log(ERROR, "[%s, line %d] MySQL Error %u: \"%s\"", __FILE__,  __LINE__,
                     mysql_errno(MeerOutput->mysql_dbh), mysql_error(MeerOutput->mysql_dbh));

        }

    //mysql_autocommit(MeerOutput->mysql_dbh, false);	/* Turn off autocommit! */

    Meer_Log(NORMAL, "Successfully connected to MySQL/MariaDB database.");
}


void MySQL_Error_Handling ( char *sql )
{

    /* Reconnect on network event */

    if ( MeerOutput->sql_reconnect == true &&
            ( mysql_errno(MeerOutput->mysql_dbh) == 2003 ||
              mysql_errno(MeerOutput->mysql_dbh) == 2006 ||
              mysql_errno(MeerOutput->mysql_dbh) == 2013 ) )
        {

            while ( mysql_errno(MeerOutput->mysql_dbh) == 2003 || mysql_errno(MeerOutput->mysql_dbh) == 2006 || mysql_errno(MeerOutput->mysql_dbh) == 2013 )
                {

                    Meer_Log(WARN, "MySQL/MariaDB has gone away.  Sleeping for %d seconds before attempting to reconnect.", MeerOutput->sql_reconnect_time);

                    sleep(MeerOutput->sql_reconnect_time);

                    if (!mysql_real_connect(MeerOutput->mysql_dbh, MeerOutput->sql_server,
                                            MeerOutput->sql_username, MeerOutput->sql_password, MeerOutput->sql_database,
                                            MeerOutput->sql_port, NULL, 0 ))
                        {

                            Meer_Log(WARN, "[%s, line %d] MySQL Error %u: \"%s\"", __FILE__,  __LINE__,
                                     mysql_errno(MeerOutput->mysql_dbh), mysql_error(MeerOutput->mysql_dbh));

                        }

                }

            Meer_Log(NORMAL, "Successfully reconnected to MySQL/MariaDB database.");

            return;
        }

    /* All other errors */

    Remove_Lock_File();
    Meer_Log(ERROR, "[%s, line %d] MySQL/MariaDB Error [%u:] \"%s\"\nOffending SQL statement: %s\n", __FILE__,  __LINE__, mysql_errno(MeerOutput->mysql_dbh), mysql_error(MeerOutput->mysql_dbh), sql);

}


char *MySQL_DB_Query( char *sql )
{

    MYSQL_RES *res;
    MYSQL_ROW row;

    char tmp[MAX_SQL_QUERY] = { 0 };

    char *re = NULL;

    if ( mysql_real_query(MeerOutput->mysql_dbh, sql, strlen(sql) ) )
        {
            MySQL_Error_Handling( sql );
        }

    res = mysql_use_result(MeerOutput->mysql_dbh);

    if ( res != NULL )
        {
            while( ( row = mysql_fetch_row(res) ) )
                {
                    snprintf(tmp, sizeof(tmp), "%s", row[0]);
                    re=tmp;
                }
        }

    mysql_free_result(res);
    return(re);

}

char *MySQL_Get_Last_ID( void )
{

    char *ret = NULL;

    ret = MySQL_DB_Query("SELECT LAST_INSERT_ID()");

    return(ret);

}

void MySQL_Escape_String( char *sql, char *str, size_t size )
{

    char tmp[MAX_SQL_QUERY] = { 0 };

    int len = 0;

    len = mysql_real_escape_string(MeerOutput->mysql_dbh, tmp, sql, strlen(sql));
    tmp[len] = '\0';

    snprintf(str, size, "%s", tmp);
    return;

}

#endif
