/*
** Copyright (C) 2018-2020 Quadrant Information Security <quadrantsec.com>
** Copyright (C) 2018-2020 Champ Clark III <cclark@quadrantsec.com>
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

/* PostgreSQL specific routines */

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#ifdef HAVE_LIBPQ

#include <stdio.h>

#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <postgresql/libpq-fe.h>

#include "meer.h"
#include "meer-def.h"
#include "decode-json-alert.h"
#include "lockfile.h"
#include "output-plugins/sql.h"
#include "output-plugins/postgresql.h"

struct _MeerConfig *MeerConfig;
struct _MeerOutput *MeerOutput;

void PG_Connect( void )
{

    char pgconnect[2048] = { 0 };

    snprintf(pgconnect, sizeof(pgconnect), "hostaddr = '%s' port = '%d' dbname = '%s' user = '%s' password = '%s' connect_timeout = '%d'", MeerOutput->sql_server,  MeerOutput->sql_port, MeerOutput->sql_database, MeerOutput->sql_username, MeerOutput->sql_password, MeerOutput->sql_reconnect );

    MeerOutput->psql = PQconnectdb(pgconnect);

    if ( !MeerOutput->psql )
        {
            Remove_Lock_File();
            Meer_Log(ERROR, "[%s, line %d] Error initializing PostgreSQL. Abort", __FILE__, __LINE__);
        }

    if ( PQstatus(MeerOutput->psql) != CONNECTION_OK )
        {
            Remove_Lock_File();
            Meer_Log(ERROR, "[%s, line %d] PostgreSQL status is not okay. Abort", __FILE__, __LINE__);
        }

    return;

}

char *PG_DB_Query( char *sql )
{

    PGresult *result;
    char *ret = NULL;

    if (( result = PQexec(MeerOutput->psql, sql )) == NULL )
        {
            Remove_Lock_File();
            Meer_Log(ERROR, "[%s, line %d] PostgreSQL Error: %s", __FILE__, __LINE__, PQerrorMessage( MeerOutput->psql ));
        }

    if (PQresultStatus(result) != PGRES_COMMAND_OK &&
            PQresultStatus(result) != PGRES_TUPLES_OK)
        {
            Remove_Lock_File();
            PQclear(result);
            Meer_Log(ERROR, "[%s, line %d] PostgreSQL Error: %s", __FILE__,  __LINE__, PQerrorMessage( MeerOutput->psql ));
        }

    if ( PQntuples(result) != 0 )
        {
            ret = PQgetvalue(result,0,0);
        }

    PQclear(result);
    return(ret);
}

char *PG_Get_Last_ID( void )
{
    char *ret = NULL;

    ret = PG_DB_Query("SELECT lastval()");

    return(ret);

}

/*
void PG_Signal_Shutdown( void )
{

                    close(MeerConfig->waldo_fd);

                    PG_DB_Query("ROLLBACK");

                    MeerOutput->sql_last_cid++;

                    SQL_Record_Last_CID();

		    sleep(1);

		    PQfinish(MeerOutput->psql);

}
*/

void PG_Escape_String( char *sql, char *str, size_t size )
{

    char tmp[MAX_SQL_QUERY] = { 0 };

    PQescapeLiteral(MeerOutput->psql, (const char *)sql, size);
    snprintf(str, size, "%s", tmp);
    return;


}


#endif
