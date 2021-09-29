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


#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif


#ifdef HAVE_LIBMAXMINDDB

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <maxminddb.h>
#include <errno.h>

#include "meer.h"
#include "meer-def.h"
#include "util.h"
#include "geoip.h"

extern struct _MeerConfig *MeerConfig;

MMDB_s 	geoip;

void Open_GeoIP_Database( void )
{

    int status;

    /*
     * The GeoIP library gives a really vague error when it cannot load
     * the GeoIP database.  We give the user more information here so
     * that they might fix the issue.
     */

    status = access(MeerConfig->geoip_database, R_OK);

    if ( status != 0 )
        {
            Meer_Log(WARN, "Cannot open '%s' [%s]!",  MeerConfig->geoip_database, strerror(errno));
            Meer_Log(ERROR, "Make sure the GeoIP database '%s' is readable by '%s'.", MeerConfig->geoip_database, MeerConfig->runas);
        }

    status = MMDB_open(MeerConfig->geoip_database, MMDB_MODE_MMAP, &geoip);

    if ( status != 0 )
        {
            Meer_Log(ERROR, "Error loading Maxmind GeoIP data (%s).  Are you trying to load an older, non-GeoIP database?", MeerConfig->geoip_database);
        }


}

void GeoIP_Lookup( const char *ip_address, struct _GeoIP *GeoIP )
{

    int gai_error;
    int mmdb_error;
    int res;

    bool failure = false;

    unsigned char ip_convert[MAXIPBIT] = { 0 };


    IP2Bit( (char*)ip_address, ip_convert);

    if ( Is_Notroutable(ip_convert) )
        {
            return;
        }

    MMDB_lookup_result_s result = MMDB_lookup_string(&geoip, ip_address, &gai_error, &mmdb_error);
    MMDB_entry_data_s entry_data;

    /* Country code */

    res = MMDB_get_value(&result.entry, &entry_data, "country", "iso_code", NULL);

    if (res != MMDB_SUCCESS)
        {
            strlcpy(GeoIP->country, "LOOKUP_FAILURE", sizeof(GeoIP->country));
            failure = true;
        }

    if ( !entry_data.has_data || entry_data.type != MMDB_DATA_TYPE_UTF8_STRING )
        {
            strlcpy( GeoIP->country, "NOT_FOUND", sizeof( GeoIP->country ) );
            failure = true;
        }

    if ( failure == false )
        {
            strlcpy(GeoIP->country, entry_data.utf8_string, 3);
        }

    /* City */

    MMDB_get_value(&result.entry, &entry_data, "city", "names", "en", NULL);

    if ( entry_data.has_data )
        {
            strlcpy(GeoIP->city, entry_data.utf8_string, entry_data.data_size+1);
        }

    /* Subdivision */

    MMDB_get_value(&result.entry, &entry_data, "subdivisions", "0", "iso_code", NULL);

    if ( entry_data.has_data )
        {
            strlcpy(GeoIP->subdivision, entry_data.utf8_string, entry_data.data_size+1);
        }

    /* Postal */

    MMDB_get_value(&result.entry, &entry_data, "postal", "code", NULL);

    if ( entry_data.has_data )
        {
            strlcpy(GeoIP->postal, entry_data.utf8_string, entry_data.data_size+1);
        }

    /* Timezone */

    MMDB_get_value(&result.entry, &entry_data, "location", "time_zone", NULL);

    if ( entry_data.has_data )
        {
            strlcpy(GeoIP->timezone, entry_data.utf8_string, entry_data.data_size+1);
        }

    /* Latitude */

    MMDB_get_value(&result.entry, &entry_data, "location", "latitude", NULL);

    if ( entry_data.has_data )
        {
            snprintf(GeoIP->latitude, sizeof(GeoIP->latitude), "%f", entry_data.double_value);
            GeoIP->latitude[ sizeof(GeoIP->latitude) - 1 ] = '\0';
        }

    /* Longitude */

    MMDB_get_value(&result.entry, &entry_data, "location", "longitude", NULL);

    if ( entry_data.has_data )
        {
            snprintf(GeoIP->longitude, sizeof(GeoIP->longitude), "%f", entry_data.double_value);
            GeoIP->longitude[ sizeof(GeoIP->longitude) - 1 ] = '\0';
        }

}

#endif
