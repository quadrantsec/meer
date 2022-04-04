/*
** Copyright (C) 2018-2022 Quadrant Information Security <quadrantsec.com>
** Copyright (C) 2018-2022 Champ Clark III <cclark@quadrantsec.com>
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

#include <stdio.h>

#include "meer-def.h"
#include "version.h"

void Usage( void )
{

    printf("\n");
    printf("@@@@@@@@@@  @@@@@@@@ @@@@@@@@ @@@@@@@    Meer version %s\n", VERSION);
    printf("@@! @@! @@! @@!      @@!      @@!  @@@   Quadrant Information Security\n");
    printf("@!! !!@ @!@ @!!!:!   @!!!:!   @!@!!@a    https://quadrantsec.com\n");
    printf("!!:     !!: !!:      !!:      !!: :!a    Copyright (C) 2018-2022\n");
    printf(":      :   : :: ::  : :: ::   :   : :\n\n");

    printf("-D, --dameon\t\tPut Meer in the background.\n");
    printf("-c, --config\t\tMeer Configuration File [default: %s]\n", DEFAULT_CONFIG);
    printf("-h, --help\t\tMeer help screen.\n");
    printf("-q, --quiet\t\tTell Meer to be quiet.\n");
    printf("\nMeer was compile on %s at %s.\n", __DATE__, __TIME__);


}
