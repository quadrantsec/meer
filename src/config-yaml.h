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

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

/* Prototypes */

void Load_YAML_Config ( char *yaml_file );


#ifdef HAVE_LIBYAML

/************************/
/* Minimum YAML version */
/************************/

#define YAML_VERSION_MAJOR 1
#define YAML_VERSION_MINOR 1

/*****************/
/* Primary types */
/*****************/

#define         YAML_TYPE_MEER           1
#define         YAML_TYPE_OUTPUT	 2
#define		YAML_TYPE_INPUT		 3

/*******************/
/* Secondary types */
/*******************/

#define         YAML_MEER_CORE_CORE     1
#define		YAML_MEER_PIPE		2
#define		YAML_MEER_EXTERNAL	3
#define 	YAML_MEER_REDIS		4
#define		YAML_MEER_BLUEDOT	5
#define		YAML_MEER_ELASTICSEARCH	6
#define		YAML_MEER_FILE		7

/***************/
/* Input types */
/***************/

#define		YAML_INPUT_FILE		1
#define		YAML_INPUT_PIPE		2
#define		YAML_INPUT_REDIS 	3
#define		YAML_INPUT_COMMAND_LINE 4


#endif
