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

#include <stdio.h>
#include <pwd.h>
#include <grp.h>
#include <errno.h>
#include <stdlib.h>
#include <time.h>
#include <stdarg.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/stat.h>
#include <ctype.h>

#include "meer.h"
#include "meer-def.h"
#include "lockfile.h"
#include "stats.h"
#include "util.h"

extern struct _MeerConfig *MeerConfig;
extern struct _MeerCounters *MeerCounters;

void Drop_Priv(void)
{

    struct passwd *pw = NULL;

    pw = getpwnam(MeerConfig->runas);

    if (!pw)
        {
            Meer_Log(ERROR, "Couldn't locate user '%s'. Aborting...\n", MeerConfig->runas);
        }

    if ( getuid() == 0 )
        {
            Meer_Log(NORMAL, "Dropping privileges! [UID: %lu GID: %lu]", (unsigned long)pw->pw_uid, (unsigned long)pw->pw_gid);

            if (initgroups(pw->pw_name, pw->pw_gid) != 0 ||
                    setgid(pw->pw_gid) != 0 || setuid(pw->pw_uid) != 0)
                {
                    Meer_Log(ERROR, "[%s, line %d] Could not drop privileges to uid: %lu gid: %lu - %s!", __FILE__, __LINE__, (unsigned long)pw->pw_uid, (unsigned long)pw->pw_gid, strerror(errno));
                }

        }
    else
        {
            Meer_Log(NORMAL,"Not dropping privileges.  Already running as a non-privileged user");
        }
}


void Meer_Log (int type, const char *format,... )
{

    char *buf = malloc( MeerConfig->payload_buffer_size );

    if ( buf == NULL )
        {
            fprintf(stderr, "[%s, line %d] Fatal Error:  Can't allocate memory for Meer_Log()! Abort!\n", __FILE__, __LINE__);
            exit(-1);
        }

    memset(buf, 0, MeerConfig->payload_buffer_size);

    va_list ap;

    va_start(ap, format);

    char *chr="*";
    char curtime[64];
    time_t t;
    struct tm *now;
    t = time(NULL);
    now=localtime(&t);
    strftime(curtime, sizeof(curtime), "%m/%d/%Y %H:%M:%S",  now);

    if ( type == ERROR )
        {
            chr="E";
        }

    if ( type == WARN )
        {
            chr="W";
        }

    if ( type == DEBUG )
        {
            chr="D";
        }

    vsnprintf(buf, MeerConfig->payload_buffer_size, format, ap);

    if ( MeerConfig->meer_log_on == true )
        {
            fprintf(MeerConfig->meer_log_fd, "[%s] [%s] - %s\n", chr, curtime, buf);
            fflush(MeerConfig->meer_log_fd);
        }

    if ( MeerConfig->daemonize == false && MeerConfig->quiet == false )
        {
            printf("[%s] [%s] %s\n", chr, curtime, buf);
        }

    if ( type == 1 )
        {
            exit(-11);
        }

    free(buf);

}

void Remove_Return(char *s)
{
    char *s1, *s2;
    for(s1 = s2 = s; *s1; *s1++ = *s2++ )
        {
            while( *s2 == '\n' )s2++;
            while( (int)*s2 == 13 )s2++;

        }
}

void Remove_Spaces(char *s)
{
    char *s1, *s2;
    for(s1 = s2 = s; *s1; *s1++ = *s2++ )
        while( *s2 == ' ')s2++;
}


bool IP2Bit(char *ipaddr, unsigned char *out)
{

    bool ret = false;
    struct addrinfo hints = {0};
    struct addrinfo *result = NULL;

    /* Use getaddrinfo so we can get ipv4 or 6 */

    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = AI_PASSIVE|AI_NUMERICHOST;

    if ( ipaddr == NULL || ipaddr[0] == '\0' )
        {
            return false;
        }

    ret = getaddrinfo(ipaddr, NULL, &hints, &result) == 0;

    /*
    if (!ret)
        {
            Meer_Log(S_WARN, "Warning: Got a getaddrinfo() error for \"%s\" but continuing...", ipaddr);
        }
    else
        {
    */
    switch (((struct sockaddr_storage *)result->ai_addr)->ss_family)
        {
        case AF_INET:

            ret = true;
            if (out != NULL)
                {
                    memcpy(out, &((struct sockaddr_in *)result->ai_addr)->sin_addr, sizeof(((struct sockaddr_in *)0)->sin_addr));
                }
            break;

        case AF_INET6:

            ret = true;
            if (out != NULL)
                {
                    memcpy(out, &((struct sockaddr_in6 *)result->ai_addr)->sin6_addr, sizeof(((struct sockaddr_in6 *)0)->sin6_addr));
                }
            break;

//                default:
//                    Meer_Log(S_WARN, "Warning: Got a getaddrinfo() received a non IPv4/IPv6 address for \"%s\" but continuing...", ipaddr);
        }

    if (result != NULL)
        {
            freeaddrinfo(result);
        }

    return ret;
}


bool Mask2Bit(int mask, unsigned char *out)
{
    int i;
    bool ret = false;

    if (mask < 1 || mask > 128)
        {
            return false;
        }

    ret = true;

    for (i=0; i<mask; i+=8)
        {
            out[i/8] = i+8 <= mask ? 0xff : ~((1 << (8 - mask%8)) - 1);
        }
    return ret;

}

char *Hexify(char *xdata, int length)
{

    char conv[] = "0123456789ABCDEF";
    char *retbuf = NULL;
    char *index;
    char *end;
    char *ridx;

    index = xdata;
    end = xdata + length;
    retbuf = (char *) calloc((length*2)+1, sizeof(char));
    ridx = retbuf;

    while(index < end)
        {
            *ridx++ = conv[((*index & 0xFF)>>4)];
            *ridx++ = conv[((*index & 0xFF)&0x0F)];
            index++;
        }

    return(retbuf);
}

uint64_t Current_Epoch( void )
{

    time_t t;
    struct tm *run;
    char utime_string[20] = { 0 };

    t = time(NULL);
    run=localtime(&t);
    strftime(utime_string, sizeof(utime_string), "%s",  run);
    uint64_t utime = atol(utime_string);

    return(utime);

}

bool Is_IP (char *ipaddr, int ver )
{

    struct sockaddr_in sa;
    bool ret = false;
    char ip[MAXIP];

    strlcpy(ip, ipaddr, sizeof(ip));

    /* We don't use getaddrinfo().  Here's why:
     * See https://blog.powerdns.com/2014/05/21/a-surprising-discovery-on-converting-ipv6-addresses-we-no-longer-prefer-getaddrinfo/
     */

    if ( ver == 4 )
        {
            ret = inet_pton(AF_INET, ip,  &(sa.sin_addr));
        }
    else
        {
            ret = inet_pton(AF_INET6, ip,  &(sa.sin_addr));
        }

    return(ret);

}

bool Validate_JSON_String( const char *validate_in_string )
{

    if ( validate_in_string[0] != '{' )
        {
            Meer_Log(WARN, "JSON \"%s\".  Doesn't appear to start as a valid JSON/EVE string. Skipping line.", validate_in_string);

            return 1;
        }

    if ( ( validate_in_string[ strlen(validate_in_string) - 1] != '}' ) && ( validate_in_string[ strlen(validate_in_string) - 2] != '}' ) )
        {
            Meer_Log(WARN, "JSON: \"%s\". JSON might be truncated.  Consider increasing 'payload-buffer-size' in Suricata or Sagan. Skipping line.", validate_in_string);

            return 1;
        }

    return 0;
}

/**************************************************
 * CalcPct - Calculate percent between to numbers
 *************************************************/

double CalcPct(uint64_t cnt, uint64_t total)
{

    double pct = 0.0;

    if ( total == 0 )
        {
            return(0);
        }

    pct = ( (double)cnt / (double)total ) * 100;

    return pct;
}

/**************************
 * Checks if a file exsists
 **************************/

int File_Check (char *filename)
{
    struct stat   buffer;
    return (stat (filename, &buffer) == 0);
}

bool Is_Inrange ( unsigned char *ip, unsigned char *tests, int count)
{
    int i,j,k;
    bool inrange = false;
    for (i=0; i<count*MAXIPBIT*2; i+=MAXIPBIT*2)
        {
            inrange = true;

            // We can stop if the mask is 0.  We only handle wellformed masks.

            for(j=0,k=16; j<16 && tests[i+k] != 0x00; j++,k++)
                {
                    if((tests[i+j] & tests[i+k]) != (ip[j] & tests[i+k]))
                        {
                            inrange = false;
                            break;
                        }
                }

            if (inrange)
                {
                    break;
                }
        }
    return inrange;
}

void To_UpperC(char *const s)
{
    char* cur = s;
    while (*cur)
        {
            *cur = toupper(*cur);
            ++cur;
        }
}

/***************************************************************************
 * MariaDB/MySQL really don't like ISO8601 timestamps :(  This converts
 * the timestamp to a usable SQL value
 ***************************************************************************/

void Convert_ISO8601_For_SQL( char *time, char *str, size_t size )
{

    struct tm tm_;
    char newtime[64] = { 0 };

    strptime(time,"%FT%T",&tm_);
    strftime(newtime,sizeof(newtime),"%F %T",&tm_);

    snprintf(str, size, "%s", newtime);
    str[ size - 1 ] = '\0';
}


/****************************************************************************/
/* is_notroutable                                                           */
/*                                                                          */
/* Checks to see if an ip address is routable or not                        */
/****************************************************************************/

bool Is_Notroutable ( unsigned char *ip )
{

    /* Start of subnet followd by mask */

    static unsigned char tests[][32] =
    {

        // IPv6 Multicast - ff00::/8
        {
            0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        },
        // IPv6 Link Local fe80::/10
        {
            0xFE, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xFF, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        },
        // IPv6 RFC4193 - fc00::/7
        {
            0xFC, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xFE, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        },
        // IPv6  LocalHost - ::1/128
        {
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
        },
        // IPv4 RFC1918 - 10.0.0.0/8
        {
            0x0A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        },
        // IPv4-mapped RFC1918 - ::ffff:10.0.0.0/104
        {
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0xFF, 0xFF, 0xA0, 0x00, 0x00, 0x00,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00
        },
        // IPv4 RFC1918 - 192.168.0.0/16
        {
            0xC0, 0xA8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        },
        // IPv4-mapped RFC1918 - ::ffff:192.168.0.0/112
        {
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0xFF, 0xFF, 0xC0, 0xA8, 0x00, 0x00,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00
        },

        // IPv4 localhost - 127.0.0.0/8
        {
            0x7F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        },
        // IPv4-mapped localhost - ::ffff:127.0.0.0/104
        {
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0xFF, 0xFF, 0x7F, 0x00, 0x00, 0x00,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00
        },
        // IPv4  Mulitcast - 224.0.0.0/4
        {
            0xE0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xF0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        },
        // IPv4-mapped  Mulitcast - ::ffff:224.0.0.0/100
        {
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0xFF, 0xFF, 0xE0, 0x00, 0x00, 0x00,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xF0, 0x00, 0x00, 0x00
        },
        // IPv4  Broadcast - 255.255.255.255/32
        {
            0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        },
        // IPv4-mapped  Broadcast - ::ffff:255.255.255.255/128
        {
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
        },
        // IPv4 RFC1918 - 172.16.0.0/12
        {
            0xAC, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xFF, 0xF0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        },
        // IPv4-mapped RFC1918 - ::ffff:172.16.0.0/108
        {
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0xFF, 0xFF, 0xAC, 0x10, 0x00, 0x00,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x6C, 0x00, 0x00
        },
        // IPv4 RFC1918 - 172.16.0.0/12
        {
            0xAC, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xFF, 0xF0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        },
        // IPv4-mapped RFC1918 - ::ffff:172.16.0.0/108
        {
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0xFF, 0xFF, 0xAC, 0x10, 0x00, 0x00,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x6C, 0x00, 0x00
        },
        // 169.254.0.0/16 - APIPA - Automatic Private IP Addressing
        {
            0xA9, 0xFE, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        }

    };

    return Is_Inrange(ip, (unsigned char *)tests, sizeof(tests)/(sizeof(char[32])));
}

