typedef struct _DnsCache _DnsCache;
struct _DnsCache
{
    char ipaddress[48];
    char reverse[256];
    uint64_t lookup_time;

};


void DNS_Lookup_Reverse( char *host, char *str, size_t size );
int DNS_Lookup_Forward( const char *host, char *str, size_t size );

