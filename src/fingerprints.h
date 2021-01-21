
typedef struct _FingerprintData _FingerprintData;
struct _FingerprintData
{

    bool ret;
    char os[32];
    char type[8];
    char source[32];
    int expire;

};

//struct _FingerprintData *Parse_Fingerprint ( struct _DecodeAlert *DecodeAlert );
void Parse_Fingerprint ( struct _DecodeAlert *DecodeAlert, struct _FingerprintData *FingerprintData );

void Fingerprint_IP_JSON ( struct _DecodeAlert *DecodeAlert, char *str, size_t size );
void Fingerprint_EVENT_JSON ( struct _DecodeAlert *DecodeAlert, struct _FingerprintData *FingerprintData, char *str, size_t size );
void Fingerprint_DHCP_JSON ( struct _DecodeDHCP *DecodeDHCP, char *str, size_t size );



