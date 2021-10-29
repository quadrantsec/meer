typedef struct _FingerprintData _FingerprintData;
struct _FingerprintData
{

    char os[32];
    char type[8];
    char source[32];
    int expire;

};

bool Is_Fingerprint( struct json_object *json_obj, struct _FingerprintData *FingerprintData );
void Get_Fingerprint( struct json_object *json_obj, const char *json_string, char *str, size_t size );
void Fingerprint_JSON_Redis( struct json_object *json_obj, struct _FingerprintData *FingerprintData, char *str, size_t size);
