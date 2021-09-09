

#define MEER_USER_AGENT "User-Agent: Meer"

#define MEER_AUTO_AUTH		0
#define	MEER_BASIC_AUTH		1
#define MEER_DIGEST_AUTH	2
#define MEER_NTLM_AUTH		3
#define MEER_NEGOTIATE_AUTH	4

size_t static write_callback_func(void *buffer, size_t size, size_t nmemb, void *userp);
void Elasticsearch_Init( void );
void Elasticsearch ( const char *json_string, const char *event_type );
void Elasticsearch_Get_Index ( char *str, size_t size, const char *event_type );
