

bool Bluedot( struct _DecodeAlert *DecodeAlert );

typedef struct _Bluedot_Skip _Bluedot_Skip;
struct _Bluedot_Skip
{

    struct
    {
        unsigned char ipbits[MAXIPBIT];
        unsigned char maskbits[MAXIPBIT];
    } range;

};

