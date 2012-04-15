#include <string.h>
#include <stdio.h>
#include "dissectors.h"

guint ieee80211_addr_hash( gconstpointer key )
{
    uint32_t a = *( guint * )key;
    uint32_t b = *( ( guint * )( ( ( uint8_t * )key ) + 2 ) );
    return a ^ b;
}

gboolean ieee80211_addr_equal( gconstpointer a , gconstpointer b )
{
    return memcmp( a , b , 6 ) == 0;
}

void ieee80211_addr_sprint( const ieee80211_addr_t addr , char buffer[18] )
{
    sprintf( buffer , "%02x:%02x:%02x:%02x:%02x:%02x" ,
             addr[0] , addr[1] , addr[2] , addr[3] , addr[4] , addr[5] );
}

int ieee80211_addr_sscan( ieee80211_addr_t addr , const char buffer[18] )
{
    int n;

    n = sscanf( buffer , "%2x%*[:-]%2x%*[:-]%2x%*[:-]%2x%*[:-]%2x%*[:-]%2x" ,
                ( unsigned int * )&addr[0] ,
                ( unsigned int * )&addr[1] ,
                ( unsigned int * )&addr[2] ,
                ( unsigned int * )&addr[3] ,
                ( unsigned int * )&addr[4] ,
                ( unsigned int * )&addr[5] );

    return n == 6;
}
