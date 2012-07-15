#ifndef _ZIZZANIA_DEBUG_H
#define _ZIZZANIA_DEBUG_H

#ifdef DEBUG

#include <stdio.h>

#define DEBUG_PREFIX ">>> "

#define PRINT( string )                                             \
    do fprintf( stderr , DEBUG_PREFIX "%s\n" , string ); while ( 0 )

#define PRINTF( format , ... )                                          \
    do fprintf( stderr , DEBUG_PREFIX format "\n" , ##__VA_ARGS__ ); while ( 0 )

#else

#define PRINT( string ) do ; while ( 0 )
#define PRINTF( format , ... ) do ; while ( 0 )

#endif

#endif
