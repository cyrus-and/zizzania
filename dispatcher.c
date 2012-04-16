#include <errno.h>
#include <string.h>
#include "debug.h"
#include "zizzania.h"
#include "killer.h"
#include "dispatcher.h"

#define DISPATCHER_TIMEOUT 10

void * zizzania_dispatcher( void *arg )
{
    struct zizzania *z = arg;
    sigset_t set;
    struct timespec timeout = { 0 };

    /* prepare timed wait */
    sigemptyset( &set );
    sigaddset( &set , SIGINT );
    sigaddset( &set , SIGTERM );
    timeout.tv_sec = DISPATCHER_TIMEOUT;

    /* wait for events */
    while ( 1 )
    {
        switch( errno = 0 , sigtimedwait( &set , NULL , &timeout ) )
        {
        case SIGINT:
        case SIGTERM:
            PRINT( "signal catched" );
            z->stop = 1;
            break;

        case -1:
            /* restart system call after a signal */
            if ( errno == EINTR ) continue;

            /* start the killer after a timeout */
            if ( errno == EAGAIN ) break;
        }

        /* break loop */
        if ( z->stop == 1 ) break;

        /* deauthenticate clients */
        if ( !zizzania_start_killer( z ) )
        {
            z->stop = 1;
            return ( void * )0;
        }
    }

    return ( void * )1;
}
