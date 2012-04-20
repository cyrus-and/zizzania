#include <stdlib.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <string.h>
#include <endian.h>
#include <stdarg.h>
#include "debug.h"
#include "handshake.h"
#include "dispatcher.h"
#include "zizzania.h"

#define READ_TIMEOUT 500
#define BPF "wlan[0] == 0x08 || wlan[0] == 0x88" /* data, qos data */
#define MIN_SNAPLEN 128
#define MAX_SNAPLEN 65535

static void zizzania_drop_root()
{
    /* nothing to do for non-root users */
    if ( getuid() == 0 )
    {
        const char *sudo_user;
        uid_t uid;
        gid_t gid;

        /* if from sudo restore credential */
        if ( sudo_user = getenv( "SUDO_USER" ) , sudo_user )
        {
            PRINTF( "sudo detected, becoming %s" , sudo_user );
            uid = atoi( getenv( "SUDO_UID" ) );
            gid = atoi( getenv( "SUDO_GID" ) );

        }
        /* otherwise become nobody */
        else
        {
            struct passwd *nobody;

            PRINT( "becoming nobody" );
            nobody = getpwnam( "nobody" );
            uid = nobody->pw_uid;
            gid = nobody->pw_gid;
        }

        /* set permissions */
        setgroups( 0 , NULL );
        setgid( gid );
        setuid( uid );
    }
}

int zizzania_initialize( struct zizzania *z )
{
    memset( z , 0 , sizeof( struct zizzania ) );

    /* bssids hashtable */
    z->targets = g_hash_table_new_full( ieee80211_addr_hash ,
                                        ieee80211_addr_equal ,
                                        g_free ,
                                        ( GDestroyNotify )g_hash_table_destroy );
    /* kill list */
    z->kill_list = g_hash_table_new_full( ieee80211_addr_hash ,
                                          ieee80211_addr_equal ,
                                          g_free , g_free );

    /* create non-blocking communication pipe */
    if ( pipe( z->comm ) ||
         fcntl( z->comm[0] , F_SETFL , O_NONBLOCK ) ||
         fcntl( z->comm[1] , F_SETFL , O_NONBLOCK ) )
    {
        zizzania_set_error_messagef( z , "cannot create the non-blocking communication pipe" );
        return 0;
    }

    return 1;
}

int zizzania_set_error_messagef( struct zizzania *z , const char *format , ... )
{
    int chk;
    va_list ap;

    va_start( ap , format );
    chk = vsnprintf( z->error_buffer , ZIZZANIA_ERROR_BUFFER_SIZE + 1 , format , ap );
    va_end( ap );

    return chk != ZIZZANIA_ERROR_BUFFER_SIZE;
}

int zizzania_add_target( struct zizzania *z , const ieee80211_addr_t target )
{
    /* add a new bssid target */
    if ( !g_hash_table_lookup( z->targets , target ) )
    {
        GHashTable *clients;

        /* prepare target's hashtable */
        clients = g_hash_table_new_full( ieee80211_addr_hash ,
                                         ieee80211_addr_equal ,
                                         g_free , g_free );

        g_hash_table_insert( z->targets , g_memdup( target , 6 ) , clients );
        return 1;
    }

    return 0;
}

int zizzania_start( struct zizzania *z )
{
    struct sigaction sa;
    sigset_t set;
    struct bpf_program fp;
    const uint8_t *packet;
    struct pcap_pkthdr *packet_header;
    int dlt;
    uint8_t retval;
    int error = 0;

    /* get pcap handle live */
    if ( z->setup.live )
    {
        *z->error_buffer = '\0';
        z->handler = pcap_open_live( z->setup.input ,
                                     *( z->setup.output ) ? MAX_SNAPLEN : MIN_SNAPLEN ,
                                     1 , READ_TIMEOUT , z->error_buffer );

        /* warning */
        if ( *z->error_buffer ) PRINT( z->error_buffer );
    }
    /* from file */
    else
    {
        z->handler = pcap_open_offline( z->setup.input , z->error_buffer );
    }

    if ( !z->handler ) return 0;

    /* drop root privileges */
    zizzania_drop_root();

    /* check datalink type */
    dlt = pcap_datalink( z->handler );
    PRINTF( "datalink type %s" , pcap_datalink_val_to_name( dlt ) );

    if ( pcap_datalink( z->handler ) != DLT_IEEE802_11_RADIO )
    {
        zizzania_set_error_messagef( z , "wrong device type/mode %s; %s expected" ,
                                     pcap_datalink_val_to_name( dlt ) ,
                                     pcap_datalink_val_to_name( DLT_IEEE802_11_RADIO ) );
        return 0;
    }

    /* set capture filter */
    pcap_compile( z->handler , &fp , BPF , 1 , -1 );
    pcap_setfilter( z->handler , &fp );
    pcap_freecode( &fp );

    /* open dumper */
    if ( *( z->setup.output ) )
    {
        PRINTF( "dumping packets to %s" , z->setup.output );

        if ( z->dumper = pcap_dump_open( z->handler , z->setup.output ) , !z->dumper )
        {
            zizzania_set_error_messagef( z , pcap_geterr( z->handler ) );
            return 0;
        }
    }

    /* ignore signals */
    memset( &sa , 0 , sizeof( struct sigaction ) );
    sa.sa_handler = SIG_IGN;
    if ( sigaction( SIGINT , &sa , NULL ) ||
         sigaction( SIGTERM , &sa , NULL ) )
    {
        zizzania_set_error_messagef( z , "unable to set signal action" );
        return 0;
    }

    /* mask all signals (so everything is sent to the dispatcher, blocked on the
       sigtimedwait) */
    sigfillset( &set );
    if ( pthread_sigmask( SIG_SETMASK , &set , NULL ) )
    {
        zizzania_set_error_messagef( z , "unable to set signal mask" );
        return 0;
    }

    /* start dispatcher */
    if ( pthread_create( &z->dispatcher , NULL , zizzania_dispatcher , z ) )
    {
        zizzania_set_error_messagef( z , "unable to start dispatcher thread" );
        return 0;
    }

    /* packet loop */
    while ( !z->stop )
    {
        switch ( pcap_next_ex( z->handler , &packet_header , &packet ) )
        {
        case 0: /* timeout */
            break; /* recheck flag and eventually start over */

        case 1: /* no problem */
            error = !zizzania_process_packet( z , packet_header , packet );
            break;

        case -1: /* error */
            PRINT( pcap_geterr( z->handler ) );
            zizzania_set_error_messagef( z , pcap_geterr( z->handler ) );
            error = z->stop = 1;
            break;

        case -2: /* end of file */
            PRINT( "eof" );
            z->stop = 1;
            break;
        }
    }

    PRINT( "shuting down the dispatcher" );

    /* join dispatcher thread */
    if ( pthread_join( z->dispatcher , ( void * )&retval ) )
    {
        PRINT( "cannot join the dispatcher" );
        return 0;
    }

    return !error && retval;
}

void zizzania_finalize( struct zizzania *z )
{
    if ( z->dumper ) pcap_dump_close( z->dumper );
    pcap_close( z->handler );
    close( z->comm[0] );
    close( z->comm[1] );
    g_hash_table_destroy( z->targets );
    g_hash_table_destroy( z->kill_list );
}
