#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include "zizzania.h"

#define DUMP_ERROR_AND_DIE( z )                         \
    {                                                   \
        fprintf( stderr , "# %s\n" , z.error_buffer );  \
        return EXIT_FAILURE;                            \
    }

static void print_usage()
{
    fprintf( stderr , "Usage:\n" );
    fprintf( stderr , "\n" );
    fprintf( stderr , "    zizzania -i <device> | -r <file>\n" );
    fprintf( stderr , "             -b <bssid_1> -b <bssid_2> ... | -a\n" );
    fprintf( stderr , "             [-n] [-w <file>]\n" );
    fprintf( stderr , "\n" );
    fprintf( stderr , "    -i <device> : use <device> for both capture and injection\n" );
    fprintf( stderr , "    -r <file>   : read packets from <file>\n" );
    fprintf( stderr , "    -b <bssid>  : handshakes of <bssid> clients only\n" );
    fprintf( stderr , "    -a          : auto discover BSSIDs\n" );
    fprintf( stderr , "    -n          : passively look for handshakes\n" );
    fprintf( stderr , "    -w          : dump captured packets to <file> stripping management frames\n" );
    fprintf( stderr , "\n" );
}

static int parse_options( struct zizzania *z , int argc , char *argv[] )
{
    int opt;
    int n_target = 0 , n_input = 0 , n_output = 0;

    opterr = 0;
    while ( opt = getopt( argc , argv , ":ab:i:r:w:n" ) , opt != -1 )
    {
        switch ( opt )
        {
        case 'a':
            z->setup.auto_add_targets = 1;
            break;

        case 'b':
            {
                uint8_t bssid[6];

                /* parse bssid address */
                if ( !ieee80211_addr_sscan( bssid , optarg ) )
                {
                    zizzania_set_error_messagef( z , "Invalid MAC address '%s'" , optarg );
                    return 0;
                }

                /* use this address as target */
                zizzania_add_target( z , bssid );
                n_target++;
            }
            break;

        case 'i':
        case 'r':
            strncpy( z->setup.input , optarg , ZIZZANIA_MAX_PATH );
            z->setup.live = ( opt == 'i' );
            n_input++;
            break;

        case 'w':
            strncpy( z->setup.output , optarg , ZIZZANIA_MAX_PATH );
            n_output++;
            break;

        case 'n':
            z->setup.passive = 1;
            break;

        case ':':
            zizzania_set_error_messagef( z , "Missing argument for option '%c'" , optopt );
            return 0;

        default:
            zizzania_set_error_messagef( z , "Unknown option '%c'" , optopt );
            return 0;
        }
    }

    /* coherence checks */

    /* warn about no input */
    if ( n_input == 0 )
    {
        zizzania_set_error_messagef( z , "No input specified, use either -r or -i" );
        return 0;
    }

    /* warn about multiple input specified */
    if ( n_input > 1 )
    {
        zizzania_set_error_messagef( z , "Multiple input specified" );
        return 0;
    }

    /* warn about multiple output specified */
    if ( n_output > 1 )
    {
        zizzania_set_error_messagef( z , "Multiple output specified" );
        return 0;
    }

    /* warn about unparset options */
    if ( optind != argc )
    {
        zizzania_set_error_messagef( z , "Unparsed option '%s'" , argv[ optind ] );
        return 0;
    }

    /* warn about nothing to do */
    if ( !z->setup.auto_add_targets && n_target == 0 )
    {
        zizzania_set_error_messagef( z , "Specify at least one target BSSID (-b) or force auto mode (-a)" );
        return 0;
    }

    /* warn about useless options */
    if ( z->setup.auto_add_targets && n_target > 0 )
    {
        zizzania_set_error_messagef( z , "Option -a includes every combination of -b" );
        return 0;
    }

    /* warn about passive mode while offline */
    if ( z->setup.passive && !z->setup.live )
    {
        zizzania_set_error_messagef( z , "Offline sessions are always passive there's no need of -n" );
        return 0;
    }

    return 1;
}

static void on_new_client( const ieee80211_addr_t bssid , const ieee80211_addr_t client )
{
    char bssid_str[18] , client_str[18];

    ieee80211_addr_sprint( bssid , bssid_str );
    ieee80211_addr_sprint( client , client_str );

    printf( "N %s @ %s\n" , client_str , bssid_str );
}

static void on_handshake( const ieee80211_addr_t bssid , const ieee80211_addr_t client )
{
    char bssid_str[18] , client_str[18];

    ieee80211_addr_sprint( bssid , bssid_str );
    ieee80211_addr_sprint( client , client_str );

    printf( "H %s @ %s <<<\n" , client_str , bssid_str );
}

int main( int argc , char *argv[] )
{
    struct zizzania z;

    if ( !zizzania_initialize( &z ) ) DUMP_ERROR_AND_DIE( z );

    if ( !parse_options( &z , argc , argv ) )
    {
        print_usage();
        DUMP_ERROR_AND_DIE( z );
    }

    z.setup.on_new_client = on_new_client;
    z.setup.on_handshake = on_handshake;

    if ( !zizzania_start( &z ) ) DUMP_ERROR_AND_DIE( z );

    zizzania_finalize( &z );
    return EXIT_SUCCESS;
}
