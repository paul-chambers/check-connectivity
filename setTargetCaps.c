//
// Created by paul on 11/28/23.
//
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#include <sys/capability.h>
#include <errno.h>
#include <string.h>


int main( int argc, char * argv[] )
{
    cap_value_t capsToSet[2] = { CAP_NET_RAW, CAP_NET_ADMIN };

    const char * myName = strrchr( argv[0], '/' );
    if ( myName++ == NULL ) {
        myName = argv[0];
    }

    if (argc != 2) {
        fprintf( stderr, "Usage: %s <path to file>\n", myName );
    } else if ( access( argv[1], X_OK ) != F_OK )
    {
        perror( "file is not executable" );
    } else {
        cap_t caps = cap_get_file( argv[1] );
        if ( caps == NULL ) {
            caps = cap_init();
        }
        if ( caps != NULL ) {
            //fprintf(stderr, "before: %s\n", cap_to_text( caps, NULL ) );

            if ( cap_set_flag( caps, CAP_EFFECTIVE, 2, capsToSet, CAP_SET ) != 0 ) {
                perror( "cap_set_flag 1" );
            } else if ( cap_set_flag( caps, CAP_PERMITTED, 2, capsToSet, CAP_SET ) != 0 ) {
                perror( "cap_set_flag 2" );
            } else if ( cap_set_file( argv[1], caps ) != 0 ) {
                if ( errno == EPERM ) {
                    fprintf(stderr,
                            "Error: %s needs to have the CAP_SETFCAP capability to work. To fix, please execute:\n"
                            "   sudo setcap CAP_SETFCAP+ep %s\n\n", myName, myName );
                } else perror( "cap_set_file" );
            }

            //fprintf(stderr, " after: %s\n", cap_to_text( caps, NULL ) );

            cap_free( caps );
        }
    }
}