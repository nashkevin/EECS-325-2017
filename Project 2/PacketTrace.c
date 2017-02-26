// 
// Kevin Nash (kjn33)
// PacketTrace.c
// 2017-02-26
// [description goes here]
// 

#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>


struct metadata {
    /* number of seconds since Unix epoch */
    uint32_t timestamp;
    /* number of microseconds since timestamp */
    uint32_t timespan;
    /* capture length, the number of bytes captured */
    uint16_t caplen;
};

int main(int argc, char **argv) {
    
    /* reusable counting variable */
    int i;
    /* iterator for command line args */
    int option;

    /* specifies printing a trace summary */
    int flag_s = 0;
    /* specifies printing ethernet headers */
    int flag_e = 0;
    /* specifies printing ip headers */
    int flag_i = 0;
    /* specifies printing a count of packet types */
    int flag_t = 0;
    /* specifies printing a traffic matrix */
    int flag_m = 0;

    /* filename for the binary packet trace file */
    char *traceFilename = NULL;
    /* pointer to the file opened by traceFilename */
    FILE *traceFilePtr = NULL;

    /* external variable set to zero to override getopt error handling */
    opterr = 0;

    // Parse arguments
    while ((option = getopt(argc, argv, "r:seit")) != -1)
    switch (option) {
        case 's':
            flag_s = 1;
            break;
        case 'e':
            flag_e = 1;
            break;
        case 'i':
            flag_i = 1;
            break;
        case 't':
            flag_t = 1;
            break;
        case 'm':
            flag_m = 1;
            break;
        case 'r':
            traceFilename = optarg;
            break;
        case '?':
            if (optopt == 'r') {
                fprintf (stderr, "Option -%c requires an argument.\n", optopt);
            }
            else if (isprint (optopt)) {
                fprintf(stderr, "Unknown option `-%c'.\n", optopt);
            }
            else {
                fprintf(stderr, "Unknown option character `\\x%x'.\n", optopt);
            }
        default:
            exit(EXIT_FAILURE);
    }

    // Tell the user they typed something wrong
    for (i = optind; i < argc; i++) {
        fprintf(stderr, "Invalid argument: %s\n", argv[optind]);
        exit(EXIT_FAILURE); // Can be removed if we don't want to fail-fast
    }

    // Check whether an input filename was given
    if (traceFilename == NULL) {
        printf("Use of -r <filename> is required.\n");
        exit(EXIT_FAILURE);
    } else {
        // Attempt to open the specified file
        traceFilePtr = fopen(traceFilename, "rb");
        if (traceFilePtr == NULL) {
            perror("Error");
            exit(EXIT_FAILURE);
        }
    }

    if (flag_s) {};
    if (flag_e) {};
    if (flag_i) {};
    if (flag_t) {};
    if (flag_m) {};
    
    exit(EXIT_SUCCESS);
}

