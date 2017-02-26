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

static struct {
    /* specifies printing a trace summary */
    int s;
    /* specifies printing ethernet headers */
    int e;
    /* specifies printing ip headers */
    int i;
    /* specifies printing a count of packet types */
    int t;
    /* specifies printing a traffic matrix */
    int m;
} options;

void write_output(FILE *trace_fileptr);

int main(int argc, char **argv) {
    
    /* reusable counting variable */
    int i;
    /* iterator for command line args */
    int option;
    /* count of the optional flags provided */
    int option_cnt;

    /* filename for the binary packet trace file */
    char *trace_filename = NULL;
    /* pointer to the file opened by trace_filename */
    FILE *trace_fileptr = NULL;

    /* external variable set to zero to override getopt error handling */
    opterr = 0;

    // Parse arguments
    while (-1 != (option = getopt(argc, argv, "r:seitm")))
    switch (option) {
        case 's':
            options.s = 1;
            option_cnt++;
            break;
        case 'e':
            options.e = 1;
            option_cnt++;
            break;
        case 'i':
            options.i = 1;
            option_cnt++;
            break;
        case 't':
            options.t = 1;
            option_cnt++;
            break;
        case 'm':
            options.m = 1;
            option_cnt++;
            break;
        case 'r':
            trace_filename = optarg;
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
        exit(EXIT_FAILURE); // Can be removed if we want to ignore unknown args
    }

    // Enforce mutual exclusion of options
    if (1 < option_cnt) {
        fprintf(stderr, "Specified multiple mutually exclusive options.\n");
        exit(EXIT_FAILURE);
    }

    // Check whether an input filename was given
    if (trace_filename == NULL) {
        printf("Use of -r <filename> is required.\n");
        exit(EXIT_FAILURE);
    } else {
        // Attempt to open the specified file
        trace_fileptr = fopen(trace_filename, "rb");
        if (trace_fileptr == NULL) {
            perror("Error");
            exit(EXIT_FAILURE);
        }
    }

    write_output(trace_fileptr);
    exit(EXIT_SUCCESS);
}

void write_output(FILE *trace_fileptr) {
    printf("s option: %d\n", options.s);
}

