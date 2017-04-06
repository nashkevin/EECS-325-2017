// 
// Kevin Nash (kjn33)
// PacketTrace.c
// 2017-04-06
// [description goes here]
//

#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define EXIT_SUCCESS 0
#define EXIT_FAILURE 1

static struct {
    /* specifies printing a packet dump */
    uint8_t p;
    /* specifies printing connection summaries */
    uint8_t s;
    /* specifies printing RTTs */
    uint8_t t;
} options;

void print_dump(FILE *trace_fileptr);
void print_summary(FILE *trace_fileptr);
void print_rtt(FILE *trace_fileptr);

int main(int argc, char **argv) {
    /* reusable counting variable */
    int i = 0;
    /* iterator for command line args */
    int option = 0;
    /* count of the optional flags provided */
    int option_cnt = 0;

    /* filename for the binary packet trace file */
    char *trace_filename = NULL;
    /* pointer to the file opened by trace_filename */
    FILE *trace_fileptr = NULL;

    /* external variable set to zero to override getopt error handling */
    opterr = 0;

    // Parse arguments
    while (-1 != (option = getopt(argc, argv, "r:pst")))
    switch (option) {
        case 'p':
            options.p = 1;
            option_cnt++;
            break;
        case 's':
            options.s = 1;
            option_cnt++;
            break;
        case 't':
            options.t = 1;
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
        fprintf(stderr, "Use of -r <filename> is required.\n");
        exit(EXIT_FAILURE);
    } else {
        // Attempt to open the specified file
        trace_fileptr = fopen(trace_filename, "rb");
        if (trace_fileptr == NULL) {
            perror("Error");
            exit(EXIT_FAILURE);
        }
    }

    // Begin specified task
    if (options.p) {
        print_dump(trace_fileptr);
    }
    else if (options.s) {
        print_summary(trace_fileptr);
    }
    else if (options.t) {
        print_rtt(trace_fileptr);
    }
    exit(EXIT_SUCCESS);
}

void print_dump(FILE *trace_fileptr) {
    ;
}

void print_summary(FILE *trace_fileptr) {
    ;
}

void print_rtt(FILE *trace_fileptr) {
    ;
}

