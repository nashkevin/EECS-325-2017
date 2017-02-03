// 
// Kevin Nash (kjn33)
// IPprint.c
// 2017-01-19
// Prints data about IP addresses and their associated organizations
// 

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define EXIT_SUCCESS 0
#define EXIT_FAILURE 1

void writeOutput(FILE *fileptr, int iFlag, int oFlag, int pFlag);

int main(int argc, char **argv) {
    /* specifies printing of IP addresses */
    int iFlag = 0;
    /* specifies printing of organization names */
    int oFlag = 0;
    /* specifies printing of IP prefixes */
    int pFlag = 0;
    /* filename for binary list of IP addresses */
    unsigned char *ipFilename = NULL;
    /* reusable index variable */
    int i;
    /* iterator for command line args */
    int option;
    /* pointer to the file opened by ipFilename */
    FILE *fileptr;

    /* external variable set to zero to override getopt error handling */
    opterr = 0;

    // Parse arguments
    while ((option = getopt(argc, argv, "iopL:")) != -1)
    switch (option) {
        case 'i':
            iFlag = 1;
            break;
        case 'o':
            oFlag = 1;
            break;
        case 'p':
            pFlag = 1;
            break;
        case 'L':
            ipFilename = optarg;
            break;
        case '?':
            if (optopt == 'L') {
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
        exit(EXIT_FAILURE); // Can be removed if we don't want to be fail-fast
    }

    // Check whether an input filename was given
    if (ipFilename == NULL) {
        printf("Use of -L <filename> is required.\n");
        exit(EXIT_FAILURE);
    } else {
        // Attempt to open the specified file
        fileptr = fopen(ipFilename, "rb");
        if (fileptr == NULL) {
            perror("Error");
            exit(EXIT_FAILURE);
        }
    }

    writeOutput(fileptr, iFlag, oFlag, pFlag);
    exit(EXIT_SUCCESS);
}

void writeOutput(FILE *fileptr, int iFlag, int oFlag, int pFlag) {
    /* reusable index variable */
    int i;
    /* iterator for bytes in the stream */
    int byte;

    i = 1;
    do {
        byte = fgetc(fileptr);
        if (feof(fileptr)) {
            break;
        }
        printf("%d", byte);
        if (i++ % 4 == 0) {
            printf("\n");
        } else {
            printf(".");
        }
    } while(1);
}
