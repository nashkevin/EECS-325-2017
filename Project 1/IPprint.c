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


int main (int argc, char **argv) {
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
    /* 
    unsigned char* buffer[4];

    /* external variable set to zero to override getopt error handling */
    opterr = 0;

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
        return 1;
        default:
        abort();
    }
    for (i = optind; i < argc; i++) {
        printf ("Non-option argument %s\n", argv[i]);
    }

    fileptr = fopen(ipFilename, "rb");

    if (fileptr == NULL) {
        perror("Error");
        exit(EXIT_FAILURE);
    }
    
    // fread(buffer, sizeof(buffer), 1, fileptr);

    int c;
    i = 1;
    do {
        c = fgetc(fileptr);
        if (feof(fileptr)) {
            break;
        }
        printf("%d", c);
        if (i++ % 4 == 0) {
            printf("\n");
        } else {
            printf(".");
        }
    } while(1);

    // char *p;
    // int intNumber = strtol(buffer[0], &p, 16);
    // printf("The received number is: %d.\n", intNumber);

    // for (i = 0; i < 1; i++) {
    //     printf("%x ", buffer[i]);
    // }

    return 0;
}
