// 
// Kevin Nash (kjn33)
// IPprint.c
// 2017-01-19
// Prints data about IP addresses and their associated organizations
// 

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define EXIT_SUCCESS 0
#define EXIT_FAILURE 1

#define BYTES_PER_IP 4
#define CHARS_PER_IP 16
#define MAX_CHARS_IN 512


void write_output(FILE *ipFilePtr, FILE *orgFilePtr, int iFlag, int oFlag, int pFlag);
void lookup_and_print_org(FILE *orgFilePtr, int *ipAddress);

int main(int argc, char **argv) {
    /* specifies printing of IP addresses */
    int iFlag = 0;
    /* specifies printing of organization names */
    int oFlag = 0;
    /* specifies printing of IP prefixes */
    int pFlag = 0;
    /* filename for binary list of IP addresses */
    char *ipFilename = NULL;
    /* filename for text list of prefix, org pairs */
    char *orgFilename = NULL;
    /* reusable counting variable */
    int i;
    /* iterator for command line args */
    int option;
    /* pointer to the file opened by ipFilename */
    FILE *ipFilePtr = NULL;
    /* pointer to the file opened by orgFilename */
    FILE *orgFilePtr = NULL;

    /* external variable set to zero to override getopt error handling */
    opterr = 0;

    // Parse arguments
    while ((option = getopt(argc, argv, "io:pL:")) != -1)
    switch (option) {
        case 'i':
            iFlag = 1;
            break;
        case 'o':
            oFlag = 1;
            orgFilename = optarg;
            break;
        case 'p':
            pFlag = 1;
            break;
        case 'L':
            ipFilename = optarg;
            break;
        case '?':
            if (optopt == 'L' || optopt == 'o') {
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
    if (ipFilename == NULL) {
        printf("Use of -L <filename> is required.\n");
        exit(EXIT_FAILURE);
    } else {
        // Attempt to open the specified file
        ipFilePtr = fopen(ipFilename, "rb");
        if (ipFilePtr == NULL) {
            perror("Error");
            exit(EXIT_FAILURE);
        }
    }

    if (oFlag) {
        // Attempt to open the specified file
        orgFilePtr = fopen(orgFilename, "r");
        if (orgFilePtr == NULL) {
            perror("Error");
            exit(EXIT_FAILURE);
        }
    }

    // We have our orders. Let's get printing.
    write_output(ipFilePtr, orgFilePtr, iFlag, oFlag, pFlag);
    exit(EXIT_SUCCESS);
}

void write_output(FILE *ipFilePtr, FILE *orgFilePtr, int iFlag, int oFlag, int pFlag) {
    /* reusable counting variable */
    int i;
    /* the count of all streamed bytes */
    int numBytesRead;
    /* iterator for bytes in the stream */
    int byte;
    /* the most recent IP streamed, used for -p and -o */
    int mostRecentIP[BYTES_PER_IP];

    numBytesRead = 0;
    do {
        // Read the next byte
        byte = fgetc(ipFilePtr);
        // Terminate loop upon reaching the end of the file
        if (feof(ipFilePtr)) {
            break;
        }
        // Store the current byte in mostRecentIP
        mostRecentIP[numBytesRead % BYTES_PER_IP] = byte;
        if (iFlag) {
            printf("%d", byte);
        }
        // If enough bytes have been read to complete another address
        if (++numBytesRead % BYTES_PER_IP == 0) {
            if (iFlag && (pFlag || oFlag)) {
                printf(" ");
            }
            if (pFlag) {
                for (i = 0; i < sizeof(mostRecentIP) / sizeof(mostRecentIP[0]) - 2; i++) {
                    printf("%d.", mostRecentIP[i]);
                }
                // print the last byte without the dot
                printf("%d", mostRecentIP[i]);
                if (oFlag) {
                    printf(" ");
                }
            }
            if (oFlag) {
                lookup_and_print_org(orgFilePtr, mostRecentIP);
            }
            if ((iFlag || pFlag) && !oFlag) {
                printf("\n");
            }
        }
        // We're not at the end of an address yet. Print another dot.
        else if (iFlag) {
            printf(".");
        }
    } while(1);
}

void lookup_and_print_org(FILE *orgFilePtr, int *ipAddress) {
    /* reusable counting variable */
    int i = 0;
    /* string to hold the current line */
    char line[MAX_CHARS_IN];
    /* whether or not a prefix has a corresponding organization */
    int foundMatch = 0;
    /* string to hold just the prefix */
    char *prefixString = malloc(sizeof(char) * CHARS_PER_IP);
    /* string to hold just the organization */
    char *orgString;

    // Convert the address from int array to string
    sprintf(prefixString, "%d.", ipAddress[0]);
    for (i = 1; i < sizeof(ipAddress) / sizeof(ipAddress[0]) - 2; i++) {
        sprintf(prefixString + strlen(prefixString), "%d.", ipAddress[i]);
    }
    sprintf(prefixString + strlen(prefixString), "%d", ipAddress[i]);

    // Read line by line until the prefix is found or no lines remain
    while (!foundMatch && fgets(line, MAX_CHARS_IN, orgFilePtr) != NULL) {
        // If a match is found, print only the organization
        if ((strstr(line, prefixString)) != NULL) {
            foundMatch = 1;
            orgString = strtok (line, " ");
            orgString = strtok(NULL, "\0");
            while (orgString != NULL) {
                printf("%s", orgString);
                orgString = strtok(NULL, "\0");
            }
        }
    }
    // If no match is found, print "?"
    if (!foundMatch) {
        printf("?");
    }
}
