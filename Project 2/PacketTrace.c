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

/* The number of bits in a byte, a true constant */
#define BITS_IN_BYTE 8
/* The maximum number of bytes in a single packet */
#define BYTES_CACHED 66
/* The number of bytes in metadata */
#define META_LENGTH 12
/* */
#define US_DIGIT_MAX 1000000

/* Index of the first and last byte in the seconds timestamp */
#define TIME_S_START 0
#define TIME_S_END 3

/* Index of the first and last byte in the microseconds timestamp */
#define TIME_US_START 4
#define TIME_US_END 7

/* Index of the first and last byte in caplen */
#define CAPLEN_START 8
#define CAPLEN_END 9

/* Index of the first and last byte in the ignored segment */
#define IGNORED_START 10
#define IGNORED_END 11

/* Index of the first and last byte in the Ethernet header */
#define ETH_HEAD_START 12
#define ETH_HEAD_END 25

/* Index of the first and last byte in the fixed IP header */
#define IP_HEAD_START 26
#define IP_HEAD_END 45


typedef struct {
    struct {
        /* number of seconds since Unix epoch */
        uint32_t timestamp_s;
        /* number of microseconds following timestamp_s */
        uint32_t timestamp_us;
        /* capture length, the number of bytes captured */
        uint16_t caplen;
    } metadata;

} Packet;

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
uint16_t convert_2bytes_int(unsigned char *bytes, int index);
uint32_t convert_4bytes_int(unsigned char *bytes, int index);

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
    // do nothing if the user asks for nothing
    else if (0 == option_cnt) {
        exit(EXIT_SUCCESS);
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
    /* reusable counting variable */
    int i;
    /* total number of packets contained in the FILE */
    unsigned long packet_cnt;
    /* the last packet in the file */
    Packet pkt_first;
    /* the last packet in the file */
    Packet pkt_last;
    pkt_last.metadata.caplen = BYTES_CACHED;
    /* stores some of the most recent bytes read */
    unsigned char bytes[BYTES_CACHED] = {0};

    // Store the timestamp for the first packet
    for (i = 0; !feof(trace_fileptr) && i <= TIME_US_END; i++) {
        unsigned char byte = fgetc(trace_fileptr);
        if (feof(trace_fileptr)) {
            break;
        }
        bytes[i] = byte;
        if (TIME_S_END == i) {
            pkt_first.metadata.timestamp_s = convert_4bytes_int(bytes, i);
        }
        else if (TIME_US_END == i) {
            pkt_first.metadata.timestamp_us = convert_4bytes_int(bytes, i);
        }
    }
    while (!feof(trace_fileptr)) {
        unsigned char byte = fgetc(trace_fileptr);
        if (feof(trace_fileptr)) {
            break;
        }
        bytes[i] = byte;
        if (CAPLEN_END == i) {
            pkt_last.metadata.caplen = convert_2bytes_int(bytes, i);
        }
        if (i >= pkt_last.metadata.caplen + META_LENGTH - 1) {
            packet_cnt++;
            i = 0;
        } else {
            i++;
        }
    }
    pkt_last.metadata.timestamp_s = convert_4bytes_int(bytes, TIME_S_END);
    pkt_last.metadata.timestamp_us = convert_4bytes_int(bytes, TIME_US_END);

    printf("PACKETS: %lu\n", (unsigned long)packet_cnt);
    printf("FIRST: %lu.%06lu\n", (unsigned long)pkt_first.metadata.timestamp_s,
                                 (unsigned long)pkt_first.metadata.timestamp_us);
    printf("LAST: %lu.%06lu\n", (unsigned long)pkt_last.metadata.timestamp_s,
                                (unsigned long)pkt_last.metadata.timestamp_us);
    uint32_t duration_s = pkt_last.metadata.timestamp_s -
                          pkt_first.metadata.timestamp_s;
    uint32_t duration_us;
    if (pkt_first.metadata.timestamp_us > pkt_last.metadata.timestamp_us) {
        duration_us = US_DIGIT_MAX - (pkt_first.metadata.timestamp_us -
                                      pkt_last.metadata.timestamp_us);
    } else {
        duration_us = pkt_last.metadata.timestamp_us -
                      pkt_first.metadata.timestamp_us;
    }
    printf("DURATION: %lu.%06lu\n", (unsigned long)duration_s,
                                    (unsigned long)duration_us);
}

/**
 * Converts four bytes into a 32-bit integer
 */
uint32_t convert_4bytes_int(unsigned char *bytes, int index) {
    return bytes[index] | bytes[index - 1] << BITS_IN_BYTE
                    | bytes[index - 2] << (BITS_IN_BYTE * 2)
                    | bytes[index - 3] << (BITS_IN_BYTE * 3);
}

/**
 * Converts two bytes into a 16-bit integer
 */
uint16_t convert_2bytes_int(unsigned char *bytes, int index) {
    return bytes[index] | bytes[index - 1] << BITS_IN_BYTE;

}
