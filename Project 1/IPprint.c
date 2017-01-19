// 
// Kevin Nash (kjn33)
// IPprint.c
// 2017-01-19
// Prints data about IP addresses and their associated organizations
// 

#include <stdio.h>
#include <string.h>

#define MIN_NUM_ARGS 1
#define MAX_NUM_ARGS 3


int main(int argc, char *argv[]) {
    if (argc < MIN_NUM_ARGS + 1) {
        printf("This program requires one or more arguments.\n");
        return -1;
    }
    else if(argc > MAX_NUM_ARGS) {
        printf("Too many arguments given.\n");
        return -1;
    }
    else {
        ;
    }
}
