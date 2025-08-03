#ifndef CS241_SNIFF_H
#define CS241_SNIFF_H

#include "hashset.h"

extern dynamicArray sourceIPAddressSet; //creating the set data structure to store the unique IP addresses
extern int SYNCount;
extern int ARPCount;
extern int googleURLCount;
extern int bbcURLCount;
extern int totalURLCount;

void sniff(char *interface, int verbose);
void dump(const unsigned char *data, int length);

#endif
