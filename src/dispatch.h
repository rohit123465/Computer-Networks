#ifndef CS241_DISPATCH_H
#define CS241_DISPATCH_H

#include <pcap.h>
#include "packetqueue.h"


extern struct packetQueue *work_queue;
extern int threadTerminate;
extern pthread_cond_t queueCondition;
void *handleWorkerThreads(void *arg);
void createWorkerThreads();
void joinThreads();
void dispatch(const struct pcap_pkthdr *header, 
              const unsigned char *packet,
              int verbose);




#endif
