#include "dispatch.h"
#include "hashset.h"
#include <pcap.h>
#include <pthread.h>
#include "analysis.h"
#include <stdlib.h>
#include <stdbool.h>
#include "packetqueue.h"
#define NUMTHREADS 10
pthread_mutex_t queueMutex=PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t queueCondition=PTHREAD_COND_INITIALIZER;
pthread_t tid[NUMTHREADS];
struct packetQueue *work_queue;
int threadTerminate;
/*The dispatch.c file mainly deals with the implementation of the ThreadPool model to 
  parallelize the system*/

void *handleWorkerThreads(void *arg){
  while(!threadTerminate){
    //when there is still work which is left to be done
      pthread_mutex_lock(&queueMutex);
      while(isempty(work_queue)){
        if(threadTerminate){
          break;
        }
        pthread_cond_wait(&queueCondition,&queueMutex);//Condition variables are used to prevent wastage of CPU cycles and energy
      }
      struct packetContent *packetData=dequeue(work_queue);
      pthread_mutex_unlock(&queueMutex);
      //this ensures that the packet dequeued from the queue is not a null packet
      if(packetData!=NULL){
        int verbose=1;
        analyse(packetData->header,packetData->packet,verbose);
        free(packetData);
      }
  }
  return NULL;
}
/*Method which creates the worker threads */
void createWorkerThreads(){
  for(int i=0;i<NUMTHREADS;i++){
    pthread_create(&tid[i],NULL,handleWorkerThreads,NULL);
  }
}

/*Method which joins the worker threads. The pthread_join function waits for a thread to end. 
  If successful, it returns 0, else -1*/
void joinThreads(){
  for(int i=0;i<NUMTHREADS;i++){
    pthread_join(tid[i],NULL);
  }
}

void dispatch(const struct pcap_pkthdr *header,
              const unsigned char *packet,
              int verbose) {
      pthread_mutex_lock(&queueMutex);
      enqueue(work_queue,packet,header);//the incoming packets are enqueued into the work queue
      pthread_cond_broadcast(&queueCondition);
      pthread_mutex_unlock(&queueMutex);
}
