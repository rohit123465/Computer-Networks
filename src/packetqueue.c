#include <stdio.h>
#include <stdlib.h>
#include "packetqueue.h"

struct packetQueue *create_queue(void){ //creates a queue and returns its pointer
  struct packetQueue *q=(struct packetQueue *)malloc(sizeof(struct packetQueue));
  q->head=NULL;
  q->tail=NULL;
  return(q);
}

void destroy_queue(struct packetQueue *q){  //destroys the queue and frees the memory
  while(!isempty(q)){
    dequeue(q);
  }
  free(q);
}

int isempty(struct packetQueue *q){ // checks if queue is empty
  return(q->head==NULL);
}

void enqueue(struct packetQueue *q, const unsigned char *packet, const struct pcap_pkthdr *header){ //enqueues a node with an item
  struct node *new_node=(struct node *)malloc(sizeof(struct node));
  new_node->data.packet=packet;
  new_node->data.header=header;
  new_node->next=NULL;
  if(isempty(q)){
    q->head=new_node;
    q->tail=new_node;
  }
  else{
    q->tail->next=new_node;
    q->tail=new_node;
  }
}

struct packetContent *dequeue(struct packetQueue *q){ //dequeues a the head node
  struct node *head_node;
  struct packetContent *content=NULL; //a pointer which points to the packet and the header
  if(isempty(q)){
    exit(EXIT_FAILURE);
  }
  else{
    head_node=q->head;
    q->head=q->head->next;
  
    if(q->head==NULL){
      q->tail=NULL;
    }
    content=(struct packetContent*)malloc(sizeof(struct packetContent));
    content->packet=head_node->data.packet;//when the packet is dequeued from the queue, the packet is retrieved
    content->header=head_node->data.header; //when the packet is dequeued from the queue, the header is retrieved
    
    
    free(head_node);
  }
  return content;
}

