#ifndef CS241_PACKETQUEUE_H
#define CS241_PACKETQUEUE_H


struct packetContent{
        const unsigned char *packet;
        const struct pcap_pkthdr *header;
};


struct node { // data structure for each node
    struct packetContent data;
    struct node *next;
};

struct packetQueue{ // data structure for queue
  struct node  *head;
  struct node  *tail;
};

struct packetQueue *create_queue(void);

int isempty(struct packetQueue *q);

void enqueue(struct packetQueue *q, const unsigned char *packet, const struct pcap_pkthdr *header);

struct packetContent * dequeue(struct packetQueue *q);

void printqueue(struct packetQueue *q);

void destroy_queue(struct packetQueue *q);

#endif 