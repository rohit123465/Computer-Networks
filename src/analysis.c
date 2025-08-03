#include "analysis.h"
#include "hashset.h"
#include <stdbool.h>
#include <string.h>
#include <pcap.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include "sniff.h"
#include <pthread.h>
#define PORTNO 80 //To identify if it is the port is an HTTP port

void printURLViolations(struct ip *ip_header);
/*Initializing different mutex locks for detecting the malicious packets (multithreading)*/
pthread_mutex_t SYNPackets=PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t ARPCache=PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t googleMutex=PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t bbcMutex=PTHREAD_MUTEX_INITIALIZER;

void analyse(const struct pcap_pkthdr *header,
             const unsigned char *packet,
             int verbose) {
            /*To extract the different headers to detect the possibility of network attacks*/
    struct ether_header *eth_header=(struct ether_header*)packet;
    struct ip *ip_header=(struct ip*)(packet+ETH_HLEN);
    struct tcphdr *tcp_header=(struct tcphdr*)(packet+ETH_HLEN+(ip_header->ip_hl)*4);
    struct in_addr sourceIPAddress=(ip_header->ip_src);//this is to obtain each source IP addresses
        //to check for SYN flooding attack
        if((tcp_header->syn)==1 && (tcp_header->ack)==0){
            pthread_mutex_lock(&SYNPackets);
            add(&sourceIPAddressSet,sourceIPAddress);
            SYNCount++;
            pthread_mutex_unlock(&SYNPackets);
            
        }
        
     /*to detect ARP cache poisoning attacks*/
    if(ntohs(eth_header->ether_type)==0x0806){
        pthread_mutex_lock(&ARPCache);
    struct arphdr *arp_header=(struct arphdr*)(packet+ETH_HLEN);
    if(ntohs(arp_header->ar_op)==ARPOP_REPLY){
        ARPCount++;
        pthread_mutex_unlock(&ARPCache);
        }    
    }

     /*to detect for Blacklisted URL violations*/   
    const char *googleWeb="www.google.co.uk";
    const char *bbcWeb="www.bbc.co.uk";
    if(ntohs(tcp_header->th_dport)==PORTNO){
        /*Condition to check if the destination port of the TCP header is the HTTP port
        If the condition satisfies, the HTTP payload is extracted*/
        const unsigned char *HTTPpayload=packet+ETH_HLEN+(ip_header->ip_hl)*4+(tcp_header->th_off)*4;
        if(strstr((char *)HTTPpayload,googleWeb)!=NULL){
            /*The strstr() method finds the occurance of the substring(googleWeb) in the string(HTTP payload)*/
            pthread_mutex_lock(&googleMutex);
            googleURLCount++;
            pthread_mutex_unlock(&googleMutex);
            printURLViolations(ip_header);
        }
        else if(strstr((char *)HTTPpayload,bbcWeb)!=NULL){
            /*A similar method is followed from the above to identify the malicious bbc URL website */
            pthread_mutex_lock(&bbcMutex);
            bbcURLCount++;
            pthread_mutex_unlock(&bbcMutex);
            printURLViolations(ip_header);
        }
    }  
}
void printURLViolations(struct ip *ip_header){
    /*Created a seperate method to print the Source IP address and Destination IP address of google and bbc websites
    which enhances code readability */
    printf("===================\n");
    printf("Blacklisted URL Violation Detected\n");
    printf("Source IP Address : %s\n",inet_ntoa(ip_header->ip_src));
    printf("Destination IP Address :%s\n",inet_ntoa(ip_header->ip_dst));
}