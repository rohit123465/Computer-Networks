#include "hashset.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <netinet/ip.h>
#include <string.h>
#define initialCapacity 1000
/*The data structure used to handle incoming SYN packets is a dynamic array which behaves like a set 
    by accepting only unique source IP addresses*/
void initializeArray(dynamicArray *dynamicArray){
    dynamicArray->array=(struct in_addr*)malloc(initialCapacity*sizeof(struct in_addr));
    if(dynamicArray->array==NULL){
        fprintf(stderr,"Memory allocation has failed, Please try again!\n");
        exit(0);
    }
    dynamicArray->size=0;
    dynamicArray->capacity=initialCapacity;
}
void resizeArray(dynamicArray *dynamicArray){
    dynamicArray->capacity*=10;
    dynamicArray->array=(struct in_addr*)realloc(dynamicArray,dynamicArray->capacity*sizeof(struct in_addr));
    if(dynamicArray->array==NULL){
        fprintf(stderr,"Memory allocation has failed, Please try again!\n");
        exit(EXIT_FAILURE);
    }
}
/*The add() method inserts the unique source IP address into the dynamic set*/
bool add(dynamicArray *dynamicArray,struct in_addr element){
    bool chk=false;
    if(dynamicArray->size==dynamicArray->capacity){
        /*The condition checks if the total elements in the dynamic set is equal its length*/
        resizeArray(dynamicArray);
        
    }
    for(size_t i=0; i<dynamicArray->size; i++){
            if (!(memcmp(&dynamicArray->array[i], &element, sizeof(struct in_addr)))){
                /*The memcmp method compares the bytes of the source IP address stored in the array*/
                chk=true;//this tells that there is a duplicate element in the array
            }
        }
    if(!chk){
        dynamicArray->array[dynamicArray->size++]=element;//The unique IP addresses are added into the data structure
        return true;
    }
    return false;

}

size_t getSize(dynamicArray *dynamicArray){
    return dynamicArray->size;//returns the total elements in the dynamic set
}
bool freeDynamicArray(dynamicArray *dynamicArray){
    free(dynamicArray->array);
    dynamicArray->size=0;
    dynamicArray->capacity=0;
    return true;
}
void print(dynamicArray *dynamicArray){
    printf("Set : [");
    for(size_t i=0; i<dynamicArray->size;i++){
        printf("%s, ",inet_ntoa(dynamicArray->array[i]));//converts the IP address to a string in IPv4 notation
        
    }
    printf("]");
}
