#ifndef CS241_HASHSET_H
#define CS241_HASHSET_H
#include <stdbool.h>
#include <netinet/ip.h>
typedef struct {
    struct in_addr *array;
    size_t capacity; // capacity is the total length of the array/set
    size_t size; // size is the total elements in the array
}dynamicArray;
void initializeArray(dynamicArray *dynamicArray);
void resizeArray(dynamicArray *dynamicArray);
bool add(dynamicArray *dynamicArray,struct in_addr element);
size_t getSize(dynamicArray *dynamicArray);
bool freeDynamicArray(dynamicArray * dynamicArray);
void print(dynamicArray *dynamicArray);
#endif
