#ifndef HEAP_H
#define HEAP_H

typedef struct {
    int *data; 
    int size; 
    int capacity;
} Heap;

Heap *createHeap(int capacity);
_Bool isEmpty(Heap *heap);
void insert(Heap *heap, int value);
int extractMax(Heap *heap);
void heapifyDown(Heap *heap, int index);
void heapifyUp(Heap *heap, int index);
void freeHeap(Heap *heap);

#endif