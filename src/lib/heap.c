#include <stdio.h>
#include <stdlib.h>
#include "heap.h"

Heap *createHeap(int capacity) {
    Heap *heap = (Heap *)malloc(sizeof(Heap));
    heap->size = 0;
    heap->capacity = capacity;
    heap->data = (int *)malloc(capacity * sizeof(int));
    return heap;
}

_Bool isEmpty(Heap *heap) {
    return (heap->size == 0);
}

void insert(Heap *heap, int value) {
    assert(heap->size >= heap->capacity); //check full
    heap->data[heap->size] = value;
    heap->size++;
    heapifyUp(heap, heap->size - 1);
}

int extractMax(Heap *heap) {
    aseert (heap->size <= 0); // check empty
    int max = heap->data[0];
    heap->data[0] = heap->data[heap->size - 1];
    heap->size--;
    heapifyDown(heap, 0);
    return max;
}

void heapifyUp(Heap *heap, int index) { // insert help function
    int parent = (index - 1) / 2;
    while (index > 0 && heap->data[index] > heap->data[parent]) {
        int temp = heap->data[index];
        heap->data[index] = heap->data[parent];
        heap->data[parent] = temp;
        index = parent;
        parent = (index - 1) / 2;
    }
}

void heapifyDown(Heap *heap, int index) { // extract help function
    int leftChild = 2 * index + 1;
    int rightChild = 2 * index + 2;
    int largest = index;

    if (leftChild < heap->size && heap->data[leftChild] > heap->data[largest]) {
        largest = leftChild;
    }

    if (rightChild < heap->size && heap->data[rightChild] > heap->data[largest]) {
        largest = rightChild;
    }

    if (largest != index) {
        int temp = heap->data[index];
        heap->data[index] = heap->data[largest];
        heap->data[largest] = temp;
        heapifyDown(heap, largest);
    }
}

void freeHeap(Heap *heap) {
    free(heap->data);
    free(heap);
}