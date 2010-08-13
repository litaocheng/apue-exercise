/*
 * a queue based the array
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    void ** queue;  /* the queue */
    void ** queuet; /* the queue tail */
    size_t queues;  /* the size of data in the queue */
    size_t queuen;  /* the number of the data in the queue */

    void ** tail;
    void ** head;
    size_t  n;
}queue_st;


/* alloc a new queue with specified size */
queue_st * queue_new(size_t n, size_t size)
{
    int i;
    void * ptr;
    void * offset;
    const size_t void_pl = sizeof(void *);
    queue_st * q;
    if (n <= 0) {
        return NULL;
    }
    
    /* memory layout
     * queue_st + [pointers] + [size_1]...[size_n]
     */
    ptr = malloc(n * (size+void_pl) + sizeof(queue_st));
    if (!ptr) {
        fprintf(stderr, "out of memory");
        return NULL;
    }

    q = (queue_st *)ptr;
    q->queues = size;
    q->queuen = n;
    q->queue = ptr + sizeof(queue_st);
    q->queuet = q->queue + n;
    q->n = 0;
    q->head = q->tail = NULL;

    offset = q->queue + n;
    for (i = 0; i < n; ++i) {
        q->queue[i] = offset + i * size;
    }

    return q;
}

void queue_free(queue_st * q) 
{
    if (!q) return;
    free(q);
}

int queue_push(queue_st * q, void * data, size_t size) 
{
    void * p;
    if (!q || !data) return -1;
    if (size != q->queues) return -2;
    
    if (q->tail == NULL) { /* empty */
        q->tail = q->head = q->queue;
    } else if (q->tail == q->head) { /* full */
        fprintf(stderr, "queue is full\n");
        return -3;
    }

    /* insert the data to queue */
    memcpy(*(q->tail), data, size);
    q->tail++;
    q->n++;

    if (q->tail >= q->queuet) { /* extend */
        q->tail = q->queue;
    }
    return 0;
}

void * queue_pop(queue_st * q, size_t *size)
{
    void * p;
    if (!q || !size) return NULL;

    if (q->head == NULL) { /* empty */
        fprintf(stderr, "queue is empty\n");
        return NULL;
    }

    p = *q->head;
    *size = q->queues;

    q->head++;
    q->n--;

    if (q->head >= q->queuet) { /* extend */
        q->head = q->queue;
    }

    if (q->head == q->tail) {
        q->head = q->tail = NULL;
    }

    return p;
}

size_t queue_len(queue_st *q) 
{
    if (!q) return 0;

    return q->n;
}


typedef struct {
    int k;
}opaque_st;

int main(int argc, char * argv[])
{
    int i;
    size_t len;
    opaque_st * p;
    printf("a queue based the array\n");
    queue_st * queue;
    queue = queue_new(10, sizeof(opaque_st));

    for (i = 0; i < 10; ++i) {
        opaque_st item = 
        {
            .k = i
        };
        if (queue_push(queue, &item, sizeof(opaque_st)) != 0) {
            fprintf(stderr, "push item (%d) error!", i);
            break;
        }
        printf("push item(%d)\n", i);
    }
    printf("queue len is %d\n", queue_len(queue));

    for (i =0; i < 10; ++i) {
        opaque_st item = {22};
        queue_push(queue, &item, sizeof(opaque_st));
    }

    /* pop the items */
    for (i = 0; i < 10; ++i) {
        if ((p = queue_pop(queue, &len)) != NULL) {
            printf("pop item(%d)\n", p->k);
        }
    }
    printf("queue len is %d\n", queue_len(queue));

    for (i = 0; i < 10; ++i) {
        queue_pop(queue, &len);
    }
        
    queue_free(queue);
    return 0;
}
