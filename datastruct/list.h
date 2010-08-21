/* 
   a generic double list
 */

#ifndef _LIST_H_
#define _LIST_H_

typedef struct list_node_st {
    struct list_node_st *next;
    struct list_node_st *prev;
    void * value;
} list_node_st;

typedef struct list_st {
    list_node_st *head;
    list_node_st *tail;

    void * (*dup)(void *ptr);
    void (*free)(void *ptr);
    int (*match)(void *ptr, void *value);

    uint32_t len;
} list_st;

#define LIST_ITER_BACKWORD 0
#define LIST_ITER_FORWARD 1

typedef struct list_iter_st {
    list_node_st *node;
    int direction;
} list_iter_st;

#define list_head(l) ((l)->head)
#define list_tail(l) ((l)->tail)
#define list_len(l) ((l)->len)

#define list_prev_node(n) ((n)->prev)
#define list_next_node(n) ((n)->next)

#define list_set_dup(l, dup) ((l)->dup = (dup))
#define list_set_free(l, free) ((l)->free = (free))
#define list_set_match(l, match) ((l)->match = (match))
#define list_get_dup(l) ((l)->dup)
#define list_get_free(l) ((l)->free)
#define list_get_match(l) ((l)->match)


list_st * list_new();
void list_free(list_st * l);

list_st * list_push_head(list_st *l, void *value);
list_st * list_push_tail(list_st *l, void *value);
list_st * list_pop_head(list_st *l, void **value);
list_st * list_pop_tail(list_st *l, void **value);

list_st * list_insert(list_st *l, list_node_st *pos, void *value, int after);
list_st * list_delete(list_st *l, list_node_st *node);
list_node_st * list_find(list_st *l, void *value);
list_node_st * list_index(list_st *l, int index);

list_iter_st * list_iter_new(list_st *l, int direction);
list_node_st * list_iter_next(list_iter_st *iter);
void list_iter_free(list_iter_st *iter);
void list_iter_rewind(list_st *l, list_iter_st *iter);
void list_iter_rewind_tail(list_st *l, list_iter_st *iter);

list_st * list_dup(list_st *l);

#endif /* _LIST_H_ */
