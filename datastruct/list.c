/*
  a generic double list implemention
 */

#include <stdlib.h>
#include <stdint.h>
#include <assert.h>
#include "list.h"

list_st * list_new()
{
    list_st * l;
    l = malloc(sizeof(list_st));
    if (!l) return NULL;

    l->head = l->tail = NULL;
    l->dup = NULL;
    l->free = NULL;
    l->match = NULL;
    l->len = 0;
    return l;
}

void list_free(list_st * l)
{
    assert(l);
    list_node_st *cur;
    list_node_st *node = l->head;

    while (node) {
        if (l->free) 
            l->free(node->value);
        cur = node;
        node = node->next;
        free(cur);
    }

    free(l);
}

list_st * list_push_head(list_st *l, void *value)
{
    list_node_st *node;
    node = malloc(sizeof(list_node_st));
    if (!node) return NULL;

    node->value = value;
    node->next = l->head;
    node->prev = NULL;

    if (l->head == NULL) {
        l->head = l->tail = node;
    } else {
        l->head->prev = node;
        l->head = node;
    }
    l->len++;
    return l;
}

list_st * list_push_tail(list_st *l, void *value)
{
    list_node_st *node;
    node = malloc(sizeof(list_node_st));
    if (!node) return NULL;

    node->value = value;
    node->prev = l->tail;
    node->next = NULL;

    if (l->tail == NULL) {
        l->tail = l->head = node;
    } else {
        l->tail->next = node;
        l->tail = node;
    }
    l->len++;
    return l;
}

list_st * list_pop_head(list_st *l, void **value)
{
    list_node_st *node;
    if (l->head == NULL) {
        return NULL;
    } else {
        node = l->head;
        *value = node->value;
        l->head = node->next;
        if (node == l->tail)
            l->tail = NULL;
    }
    l->len--;
    return l;
}

list_st * list_pop_tail(list_st *l, void **value)
{
    list_node_st *node;
    if (l->tail == NULL) {
        return NULL;
    } else {
        node = l->tail;
        *value = node->value;
        l->tail = node->prev;
        if (node == l->head)
            l->head = NULL;
    }
    l->len--;
    return l;
}

list_st * list_insert(list_st *l, list_node_st *pos, void *value, int after)
{
    list_node_st *node;
    assert(l && pos);

    node = malloc(sizeof(list_node_st));
    if (node == NULL) return NULL;

    node->value = value;
    if (after) {
        node->prev = pos;
        node->next = pos->next;
        if (pos->next)
            pos->next->prev = node;
        pos->next = node;

        if (l->tail == pos)
            l->tail = node;
    } else {
        node->prev = pos->prev;
        node->next = pos;
        if (pos->prev) 
            pos->prev->next = node;
        pos->prev = node;

        if (l->head = pos)
            l->head = node;
    }
    l->len++;
    return l;
}

list_st * list_delete(list_st *l, list_node_st *node)
{
    assert(node);
    if (node->prev)
        node->prev->next = node->next;
    if(node->next)
        node->next->prev = node->prev;

    if (l->head == node) {
        l->head = node->next;
    }
    if (l->tail == node) {
        l->tail = node->prev;
    }
    if (l->free) l->free(node->value);
    free(node);
    l->len--;
    return l; 
}

list_node_st * list_find(list_st *l, void *value)
{
    list_node_st *node;
    node = l->head;
    while (node) {
        if (l->match && l->match(node->value, value) == 0)
            return node;
        else if (node->value == value)
            return node;
            
        node = node->next;
        continue;
    }
    return NULL;
}

list_node_st * list_index(list_st *l, int index)
{
    list_node_st *node;
    node = l->head;

    while (index-- && node)
        node = node->next;

    return node;
}

list_iter_st * list_iter_new(list_st *l, int direction)
{
    list_iter_st *iter;
    iter = malloc(sizeof(list_iter_st));
    if (!iter) return NULL;

    iter->direction = direction;
    if (direction == LIST_ITER_BACKWORD) {
        iter->node = l->tail;
    } else if (direction = LIST_ITER_FORWARD) {
        iter->node = l->head;
    }
    return iter;
}

list_node_st * list_iter_next(list_iter_st *iter)
{
    list_node_st *node;
    assert(iter);
    if (!iter->node)
        return NULL;

    node = iter->node;
    if (iter->direction == LIST_ITER_BACKWORD) {
        iter->node = iter->node->prev;
    } else if (iter->direction == LIST_ITER_FORWARD) {
        iter->node = iter->node->next;
    }
    return node;
}

void list_iter_free(list_iter_st *iter)
{
    free(iter);
}

void list_iter_rewind(list_st *l, list_iter_st *iter)
{
    iter->node = l->head;
    iter->direction = LIST_ITER_FORWARD;
}

void list_iter_rewind_tail(list_st *l, list_iter_st *iter)
{
    iter->node = l->tail;
    iter->direction = LIST_ITER_BACKWORD;
}

list_st * list_dup(list_st *l)
{
    void *value;
    list_st *copy;
    list_node_st *node;
    if ((copy = list_new()) == NULL)
        return NULL;

    copy->head = l->head;
    copy->tail = l->tail;
    copy->dup = l->dup;
    copy->match = l->match;
    copy->free = l->free;
    copy->len = l->len;

    node = l->head;
    while (node) {
        if (l->dup) {
            value = l->dup(node->value);
        } else {
            value = node->value;
        }

        if (list_push_tail(copy, value) == NULL) {
            list_free(copy);
            return NULL;
        }
    }
    return copy;
}

#ifdef HAVE_LIST_MAIN
#include <stdio.h>

void print_list(list_st *l)
{
    list_iter_st *iter;
    list_node_st *node;
    int i = 0;
    iter = list_iter_new(l, LIST_ITER_FORWARD);
    printf("list (%d) =>\n", list_len(l));
    while (node = list_iter_next(iter)) {
        printf(" [%d] = %s\n", i++, (char *)node->value);
    }

    list_iter_free(iter);
}

void print_list_reverse(list_st *l)
{
    int i = 0;
    list_iter_st *iter;
    list_node_st *node;
    iter = list_iter_new(l, LIST_ITER_FORWARD);

    list_iter_rewind_tail(l, iter);
    i = list_len(l);
    printf("list (%d) reverse =>\n", list_len(l));
    while (node = list_iter_next(iter)) {
        printf(" [%d] = %s\n", --i, (char *)node->value);
    }
    list_iter_free(iter);
}

int main(int argc, char * argv[])
{
    const char * v[] = {
        "element0", 
        "element1",
        "element2",
        "element3",
        "element4",
        "element5"
    };
    void *value;
    list_st * list;
    list_node_st *node;

    list = list_new();
    list_push_head(list, (void *)v[0]);
    list_push_tail(list, (void *)v[1]);
    print_list(list);

    list_pop_head(list, &value);
    printf("pop head value is %s\n", (const char*)value);
    list_pop_tail(list, &value);
    printf("pop tail value is %s\n", (const char*)value);
    print_list(list);

    list_push_head(list, (void *)v[2]);
    assert(list_insert(list, list_head(list), (void *)v[3], 1));
    list_push_tail(list, (void*)v[4]);
    list_push_head(list, (void*)v[5]);
    print_list(list);
    print_list_reverse(list);

    node = list_find(list, (void *)v[3]);
    assert(list_delete(list, node));
    print_list(list);

    node = list_index(list, 0);
    printf("node is %s\n", (const char*)node->value);

    list_free(list);
}
#endif
