/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 * Licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 */
#ifndef HOST_QTA_DLIST_H
#define HOST_QTA_DLIST_H

#include <stddef.h>

#define offset_of(type, member) (unsigned long)(&(((type *)0)->member))
#ifndef container_of
#define container_of(ptr, type, member) (type *)(void *)((uintptr_t)(ptr) - offset_of(type, member))
#endif

/*
 * The dlist node structure
 * representing the head node and the body nodes of the dlist
 */
struct dlist_node {
    struct dlist_node *prev;
    struct dlist_node *next;
};

/*
 * Initialize the empty dlist
 * PRE: a dlist_node struct for the head node, with unspecified field values
 * POST: the field set to point to the head node itself, thus initialized to be an empty dlist
 */
static inline void dlist_init(struct dlist_node *head)
{
    head->prev = head;
    head->next = head;
}

/*
 * Insert after a given position of the dlist
 * PRE: pos points to a node(can be the head node) in a well formed dlist, node points to a node to be inserted(not in
 * the dlist) POST: node has been inserted into the dlist after pos, the new dlist is well formed
 */
static inline void dlist_insert(struct dlist_node *pos, struct dlist_node *node)
{
    struct dlist_node *tmp = NULL;
    tmp        = pos->next;
    tmp->prev  = node;
    node->prev = pos;
    node->next = pos->next;
    pos->next  = node;
}

/*
 * Insert a new node at head of a dlist
 * PRE: head points to the head node of a well formed dlist, node points to the node to be inserted(not in the dlist)
 * POST: the new node has been inserted to the head of the dlist, the new dlist is well formed
 */
static inline void dlist_insert_head(struct dlist_node *node, struct dlist_node *head)
{
    dlist_insert(head, node);
}

/* get the address of the containing struct */
#define dlist_entry(ptr, type, member) container_of(ptr, type, member)

/* dlist_first_entry */
#define dlist_first_entry(ptr, type, member) dlist_entry((ptr)->next, type, member)

/* dlist_last_entry */
#define dlist_last_entry(ptr, type, member) dlist_entry((ptr)->prev, type, member)

/* get the address of the next containing struct on the dlist */
#define dlist_next_entry(pos, type, member) dlist_entry((pos)->member.next, type, member)

/* get the address of the previous containing struct on the dlist */
#define dlist_prev_entry(pos, type, member) dlist_entry((pos)->member.prev, type, member)

/* dlist for each struct entry */
#define dlist_for_each_entry(pos, head, type, member)                               \
    for ((pos) = dlist_first_entry(head, type, member); &((pos)->member) != (head); \
         pos = dlist_next_entry(pos, type, member))

#define dlist_for_each_entry_safe(pos, n, head, type, member)                                      \
    for ((pos) = dlist_first_entry(head, type, member), (n) = dlist_next_entry(pos, type, member); \
         (&(pos)->member != (head)); (pos) = (n), (n) = dlist_next_entry(n, type, member))

#endif
