/*
 * Copyright (c) 2010, Andrea Mazzoleni. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/** \file
 * Double linked list for collisions into hashtables.
 *
 * This list is a double linked list mainly targetted for handling collisions
 * into an hashtables, but useable also as a generic list.
 *
 * The main feature of this list is to require only one pointer to represent the
 * list, compared to a classic implementation requiring a head an a tail pointers.
 * This reduces the memory usage in hashtables.
 *
 * Another feature is to support the insertion at the end of the list. This allow to store
 * collisions in a stable order. Where for stable order we mean that equal elements keep
 * their insertion order.
 *
 * To initialize the list, you have to call tommy_list_init(), or to simply assign
 * to it NULL, as an empty list is represented by the NULL value.
 *
 * \code
 * tommy_list list;
 *
 * tommy_list_init(&list); // initializes the list
 * \endcode
 *
 * To insert elements in the list you have to call tommy_list_insert_tail()
 * or tommy_list_insert_head() for each element.
 * In the insertion call you have to specify the address of the node and the
 * address of the object.
 * The address of the object is used to initialize the tommy_node::data field
 * of the node.
 *
 * \code
 * struct object {
 *     int value;
 *     // other fields
 *     tommy_node node;
 * };
 *
 * struct object* obj = malloc(sizeof(struct object)); // creates the object
 *
 * obj->value = ...; // initializes the object
 *
 * tommy_list_insert_tail(&list, &obj->node, obj); // inserts the object
 * \endcode
 *
 * To iterate over all the elements in the list you have to call
 * tommy_list_head() to get the head of the list and follow the
 * tommy_node::next pointer until NULL.
 *
 * \code
 * tommy_node* i = tommy_list_head(&list);
 * while (i) {
 *     struct object* obj = i->data; // gets the object pointer
 *
 *     printf("%d\n", obj->value); // process the object
 *
 *     i = i->next; // go to the next element
 * }
 * \endcode
 *
 * To destroy the list you have to remove all the elements,
 * as the list is completely inplace and it doesn't allocate memory.
 * This can be done with the tommy_list_foreach() function.
 *
 * \code
 * // deallocates all the objects iterating the list
 * tommy_list_foreach(&list, free);
 * \endcode
 */

#ifndef __TOMMYLIST_H
#define __TOMMYLIST_H

#include "tommytypes.h"

/******************************************************************************/
/* list */

/**
 * Double linked list type.
 */
typedef tommy_node* tommy_list;

/**
 * Initializes the list.
 * The list is completely inplace, so it doesn't need to be deinitialized.
 */
tommy_inline void tommy_list_init(tommy_list* list)
{
    *list = 0;
}

/**
 * Gets the head of the list.
 * \return The head node. For empty lists 0 is returned.
 */
tommy_inline tommy_node* tommy_list_head(tommy_list* list)
{
    return *list;
}

/**
 * Gets the tail of the list.
 * \return The tail node. For empty lists 0 is returned.
 */
tommy_inline tommy_node* tommy_list_tail(tommy_list* list)
{
    tommy_node* head = tommy_list_head(list);

    if (!head)
        return 0;

    return head->prev;
}

/** \internal
 * Creates a new list with a single element.
 * \param list The list to initialize.
 * \param node The node to insert.
 */
tommy_inline void tommy_list_insert_first(tommy_list* list, tommy_node* node)
{
    /* one element "circular" prev list */
    node->prev = node;

    /* one element "0 terminated" next list */
    node->next = 0;

    *list = node;
}

/** \internal
 * Inserts an element at the head of a not empty list.
 * The element is inserted at the head of the list. The list cannot be empty.
 * \param list The list. The list cannot be empty.
 * \param node The node to insert.
 */
tommy_inline void tommy_list_insert_head_not_empty(tommy_list* list, tommy_node* node)
{
    tommy_node* head = tommy_list_head(list);

    /* insert in the "circular" prev list */
    node->prev = head->prev;
    head->prev = node;

    /* insert in the "0 terminated" next list */
    node->next = head;

    *list = node;
}

/** \internal
 * Inserts an element at the tail of a not empty list.
 * The element is inserted at the tail of the list. The list cannot be empty.
 * \param head The node at the list head. It cannot be 0.
 * \param node The node to insert.
 */
tommy_inline void tommy_list_insert_tail_not_empty(tommy_node* head, tommy_node* node)
{
    /* insert in the "circular" prev list */
    node->prev = head->prev;
    head->prev = node;

    /* insert in the "0 terminated" next list */
    node->next = 0;
    node->prev->next = node;
}

/**
 * Inserts an element at the head of a list.
 * \param node The node to insert.
 * \param data The object containing the node. It's used to set the tommy_node::data field of the node.
 */
tommy_inline void tommy_list_insert_head(tommy_list* list, tommy_node* node, void* data)
{
    tommy_node* head = tommy_list_head(list);

    if (head)
        tommy_list_insert_head_not_empty(list, node);
    else
        tommy_list_insert_first(list, node);

    node->data = data;
}

/**
 * Inserts an element at the tail of a list.
 * \param node The node to insert.
 * \param data The object containing the node. It's used to set the tommy_node::data field of the node.
 */
tommy_inline void tommy_list_insert_tail(tommy_list* list, tommy_node* node, void* data)
{
    tommy_node* head = tommy_list_head(list);

    if (head)
        tommy_list_insert_tail_not_empty(head, node);
    else
        tommy_list_insert_first(list, node);

    node->data = data;
}

/**
 * Removes an element from the list.
 * You must already have the address of the element to remove.
 * \note The node content is left unchanged, including the tommy_node::next
 * and tommy_node::prev fields that still contain pointers at the list.
 * \param node The node to remove. The node must be in the list.
 * \return The tommy_node::data field of the node removed.
 */
tommy_inline void* tommy_list_remove_existing(tommy_list* list, tommy_node* node)
{
    tommy_node* head = tommy_list_head(list);

    /* remove from the "circular" prev list */
    if (node->next)
        node->next->prev = node->prev;
    else
        head->prev = node->prev; /* the last */

    /* remove from the "0 terminated" next list */
    if (head == node)
        *list = node->next; /* the new head, in case 0 */
    else
        node->prev->next = node->next;

    return node->data;
}

/**
 * Concats two lists.
 * The second list is concatenated at the first list.
 * \param first The first list.
 * \param second The second list. After this call the list content is undefined,
 * and you should not use it anymore.
 */
tommy_inline void tommy_list_concat(tommy_list* first, tommy_list* second)
{
    tommy_node* first_head;
    tommy_node* first_tail;
    tommy_node* second_head;

    /* if the second is empty, nothing to do */
    second_head = tommy_list_head(second);
    if (second_head == 0)
        return;

    /* if the first is empty, copy the second */
    first_head = tommy_list_head(first);
    if (first_head == 0) {
        *first = *second;
        return;
    }

    /* tail of the first list */
    first_tail = first_head->prev;

    /* set the "circular" prev list */
    first_head->prev = second_head->prev;
    second_head->prev = first_tail;

    /* set the "0 terminated" next list */
    first_tail->next = second_head;
}

/**
 * Sorts a list.
 * It's a stable merge sort with O(N*log(N)) worst complexity.
 * It's faster on degenerated cases like partially ordered lists.
 * \param cmp Compare function called with two elements.
 * The function should return <0 if the first element is less than the second, ==0 if equal, and >0 if greather.
 */
void tommy_list_sort(tommy_list* list, tommy_compare_func* cmp);

/**
 * Checks if empty.
 * \return If the list is empty.
 */
tommy_inline tommy_bool_t tommy_list_empty(tommy_list* list)
{
    return tommy_list_head(list) == 0;
}

/**
 * Gets the number of elements.
 * \note This operation is O(n).
 */
tommy_inline tommy_size_t tommy_list_count(tommy_list* list)
{
    tommy_size_t count = 0;
    tommy_node* i = tommy_list_head(list);

    while (i) {
        ++count;
        i = i->next;
    }

    return count;
}

/**
 * Calls the specified function for each element in the list.
 *
 * You cannot add or remove elements from the inside of the callback,
 * but can use it to deallocate them.
 *
 * \code
 * tommy_list list;
 *
 * // initializes the list
 * tommy_list_init(&list);
 *
 * ...
 *
 * // creates an object
 * struct object* obj = malloc(sizeof(struct object));
 *
 * ...
 *
 * // insert it in the list
 * tommy_list_insert_tail(&list, &obj->node, obj);
 *
 * ...
 *
 * // deallocates all the objects iterating the list
 * tommy_list_foreach(&list, free);
 * \endcode
 */
tommy_inline void tommy_list_foreach(tommy_list* list, tommy_foreach_func* func)
{
    tommy_node* node = tommy_list_head(list);

    while (node) {
        void* data = node->data;
        node = node->next;
        func(data);
    }
}

/**
 * Calls the specified function with an argument for each element in the list.
 */
tommy_inline void tommy_list_foreach_arg(tommy_list* list, tommy_foreach_arg_func* func, void* arg)
{
    tommy_node* node = tommy_list_head(list);

    while (node) {
        void* data = node->data;
        node = node->next;
        func(arg, data);
    }
}

#endif
