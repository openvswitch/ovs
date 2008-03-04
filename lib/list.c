#include "list.h"
#include <assert.h>

/* Initializes 'list' as an empty list. */
void
list_init(struct list *list)
{
    list->next = list->prev = list;
}

/* Inserts 'elem' just before 'before'. */
void
list_insert(struct list *before, struct list *elem)
{
  elem->prev = before->prev;
  elem->next = before;
  before->prev->next = elem;
  before->prev = elem;
}

/* Removes elements 'first' though 'last' (exclusive) from their current list,
   then inserts them just before 'before'. */
void
list_splice(struct list *before, struct list *first, struct list *last)
{
  if (first == last)
    return;
  last = last->prev;

  /* Cleanly remove 'first'...'last' from its current list. */
  first->prev->next = last->next;
  last->next->prev = first->prev;

  /* Splice 'first'...'last' into new list. */
  first->prev = before->prev;
  last->next = before;
  before->prev->next = first;
  before->prev = last;
}

/* Inserts 'elem' at the beginning of 'list', so that it becomes the front in
   'list'. */
void
list_push_front(struct list *list, struct list *elem)
{
  list_insert(list->next, elem);
}

/* Inserts 'elem' at the end of 'list', so that it becomes the back in
 * 'list'. */
void
list_push_back(struct list *list, struct list *elem)
{
  list_insert(list, elem);
}

/* Removes 'elem' from its list and returns the element that followed it.
   Undefined behavior if 'elem' is not in a list. */
struct list *
list_remove(struct list *elem)
{
  elem->prev->next = elem->next;
  elem->next->prev = elem->prev;
  return elem->next;
}

/* Removes the front element from 'list' and returns it.  Undefined behavior if
   'list' is empty before removal. */
struct list *
list_pop_front(struct list *list)
{
  struct list *front = list->next;
  list_remove(front);
  return front;
}

/* Removes the back element from 'list' and returns it.
   Undefined behavior if 'list' is empty before removal. */
struct list *
list_pop_back(struct list *list)
{
  struct list *back = list->prev;
  list_remove(back);
  return back;
}

/* Returns the front element in 'list'.
   Undefined behavior if 'list' is empty. */
struct list *
list_front(struct list *list)
{
  assert(!list_is_empty(list));
  return list->next;
}

/* Returns the back element in 'list'.
   Undefined behavior if 'list' is empty. */
struct list *
list_back(struct list *list)
{
  assert(!list_is_empty(list));
  return list->prev;
}

/* Returns the number of elements in 'list'.
   Runs in O(n) in the number of elements. */
size_t
list_size(const struct list *list)
{
  const struct list *e;
  size_t cnt = 0;

  for (e = list->next; e != list; e = e->next)
    cnt++;
  return cnt;
}

/* Returns true if 'list' is empty, false otherwise. */
bool
list_is_empty(const struct list *list)
{
  return list->next == list;
}
