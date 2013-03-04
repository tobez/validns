#ifndef _CBTREE_H
#define _CBTREE_H

#include <stdint.h>
#include <stdio.h>

struct cbtree {
  void *root;
};

/* Re: use of intptr_t instead of void * or a union { void *; int }:
 * I am aware it is not recommened (see
 * http://stackoverflow.com/questions/9492798/using-intptr-t-instead-of-void),
 * but I am not sure I agree;  maybe I just don't understand all
 * implications.  Anyways, Judy trees, which I am replacing in my code
 * with this tiny library, are using "unsigned long", which
 * is even worse, but works everywherewhere I tested it.
 */

/* Search for the string u in the tree t.
 * Returns:
 *   NULL if not found, or
 *   a pointer to a user value associated with the string
 */
intptr_t *cbtree_find(struct cbtree *t, const char *u);

/* Insert the string u into the tree t.
 * Returns:
 *   NULL in case of an error, or
 *   a pointer to a user value associated with the string;
 *   the user value will be initialized to 0 in
 *   case the insertion has happened, and left
 *   untouched in case the string was already in the tree.
 */
intptr_t *cbtree_insert(struct cbtree *t, const char *u);

/* Delete the string u from the tree t.
 * Returns:
 *   0 in case u was not in t, or
 *   a user value which was associated with the string;
 *   please note that the user value can be 0 as well,
 *   so there is no general way to distinguish these two
 *   situations
 */
intptr_t cbtree_delete(struct cbtree *t, const char *u);

void cbtree_clear(struct cbtree *t);

int cbtree_allprefixed(struct cbtree *t, const char *prefix,
					   int (*handle)(const char *, intptr_t *, void *),
					   void *arg);

void cbtree_dump(struct cbtree *t);

char *cbtree_next(struct cbtree *t, const char *u, intptr_t *data);

#endif
