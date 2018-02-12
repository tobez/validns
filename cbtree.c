/* djb's critbit with associated data storage.
 *
 * Based on https://github.com/agl/critbit, which is in public domain.
 * Changes:
 *   - data storage added
 *   - cweb removed
 *   - functions renamed and data types cleaned to my liking
 */
#include <sys/types.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include "cbtree.h"

struct node {
  void *child[2];
  uint32_t byte;
  uint8_t otherbits;
};

/* our own memory management */

struct pool
{
    struct pool *next;
    size_t pool_size;
    size_t free_index;
    char mem[0];
};

static struct pool *internal = NULL;
static struct pool *external = NULL;

static int new_pool(struct pool **root, size_t size)
{
    struct pool *pool;

    size = (size + sizeof(void *) - 1) / sizeof(void *);
    size *= sizeof(void *);
    pool = malloc(size + sizeof(struct pool));
    if (!pool) {
        return 1;
    }
    pool->next = *root;
    pool->free_index = 0;
    pool->pool_size = size;
    *root = pool;
    return 0;
}

static void *alloc(struct pool **root, size_t size)
{
    void *ret;
    size = (size + sizeof(void *) - 1) / sizeof(void *);
    size *= sizeof(void *);
    if (!*root)
        if (new_pool(root, size > 256000 ? size : 256000) != 0)
            return NULL;
    if ((*root)->pool_size - (*root)->free_index < size)
        if (new_pool(root, size > 256000 ? size : 256000) != 0)
            return NULL;
    ret = (*root)->mem + (*root)->free_index;
    (*root)->free_index += size;
    return ret;
}

/* main code */

intptr_t*
cbtree_find(struct cbtree *t, const char *u)
{
    const uint8_t *ubytes = (void *)u;
    const size_t ulen = strlen(u);
    uint8_t *p = t->root;

    /* Test for empty tree */
    if (!p) return NULL;

    /* Walk tree for best member */
    while (1 & (intptr_t) p) {
        struct node *q = (void *)(p - 1);
        /* Calculate direction */
        int direction;
        uint8_t c = 0;

        if (q->byte < ulen)
            c = ubytes[q->byte];
        direction = (1 + (q->otherbits | c)) >> 8;

        p = q->child[direction];
    }

    /* The leaves contain "[data ptr][string]" */
    if (strcmp(u, (const char *)(p + sizeof(intptr_t))) == 0)
        return (intptr_t *)p;
    return NULL;
}

intptr_t*
cbtree_insert(struct cbtree *t, const char *u)
{
    const uint8_t *const ubytes = (void *) u;
    const size_t ulen = strlen(u);
    uint8_t *p = t->root;

    /* Deal with inserting into an empty tree */
    if (!p) {
        char *x = alloc(&external, ulen + 1 + sizeof(intptr_t));
        if (!x)
            return NULL;
        *((intptr_t *)x) = 0;
        memcpy(x + sizeof(intptr_t), u, ulen + 1);
        t->root = x;
        return (intptr_t *)x;
    }

    /* Walk tree for best member */
    while (1 & (intptr_t) p) {
        struct node *q = (void *)(p - 1);
        /* Calculate direction */
        int direction;
        uint8_t c = 0;

        if (q->byte < ulen)
            c = ubytes[q->byte];
        direction = (1 + (q->otherbits | c)) >> 8;

        p = q->child[direction];
    }

    /* Find the critical bit */
    /* 1: Find differing byte */
    uint32_t newbyte;
    uint32_t newotherbits;

    for (newbyte = 0; newbyte < ulen; ++newbyte) {
        if (p[sizeof(intptr_t) + newbyte] != ubytes[newbyte]) {
            newotherbits = p[sizeof(intptr_t) + newbyte] ^ ubytes[newbyte];
            goto different_byte_found;
        }
    }

    if (p[sizeof(intptr_t) + newbyte] != 0) {
        newotherbits = p[sizeof(intptr_t) + newbyte];
        goto different_byte_found;
    }
    return (intptr_t *)p;

different_byte_found:

    /* 2: Find differing bit */
    newotherbits |= newotherbits >> 1;
    newotherbits |= newotherbits >> 2;
    newotherbits |= newotherbits >> 4;
    newotherbits = (newotherbits & ~(newotherbits >> 1)) ^ 255;
    uint8_t c = p[sizeof(intptr_t) + newbyte];
    int newdirection = (1 + (newotherbits | c)) >> 8;

    /* Insert new string */

    /* 1: Allocate new node structure */
    struct node *newnode;

    newnode = alloc(&internal, sizeof(struct node));
    if (!newnode)
        return NULL;

    char *x = alloc(&external, ulen + 1 + sizeof(intptr_t));
    if (!x)
        return NULL;
    *((intptr_t *)x) = 0;
    memcpy(x + sizeof(intptr_t), ubytes, ulen + 1);

    newnode->byte = newbyte;
    newnode->otherbits = newotherbits;
    newnode->child[1 - newdirection] = x;

    /* 2: Insert new node */
    void **wherep = &t->root;
    for (;;) {
        uint8_t *p = *wherep;
        if (!(1 & (intptr_t) p)) break;
        struct node *q = (void *) (p - 1);
        if (q->byte > newbyte) break;
        if (q->byte == newbyte && q->otherbits > newotherbits) break;
        uint8_t c = 0;
        if (q->byte < ulen) c = ubytes[q->byte];
        const int direction = (1 + (q->otherbits | c)) >> 8;
        wherep = q->child + direction;
    }

    newnode->child[newdirection] = *wherep;
    *wherep = (void *) (1 + (char *) newnode);

    return (intptr_t *)x;
}

intptr_t
cbtree_delete(struct cbtree *t, const char *u)
{
    const uint8_t *ubytes = (void *) u;
    const size_t ulen = strlen(u);
    uint8_t *p = t->root;
    void **wherep = &t->root;
    void **whereq = 0;
    struct node *q = 0;
    int direction = 0;
    intptr_t ret;

    /* Deal with deleting from an empty tree */
    if (!p) return 0;

    /* Walk the tree for the best match */
    while (1 & (intptr_t) p) {
        whereq = wherep;
        q = (void *) (p - 1);
        uint8_t c = 0;
        if (q->byte < ulen) c = ubytes[q->byte];
        direction = (1 + (q->otherbits | c)) >> 8;
        wherep = q->child + direction;
        p = *wherep;
    }

    /* Check the best match */
    if (0 != strcmp(u, (const char *)(p + sizeof(intptr_t))))
        return 0;
    ret = *((intptr_t *)p);

    /* Remove the element and/or node */
    if (!whereq) {
        t->root = 0;
        return ret;
    }

    *whereq = q->child[1 - direction];
    // free(q);

    return ret;
}

static void
traverse(void *top) {
    uint8_t *p = top;

    if (1 & (intptr_t) p) {
        struct node *q = (void *) (p - 1);
        traverse(q->child[0]);
        traverse(q->child[1]);
        // free(q);
    } else {
        // free(p);
    }
}

void
cbtree_clear(struct cbtree *t)
{
    if (t->root) traverse(t->root);
    t->root = NULL;
}

static int
allprefixed_traverse(uint8_t *top, int (*handle)(const char *, intptr_t *, void *), void *arg)
{
    int direction;

    /* Deal with an internal node */
    if (1 & (intptr_t) top) {
        struct node *q = (void *) (top - 1);
        for (direction = 0; direction < 2; ++direction)
            switch(allprefixed_traverse(q->child[direction], handle, arg)) {
            case 1: break;
            case 0: return 0;
            default: return -1;
            }
        return 1;
    }

    /* Deal with an external node */
    return handle((const char *)(top + sizeof(intptr_t)), (intptr_t *)top, arg);
}

int
cbtree_allprefixed(struct cbtree *t, const char *prefix,
                   int (*handle)(const char *, intptr_t *, void *),
                   void *arg)
{
    const uint8_t *ubytes = (void *) prefix;
    const size_t ulen = strlen(prefix);
    uint8_t *p = t->root;
    uint8_t *top = p;
    int i;

    if (!p) return 1; /* S = $\emptyset$ */

    /* Walk tree, maintaining top pointer */
    while (1 & (intptr_t) p) {
        struct node *q = (void *) (p - 1);
        uint8_t c = 0;
        if (q->byte < ulen) c = ubytes[q->byte];
        const int direction = (1 + (q->otherbits | c)) >> 8;
        p = q->child[direction];
        if (q->byte < ulen) top = p;
    }

    /* Check prefix */
    for (i = 0; i < ulen; ++i) {
        if (p[i+sizeof(intptr_t)] != ubytes[i]) return 1;
    }

    return allprefixed_traverse(top, handle, arg);
}

static const char *byte_to_binary(int x)
{
    static char b[9];
    int z;

    b[0] = '\0';
    for (z = 128; z > 0; z >>= 1)
        strcat(b, ((x & z) == z) ? "1" : "0");

    return b;
}

static void
traverse_dump(void *top, int level, int byte)
{
    uint8_t *p = top;
    int i;

    for (i = 0; i < level; i++) printf(" ");
    if (1 & (intptr_t) p) {
        struct node *q = (void *) (p - 1);
        printf("[byte(%d),otherbits(%s)]\n", q->byte, byte_to_binary(q->otherbits));
        traverse_dump(q->child[0], level + 1, q->byte);
        traverse_dump(q->child[1], level + 1, q->byte);
    } else {
        const size_t ulen = strlen((char *)(p + sizeof(intptr_t)));
        int c = byte < ulen ? p[sizeof(intptr_t) + byte] : 0;
        printf("\"%s\" (%s)\n", p + sizeof(intptr_t), byte_to_binary(c));
    }
}

void
cbtree_dump(struct cbtree *t)
{
    if (t->root)
        traverse_dump(t->root, 0, 0);
    printf("\n");
}

char*
cbtree_next(struct cbtree *t, const char *u, intptr_t *data)
{
    const uint8_t *ubytes = (void *) u;
    const size_t ulen = strlen(u);
    uint8_t *p = t->root;
    uint8_t *branch = NULL;

    if (!p) return NULL;

    /* Walk tree, maintaining top pointer */
    while (1 & (intptr_t) p) {
        struct node *q = (void *) (p - 1);
        uint8_t c = 0;
        if (q->byte < ulen) c = ubytes[q->byte];
        const int direction = (1 + (q->otherbits | c)) >> 8;
        if (direction == 0)
            branch = q->child[1];
        p = q->child[direction];
    }

    /* check whether what we found is what we are looking for already */
    if (strcmp((char *)(p + sizeof(intptr_t)), u) > 0) {
        if (data) *data = *((intptr_t *)p);
        return (char *)(p + sizeof(intptr_t));
    }

    if (!branch) return NULL;

    /* select the lowest value on the branch */
    p = branch;
    while (1 & (intptr_t) p) {
        struct node *q = (void *) (p - 1);
        p = q->child[0];
    }
    if (data) *data = *((intptr_t *)p);
    return (char *)(p + sizeof(intptr_t));
}
