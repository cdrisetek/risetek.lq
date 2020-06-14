// SPDX-License-Identifier: BSD-2-Clause
//
// Copyright (c) 2014-2020, NetApp, Inc.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice,
//    this list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

/*      $NetBSD: tree.h,v 1.8 2004/03/28 19:38:30 provos Exp $  */
/*      $OpenBSD: tree.h,v 1.7 2002/10/17 21:51:54 art Exp $    */
/* $FreeBSD$ */

/*-
 * Copyright 2002 Niels Provos <provos@citi.umich.edu>
 * Copyright (c) 2014-2020, NetApp, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef __TREE_H__
#define __TREE_H__
// IWYU pragma: private, include <quant/quant.h>

/*
 * This file defines data structures for different types of trees:
 * splay trees and red-black trees.
 *
 * A splay tree is a self-organizing data structure.  Every operation
 * on the tree causes a splay to happen.  The splay moves the requested
 * node to the root of the tree and partly rebalances it.
 *
 * This has the benefit that request locality causes faster lookups as
 * the requested nodes move to the top of the tree.  On the other hand,
 * every lookup causes memory writes.
 *
 * The Balance Theorem bounds the total access time for m operations
 * and n inserts on an initially empty tree as O((m + n)lg n).  The
 * amortized cost for a sequence of m accesses to a splay tree is O(lg n);
 *
 * A red-black tree is a binary search tree with the node color as an
 * extra attribute.  It fulfills a set of conditions:
 *      - every search path from the root to a leaf consists of the
 *        same number of black nodes,
 *      - each red node (except for the root) has a black parent,
 *      - each leaf node is black.
 *
 * Every operation on a red-black tree is bounded as O(lg n).
 * The maximum height of a red-black tree is 2lg (n+1).
 */

#define splay_head(name, type)                                                 \
    _Pragma("clang diagnostic push")                                           \
        _Pragma("clang diagnostic ignored \"-Wpadded\"") struct name {         \
        struct type * sph_root; /* root of the tree */                         \
        uint_t sph_cnt;         /* number of nodes in the tree */              \
    } _Pragma("clang diagnostic pop")

#define splay_initializer(root)                                                \
    {                                                                          \
        NULL, 0                                                                \
    }

#define splay_init(root)                                                       \
    do {                                                                       \
        (root)->sph_root = NULL;                                               \
        (root)->sph_cnt = 0;                                                   \
    } while (/*CONSTCOND*/ 0)

#define splay_entry(type)                                                      \
    struct {                                                                   \
        struct type * spe_left;  /* left element */                            \
        struct type * spe_right; /* right element */                           \
    }

#define splay_left(elm, field) (elm)->field.spe_left
#define splay_right(elm, field) (elm)->field.spe_right
#define splay_root(head) (head)->sph_root
#define splay_empty(head) (splay_root(head) == NULL)
#define splay_count(head) (head)->sph_cnt

/* splay_rotate_{left,right} expect that tmp hold splay_{right,left} */
#define splay_rotate_right(head, tmp, field)                                   \
    do {                                                                       \
        splay_left((head)->sph_root, field) = splay_right(tmp, field);         \
        splay_right(tmp, field) = (head)->sph_root;                            \
        (head)->sph_root = tmp;                                                \
    } while (/*CONSTCOND*/ 0)

#define splay_rotate_left(head, tmp, field)                                    \
    do {                                                                       \
        splay_right((head)->sph_root, field) = splay_left(tmp, field);         \
        splay_left(tmp, field) = (head)->sph_root;                             \
        (head)->sph_root = tmp;                                                \
    } while (/*CONSTCOND*/ 0)

#define splay_linkleft(head, tmp, field)                                       \
    do {                                                                       \
        splay_left(tmp, field) = (head)->sph_root;                             \
        tmp = (head)->sph_root;                                                \
        (head)->sph_root = splay_left((head)->sph_root, field);                \
    } while (/*CONSTCOND*/ 0)

#define splay_linkright(head, tmp, field)                                      \
    do {                                                                       \
        splay_right(tmp, field) = (head)->sph_root;                            \
        tmp = (head)->sph_root;                                                \
        (head)->sph_root = splay_right((head)->sph_root, field);               \
    } while (/*CONSTCOND*/ 0)

#define splay_assemble(head, node, left, right, field)                         \
    do {                                                                       \
        splay_right(left, field) = splay_left((head)->sph_root, field);        \
        splay_left(right, field) = splay_right((head)->sph_root, field);       \
        splay_left((head)->sph_root, field) = splay_right(node, field);        \
        splay_right((head)->sph_root, field) = splay_left(node, field);        \
    } while (/*CONSTCOND*/ 0)

/* Generates prototypes and inline functions */

#define SPLAY_PROTOTYPE(name, type, field, cmp)                                \
    _Pragma("clang diagnostic push")                                           \
        _Pragma("clang diagnostic ignored \"-Wunused-function\"")              \
                                                                               \
            void __attribute__((no_instrument_function))                       \
                name##_splay(struct name *, const struct type *);              \
    void __attribute__((no_instrument_function))                               \
        name##_splay_minmax(struct name *, int);                               \
    struct type * __attribute__((no_instrument_function))                      \
        name##_splay_insert(struct name *, struct type *);                     \
    struct type * __attribute__((no_instrument_function))                      \
        name##_splay_remove(struct name *, struct type *);                     \
                                                                               \
    /* Finds the node with the same key as elm */                              \
    static inline struct type * __attribute__((no_instrument_function))        \
        name##_splay_find(struct name * head, const struct type * elm)         \
    {                                                                          \
        if (splay_empty(head))                                                 \
            return (NULL);                                                     \
        name##_splay(head, elm);                                               \
        if ((cmp)(elm, (head)->sph_root) == 0)                                 \
            return (head->sph_root);                                           \
        return (NULL);                                                         \
    }                                                                          \
                                                                               \
    static inline struct type * __attribute__((no_instrument_function))        \
        name##_splay_next(struct name * head, struct type * elm)               \
    {                                                                          \
        name##_splay(head, elm);                                               \
        if (splay_right(elm, field) != NULL) {                                 \
            elm = splay_right(elm, field);                                     \
            while (splay_left(elm, field) != NULL) {                           \
                elm = splay_left(elm, field);                                  \
            }                                                                  \
        } else                                                                 \
            elm = NULL;                                                        \
        return (elm);                                                          \
    }                                                                          \
                                                                               \
    static inline struct type * __attribute__((no_instrument_function))        \
        name##_splay_prev(struct name * head, struct type * elm)               \
    {                                                                          \
        name##_splay(head, elm);                                               \
        if (splay_left(elm, field) != NULL) {                                  \
            elm = splay_left(elm, field);                                      \
            while (splay_right(elm, field) != NULL) {                          \
                elm = splay_right(elm, field);                                 \
            }                                                                  \
        } else                                                                 \
            elm = NULL;                                                        \
        return (elm);                                                          \
    }                                                                          \
                                                                               \
    static inline struct type * __attribute__((no_instrument_function))        \
        name##_splay_min_max(struct name * head, int val)                      \
    {                                                                          \
        name##_splay_minmax(head, val);                                        \
        return (splay_root(head));                                             \
    }                                                                          \
                                                                               \
    _Pragma("clang diagnostic pop")

/* Main splay operation.
 * Moves node close to the key of elm to top
 */
#define SPLAY_GENERATE(name, type, field, cmp)                                 \
    struct type * name##_splay_insert(struct name * head, struct type * elm)   \
    {                                                                          \
        if (splay_empty(head)) {                                               \
            splay_left(elm, field) = splay_right(elm, field) = NULL;           \
        } else {                                                               \
            int __comp;                                                        \
            name##_splay(head, elm);                                           \
            __comp = (cmp)(elm, (head)->sph_root);                             \
            if (__comp < 0) {                                                  \
                splay_left(elm, field) = splay_left((head)->sph_root, field);  \
                splay_right(elm, field) = (head)->sph_root;                    \
                splay_left((head)->sph_root, field) = NULL;                    \
            } else if (__comp > 0) {                                           \
                splay_right(elm, field) =                                      \
                    splay_right((head)->sph_root, field);                      \
                splay_left(elm, field) = (head)->sph_root;                     \
                splay_right((head)->sph_root, field) = NULL;                   \
            } else                                                             \
                return ((head)->sph_root);                                     \
        }                                                                      \
        splay_count(head)++;                                                   \
        (head)->sph_root = (elm);                                              \
        return (NULL);                                                         \
    }                                                                          \
                                                                               \
    struct type * name##_splay_remove(struct name * head, struct type * elm)   \
    {                                                                          \
        struct type * __tmp;                                                   \
        if (splay_empty(head))                                                 \
            return (NULL);                                                     \
        name##_splay(head, elm);                                               \
        if ((cmp)(elm, (head)->sph_root) == 0) {                               \
            if (splay_left((head)->sph_root, field) == NULL) {                 \
                (head)->sph_root = splay_right((head)->sph_root, field);       \
            } else {                                                           \
                __tmp = splay_right((head)->sph_root, field);                  \
                (head)->sph_root = splay_left((head)->sph_root, field);        \
                name##_splay(head, elm);                                       \
                splay_right((head)->sph_root, field) = __tmp;                  \
            }                                                                  \
            splay_count(head)--;                                               \
            return (elm);                                                      \
        }                                                                      \
        return (NULL);                                                         \
    }                                                                          \
                                                                               \
    void name##_splay(struct name * const head, const struct type * const elm) \
    {                                                                          \
        struct type __node;                                                    \
        struct type * __left;                                                  \
        struct type * __right;                                                 \
        struct type * __tmp;                                                   \
        int __comp;                                                            \
                                                                               \
        splay_left(&__node, field) = splay_right(&__node, field) = NULL;       \
        __left = __right = &__node;                                            \
                                                                               \
        while ((__comp = (cmp)(elm, (head)->sph_root)) != 0) {                 \
            if (__comp < 0) {                                                  \
                __tmp = splay_left((head)->sph_root, field);                   \
                if (__tmp == NULL)                                             \
                    break;                                                     \
                if ((cmp)(elm, __tmp) < 0) {                                   \
                    splay_rotate_right(head, __tmp, field);                    \
                    if (splay_left((head)->sph_root, field) == NULL)           \
                        break;                                                 \
                }                                                              \
                splay_linkleft(head, __right, field);                          \
            } else if (__comp > 0) {                                           \
                __tmp = splay_right((head)->sph_root, field);                  \
                if (__tmp == NULL)                                             \
                    break;                                                     \
                if ((cmp)(elm, __tmp) > 0) {                                   \
                    splay_rotate_left(head, __tmp, field);                     \
                    if (splay_right((head)->sph_root, field) == NULL)          \
                        break;                                                 \
                }                                                              \
                splay_linkright(head, __left, field);                          \
            }                                                                  \
        }                                                                      \
        splay_assemble(head, &__node, __left, __right, field);                 \
    }                                                                          \
                                                                               \
    /* Splay with either the minimum or the maximum element                    \
     * Used to find minimum or maximum element in tree.                        \
     */                                                                        \
    void name##_splay_minmax(struct name * head, int __comp)                   \
    {                                                                          \
        struct type __node;                                                    \
        struct type * __left;                                                  \
        struct type * __right;                                                 \
        struct type * __tmp;                                                   \
                                                                               \
        splay_left(&__node, field) = splay_right(&__node, field) = NULL;       \
        __left = __right = &__node;                                            \
                                                                               \
        while (1) {                                                            \
            if (__comp < 0) {                                                  \
                __tmp = splay_left((head)->sph_root, field);                   \
                if (__tmp == NULL)                                             \
                    break;                                                     \
                if (__comp < 0) {                                              \
                    splay_rotate_right(head, __tmp, field);                    \
                    if (splay_left((head)->sph_root, field) == NULL)           \
                        break;                                                 \
                }                                                              \
                splay_linkleft(head, __right, field);                          \
            } else if (__comp > 0) {                                           \
                __tmp = splay_right((head)->sph_root, field);                  \
                if (__tmp == NULL)                                             \
                    break;                                                     \
                if (__comp > 0) {                                              \
                    splay_rotate_left(head, __tmp, field);                     \
                    if (splay_right((head)->sph_root, field) == NULL)          \
                        break;                                                 \
                }                                                              \
                splay_linkright(head, __left, field);                          \
            }                                                                  \
        }                                                                      \
        splay_assemble(head, &__node, __left, __right, field);                 \
    }

#define splay_neginf -1
#define splay_inf 1

#define splay_insert(name, x, y) name##_splay_insert(x, y)
#define splay_remove(name, x, y) name##_splay_remove(x, y)
#define splay_find(name, x, y) name##_splay_find(x, y)
#define splay_next(name, x, y) name##_splay_next(x, y)
#define splay_prev(name, x, y) name##_splay_prev(x, y)
#define splay_min(name, x)                                                     \
    (splay_empty(x) ? NULL : name##_splay_min_max(x, splay_neginf))
#define splay_max(name, x)                                                     \
    (splay_empty(x) ? NULL : name##_splay_min_max(x, splay_inf))

#define splay_foreach(x, name, head)                                           \
    for ((x) = splay_min(name, head); (x) != NULL;                             \
         (x) = splay_next(name, head, x))

#define splay_foreach_rev(x, name, head)                                       \
    for ((x) = splay_max(name, head); (x) != NULL;                             \
         (x) = splay_prev(name, head, x))

#endif // __TREE_H__
