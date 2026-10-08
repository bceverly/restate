/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
/*
 * The matcher is a simulation of the pattern as a nondeterministic automaton:
 * the set of pattern positions that are still alive is carried across the
 * path one character at a time. No backtracking, so no pathological pattern.
 *
 * Positions are byte offsets into the pattern. A position is "alive" if the
 * part of the path consumed so far can be matched by the part of the pattern
 * before it.
 */
#include "glob.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "util.h"

/* The token at pattern position i. */
enum tok {
    TOK_END,
    TOK_ANYDIRS,    /* "**" + "/": zero or more whole directories    */
    TOK_STARSTAR,   /* "**" anywhere else: any run, slashes included */
    TOK_STAR,       /* "*"                                           */
    TOK_QUESTION,   /* "?"                                           */
    TOK_LITERAL     /* any other byte, or "\c"                       */
};

static enum tok token_at(const char *p, size_t i, size_t plen, char *lit, size_t *width)
{
    if (i >= plen)
    {
        *width = 0;
        return TOK_END;
    }
    if (p[i] == '*')
    {
        if (i + 1 < plen && p[i + 1] == '*')
        {
            if (i + 2 < plen && p[i + 2] == '/')
            {
                *width = 3;
                return TOK_ANYDIRS;
            }
            *width = 2;
            return TOK_STARSTAR;
        }
        *width = 1;
        return TOK_STAR;
    }
    if (p[i] == '?')
    {
        *width = 1;
        return TOK_QUESTION;
    }
    if (p[i] == '\\' && i + 1 < plen)
    {
        *lit = p[i + 1];
        *width = 2;
        return TOK_LITERAL;
    }
    *lit = p[i];
    *width = 1;
    return TOK_LITERAL;
}

/*
 * The automaton's state is two sets of pattern positions.
 *
 *   live[i]  the pattern before position i has matched everything consumed
 *   mid[i]   position i is a "**" + "/" token that is part-way through a
 *            directory name -- it has consumed some characters since the last
 *            slash, so it may not yet end
 *
 * The second set is what makes "**" + "/" mean whole directories: from live[i]
 * it may vanish (zero directories), but once it has eaten "x" it must eat up to
 * and including a '/' before the rest of the pattern can start. Without it,
 * ".cache" -- which is anchored as "**" + "/.cache" -- would match "x.cache".
 */
struct nfa {
    unsigned char *live;
    unsigned char *mid;
    size_t        *work;
    const char    *p;
    size_t         plen;
};

/*
 * Adds position i to the live set, with everything reachable from it without
 * consuming a character: past "*" and "**" (either may match nothing) and past
 * "**" + "/" (zero directories).
 *
 * A worklist rather than recursion, so ten thousand stars cost a loop rather
 * than a stack. Each position is pushed at most once -- it is marked as it is
 * pushed -- so `work` never needs more than plen + 1 slots.
 */
static void add_closure(const struct nfa *n, unsigned char *live, size_t start)
{
    size_t top = 0;

    if (live[start])
    {
        return;
    }
    live[start] = 1;
    n->work[top++] = start;
    while (top > 0)
    {
        size_t   i = n->work[--top];
        size_t   width;
        char     lit = 0;
        enum tok t = token_at(n->p, i, n->plen, &lit, &width);

        if (t == TOK_STAR || t == TOK_STARSTAR || t == TOK_ANYDIRS)
        {
            size_t to = i + width;

            if (to <= n->plen && !live[to])
            {
                live[to] = 1;
                n->work[top++] = to;
            }
        }
    }
}

/* Patterns this long or shorter are matched without allocating. */
#define SMALL_PATTERN 256

/*
 * Runs the automaton for `pattern` over `path`: true if it matches the whole
 * of `path` or, with `ancestors`, any ancestor of it -- the path up to any
 * '/' after the first character, "/" itself excepted. An ancestor is a prefix
 * the automaton has read when it reaches that '/', so one pass answers for
 * all of them.
 */
static bool run(const char *pattern, const char *path, bool ancestors)
{
    unsigned char  small[4][SMALL_PATTERN + 4];
    size_t         small_work[SMALL_PATTERN + 4];
    char           small_p[SMALL_PATTERN + 4];
    char          *anchored = small_p;
    struct nfa     n;
    unsigned char *next;
    unsigned char *next_mid;
    size_t         plen = strlen(pattern);
    size_t         s;
    bool           heap;
    bool           matched = false;

    /* An unanchored pattern matches at any depth. */
    n.plen = plen + (pattern[0] != '/' ? 3 : 0);
    heap = n.plen > SMALL_PATTERN;
    if (heap)
    {
        anchored = rs_xmalloc(n.plen + 1);
    }
    (void)snprintf(anchored, n.plen + 1, "%s%s", pattern[0] != '/' ? "**/" : "", pattern);
    n.p = anchored;
    if (heap)
    {
        n.live = rs_xcalloc(n.plen + 1, 1);
        n.mid = rs_xcalloc(n.plen + 1, 1);
        n.work = rs_xcalloc(n.plen + 1, sizeof(*n.work));
        next = rs_xcalloc(n.plen + 1, 1);
        next_mid = rs_xcalloc(n.plen + 1, 1);
    } else
    {
        n.live = small[0];
        n.mid = small[1];
        n.work = small_work;
        next = small[2];
        next_mid = small[3];
        memset(n.live, 0, n.plen + 1);
        memset(n.mid, 0, n.plen + 1);
    }
    add_closure(&n, n.live, 0);

    for (s = 0; path[s] != '\0'; s++)
    {
        char   c = path[s];
        size_t i;
        bool   any = false;

        if (ancestors && c == '/' && s > 0 && n.live[n.plen])
        {
            matched = true;
            break;
        }
        memset(next, 0, n.plen + 1);
        memset(next_mid, 0, n.plen + 1);
        for (i = 0; i < n.plen; i++)
        {
            size_t   width;
            char     lit = 0;
            enum tok t;

            if (!n.live[i] && !n.mid[i])
            {
                continue;
            }
            t = token_at(n.p, i, n.plen, &lit, &width);
            if (t == TOK_ANYDIRS)
            {
                /* From either state: a slash completes a directory, which
                 * returns to the fresh state where the token may end; any
                 * other character is the inside of a name. */
                if (c == '/')
                {
                    add_closure(&n, next, i);
                } else
                {
                    next_mid[i] = 1;
                }
                any = true;
                continue;
            }
            if (!n.live[i])
            {
                continue;
            }
            switch (t)
            {
            case TOK_STARSTAR:
                add_closure(&n, next, i);
                any = true;
                break;
            case TOK_STAR:
                if (c != '/')
                {
                    add_closure(&n, next, i);
                    any = true;
                }
                break;
            case TOK_QUESTION:
                if (c != '/')
                {
                    add_closure(&n, next, i + width);
                    any = true;
                }
                break;
            case TOK_LITERAL:
                if (c == lit)
                {
                    add_closure(&n, next, i + width);
                    any = true;
                }
                break;
            case TOK_ANYDIRS:
            case TOK_END:
            default:
                break;
            }
        }
        {
            unsigned char *swap = n.live;

            n.live = next;
            next = swap;
            swap = n.mid;
            n.mid = next_mid;
            next_mid = swap;
        }
        if (!any)
        {
            break;
        }
    }

    if (!matched)
    {
        matched = path[s] == '\0' && n.live[n.plen];
    }
    if (heap)
    {
        free(n.live);
        free(n.mid);
        free(n.work);
        free(next);
        free(next_mid);
        free(anchored);
    }
    return matched;
}

/* The length of the literal start of an anchored pattern: everything before
 * its first "*", "?" or "\\". */
static size_t literal_len(const char *pattern)
{
    return strcspn(pattern, "*?\\");
}

/*
 * Whether `path` holds the longest run of plain characters in `pattern`.
 * Whatever the pattern matches -- the path, or an ancestor, itself a prefix
 * of the path -- holds every such run, so a path without it cannot match,
 * and most paths are turned away here for the cost of a substring search.
 */
static bool holds_literal(const char *pattern, const char *path)
{
    char   needle[SMALL_PATTERN + 1];
    size_t best = 0;
    size_t at = 0;
    size_t start = 0;
    size_t i;

    /* An escape makes the plain runs harder to see; leave it to the
     * automaton. */
    if (strchr(pattern, '\\'))
    {
        return true;
    }
    for (i = 0;; i++)
    {
        char c = pattern[i];

        if (c == '\0' || c == '*' || c == '?')
        {
            if (i - start > best)
            {
                best = i - start;
                at = start;
            }
            if (c == '\0')
            {
                break;
            }
            start = i + 1;
        }
    }
    if (best == 0 || best > SMALL_PATTERN)
    {
        return true;
    }
    memcpy(needle, pattern + at, best);
    needle[best] = '\0';
    return strstr(path, needle) != NULL;
}

bool rs_glob_match(const char *pattern, const char *path)
{
    if (pattern[0] == '/')
    {
        size_t lit = literal_len(pattern);

        if (pattern[lit] == '\0')
        {
            return strcmp(pattern, path) == 0;
        }
        if (strncmp(pattern, path, lit) != 0)
        {
            return false;
        }
    }
    return holds_literal(pattern, path) && run(pattern, path, false);
}

bool rs_glob_covers(const char *pattern, const char *path)
{
    /* Every caller passes a clean absolute path, but an empty one has no
     * ancestors, and this is the kind of assumption the fuzzer exists to
     * test, and it did. "/" itself is never an ancestor that is tried, so a
     * rule for everything has to say "/" followed by "**": a rule that
     * silently covered the whole filesystem because of a typo would be a bad
     * thing to make easy. */
    if (pattern[0] == '/')
    {
        size_t lit = literal_len(pattern);

        /* Whatever matches -- the path or an ancestor, itself a prefix of
         * the path -- starts with the pattern's literal start. */
        if (strncmp(pattern, path, lit) != 0)
        {
            return false;
        }
        if (pattern[lit] == '\0')
        {
            return path[lit] == '\0' || path[lit] == '/';
        }
    }
    return holds_literal(pattern, path) && run(pattern, path, path[0] != '\0');
}
