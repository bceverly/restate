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

bool rs_glob_match(const char *pattern, const char *path)
{
    struct rs_buf  anchored;
    struct nfa     n;
    unsigned char *next;
    unsigned char *next_mid;
    size_t         s;
    bool           matched;

    /* An unanchored pattern matches at any depth. */
    rs_buf_init(&anchored);
    if (pattern[0] != '/')
    {
        rs_buf_addstr(&anchored, "**/");
    }
    rs_buf_addstr(&anchored, pattern);
    n.p = anchored.data;
    n.plen = anchored.len;
    n.live = rs_xcalloc(n.plen + 1, 1);
    n.mid = rs_xcalloc(n.plen + 1, 1);
    n.work = rs_xcalloc(n.plen + 1, sizeof(*n.work));
    next = rs_xcalloc(n.plen + 1, 1);
    next_mid = rs_xcalloc(n.plen + 1, 1);
    add_closure(&n, n.live, 0);

    for (s = 0; path[s] != '\0'; s++)
    {
        char   c = path[s];
        size_t i;
        bool   any = false;

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

    matched = path[s] == '\0' && n.live[n.plen];
    free(n.live);
    free(n.mid);
    free(n.work);
    free(next);
    free(next_mid);
    rs_buf_free(&anchored);
    return matched;
}

bool rs_glob_covers(const char *pattern, const char *path)
{
    char  *prefix;
    size_t i;
    bool   hit = false;

    if (rs_glob_match(pattern, path))
    {
        return true;
    }
    /* An empty path has no ancestors, and the loop below starts one byte in.
     * Every caller passes a clean absolute path, but this is the kind of
     * assumption the fuzzer exists to test, and it did. */
    if (path[0] == '\0')
    {
        return false;
    }
    /* Each ancestor: "/a/b/c" tries "/a" and "/a/b". "/" itself is not
     * tried, so a rule for everything has to say "/" followed by "**": a rule
     * that silently covered the whole filesystem because of a typo would be a
     * bad thing to make easy. */
    prefix = rs_xstrdup(path);
    for (i = 1; prefix[i] != '\0' && !hit; i++)
    {
        if (prefix[i] == '/')
        {
            prefix[i] = '\0';
            hit = rs_glob_match(pattern, prefix);
            prefix[i] = '/';
        }
    }
    free(prefix);
    return hit;
}
