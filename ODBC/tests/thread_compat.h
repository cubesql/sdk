/*
 * Threading minimo e portabile per la suite di conformita'.
 *
 * Il test di concorrenza esiste per far emergere i lock mancanti, e il locking
 * che deve mettere sotto sforzo e' quello di Windows (CRITICAL_SECTION): finche'
 * il test usava direttamente pthread girava solo su POSIX, cioe' proprio dove
 * quel codice non viene compilato.
 */
#ifndef CUBESQL_ODBC_THREAD_COMPAT_H
#define CUBESQL_ODBC_THREAD_COMPAT_H

#include <stdlib.h>

typedef void *(*cs_thread_fn)(void *);

#ifdef _WIN32
#include <windows.h>

typedef HANDLE cs_thread;

struct cs_thread_start { cs_thread_fn fn; void *arg; };

static DWORD WINAPI cs_thread_trampoline(LPVOID raw) {
    struct cs_thread_start *s = (struct cs_thread_start *)raw;
    cs_thread_fn fn = s->fn;
    void *arg = s->arg;
    free(s);
    fn(arg);
    return 0;
}

static int cs_thread_create(cs_thread *t, cs_thread_fn fn, void *arg) {
    struct cs_thread_start *s = (struct cs_thread_start *)malloc(sizeof(*s));
    if (!s) return -1;
    s->fn = fn;
    s->arg = arg;
    *t = CreateThread(NULL, 0, cs_thread_trampoline, s, 0, NULL);
    if (*t == NULL) { free(s); return -1; }
    return 0;
}

static void cs_thread_join(cs_thread t) {
    WaitForSingleObject(t, INFINITE);
    CloseHandle(t);
}

#else
#include <pthread.h>

typedef pthread_t cs_thread;

static int cs_thread_create(cs_thread *t, cs_thread_fn fn, void *arg) {
    return pthread_create(t, NULL, fn, arg);
}

static void cs_thread_join(cs_thread t) {
    pthread_join(t, NULL);
}

#endif

#endif
