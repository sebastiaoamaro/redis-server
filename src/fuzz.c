/*
 * redis/src/fuzz.c
 *
 * Simple fuzz helper: spawn a thread that reads lines from an input file
 * and sends each line over a TCP connection to a Redis server (inline
 * command mode). The thread reconnects on failures and keeps going until
 * EOF. The main function `fuzz_server` starts the background thread and
 * returns immediately.
 *
 * Configuration via environment variables:
 *   FUZZ_REDIS_HOST  - default "127.0.0.1"
 *   FUZZ_REDIS_PORT  - default "6379"
 *   FUZZ_DELAY_MS    - optional delay between lines in milliseconds (default 0)
 *
 * Notes:
 *  - Lines are sent as "line\r\n" (Redis inline command style). If your
 *    inputs are raw Redis RESP messages, you can change the formatting.
 *  - The thread is detached and runs independently.
 */

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <unistd.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>

/* Defaults */
static const char *DEFAULT_REDIS_HOST = "127.0.0.1";
static const char *DEFAULT_REDIS_PORT = "6379";

/* Helper: get integer from env or default */
static int getenv_int_with_default(const char *name, int def) {
    const char *v = getenv(name);
    if (!v) return def;
    char *end;
    long val = strtol(v, &end, 10);
    if (end == v || val <= 0) return def;
    return (int)val;
}

/* Helper: connect to host:port using getaddrinfo, returns socket fd or -1 */
static int connect_to_redis(const char *host, const char *port) {
    struct addrinfo hints, *res = NULL, *rp;
    int sfd = -1;
    int rc;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;       /* Allow IPv4 or IPv6 */
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    rc = getaddrinfo(host, port, &hints, &res);
    if (rc != 0) {
        fprintf(stderr, "fuzz: getaddrinfo(%s:%s) failed: %s\n", host, port, gai_strerror(rc));
        return -1;
    }

    for (rp = res; rp != NULL; rp = rp->ai_next) {
        sfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sfd == -1) continue;
        if (connect(sfd, rp->ai_addr, rp->ai_addrlen) == 0) {
            /* success */
            break;
        }
        close(sfd);
        sfd = -1;
    }

    freeaddrinfo(res);
    if (sfd == -1) {
        fprintf(stderr, "fuzz: could not connect to %s:%s\n", host, port);
    }
    return sfd;
}

/* Trim trailing newline and carriage return from a line in-place */
static void trim_newline(char *s) {
    size_t len = strlen(s);
    while (len > 0) {
        if (s[len - 1] == '\n' || s[len - 1] == '\r') {
            s[len - 1] = '\0';
            len--;
        } else break;
    }
}

/* The thread routine: read lines and send to Redis */
struct fuzz_thread_args {
    char *input_file;
    char *host;
    char *port;
    int delay_ms;
};

static void *fuzz_thread_func(void *arg) {
    struct fuzz_thread_args *a = (struct fuzz_thread_args *)arg;
    FILE *fp = NULL;
    int sock = -1;

    /* Open file in binary mode to read raw RESP messages */
    fp = fopen(a->input_file, "rb");
    if (!fp) {
        fprintf(stderr, "fuzz: failed to open input file '%s': %s\n", a->input_file, strerror(errno));
        goto cleanup;
    }

    /* Buffer for streaming binary data */
    const size_t BUF_SZ = 4096;
    unsigned char *buf = malloc(BUF_SZ);
    if (!buf) {
        fprintf(stderr, "fuzz: malloc buffer failed\n");
        goto cleanup;
    }

    /* Try to establish a connection before reading if possible */
    sock = connect_to_redis(a->host, a->port);

    /* Read raw bytes and forward them to Redis as-is */
    while (!feof(fp)) {
        size_t nread = fread(buf, 1, BUF_SZ, fp);
        if (nread == 0) {
            if (ferror(fp)) {
                fprintf(stderr, "fuzz: fread error: %s\n", strerror(errno));
                clearerr(fp);
                /* small backoff on read error */
                struct timespec ts = { .tv_sec = 0, .tv_nsec = 100000000L }; /* 100ms */
                nanosleep(&ts, NULL);
                continue;
            } else {
                break; /* EOF */
            }
        }

        /* Ensure connection; if not connected, attempt to connect, with retry */
        if (sock == -1) {
            sock = connect_to_redis(a->host, a->port);
            if (sock == -1) {
                /* If we can't connect, wait a bit and retry */
                struct timespec ts = { .tv_sec = 1, .tv_nsec = 0 };
                nanosleep(&ts, NULL);
                /* Seek back by nread so we will resend this chunk after reconnect */
                if (fseek(fp, -(long)nread, SEEK_CUR) == 0) {
                    continue;
                } else {
                    /* If fseek fails on this stream, just continue reading forward */
                    continue;
                }
            }
        }

        /* Send the exact binary data read */
        size_t sent_total = 0;
        while (sent_total < nread) {
            ssize_t s = send(sock, buf + sent_total, nread - sent_total, 0);
            if (s < 0) {
                if (errno == EINTR) continue;
                fprintf(stderr, "fuzz: send failed: %s\n", strerror(errno));
                close(sock);
                sock = -1;
                /* Rewind the file by the unsent portion so it's retried after reconnect */
                if (sent_total > 0) {
                    long rewind_bytes = (long)(nread - sent_total);
                    if (fseek(fp, -rewind_bytes, SEEK_CUR) != 0) {
                        /* if rewind fails, just continue */
                    }
                } else {
                    /* nothing sent from this chunk, rewind whole chunk */
                    if (fseek(fp, -(long)nread, SEEK_CUR) != 0) {
                        /* can't rewind, continue */
                    }
                }
                break;
            }
            sent_total += (size_t)s;
        }

        /* Optional small delay between chunks to avoid overwhelming server */
        if (a->delay_ms > 0) {
            struct timespec ts;
            ts.tv_sec = a->delay_ms / 1000;
            ts.tv_nsec = (a->delay_ms % 1000) * 1000000L;
            nanosleep(&ts, NULL);
        }
    }

    free(buf);

cleanup:
    if (sock != -1) close(sock);
    if (fp) fclose(fp);
    free(a->input_file);
    free(a->host);
    free(a->port);
    free(a);
    return NULL;
}

/*
 * Public API:
 *   fuzz_server(input_file)
 *
 * Starts a detached thread that streams lines from `input_file` to Redis.
 * Returns 0 on successful thread creation, -1 on error.
 */
int fuzz_server(char *input_file) {
    if (!input_file) {
        fprintf(stderr, "fuzz: input_file is NULL\n");
        return -1;
    }

    /* Read configuration from environment, copy strings for the thread */
    const char *env_host = getenv("FUZZ_REDIS_HOST");
    const char *env_port = getenv("FUZZ_REDIS_PORT");
    int delay_ms = getenv_int_with_default("FUZZ_DELAY_MS", 0);

    struct fuzz_thread_args *args = calloc(1, sizeof(*args));
    if (!args) {
        fprintf(stderr, "fuzz: calloc failed\n");
        return -1;
    }

    args->input_file = strdup(input_file);
    args->host = strdup(env_host ? env_host : DEFAULT_REDIS_HOST);
    args->port = strdup(env_port ? env_port : DEFAULT_REDIS_PORT);
    args->delay_ms = delay_ms;

    if (!args->input_file || !args->host || !args->port) {
        fprintf(stderr, "fuzz: strdup failed\n");
        free(args->input_file);
        free(args->host);
        free(args->port);
        free(args);
        return -1;
    }

    pthread_t tid;
    int rc = pthread_create(&tid, NULL, fuzz_thread_func, args);
    if (rc != 0) {
        fprintf(stderr, "fuzz: pthread_create failed: %s\n", strerror(rc));
        free(args->input_file);
        free(args->host);
        free(args->port);
        free(args);
        return -1;
    }

    /* Detach thread: it will clean up its own arguments */
    rc = pthread_detach(tid);
    if (rc != 0) {
        fprintf(stderr, "fuzz: pthread_detach failed: %s\n", strerror(rc));
        /* Not fatal: the thread is still running; we just didn't detach it */
    }

    return 0;
}

/* If built as a standalone test binary, you could add a main() here.
 * For integration in Redis sources we do not add a main by default.
 */