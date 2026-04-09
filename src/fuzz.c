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

    /* Open file in text mode and read line-by-line, sending each line as an inline
     * Redis command (line\r\n). The loop tails the file: when EOF is reached it
     * sleeps briefly and continues waiting for new lines to appear.
     */
    fp = fopen(a->input_file, "r");
    if (!fp) {
        fprintf(stderr, "fuzz: failed to open input file '%s': %s\n", a->input_file, strerror(errno));
        goto cleanup;
    }

    /* Try to establish a connection before reading if possible */
    sock = connect_to_redis(a->host, a->port);

    char *line = NULL;
    size_t linecap = 0;
    ssize_t linelen;

    while (1) {
        /* Record current file position so we can rewind on send/connect failures */
        long off = ftell(fp);

        linelen = getline(&line, &linecap, fp);
        if (linelen == -1) {
            if (feof(fp)) {
                /* No new line yet - sleep briefly and continue (tail -f behavior) */
                clearerr(fp);
                struct timespec ts = { .tv_sec = 0, .tv_nsec = 100000000L }; /* 100ms */
                nanosleep(&ts, NULL);
                continue;
            } else {
                /* Some read error - log and back off */
                fprintf(stderr, "fuzz: getline error: %s\n", strerror(errno));
                clearerr(fp);
                struct timespec ts = { .tv_sec = 0, .tv_nsec = 100000000L }; /* 100ms */
                nanosleep(&ts, NULL);
                continue;
            }
        }

        /* Trim trailing newline/carriage return */
        trim_newline(line);

        /* Prepare payload: line + CRLF (inline command) */
        size_t payload_len = strlen(line) + 2;
        char *payload = malloc(payload_len + 1);
        if (!payload) {
            fprintf(stderr, "fuzz: malloc failed for payload\n");
            /* On allocation failure, skip this line after a short backoff */
            struct timespec ts = { .tv_sec = 0, .tv_nsec = 100000000L };
            nanosleep(&ts, NULL);
            continue;
        }
        memcpy(payload, line, strlen(line));
        payload[strlen(line)] = '\r';
        payload[strlen(line) + 1] = '\n';
        payload[payload_len] = '\0';

        /* Ensure connection; if not connected, attempt to connect, with retry.
         * If connect fails, rewind file to re-read this line later.
         */
        if (sock == -1) {
            sock = connect_to_redis(a->host, a->port);
            if (sock == -1) {
                struct timespec ts = { .tv_sec = 1, .tv_nsec = 0 };
                nanosleep(&ts, NULL);
                if (fseek(fp, off, SEEK_SET) == 0) {
                    free(payload);
                    continue;
                } else {
                    /* If we can't rewind, drop the line and continue */
                    free(payload);
                    continue;
                }
            }
        }

        /* Send the payload, retrying on EINTR. On failure, close socket and rewind
         * the file so the line is retried after reconnect.
         */
        size_t sent_total = 0;
        while (sent_total < payload_len) {
            printf("SENT PAYLOAD:%s\n", payload);
            ssize_t s = send(sock, payload + sent_total, payload_len - sent_total, 0);
            if (s < 0) {
                if (errno == EINTR) continue;
                fprintf(stderr, "fuzz: send failed: %s\n", strerror(errno));
                close(sock);
                sock = -1;
                if (fseek(fp, off, SEEK_SET) != 0) {
                    /* can't rewind - give up on rewinding this line */
                }
                break;
            }
            sent_total += (size_t)s;
        }

        free(payload);

        /* Optional small delay between lines to avoid overwhelming server */
        if (a->delay_ms > 0) {
            struct timespec ts;
            ts.tv_sec = a->delay_ms / 1000;
            ts.tv_nsec = (a->delay_ms % 1000) * 1000000L;
            nanosleep(&ts, NULL);
        }
    }

    free(line);

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

    printf("INPUT_FILE:%s, HOST:%s, PORT:%s, DELAY_MS:%d\n", args->input_file, args->host, args->port, args->delay_ms);
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
