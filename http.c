#define _GNU_SOURCE
#include <arpa/inet.h>
#include <ctype.h>
#include <err.h>
#include <netdb.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include "truncate.h"
#include "chunked.h"
#include "inflate.h"
#include "http.h"
#include "json.h"

static SSL_CTX *ssl_ctx = NULL;

static char token[16384] = { 0 };

static void ssl_destroy()
{
    if (ssl_ctx) {
        SSL_CTX_free(ssl_ctx);
    }
}

static void ssl_init()
{
    if (!ssl_ctx) {
        SSL_load_error_strings();
        SSL_library_init();
        ssl_ctx = SSL_CTX_new(TLS_client_method());
        SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER, NULL);
        int err = SSL_CTX_set_default_verify_paths(ssl_ctx);
        if (err != 1) {
            fprintf(stderr, "SSL_CTX_set_default_verify_paths: %s\n", ERR_error_string(ERR_get_error(), NULL));
        }

        at_quick_exit(ssl_destroy);
        atexit(ssl_destroy);
    }
}

int urlencode(char *dest, const char *src)
{
    int n = 0;
    for (int i = 0; src[i]; i++) {
        if ('A' <= src[i] && src[i] <= 'Z') dest[n++] = src[i];
        else if ('a' <= src[i] && src[i] <= 'z') dest[n++] = src[i];
        else if ('0' <= src[i] && src[i] <= '9') dest[n++] = src[i];
        else if (src[i] == '-' || src[i] == '_' || src[i] == '.' || src[i] == '~') dest[n++] = src[i];
        else n += sprintf(dest+n, "%%%02X", src[i]);
    }

    return n;
}

int urlparse(const char *url, bool *is_https, char *host, char *port, char *path)
{
    if (!strncmp(url, "http://", strlen("http://"))) {
        *is_https = false;
        url += strlen("http://");
    }
    else if (!strncmp(url, "https://", strlen("https://"))) {
        *is_https = true;
        url += strlen("https://");
    }
    else return -1;

    if (!sscanf(url, "%" URLLEN_S "[^:/]", host)) return -1;
    url += strlen(host);

    if (*url == ':') {
        if (!sscanf(url+1, "%" URLLEN_S "[0123456789]", port)) return -1;
        url += strlen(port) + 1;
    }
    else strcpy(port, *is_https ? "443" : "80");

    if (*url) strcpy(path, url);
    else strcpy(path, "/");

    return 0;
}

static int ssl_close(void *cookie)
{
    SSL *ssl = (SSL *)cookie;
    int fd = SSL_get_fd(ssl);
    SSL_shutdown(ssl);
    SSL_free(ssl);
    return close(fd);
}

static ssize_t ssl_read(void *cookie, char *buf, size_t size)
{
    SSL *ssl = (SSL *)cookie;
    int ret = SSL_read(ssl, buf, size);
    
    switch (SSL_get_error(ssl, ret)) {
    case SSL_ERROR_NONE:
        return ret;
    case SSL_ERROR_ZERO_RETURN:
        return 0;
    case SSL_ERROR_SYSCALL:
        err(1, "ssl_read");
    default:
        return -1;
    }
}

static ssize_t ssl_write(void *cookie, const char *buf, size_t size)
{
    SSL *ssl = (SSL *)cookie;
    int ret = SSL_write(ssl, buf, size);

    switch (SSL_get_error(ssl, ret)) {
    case SSL_ERROR_NONE:
        return ret;
    case SSL_ERROR_SYSCALL:
        perror("ssl_write");
    default:
        return 0;
    }
}

FILE *urlopen(char *url, unsigned flags, const char *accept)
{
    bool is_https;
    char host[URLLEN+1], port[URLLEN+1], path[URLLEN+1];

    int sock = -1;
    SSL *ssl = NULL;
    FILE *f = NULL;

    if (urlparse(url, &is_https, host, port, path) < 0) goto out;

    fprintf(stderr, "Resolving %s on %s; requesting %s...\n", host, port, path);

    struct addrinfo hints = {
        .ai_family = AF_UNSPEC,
        .ai_socktype = SOCK_STREAM,
        .ai_flags = 0,
        .ai_protocol = 0
    };

    struct addrinfo *result;
    int ret = getaddrinfo(host, port, &hints, &result);
    if (ret != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(ret));
        goto out;
    }

    for (struct addrinfo *rp = result; rp; rp = rp->ai_next) {
        char ip[INET6_ADDRSTRLEN];
        inet_ntop(rp->ai_family, rp->ai_family == AF_INET ? (void *)&((struct sockaddr_in *)rp->ai_addr)->sin_addr : (void *)&((struct sockaddr_in6 *)rp->ai_addr)->sin6_addr, ip, INET6_ADDRSTRLEN);
        fprintf(stderr, "Trying %s...\n", ip);

        sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sock == -1) {
            perror("socket");
            continue;
        }
        
        if (connect(sock, rp->ai_addr, rp->ai_addrlen) != -1) break;
        else perror("connect");

        close(sock);
        sock = -1;
    }

    freeaddrinfo(result);

    if (sock == -1) {
        fprintf(stderr, "Could not connect to any of the addresses.\n");
        goto out;
    }

    if (is_https) {
        ssl_init();

        ssl = SSL_new(ssl_ctx);

        if (flags & HTTP_IGNSSL) SSL_set_verify(ssl, SSL_VERIFY_NONE, NULL);

        SSL_set_hostflags(ssl, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
        if (!SSL_set1_host(ssl, host)) {
            fprintf(stderr, "SSL_set1_host: %s\n", ERR_error_string(ERR_get_error(), NULL));
            goto out;
        }

        SSL_set_fd(ssl, sock);
        SSL_set_tlsext_host_name(ssl, host);

        if (SSL_connect(ssl) != 1) {
            fprintf(stderr, "SSL_connect: %s, verification: %s\n", ERR_error_string(ERR_get_error(), NULL), X509_verify_cert_error_string(SSL_get_verify_result(ssl)));
            goto out;
        }

        cookie_io_functions_t io_funcs = {
            .close = ssl_close,
            .read = ssl_read,
            .write = ssl_write,
            .seek = NULL
        };

        f = fopencookie(ssl, "w+", io_funcs);
    }
    else f = fdopen(sock, "w+");

    fprintf(f, "GET %s HTTP/1.1\r\nHost: %s:%s\r\nConnection: close\r\nAccept-Encoding: gzip, deflate, identity\r\n", path, host, port);
    if (accept) fprintf(f, "Accept: %s\r\n", accept);
    if (token[0]) fprintf(f, "Authorization: Bearer %s\r\n", token);
    fprintf(f, "\r\n");

    char buf[1024];
    if (!fgets(buf, 1024, f)) goto out; // Server hung up too early

    int code; char msg[1024];
    if (sscanf(buf, "HTTP/1.1 %d %100[^\r]", &code, msg) != 2) {
        fprintf(stderr, "Invalid response: %s\n", buf);
        goto out;
    }
    
    int inflate = 0, chunked = 0;
    size_t length = 0;
    while (fgets(buf, 1024, f) && buf[0] != '\r') {
        for (int i = 0; buf[i] && buf[i] != ':'; i++) buf[i] = tolower(buf[i]);

        char header[1024] = { 0 };

        if (sscanf(buf, "location: %1000s", header) && 300 <= code && code < 400 && !(flags & HTTP_IGNREDIR)) {
            fprintf(stderr, "HTTP %d: %s, location: %s\n", code, msg, header);
            fclose(f);
            return urlopen(header, flags | HTTP_IGNREDIR, accept);
        }

        if (sscanf(buf, "www-authenticate: Bearer %1000[^\r]", header) && 400 <= code && code < 500 && !(flags & HTTP_IGNBEARER)) {
            fprintf(stderr, "HTTP %d: %s, Bearer %s\n", code, msg, header);
            fclose(f);

            char bearer_url[URLLEN] = { 0 }, bearer_query[URLLEN] = { 0 };
            int n = 0;

            FILE *fs = fmemopen(header, 1024, "r");
            char key[100] = { 0 }, val[100] = { 0 };
            while (fscanf(fs, "%100[^=]=\"%100[^\"]\",", key, val) == 2) {
                if (!strcmp(key, "realm")) {
                    strcpy(bearer_url, val);
                }
                else {
                    n += sprintf(bearer_query + n, "%s=", key);
                    n += urlencode(bearer_query + n, val);
                    bearer_query[n++] = '&';
                }
            }
            fclose(fs);

            if (n > 0) {
                strcat(bearer_url, "?");
                strcat(bearer_url, bearer_query);
            }

            FILE *f_bearer = urlopen(bearer_url, flags | HTTP_IGNBEARER, "text/json");
            if (!f_bearer) errx(1, "Could not open %s", bearer_url);

            char json[16384];
            if (!fread(json, 1, 16384, f_bearer)) errx(1, "Could not read from %s", bearer_url);
            if (!feof(f_bearer)) errx(1, "Buffer too short");
            fclose(f_bearer);

            jstr(jget(json, "token"), token, 16384);

            return urlopen(url, flags | HTTP_IGNBEARER, accept);
        }

        if (sscanf(buf, "content-encoding: %1000s", header)) {
            if (!strcmp(header, "gzip")) inflate = 1;
            else if (!strcmp(header, "deflate")) inflate = -1;
            else {
                fprintf(stderr, "Unsupported content-encoding: %s\n", header);
                fclose(f);
                return NULL;
            }
        }

        if (sscanf(buf, "transfer-encoding: %1000s", header)) {
            if (!strcmp(header, "chunked")) chunked = 1;
            else if (strcmp(header, "identity")) {
                fprintf(stderr, "Unsupported transfer-encoding: %s\n", header);
                fclose(f);
                return NULL;
            }
        }

        sscanf(buf, "Content-Length: %lu", &length);
    }

    if (code >= 400) {
        fprintf(stderr, "HTTP %d: %s\n", code, msg);
        goto out;
    }

    if (length) f = ftrunc(f, length, TRUNC_AUTOCLOSE);
    if (chunked) f = fchunk(f, CHUNK_AUTOCLOSE);
    if (inflate == 1) f = finfl(f, INFL_AUTOCLOSE);
    if (inflate == -1) f = finfl(f, INFL_RAW | INFL_AUTOCLOSE);

    return f;

out:
    if (f) {
        fclose(f);
    }
    else {
        if (ssl) {
            SSL_shutdown(ssl);
            SSL_free(ssl);
        }
        if (sock != -1) {
            close(sock);
        }
    }
    return NULL;
}
