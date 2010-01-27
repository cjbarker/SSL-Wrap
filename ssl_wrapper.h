#ifndef __SSL_WRAPPER_H__
#define __SSL_WRAPPER_H__

#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/err.h>

#ifdef  __cplusplus
extern "C" {
#endif

/* globals */
enum MethodType 
{
    Server, 
    Client
};

static int initialized_engine = 0;        

typedef struct {
    SSL_CTX *ctx;
    SSL *ssl;
    enum MethodType type;
    int state_set;
    int sock_fd;
} SSLWrapper;


/* prototypes */
static void init_ssl(void);
SSLWrapper* SSLWrapper_new(enum MethodType);
void SSLWrapper_free(SSLWrapper *wrapper);
void SSLWrapper_close_ssl(SSLWrapper *wrapper);
int SSLWrapper_accept(SSLWrapper *wrapper);
int SSLWrapper_load_certificate(SSLWrapper * wrapper, char* certFile, char* keyFile);
int SSLWrapper_read(SSLWrapper *wrapper, const void *buf, int num);
int SSLWrapper_write(SSLWrapper *wrapper, const void *buf, int num);
int SSLWrapper_set_state(SSLWrapper * wrapper);
int SSLWrapper_verify_cert(SSLWrapper * wrapper);
void SSLWrapper_print_cert(SSLWrapper * wrapper);
int SSLWrapper_set_ctx_cipher(SSLWrapper *wrapper, const char *cipher);
int SSLWrapper_set_ssl_cipher(SSLWrapper *wrapper, const char *cipher);

#ifdef  __cplusplus
}
#endif

#endif  /* __SSL_WRAPPER_H__ */
