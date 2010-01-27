/*******************************************************
 * OpenSSL wrapper that provides a simplified API
 * for secure socket layer.  Internally handles 
 * managing the appropriate state and configuration 
 * settings for client and server SSL context and
 * sessions.
 *
 * Author: CJ Barker
 * Copyright 2010 
 ******************************************************/

#include <stdio.h>
#include <unistd.h>
#include "ssl_wrapper.h"


/**
 * Initializes open SSL engine
 */
void init_ssl(void)
{
    if (initialized_engine)
        return;

    SSL_library_init();
    OpenSSL_add_all_algorithms();   /* load cryptos, etc */
    SSL_load_error_strings();       /* load all error messages */
    initialized_engine++;
#ifdef DEBUG_OUTPUT
    fprintf(stdout, "Socket engine initialized\n");
#endif
}

/**
 * Initialize open SSL engine
 * Returns valid SSL context or null if failed to create it.
 */
SSLWrapper* SSLWrapper_new(enum MethodType type)
{
    init_ssl();

    SSL_METHOD *method;
    SSL_CTX *ctx;

    if (type == Server) {
        method = SSLv2_server_method();     
    }
    else if (type == Client) {
        method = SSLv2_client_method();
    }
    else {
#ifdef DEBUG_OUTPUT
        fprintf(stderr, "Invalid method type received %d\n", type);
#endif
        return NULL;
    }

    ctx = SSL_CTX_new(method);

    if (ctx == NULL) {
#ifdef DEBUG_OUTPUT
        ERR_print_errors_fp(stderr);
#endif
    }

    SSLWrapper *wrapper = (SSLWrapper *)malloc(sizeof(SSLWrapper));
    wrapper->ctx = ctx;
    wrapper->ssl = NULL;
    wrapper->type = type;
    wrapper->state_set = 0;
    wrapper->sock_fd = 0;

    return wrapper;
}

/**
 * Accepts the incoming client connection
 * Also handles creating the SSL if need be.
 * Only call from server code.
 */
int SSLWrapper_accept(SSLWrapper *wrapper)
{
    if (wrapper->ssl == NULL) {
        wrapper->ssl = SSL_new(wrapper->ctx);
    }

    return SSL_accept(wrapper->ssl);
}

/**
 * Decrypts and reads incoming bytes by loading them into buffer.
 * Must set size of buffer before invoking.
 * Will also set the appropriate SSL connection state.
 *
 * Returns the number of bytes read
 */
int SSLWrapper_read(SSLWrapper *wrapper, const void *buf, int num)
{
    int result = SSLWrapper_set_state(wrapper);
    
    if (result != 0)
        return result;

    return SSL_read(wrapper->ssl, (void *)buf, num);
}

/**
 * Encrypts and Writes outgoing bytes by loading them into buffer.
 * Must set size of buffer and buffer before invoking.
 * Will also set the appropriate SSL connection state.
 *
 * Returns the number of bytes written
 */ 
int SSLWrapper_write(SSLWrapper *wrapper, const void *buf, int num)
{
    int result = SSLWrapper_set_state(wrapper);
    
    if (result != 0)
        return result;

    return SSL_write(wrapper->ssl, (void *)buf, num);
}

/**
 * Sets the connection socket to SSL state and performs connection
 * if it is a client type.
 * Returns 0 if successfully attached/set/connected; otherwise, negative number.
 */
int SSLWrapper_set_state(SSLWrapper *wrapper)
{
    if (wrapper->state_set)
        return 0;

    if (wrapper->sock_fd <= 0) {
#ifdef DEBUG_OUTPUT
        fprintf(stderr, "Invalid socket file descriptor: %d\n", wrapper->sock_fd); 
#endif
        return -1;
    }
    
    if (wrapper->ssl == NULL) {
        wrapper->ssl = SSL_new(wrapper->ctx);
    }
    else {
        SSL_clear(wrapper->ssl);
    }

    SSL_set_fd(wrapper->ssl, wrapper->sock_fd);

    if (wrapper->type == Client)
    {
        if (SSL_connect(wrapper->ssl) < 0) {
#ifdef DEBUG_OUTPUT
            fprintf(stderr, "Failed to connect client to server socket for SSL\n");
#endif
            return -2;
        }
    }

    wrapper->state_set = 1;

#ifdef DEBUG_OUTPUT
    fprintf(stdout, "SSL connection state set.\n");
#endif

    return 0;
}

/**
 * Frees up the SSL connection and closes the client socket
 * if it exists.
 */
void SSLWrapper_close_ssl(SSLWrapper *wrapper)
{
    int sd = SSL_get_fd(wrapper->ssl);       /* get socket connection */

    /* only need to clear ssl state rather than freeing - faster */
    if (wrapper->ssl != NULL) {
        SSL_clear(wrapper->ssl);        
        //SSL_free(wrapper->ssl);     
        //wrapper->ssl = NULL;
    }
    
    if (sd > 0) close(sd);

    wrapper->state_set = 0;
}

/**
 * Sets the cipher function to use for the entire context.
 * Inherited by all SSL sessions created.
 * Server must invoke after have accepted the incoming connection.
 * When not invoked defaults to DES-CBC3-MD5
 * Triple-DES (168-bit key) for data encryption; MD5 for message integrity
 */
int SSLWrapper_set_ctx_cipher(SSLWrapper *wrapper, const char *cipher)
{
    return SSL_CTX_set_cipher_list(wrapper->ctx, cipher);
}

/**
 * Sets the cipher function to use for a specific SSL session.
 * Server must invoke after have accepted the incoming connection.
 * When not invoked defaults to DES-CBC3-MD5
 * Triple-DES (168-bit key) for data encryption; MD5 for message integrity
 */
int SSLWrapper_set_ssl_cipher(SSLWrapper *wrapper, const char *cipher)
{
    return SSL_set_cipher_list(wrapper->ssl, cipher);
}

/**
 * Loads the certificate and private key from the associated files.
 *
 * Returns 0 if succesffully loaded.
 */
int SSLWrapper_load_certificate(SSLWrapper * wrapper, char* certFile, char* keyFile)
{
    if (wrapper->ctx == NULL)
        return 1;

    if (SSL_CTX_use_certificate_file(wrapper->ctx, certFile, SSL_FILETYPE_PEM) <= 0) {
#ifdef DEBUG_OUTPUT
        fprintf(stderr, "Unable to use local certificate file from %s\n", certFile);
#endif
        return 2;
    }

    if (SSL_CTX_use_PrivateKey_file(wrapper->ctx, keyFile, SSL_FILETYPE_PEM) <= 0) {
#ifdef DEBUG_OUTPUT
        fprintf(stderr, "Unable to use private key file from %s\n", keyFile);
#endif
        return 3;
    }

    /* verify private key */
    if (!SSL_CTX_check_private_key(wrapper->ctx)) {
#ifdef DEBUG_OUTPUT
        fprintf(stderr, "Private key does not match the public certificate\n");
#endif
        return 4;
    }

    return 0;
}

/**
 * Verifies that X509 certificate exists and is valid.
 * Invoke AFTER SSL connection has been established.
 *
 * Returns 0 if all is well.
 */
int SSLWrapper_verify_cert(SSLWrapper * wrapper)
{
    X509 *cert;
    int err;

    cert = SSL_get_peer_certificate(wrapper->ssl);
    if (cert == NULL) {
#ifdef DEBUG_OUTPUT
        fprintf(stderr, "No X509 certificate exists.\n");
#endif
        return -1;
    }

    X509_free(cert); 

    err = SSL_get_verify_result(wrapper->ssl);

    if (err == X509_V_OK)
        return 0;

#ifdef DEBUG_OUTPUT
    fprintf(stderr, "Cannot verify certificate: %s (%d)\n", X509_verify_cert_error_string(err), err);
#endif
    return err;
}

/**
 * Displays X509 certificate information to STDOUT
 * Invoke AFTER SSL connection has been established via set_state function.
 */
void SSLWrapper_print_cert(SSLWrapper * wrapper)
{
    if (wrapper->ssl == NULL)
        return;

    X509 *cert;
    char *line;

    cert = SSL_get_peer_certificate(wrapper->ssl);
    if (cert != NULL)
    {
        fprintf(stdout, "Server certificates:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        fprintf(stdout, "Subject: %s\n", line);
        if (line != NULL) free(line);
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        fprintf(stdout,"Issuer: %s\n", line); 
        if (line != NULL) free(line);
        X509_free(cert);
    }
    else {
#ifdef DEBUG_OUTPUT
        fprintf(stdout, "No certificates found.\n");
#endif
    }
}

/**
 * Free up resources 
 * Will close existing client/server sockets if they exist.
 */
void SSLWrapper_free(SSLWrapper *wrapper)
{
    if (wrapper == NULL)
        return;

    if (wrapper->ssl != NULL) {
        int sd = SSL_get_fd(wrapper->ssl);
        SSL_free(wrapper->ssl);
        if (sd > 0) close(sd);
    }
    
    if (wrapper->sock_fd > 0) close(wrapper->sock_fd);
    if (wrapper->ctx != NULL) SSL_CTX_free(wrapper->ctx);

    free(wrapper);
}
