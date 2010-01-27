/*******************************************************
 * Simple server program/driver to be used as an
 * example for how to interface with the SSLWrapper
 * for receving and sending encrypted sockets.
 *
 * Author: CJ Barker
 * Copyright 2010 
 ******************************************************/

#include <stdio.h>
#include <assert.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include "ssl_wrapper.h"

static int req_count;

/**
 * Binds socket to port and listen for connections
 */
int open_listener(int port)
{
    int sd;
    struct sockaddr_in addr;

    sd = socket(PF_INET, SOCK_STREAM, 0);
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0)
    {
        perror("can't bind to port");
        exit(1);
    }

    if (listen(sd, 10) != 0) 
    {
        perror("Can't configure listening port");
        exit(2);
    }

    return sd; 
}

void handle_request(SSLWrapper* wrapper)
{
    char buf[1024];
    char reply[1024];
    int sd, bytes;
    const char* msg = "Hello, received message...responding";
    req_count++;

    assert(SSLWrapper_accept(wrapper) > -1);

    //SSLWrapper_print_cert(ssl);

    /* get and decrypt messages */
    bytes = SSLWrapper_read(wrapper, buf, sizeof(buf));
    assert(bytes > 0);
    buf[bytes] = 0;
    printf("Client msg[%d]: %s\n", req_count, buf);
    printf("Sending back: %s\n", msg);
    sprintf(reply, msg, buf);

    /* encrypt and send response back to client */
    SSLWrapper_write(wrapper, reply, strlen(reply));

    SSLWrapper_close_ssl(wrapper); 
}

/**
 * Test example of client utilizing SSL within socket communication
 */
int main(int argc, char *argv[]) 
{
    /*
     * Server Steps: 
     *  1) create new SSLWrapper
     *  2) load certs
     *  3) open listener for incoming sockets
     *  4) wait for client requests
     *  5) set SSL state via SSLWrapper_set_state
     *  6) call SSLWrapper_accept
     *  7) Send and receive bytes via SSLWrapper_write/read
     *  6) free up resources via SSLWrapper_free
     */
    SSLWrapper *wrapper;
    int serverSock;
    char *port, *cert, *key;

    if (argc != 4) {
        printf("Usage: %s <port> <cert_path> <key_path>\n", argv[0]);
        exit(0);
    }
    port = argv[1];
    cert = argv[2];
    key  = argv[3];

    wrapper = SSLWrapper_new(Server);
    assert(wrapper != NULL);

    /* load certs */
    assert(SSLWrapper_load_certificate(wrapper, cert, key) == 0);

    /* optional set cipher to use for ALL connections */
    //assert(SSLWrapper_set_ctx_cipher(wrapper, (char*)"RC4-MD5") == 1);

    /* open listener */ 
    serverSock = open_listener(atoi(port)); 
    assert(serverSock >= 0);

    /* wait for client requests */
    req_count=0;
    while (1)
    {
        struct sockaddr_in addr;
        int len = sizeof(addr);

        int clientSock = accept(serverSock, (struct sockaddr*)&addr, (socklen_t *)&len);
        wrapper->sock_fd = clientSock;
        printf("Connection: %s: %d\n", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));

        SSLWrapper_set_state(wrapper);

        /* receive/send input */
        handle_request(wrapper);
        //break;
    }

    /* free resources */
    close(serverSock);              /* close socket */
    SSLWrapper_free(wrapper);       /* release context */

    return 0;
}
