/*******************************************************
 * Simple client program/driver to be used as an
 * example for how to interface with the SSLWrapper
 * for sending and receiving encrypted sockets.
 *
 * Author: CJ Barker
 * Copyright 2010 
 ******************************************************/

#include <stdio.h>
#include <assert.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netdb.h>
#include "ssl_wrapper.h"

/**
 * Opens socket connection to hostname on given port
 */
int open_connection(const char *hostname, int port)
{
    int sd;
    struct hostent *host;
    struct sockaddr_in addr;

    if ((host = gethostbyname(hostname)) == NULL) {
        perror(hostname);
        exit(1);
    }

    sd = socket(PF_INET, SOCK_STREAM, 0);
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = *(long*)(host->h_addr);
    
    if (connect(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0)
    {
        close(sd);
        perror(hostname);
        exit(2);
    }

    return sd; 
}

/**
 * Test example of client utilizing SSL within socket communication
 */
int main(int argc, char *argv[]) 
{
    /*
     * Client Steps: 
     *  1) create new SSLWrapper
     *  2) open socket connection to server
     *  3) set state via SSLWrapper_set_state
     *  4) send and/or receive bytes SSLWrapper_write/read
     *  5) free up resources via SSLWrapper_free
     */
    SSLWrapper *wrapper;

    int serverSock;
    char *hostname, *port;
    int bytes;
    char buf[1024];

    if (argc != 3) {
        printf("Usage: %s <hostname> <port>\n", argv[0]);
        exit(0);
    }
    hostname = argv[1];
    port = argv[2];

    wrapper = SSLWrapper_new(Client);
    assert(wrapper != NULL);

    /* open socket connection */
    serverSock = open_connection(hostname, atoi(port)); 
    wrapper->sock_fd = serverSock;
    assert(serverSock >= 0);

    SSLWrapper_set_state(wrapper);

    /* output certificate info */
    SSLWrapper_print_cert(wrapper);

    /* send encrypted message */
    char *msg = (char *)"Testing SSL...hello?";
    printf("Connected with %s encryption\n", SSL_get_cipher(wrapper->ssl));
    printf("Sending: %s\n", msg);
    bytes = SSLWrapper_write(wrapper, msg, strlen(msg)); 
    assert(bytes > 0);

    bytes = SSLWrapper_read(wrapper, buf, sizeof(buf));    /* get reply and decrypt */
    assert(bytes > 0);
    buf[bytes] = 0;
    printf("Received: %s\n", buf);
    
    /* free resources */
    close(serverSock);              /* close socket */
    SSLWrapper_free(wrapper);       /* release context */

    return 0;
}
