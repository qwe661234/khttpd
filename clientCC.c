#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#define MAX 80
#define PORT 9090
#define CRLF "\r\n"
#define HTTP_REQ                                              \
    "POST /c.txt HTTP/1.1" CRLF "Host: localhost:9090" CRLF   \
    "Content-Type: text/plain" CRLF "Content-Length: 12" CRLF \
    "Connection: keep-alive" CRLF CRLF "Add new file!!"


int main(int argc, char *argv[])
{
    int sockfd;
    struct sockaddr_in servaddr;
    char recvmsg[1024], sendmsg[4096];
    FILE *file;

    file = fopen(argv[1], "r");

    if (!file) {
        perror("Fail to open file QQ\n");
        return 1;
    }
    char *p = sendmsg;
    while (fread(p, 1, 1, file)) {
        p = p + 1;
    }

    // socket create and verification
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        printf("socket creation failed...\n");
        exit(0);
    } else
        printf("Socket successfully created..\n");
    bzero(&servaddr, sizeof(servaddr));

    // assign IP, PORT
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = inet_addr("127.0.0.1");
    servaddr.sin_port = htons(PORT);

    // connect the client socket to server socket
    if (connect(sockfd, (struct sockaddr *) &servaddr, sizeof(servaddr)) != 0) {
        printf("connection with the server failed...\n");
        exit(0);
    } else
        printf("connected to the server..\n");

    char req[4096];
    snprintf(req, 4096,
             "POST /%s HTTP/1.1\r\n"
             "Host: localhost:9090\r\n"
             "Content-Type: text/plain\r\n"
             "Content-Length: %lu\r\n"
             "Connection: keep-alive\r\n\r\n"
             "%s",
             argv[1], (unsigned long) strlen(sendmsg), sendmsg);
    send(sockfd, req, strlen(req), 0);

    while (recv(sockfd, recvmsg, 1024, 0))
        printf("recv = %s\n", recvmsg);
    // close the socket
    close(sockfd);
    return 0;
}