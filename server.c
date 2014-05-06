#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define PORT 3490
#define BACKLOG 10

int client_upload() {

    return 0;
}

void send_message(int client_fd, char *buffer) {
    if ((send(client_fd,buffer, strlen(buffer),0))== -1) 
    {
         fprintf(stderr, "Failure Sending Message\n");
         close(client_fd);
    }
}

int main()
{
    struct sockaddr_in server;
    struct sockaddr_in dest;
    int status,socket_fd, client_fd,num;
    socklen_t size;

    char buffer[1024];
    char *buff;
//  memset(buffer,0,sizeof(buffer));
    int yes =1;



    if ((socket_fd = socket(AF_INET, SOCK_STREAM, 0))== -1) {
        fprintf(stderr, "Socket failure!!\n");
        exit(EXIT_FAILURE);
    }

    if (setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }
    memset(&server, 0, sizeof(server));
    memset(&dest,0,sizeof(dest));
    server.sin_family = AF_INET;
    server.sin_port = htons(PORT);
    server.sin_addr.s_addr = INADDR_ANY; 
    if ((bind(socket_fd, (struct sockaddr *)&server, sizeof(struct sockaddr )))== -1)    { //sizeof(struct sockaddr) 
        fprintf(stderr, "Binding Failure\n");
        exit(EXIT_FAILURE);
    }

    if ((listen(socket_fd, BACKLOG))== -1){
        fprintf(stderr, "Listening Failure\n");
        exit(EXIT_FAILURE);
    }

    while(1) {

        size = sizeof(struct sockaddr_in);

        if ((client_fd = accept(socket_fd, (struct sockaddr *)&dest, &size))==-1 ) {
            perror("accept");
            exit(EXIT_FAILURE);
        }
        printf("Server got connection from client %s\n", inet_ntoa(dest.sin_addr));

        send_message(client_fd, "What would you like to do?\0");
        if ((num = recv(client_fd, buffer, 1024,0))== -1) {
                perror("recv");
                exit(EXIT_FAILURE);
        }
        else if (num == 0) {
                printf("Connection closed\n");
                //So I can now wait for another client
                continue;
        } 
        
        printf("%s\n", buffer);

        if (strcmp(buffer, "send") == 0) {
            printf("SERVER: receiving file\n");
            FILE *fp;
            if (!(fp = fopen("written.txt", "w"))) {
                perror("fopen");
                exit(EXIT_FAILURE);
            }

            size_t wrote;
            while (1) {
                printf("receiving data..\n");
                 if ((num = recv(client_fd, buffer, 1024,0))== -1) {
                        perror("recv");
                        exit(EXIT_FAILURE);
                }
                else if (num == 0) {
                        printf("Connection closed\n");
                        //So I can now wait for another client
                        break;
                }
                wrote = fwrite(buffer, 1, num, fp);
                printf("%s\n", buffer);
                if (wrote != num) {
                    perror("fwrite");
                    exit(EXIT_FAILURE);
                }
                // send_message(client_fd, "Received data\0");
                printf("wrote data: %s", buffer);
            }
            fclose(fp);
        }
  

        while(1) {
            break;
                if ((num = recv(client_fd, buffer, 1024,0))== -1) {
                        perror("recv");
                        exit(EXIT_FAILURE);
                }
                else if (num == 0) {
                        printf("Connection closed\n");
                        //So I can now wait for another client
                        break;
                }
                buffer[num] = '\0';
                printf("Server:Msg Received %s\n", buffer);
                send_message(client_fd, buffer);

                printf("Server:Msg being sent: %s\nNumber of bytes sent: %lu\n", buffer, strlen(buffer));

        } //End of Inner While...
        //Close Connection Socket
        close(client_fd);
    } //Outer While

    close(socket_fd);
    return 0;
} //End of main