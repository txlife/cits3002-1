#include "trustcloud.h"

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

        char header_buf[1024];
        // read header - then do action based on header parsing
        if ((num = recv(client_fd, header_buf, 1024,0))== -1) {
                perror("recv");
                exit(EXIT_FAILURE);
        }
        else if (num == 0) {
                printf("No header received. Connection closed\n");
                //So I can now wait for another client
                continue;
        } 

        header h;
        if (unpack_header_string(header_buf, &h) == -1) {
            fprintf(stderr, "[SERVER] Could not unpack header information from client\n");
            exit(EXIT_FAILURE);
        }
        printf("%d\n", h.action);
        printf("%d\n", h.file_size);
        printf("%s", h.file_name);
        // if client requests to uplaod file
        if (h.action == ADD_FILE) {
            char *serv_dir = "server_files";
            // char *file_name = "written.txt";
            // TODO get file_name from header
            char *target[1024];
            sprintf(target, "%s/%s", serv_dir, h.file_name);
            printf("[SERVER] Adding file %s\n", target);
            receive_file(client_fd, strcat(serv_dir, h.file_name));
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
