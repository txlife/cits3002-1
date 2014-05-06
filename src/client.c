#include "trustcloud.h"

int main(int argc, char *argv[])
{
    struct sockaddr_in server_info;
    struct hostent *he;
    int socket_fd,num;
    char buffer[1024];
    char *hostname = NULL;

    char buff[1024];

    if (argc < 2) {
        fprintf(stderr, "Usage: client -h hostname [-s send_file_name]\n");
        exit(EXIT_FAILURE);
    }

    char *file_name = NULL;
    int send_flag = 0;
    int index;
    int c;
    opterr = 0;

    while ((c = getopt(argc, argv, "h:s:")) != -1) {
        switch(c) {
            case 'h':
                hostname = optarg;
                break;
            case 's':
                file_name = optarg;
                send_flag = 1;
                break;
            default:
                abort();
        }
    }

    if (send_flag) printf("Sending file '%s'\n", file_name);

    if ((he = gethostbyname(hostname))==NULL) {
        fprintf(stderr, "Cannot get host name\n");
        exit(EXIT_FAILURE);
    }

    if ((socket_fd = socket(AF_INET, SOCK_STREAM, 0))== -1) {
        fprintf(stderr, "Socket Failure!!\n");
        exit(EXIT_FAILURE);
    }

    memset(&server_info, 0, sizeof(server_info));
    server_info.sin_family = AF_INET;
    server_info.sin_port = htons(PORT);
    server_info.sin_addr = *((struct in_addr *)he->h_addr);
    if (connect(socket_fd, (struct sockaddr *)&server_info, sizeof(struct sockaddr))<0) {
        //fprintf(stderr, "Connection Failure\n");
        perror("connect");
        exit(EXIT_FAILURE);
    }

	while(1) {
        // printf("Client: Enter Data for Server:\n");
        // fgets(buffer,MAXSIZE-1,stdin);
        if (send_flag) {
            // buffer = "send";
            sprintf(buffer, "send");
            send_message(socket_fd, buffer);
            recv(socket_fd, NULL, 1, 0);
            FILE *fp;
            if ((fp = fopen(file_name, "r"))){
                send_file(socket_fd, fp);
            } else {
                perror("fopen");
                exit(EXIT_FAILURE);
            }
            break;
        }
        if ((send(socket_fd,buffer, strlen(buffer),0))== -1) {
                fprintf(stderr, "Failure Sending Message\n");
                close(socket_fd);
                exit(1);
        }
        else {
            printf("Client:Message being sent: %s\n",buffer);
            num = recv(socket_fd, buffer, sizeof(buffer),0);
            if ( num <= 0 )
            {
                    printf("Either Connection Closed or Error\n");
                    //Break from the While
                    break;
            }

            buff[num] = '\0';
            printf("Client:Message Received From Server -  %s\n",buffer);
        }
    }
    close(socket_fd);

}//End of main
