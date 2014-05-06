#include "trustcloud.h"

/** 
 * Receive file from socket connection
 */
void receive_file(int sock_fd, char *file_name) {
    int num;
    char buffer[1024];
    printf("SERVER: receiving file\n");
    FILE *fp;
    if (!(fp = fopen(file_name, "w"))) {
        perror("fopen");
        exit(EXIT_FAILURE);
    }

    size_t wrote;
    while (1) {
         if ((num = recv(sock_fd, buffer, 1024,0))== -1) {
                perror("recv");
                exit(EXIT_FAILURE);
        }
        else if (num == 0) {
                printf("Connection closed\n");
                //So I can now wait for another client
                break;
        }
        wrote = fwrite(buffer, 1, num, fp);
        if (wrote != num) {
            perror("fwrite");
            exit(EXIT_FAILURE);
        }
    }
    fclose(fp);
}

/** 
 * Read file and send data to server
 */ 
void send_file(int sock_fd, FILE *fp) {
    // get file size
    fseek(fp, 0L, SEEK_END);
    int file_size = ftell(fp);
    fseek(fp, 0L, SEEK_SET); // back to start
    int num_chunks = floor(file_size / 1024);

    // int sock_fd = open_socket(host);

    while (1) {
        char buffer[1024];
        size_t size_read, size_sent;
        if ((size_read = fread(buffer, 1, 1024, fp)) == 0) {
            perror("fread()\n");
            exit(EXIT_FAILURE);
        } else { // try and send the file chunk
            if ((sendall(sock_fd, buffer, (int *)&size_read)) == -1) {
                fprintf(stderr, "Failure Sending File\n");
                close(sock_fd);
                exit(EXIT_FAILURE);
            }
            size_sent = size_read;
            if (size_sent == 0) {
                perror("send");
                exit(EXIT_FAILURE);
            }else {
                // int num = recv(sock_fd, )
                printf("%.2f%% complete, %lu bytes sent\n",
                         100.0*(float)ftell(fp)/(float)file_size, size_sent);
            }
        }
        if (ftell(fp) >= file_size) break;
    }

    // close(sock_fd);
    printf("File successfully transferred\n");
}

/** Send short message (generally string) **/ 
void send_message(int sock_fd, char *buffer) {
    if ((send(sock_fd, buffer, strlen(buffer),0))== -1) {
        fprintf(stderr, "Failure Sending Message\n");
        close(sock_fd);
        exit(EXIT_FAILURE);
    }
}

/** Beej's Guide to Network Programming, Hall B.J., 2009 **/
int sendall(int s, char *buf, int *len) {
    int total = 0;        // how many bytes we've sent
    int bytesleft = *len; // how many we have left to send
    int n;
    while(total < *len) {
        n = send(s, buf+total, bytesleft, 0);
        if (n == -1) { break; }
        total += n;
        bytesleft -= n;
    }
    *len = total; // return number actually sent here
    return n==-1?-1:0; // return -1 on failure, 0 on success
}
