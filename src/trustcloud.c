#include "trustcloud.h"

/** 
 * Receive file from socket connection
 */
void receive_file(int sock_fd, char *file_name, int file_size) {
    int num;
    int received = 0;
    char rec_buff[1024];
    // printf("SERVER: receiving file\n");
    FILE *fp;
    if (!(fp = fopen(file_name, "w"))) {
        perror("fopen");
        exit(EXIT_FAILURE);
    }

    size_t wrote;
    while (received < file_size) {
        // int temp_num = 0;
        // while (temp_num < 1024) {
            // if ((num = recv(sock_fd, rec_buff, 1024,0))== -1) {
        int size_rcvd = 1024;
        if ((num = recv_all(sock_fd, rec_buff, &size_rcvd))== -1) {
                perror("recv");
                exit(EXIT_FAILURE);
        } 
        if (num < 0) {
                printf("Connection closed\n");
                //So I can now wait for another client
                break;
        }
        printf("%d bytes received\n", size_rcvd);
        wrote = fwrite(rec_buff, 1, size_rcvd, fp);
        received += size_rcvd;
        // temp_num += ;
        if (wrote != size_rcvd) {
            perror("fwrite");
            exit(EXIT_FAILURE);
        }
            // if (received >= file_size) break;
        // }

    }
    printf("Wrote %d bytes\n", received);
    fclose(fp);
}

int recv_all(int sock, char *buf, int *len) { 
    int total = 0;        // how many bytes we've sent
    int bytesleft = *len; // how many we have left to send
    int n;
    while(total < *len) {
        n = recv(sock, buf+total, bytesleft, 0);
        // printf("%d\n", n);
        if (n == -1) { break; }
        total += n;
        bytesleft -= n;
    }
    *len = total; // return number actually sent here
    return n==-1?-1:0;
}

int get_file_size(FILE *fp) {
    fseek(fp, 0L, SEEK_END);
    int file_size = ftell(fp);
    fseek(fp, 0L, SEEK_SET); // back to start
    return file_size;
}

/** 
 * Read file and send data to server
 */ 
void send_file(int sock_fd, FILE *fp) {
    // get file size
    int file_size = get_file_size(fp);
    int num_chunks = floor(file_size / 1024);

    // int sock_fd = open_socket(host);

    while (1) {
        // char buffer[1024];
        char *buffer = malloc(1024*sizeof(char *));
        size_t size_read, size_sent;
        // size_t
        if ((size_read = fread(buffer, 1, 1024, fp)) == 0) {
            perror("fread()\n");
            exit(EXIT_FAILURE);
        } else if (ferror(fp)) {
            perror("fread()\n");
            exit(EXIT_FAILURE);
        } else { // try and send the file chunk
            // unsigned char send_buff[1024];
            // strcpy(send_buff, buffer);
            // size_read = (size_t)1024;
            int len = 1024;
            if ((sendall(sock_fd, buffer, &len)) == -1) {
                fprintf(stderr, "Failure Sending File\n");
                close(sock_fd);
                exit(EXIT_FAILURE);
            }
            // size_sent = size_read;
            if (len <= 0) {
                perror("send");
                exit(EXIT_FAILURE);
            } else {
                // int num = recv(sock_fd, )
                printf("%.2f%% complete, %lu bytes sent\n",
                         100.0*(float)ftell(fp)/(float)file_size, len);
            }
        }
        free(buffer);
        if (ftell(fp) >= file_size) break;
    }

    // close(sock_fd);
    printf("File successfully transferred\n");
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

/** Send short message (generally string) **/ 
void send_message(int sock_fd, char *buffer) {
    if ((send(sock_fd, buffer, strlen(buffer),0))== -1) {
        fprintf(stderr, "Failure Sending Message\n");
        close(sock_fd);
        exit(EXIT_FAILURE);
    }
}

void send_header(int sock_fd, header h) {
    char head_buff[64];

    if (h.action != ADD_FILE && h.action != FETCH_FILE) {
        fprintf(stderr, "Incorrect header action for sending header\n");
        exit(EXIT_FAILURE);
    }
    char *head_buff_loc = head_buff;
    sprintf(head_buff_loc, "%d\n", (short)h.action);
    while (*head_buff_loc != '\n' && *head_buff_loc != '\0') head_buff_loc++;
    sprintf(++head_buff_loc, "%d\n", (int)h.file_size);
    while (*head_buff_loc != '\n' && *head_buff_loc != '\0') head_buff_loc++;
    char *file_name = h.file_name;
    if (file_name[strlen(file_name) - 1] == '\0') 
        file_name[strlen(file_name) - 1] = '\n';
    sprintf(++head_buff_loc, "%s\n", file_name);

    printf("%s\n", head_buff);
    send_message(sock_fd, head_buff);
}   

int unpack_header_string(char *head_string, header *h) {
    // header h;
    int i;

    char *loc = head_string;

    for (i = 0; i < NUM_HEAD_FIELDS; i++) {
        char buff[59];
        char *buff_loc = buff;
        while (*loc != '\n') {
            *buff_loc = *loc;
            // printf("%c\n", *buff_loc);
            buff_loc++; loc++;
        }
        loc++;
        // buff_loc++;
        *buff_loc = '\0';
        switch(i) {
            case 0:
                h->action = (short)atoi(buff);
                break;
            case 1:
                h->file_size = atoi(buff);
                break;
            case 2:
                h->file_name = malloc(strlen(buff) * sizeof(h->file_name));
                strcpy(h->file_name, buff);
                break;
            default:
                break;
        }
    }
    // *h.action = (short)
    // h.action = (short)atoi(head_string[0]);
    // h.file_size = atoi(head_string[1]);
    // h.file_name = head_string[2];
    return 0;
}
