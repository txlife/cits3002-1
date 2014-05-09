#include "trustcloud.h"

/** 
 * Receive file from socket connection
 */
void receive_file(SSL *ssl, char *file_name, int file_size) {
    int num;
    int received = 0;
    unsigned char rec_buff[BLOCK_SIZE];
    // printf("SERVER: receiving file\n");
    FILE *fp;
    if (!(fp = fopen(file_name, "w"))) {
        perror("fopen");
        exit(EXIT_FAILURE);
    }

    size_t wrote;
    while (received < file_size) {
        int size_rcvd = (int)fmin(BLOCK_SIZE, file_size - received);
        if ((num = recv_all(ssl, rec_buff, &size_rcvd))== -1) {
                perror("recv");
                exit(EXIT_FAILURE);
        } 
        if (size_rcvd <= 0) {
                printf("Connection closed\n");
                //So I can now wait for another client
                break;
        }
        printf("%d bytes received\n", size_rcvd);
        wrote = fwrite(rec_buff, 1, size_rcvd, fp);
        received += size_rcvd;
        if ((int)wrote != size_rcvd) {
            perror("fwrite");
            exit(EXIT_FAILURE);
        }
    }
    printf("Wrote %d bytes\n", received);
    fclose(fp);
}

int recv_all(SSL *ssl, unsigned char *buf, int *len) { 
    int total = 0;        // how many bytes we've received
    int bytesleft = *len; // how many we have left to receive
    int n;
    while(total < *len) {
        // n = recv(sock, buf+total, bytesleft, 0);
        n = SSL_read(ssl, buf+total, bytesleft);
        if (n == -1 || n == 0) { break; }
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
void send_file(SSL *ssl, FILE *fp) {
    // get file size
    int file_size = get_file_size(fp);

    while (1) {
        char unsigned buffer[BLOCK_SIZE];
        // char *buffer = malloc(1024*sizeof(char *));
        size_t size_read;
        if ((size_read = fread(buffer, 1, BLOCK_SIZE, fp)) == 0) {
            perror("fread()\n");
            exit(EXIT_FAILURE);
        } else if (ferror(fp)) {
            perror("fread()\n");
            exit(EXIT_FAILURE);
        } else { // try and send the file chunk
            int len = (int)size_read;
            if ((sendall(ssl, buffer, &len)) == -1) {
                fprintf(stderr, "Failure Sending File\n");
                SSL_shutdown(ssl);
                SSL_free(ssl);
                exit(EXIT_FAILURE);
            }
            if (len <= 0) {
                perror("send");
                exit(EXIT_FAILURE);
            } else {
                printf("%.2f%% complete, %i bytes sent\n",
                         100.0*(float)ftell(fp)/(float)file_size, len);
            }
        }
        if (ftell(fp) >= file_size) break;
    }

    // close(sock_fd);
    printf("File successfully transferred\n");
}

/** Beej's Guide to Network Programming, Hall B.J., 2009 **/
int sendall(SSL *ssl, unsigned char *buf, int *len) {
    int total = 0;        // how many bytes we've sent
    int bytesleft = *len; // how many we have left to send
    int n;
    while(total < *len) {
        // n = send(s, buf+total, bytesleft, 0);
        n = SSL_write(ssl, buf + total, bytesleft);
        if (n == -1) { break; }
        total += n;
        bytesleft -= n;
    }
    *len = total; // return number actually sent here
    return n==-1?-1:0; // return -1 on failure, 0 on success
}

/** Send short message (generally string) **/ 
void send_message(SSL *ssl, char *buffer) {
    // if ((send(sock_fd, buffer, strlen(buffer),0))== -1) {
    int len = strlen(buffer);
    if ((sendall(ssl, (unsigned char *)buffer, &len))== -1) {
        fprintf(stderr, "Failure Sending Message\n");
        SSL_shutdown(ssl);
        SSL_free(ssl);
        exit(EXIT_FAILURE);
    } 
    if (len < (int)strlen(buffer)) {
        fprintf(stderr, "Didn't send full message\n");
        SSL_shutdown(ssl);
        SSL_free(ssl);
        exit(EXIT_FAILURE);
    }
}

void send_header(SSL *ssl, header h) {
    char head_buff[HEADER_SIZE];
    if (h.action != ADD_FILE && h.action != FETCH_FILE && h.action != LIST_FILE) {
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

    head_buff_loc += 1 + strlen(file_name);

    while (head_buff_loc < head_buff + HEADER_SIZE - 1) {
        *head_buff_loc = '\0';
        head_buff_loc++;
    }

    printf("Sending header buff:\n %s\n", head_buff);
    int len = HEADER_SIZE;
    sendall(ssl, (unsigned char *)head_buff, &len);
    if (len < HEADER_SIZE) {
        fprintf(stderr, "Error sending header\n");
        exit(EXIT_FAILURE);
    }
}   

int unpack_header_string(char *head_string, header *h) {
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

    return 0;
}

/**server list current dir files
 * based on : http://stackoverflow.com/questions/11291154/save-file-listing-into-array-or-something-else-c
**/
size_t file_list(const char *path, char ***ls) {
    size_t count = 0;
    DIR *dp = NULL;
    struct dirent *ep = NULL;

    dp = opendir(path);
    if(NULL == dp) {
        fprintf(stderr, "no such directory: '%s'", path);
        return 0;
    }

    *ls = NULL;
    ep = readdir(dp);
    while(ep != NULL){
        count++;
        ep = readdir(dp);
    }

    rewinddir(dp);
    *ls = calloc(count, sizeof(char *));

    count = 0;
    ep = readdir(dp);
    while(ep != NULL){
        (*ls)[count++] = strdup(ep->d_name);
        ep = readdir(dp);
    }

    closedir(dp);
    return count;
}

/* Client Show Certificates
 * http://mooon.blog.51cto.com/1246491/909932
 */
void ShowCerts(SSL * ssl){
    X509 *cert;
    char *line;
    cert = SSL_get_peer_certificate(ssl);
    if (cert != NULL) {
        printf("Certificate Information:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Certificate: %s\n", line);
        free(line);
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Signed by: %s\n", line);
        free(line);
        X509_free(cert);
    } 
    else{
        printf("No Certificate Information found！\n");
    }
}

/* Display Command Line Options */
int help(){
    fprintf(stderr, "Usage: client -h hostname [-a add_file_name] [-l]\n");
    return 0;
}
