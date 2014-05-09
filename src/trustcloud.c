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
        if ((int)wrote != size_rcvd) {
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
    //int num_chunks = floor(file_size / 1024);

    // int sock_fd = open_socket(host);

    while (1) {
        // char buffer[1024];
        char *buffer = malloc(1024*sizeof(char *));
        size_t size_read;
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
                printf("%.2f%% complete, %i bytes sent\n",
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
    if (h.action != ADD_FILE && h.action != FETCH_FILE && h.action != LIST_FILE && h.action != VOUCH_FILE) {
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
    while (*head_buff_loc != '\n' && *head_buff_loc != '\0') head_buff_loc++;
    char *certificate = h.certificate;
    if (certificate[strlen(certificate) - 1] == '\0') 
        certificate[strlen(certificate) - 1] = '\n';
    sprintf(++head_buff_loc, "%s\n", h.certificate);

    printf("Client sending header buff: %s\n", head_buff);
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
                // h->file_name = buff;
                // printf("%s\n", buff);
                h->file_name = malloc(strlen(buff) * sizeof(h->file_name));
                strcpy(h->file_name, buff);
                // printf("%s\n", h->file_name);
                break;
            case 3:
                h->certificate = malloc(strlen(buff) * sizeof(h->certificate));
                strcpy(h->certificate, buff);
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

/* RSA password stuff, for vouch file */
int pass_cb( char *buf, int size, int rwflag, void *u )
{
  if ( rwflag == 1 ) {
    /* What does this really means? */
  }
  int len;
  char tmp[1024];
  printf( "Enter pass phrase for '%s': ", (char*)u );
  scanf( "%s", tmp );
  len = strlen( tmp );

  if ( len <= 0 ) return 0;
  if ( len > size ) len = size;

  memset( buf, '\0', size );
  memcpy( buf, tmp, len );
  return len;
}

/* get RSA cert, for vouch file */
RSA* getRsaFp( const char* rsaprivKeyPath )
{
  FILE* fp;
  fp = fopen( rsaprivKeyPath, "r" );
  if ( fp == 0 ) {
    fprintf( stderr, "Couldn't open RSA priv key: '%s'. %s\n",
             rsaprivKeyPath, strerror(errno) );
    exit(1);
  }
 
  RSA *rsa = 0;
  rsa = RSA_new();
  if ( rsa == 0 ) {
    fprintf( stderr, "Couldn't create new RSA priv key obj.\n" );
    unsigned long sslErr = ERR_get_error();
    if ( sslErr ) fprintf(stderr, "%s\n", ERR_error_string(sslErr, 0));
    fclose( fp );
    exit( 1 );
  }
 
  rsa = PEM_read_RSAPrivateKey(fp, 0, pass_cb, (char*)rsaprivKeyPath);
  if ( rsa == 0 ) {
    fprintf( stderr, "Couldn't use RSA priv keyfile.\n" );
    unsigned long sslErr = ERR_get_error();
    if ( sslErr ) fprintf(stderr, "%s\n", ERR_error_string(sslErr, 0));
    fclose( fp );
    exit( 1 );
  }
  fclose( fp );
  return rsa;
}

/* store signature to file */
int writeSig(unsigned char *sig, char *sig_name){
    FILE *fp; 
    fp = fopen(sig_name,"w"); /* write to file or create a file if it does not exist.*/ 
    if ( fp == 0 ) {
        fprintf( stderr, "Couldn't open signature file: '%s'. %s\n",sig_name, strerror(errno) );
        exit(1);
    }
    fprintf(fp,"%s",sig); /*writes*/ 
    fclose(fp); /*done!*/ 
    return 0;
}

/* Get signature length, used part of the formal code */
int sigLength(char *rsaprivKeyPath, const char *clearText){
    EVP_PKEY *evpKey;
    if ( (evpKey = EVP_PKEY_new()) == 0 ) {
        fprintf( stderr, "Couldn't create new EVP_PKEY object.\n" );
        unsigned long sslErr = ERR_get_error();
        if ( sslErr ) fprintf(stderr, "%s\n", ERR_error_string(sslErr, 0));
        exit(1);
    }
    RSA *rsa;
    /* get private key file */
    rsa = getRsaFp( rsaprivKeyPath );
    if ( EVP_PKEY_set1_RSA( evpKey, rsa ) == 0 ) {
        fprintf( stderr, "Couldn't set EVP_PKEY to RSA key.\n" );
        unsigned long sslErr = ERR_get_error();
        if ( sslErr ) fprintf(stderr, "%s\n", ERR_error_string(sslErr, 0));
        exit(1);
    }

    /* create EVP_CTX */
    EVP_MD_CTX *evp_ctx;
    if ( (evp_ctx = EVP_MD_CTX_create()) == 0 ) {
        fprintf( stderr, "Couldn't create EVP context.\n" );
        unsigned long sslErr = ERR_get_error();
        if ( sslErr ) fprintf(stderr, "%s\n", ERR_error_string(sslErr, 0));
        exit(1);
    }
     
    if ( EVP_SignInit_ex( evp_ctx, EVP_sha1(), 0 ) == 0 ) {
        fprintf( stderr, "Couldn't exec EVP_SignInit.\n" );
        unsigned long sslErr = ERR_get_error();
        if ( sslErr ) fprintf(stderr, "%s\n", ERR_error_string(sslErr, 0));
        exit(1);
    }
     
    if ( EVP_SignUpdate( evp_ctx, clearText, strlen( clearText ) ) == 0 ) {
        fprintf( stderr, "Couldn't calculate hash of message.\n" );
        unsigned long sslErr = ERR_get_error();
        if ( sslErr ) fprintf(stderr, "%s\n", ERR_error_string(sslErr, 0));
        exit(1);
    }

    unsigned char *sig = NULL;
    unsigned int sigLen = 0;
    //memset(sig, 0, MAXSIZE+1024);
    sig = malloc(EVP_PKEY_size(evpKey));
    /* check sig */
    if ( EVP_SignFinal( evp_ctx, sig, &sigLen, evpKey ) == 0 ) {
        fprintf( stderr, "Couldn't calculate signature.\n" );
        unsigned long sslErr = ERR_get_error();
        if ( sslErr ) fprintf(stderr, "%s\n", ERR_error_string(sslErr, 0));
        exit(1);
    }

    EVP_MD_CTX_destroy( evp_ctx );
    RSA_free( rsa );
    EVP_PKEY_free( evpKey );
    ERR_free_strings();
    return sigLen;
}

/* Verify file with certain certificate 
 * http://openssl.6102.n7.nabble.com/EVP-VerifyFinal-fail-use-RSA-public-key-openssl-1-0-0d-win32-vc2008sp1-td9539.html
 */
int verifySig(char *rsaprivKeyPath, const char *clearText, unsigned char *sig){
    printf("-----start verify-----\n");
    EVP_PKEY *evpKey;
    RSA *rsa;
    if ( (evpKey = EVP_PKEY_new()) == 0 ) {
        fprintf( stderr, "Couldn't create new EVP_PKEY object.\n" );
        unsigned long sslErr = ERR_get_error();
        if ( sslErr ) fprintf(stderr, "%s\n", ERR_error_string(sslErr, 0));
        exit(1);
    }

    /* get private key file */
    rsa = getRsaFp( rsaprivKeyPath );
    printf("%s\n",rsaprivKeyPath);
    if ( EVP_PKEY_set1_RSA( evpKey, rsa ) == 0 ) {
        fprintf( stderr, "Couldn't set EVP_PKEY to RSA key.\n" );
        unsigned long sslErr = ERR_get_error();
        if ( sslErr ) fprintf(stderr, "%s\n", ERR_error_string(sslErr, 0));
        exit(1);
    }

    /*create evp_ctx */
    EVP_MD_CTX *evp_ctx;
    if ( (evp_ctx = EVP_MD_CTX_create()) == 0 ) {
        fprintf( stderr, "Couldn't create EVP context.\n" );
        unsigned long sslErr = ERR_get_error();
        if ( sslErr ) fprintf(stderr, "%s\n", ERR_error_string(sslErr, 0));
        exit(1);
    }


    if ( EVP_VerifyInit(evp_ctx, EVP_sha1()) == 0 ) {
        fprintf( stderr, "Couldn't exec EVP_VerifyInit.\n" );
        unsigned long sslErr = ERR_get_error();
        if ( sslErr ) fprintf(stderr, "%s\n", ERR_error_string(sslErr, 0));
        exit(1);
    }


    if(!EVP_VerifyUpdate( evp_ctx, clearText, strlen(clearText))){

               printf("EVP_VerifyUpdate error. \n");

               exit(1);

    }
    //printf("ClearText:%s\n",clearText);
    int vsigLen = sigLength(rsaprivKeyPath,clearText);
    int vr;
    //memset(sig, 0, MAXSIZE+1024);
    //printf("strlen(sig):%lu\n",strlen((const char *)sig));
    //printf("vsiglen:%u\n",vsigLen);
    vr = EVP_VerifyFinal( evp_ctx, sig, vsigLen, evpKey);
    if( vr == -1){

               printf("verify by public key error. \n");

               exit(1);

    }
    else if(vr == 1){
        printf("verified\n");
    }
    else{
        printf("failed\n");
    }
    return 0;
}

