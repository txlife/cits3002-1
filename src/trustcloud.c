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
    if (   h.action != ADD_FILE 
        && h.action != FETCH_FILE 
        && h.action != LIST_FILE 
        && h.action != VOUCH_FILE
		&& h.action != VERIFY_FILE) {
        fprintf(stderr, "Incorrect header action for sending header\n");
        exit(EXIT_FAILURE);
    }
    // pack header into string, using new line characters as delimiters
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

    head_buff_loc += 1 + strlen(certificate);

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
            case 3:
                h->certificate = malloc(strlen(buff) * sizeof(h->certificate));
                strcpy(h->certificate, buff);
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
    char *certificate = NULL;
    certificate = malloc(MAXSIZE);
    sprintf(certificate,"client_certs/%s", rsaprivKeyPath);

    FILE* fp;
    fp = fopen( certificate, "r" );
    if ( fp == 0 ) {
    fprintf( stderr, "Couldn't open RSA priv key: '%s'. %s\n",certificate, strerror(errno) );
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

    rsa = PEM_read_RSAPrivateKey(fp, 0, pass_cb, (char*)certificate);
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
    fwrite(sig, sizeof(char *), strlen((const char *)sig), fp);
    //fprintf(fp,"%s",sig); /*writes*/ 
    fclose(fp); /*done!*/ 
    return 0;
}

unsigned char * readSig(unsigned char *sig, char *sig_name){
    FILE *fp; 
    size_t len;
    size_t bytesRead;
    fp = fopen(sig_name,"r"); /* write to file or create a file if it does not exist.*/ 
    if ( fp == 0 ) {
        fprintf( stderr, "Couldn't open signature file: '%s'. %s\n",sig_name, strerror(errno) );
        exit(1);
    }

    /* get the file size */
    fseek(fp, 0 , SEEK_END);
    len = ftell(fp);
    rewind(fp);

    /* read contents */
    sig = (unsigned char*) malloc(sizeof(char) * len );
    //sig[len] = (unsigned char) "\0";
    if(sig == NULL){
        fprintf(stderr, "Failed to allocate memory\n");
        exit(EXIT_FAILURE);
    }
    //fscanf(fp, "%s", (char *) sig);
    bytesRead = fread(sig, sizeof(char *), len, fp);
    //if( fgets ((char *)sig, len, fp) ==NULL ) {
    //    fprintf(stderr, "Failed to get file contents\n");
    //    exit(EXIT_FAILURE);
    //}
    fclose(fp); /*done!*/ 
    printf("read sig :%s\nlen: %zu\n",sig,len);
    return sig;
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
    unsigned char *md5Value1 = hashFile(clearText);
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
     
    if ( EVP_SignUpdate( evp_ctx, (const char *)md5Value1, strlen( (const char *)md5Value1 ) ) == 0 ) {
        fprintf( stderr, "Couldn't calculate hash of message.\n" );
        unsigned long sslErr = ERR_get_error();
        if ( sslErr ) fprintf(stderr, "%s\n", ERR_error_string(sslErr, 0));
        exit(1);
    }

    unsigned char *sig1 = NULL;
    unsigned int sigLen = 0;
    //memset(sig, 0, MAXSIZE+1024);
    sig1 = malloc(EVP_PKEY_size(evpKey));
    sig1[EVP_PKEY_size(evpKey)] = (unsigned char) "\0";
    /* check sig */
    if ( EVP_SignFinal( evp_ctx, sig1, &sigLen, evpKey ) == 0 ) {
        fprintf( stderr, "Couldn't calculate signature.\n" );
        unsigned long sslErr = ERR_get_error();
        if ( sslErr ) fprintf(stderr, "%s\n", ERR_error_string(sslErr, 0));
        exit(1);
    }
    EVP_MD_CTX_destroy( evp_ctx );
    RSA_free( rsa );
    EVP_PKEY_free( evpKey );
    ERR_free_strings();
    free(md5Value1);
    free(sig1);
    return sigLen;
}

/* Verify file with certain certificate 
 * http://openssl.6102.n7.nabble.com/EVP-VerifyFinal-fail-use-RSA-public-key-openssl-1-0-0d-win32-vc2008sp1-td9539.html
 */
int verifySig(char *rsaprivKeyPath, const char *clearText){
    char *sig_name = NULL;
    sig_name = malloc(MAXSIZE);
    sprintf( sig_name, "%s_%s.sig",  clearText, rsaprivKeyPath );
    printf("-----start verify-----\n");
    EVP_PKEY *evpKey;
    RSA *rsa;
    unsigned char *md5Value = NULL;
    md5Value = malloc(128);
    md5Value = hashFile(clearText);
    printf("MD5: %s\n",md5Value);
    if ( (evpKey = EVP_PKEY_new()) == 0 ) {
        fprintf( stderr, "Couldn't create new EVP_PKEY object.\n" );
        unsigned long sslErr = ERR_get_error();
        if ( sslErr ) fprintf(stderr, "%s\n", ERR_error_string(sslErr, 0));
        exit(1);
    }

    /* get private key file */
    rsa = getRsaFp( rsaprivKeyPath );
    int vsigLen = sigLength(rsaprivKeyPath,clearText);
    int vr;
    unsigned char *sig2 = NULL;
    sig2 = readSig(sig2, sig_name);
    printf("verify : %s\n length:%i\n",sig2,vsigLen);
    char *certificate = malloc(MAXSIZE);
    strcpy(certificate,rsaprivKeyPath);
    sprintf(rsaprivKeyPath,"client_certs/%s", certificate);
    //printf("%s\n",certificate);
    //printf("%s\n",rsaprivKeyPath);
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

    if(!EVP_VerifyUpdate( evp_ctx, (const char *)md5Value, strlen( (const char *)md5Value ))){

               printf("EVP_VerifyUpdate error. \n");

               exit(1);

    }
    //printf("ClearText:%s\n",clearText);
    //memset(sig, 0, MAXSIZE+1024);
    //printf("strlen(sig):%lu\n",strlen((const char *)sig));
    //printf("vsiglen:%u\n",vsigLen);
    vr = EVP_VerifyFinal( evp_ctx, sig2, vsigLen, evpKey);
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
    EVP_MD_CTX_destroy( evp_ctx );
    RSA_free( rsa );
    EVP_PKEY_free( evpKey );
    ERR_free_strings();
    free(md5Value);
    free(sig2);
    return 0;
}

/* vouch file */
int vouchFile(char *rsaprivKeyPath, const char *clearText, SSL *ssl){
    EVP_PKEY *evpKey;
    if ( (evpKey = EVP_PKEY_new()) == 0 ) {
        fprintf( stderr, "Couldn't create new EVP_PKEY object.\n" );
        unsigned long sslErr = ERR_get_error();
        if ( sslErr ) fprintf(stderr, "%s\n", ERR_error_string(sslErr, 0));
        exit(1);
    }
    RSA *rsa;
    unsigned char *md5Value = NULL;
    md5Value = malloc(128);
    md5Value = hashFile(clearText);
    printf("MD5: %s\n",md5Value);
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
     
    if ( EVP_SignUpdate( evp_ctx, (const char *)md5Value, strlen( (const char *)md5Value ) ) == 0 ) {
        fprintf( stderr, "Couldn't calculate hash of message.\n" );
        unsigned long sslErr = ERR_get_error();
        if ( sslErr ) fprintf(stderr, "%s\n", ERR_error_string(sslErr, 0));
        exit(1);
    }

    unsigned char *sig1 = NULL;
    unsigned int sigLen = 0;
    //memset(sig, 0, MAXSIZE+1024);
    sig1 = malloc(EVP_PKEY_size(evpKey));
    sig1[EVP_PKEY_size(evpKey)] = (unsigned char) "\0";
    /* check sig */
    if ( EVP_SignFinal( evp_ctx, sig1, &sigLen, evpKey ) == 0 ) {
        fprintf( stderr, "Couldn't calculate signature.\n" );
        unsigned long sslErr = ERR_get_error();
        if ( sslErr ) fprintf(stderr, "%s\n", ERR_error_string(sslErr, 0));
        exit(1);
    }
    printf("got sig1 : %s\nlength: %i\n",sig1, sigLen);
    //printf( "Got signature: '%s'\n", sig );
    int ws = 0;
    char *sig_name = NULL;
    //memset(sig_name, 0, MAXSIZE);
    sig_name = malloc(MAXSIZE);
    sprintf( sig_name, "%s_%s.sig",  clearText, rsaprivKeyPath );
    ws = writeSig(sig1,sig_name);
    if(ws != 0){
        fprintf( stderr, "Couldn't write signature to file.\n" );
        exit(1);
    }
    else{
        printf("Signature file successfully written : %s\n", sig_name);
    }
    EVP_MD_CTX_destroy( evp_ctx );
    RSA_free( rsa );
    EVP_PKEY_free( evpKey );
    ERR_free_strings();
    SSL_write(ssl,"From Server : Vouching File Succeeded",strlen("From Server : Vouching File Succeeded"));
    free(md5Value);
    //free(sig1);
    return 0;
}

/* get the md5 hash for a file 
 * http://stackoverflow.com/questions/10324611/how-to-calculate-the-md5-hash-of-a-large-file-in-c
 */
unsigned char * hashFile(const char *fileName){
    unsigned char *c = NULL;
    c = malloc(128);
    char *filename= (char *)fileName;
    FILE *fp = fopen (filename, "rb");
    MD5_CTX mdContext;
    int bytes;
    unsigned char data[1024];

    if (fp == NULL) {
        printf ("%s can't be opened.\n", filename);
        exit(EXIT_FAILURE);
    }

    MD5_Init (&mdContext);
    while ((bytes = fread (data, 1, 1024, fp)) != 0)
        MD5_Update (&mdContext, data, bytes);
    MD5_Final (c,&mdContext);
    //for(i = 0; i < MD5_DIGEST_LENGTH; i++) printf("%02x", c[i]);
    //printf (" %s\n", filename);
    fclose (fp);
    return c;
}
