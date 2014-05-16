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
    int n = 0;
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
    int n = 0;
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
    char *head_buff= NULL;
    head_buff = malloc(HEADER_SIZE);
    if (   h.action != ADD_FILE 
        && h.action != FETCH_FILE 
        && h.action != LIST_FILE 
        && h.action != VOUCH_FILE
		&& h.action != VERIFY_FILE
		&& h.action != UPLOAD_CERT
        && h.action != FIND_ISSUER 
        && h.action != TEST_RINGOFTRUST
        && h.action != FAIL_ERROR) {
        fprintf(stderr, "Incorrect header action for sending header\n");
        exit(EXIT_FAILURE);
    }

    char *file_name = h.file_name;
    if (file_name[strlen(file_name) - 1] == '\0') 
        file_name[strlen(file_name) - 1] = '\n';
    
    char *certificate = h.certificate;
    if (certificate[strlen(certificate) - 1] == '\0') 
        certificate[strlen(certificate) - 1] = '\n';
    

    sprintf(head_buff,"%d\n%d\n%s\n%s\n%i\n",(short)h.action,(int)h.file_size,file_name,h.certificate,h.circ);
    head_buff[HEADER_SIZE]= (char)'\0';

    printf("Sending header buff:\n %s\n", head_buff);
    int len = HEADER_SIZE;
    sendall(ssl, (unsigned char *)head_buff, &len);
    if (len < HEADER_SIZE) {
        fprintf(stderr, "Error sending header\n");
        exit(EXIT_FAILURE);
    }
    //free(head_buff);
}   

int unpack_header_string(char *head_string, header *h) {
    int i;

    char *loc = head_string;
    for (i = 0; i < NUM_HEAD_FIELDS; i++) {
        char buff[MAXSIZE];
        char *buff_loc = buff;
        while (*loc != '\n') {
            *buff_loc = *loc;
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
                h->file_name = malloc(strlen(buff));
                strcpy(h->file_name, buff);
                break;
            case 3:
                h->certificate = malloc(strlen(buff));
                strcpy(h->certificate, buff);
                break;
            case 4:
                h->circ = atoi(buff);
                break;
            default:
                break;
        }
    }
    return 0;
}

/**
 * From cboard.cprogramming.com/c-programming/95462-compiler-error-warning-implicit-declaration-function-'strdup'.html
 */
char *strdup(const char *str) {
	int n = strlen(str) + 1;
	char *dupStr = malloc(n);
	if (dupStr) {
		strcpy(dupStr, str);
	}
	return dupStr;
}

/**server list current dir files
 * based on : http://stackoverflow.com/questions/11291154/save-file-listing-into-array-or-something-else-c
**/
size_t file_list(const char *path, char ***ls) {
    size_t count = 0;
    DIR *dp = NULL;
    struct dirent *ep = NULL;

    if((dp = opendir(path)) == NULL) {
        fprintf(stderr, "no such directory: '%s'", path);
        return 0;
    }

    *ls = NULL;
    while((ep=readdir(dp))!= NULL){
        char curFileName[MAXSIZE];
        sprintf(curFileName, "%s",ep->d_name);
        if(!strcmp(ep->d_name,"..")||!strcmp(ep->d_name,".")){
            continue;
        }
        count++;
    }

    rewinddir(dp);
    free(ep);
    *ls = calloc(count, sizeof(char *));
    count = 0;
    while((ep = readdir(dp))!= NULL){
        char curFileName[MAXSIZE];
        sprintf(curFileName, "%s", ep->d_name);
        if(!strcmp(ep->d_name,"..")||!strcmp(ep->d_name,".")){
            continue;
        }
        (*ls)[count++] = strdup(ep->d_name);
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
    sprintf(certificate,"%s", rsaprivKeyPath);

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

RSA* getRsaPubFp( const char* rsaprivKeyPath )
{
    char *certificate = NULL;
    certificate = malloc(MAXSIZE);
    sprintf(certificate,"server_certs/%s", rsaprivKeyPath);

    FILE* fp;
    fp = fopen( certificate, "r" );
    if ( fp == 0 ) {
    fprintf( stderr, "Couldn't open RSA public key: '%s'. %s\n",certificate, strerror(errno) );
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

    if (!PEM_read_RSA_PUBKEY(fp, &rsa, NULL, NULL))
    {
        fprintf(stderr, "Error loading RSA Public Key File.\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    fclose( fp );
    return rsa;
}

/* store signature to file 
 *
 *  stored sig file will have nameing convention: 
 *              clrtextFileName_signatorysCertName.sig
 */
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

/* Read signature
 * http://stackoverflow.com/questions/15827264/reading-a-text-file-in-c
 */
unsigned char * readSig(unsigned char *sig, char *sig_name){
    FILE *fp; 
    size_t len;
    size_t bytesRead;
    fp = fopen(sig_name,"r"); /* write to file or create a file if it does not exist.*/ 
    if ( fp == 0 ) {
        fprintf( stderr, "Couldn't open signature file: '%s'. %s\n",sig_name, strerror(errno) );
        return (unsigned char *)' ';
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
    //printf("read sig :%s\nlen: %zu\n",sig,len);
    return sig;
}

/* Check if signature of digest was signed by public key */
int isSignedBy(X509 *cert, X509 *CA) {
    EVP_PKEY *pubKey; // pub key of CA
    if ((pubKey = EVP_PKEY_new()) == 0) {
        fprintf( stderr, "Couldn't create new EVP_PKEY object.\n" );
        unsigned long sslErr = ERR_get_error();
        if ( sslErr ) fprintf(stderr, "%s\n", ERR_error_string(sslErr, 0));
        exit(1);
    }

    // verified result identifier
    int vr;
    // extract public key from X509 CA (parent)
    pubKey = X509_get_pubkey(CA);

    /*create evp_md_ctx */
    EVP_MD_CTX *evp_md_ctx;
    if ( (evp_md_ctx = EVP_MD_CTX_create()) == 0 ) {
        fprintf( stderr, "Couldn't create EVP context.\n" );
        unsigned long sslErr = ERR_get_error();
        if ( sslErr ) fprintf(stderr, "%s\n", ERR_error_string(sslErr, 0));
        exit(EXIT_FAILURE);
    }

        if ( EVP_VerifyInit(evp_md_ctx, EVP_sha1()) == 0 ) {
        fprintf( stderr, "Couldn't exec EVP_VerifyInit.\n" );
        unsigned long sslErr = ERR_get_error();
        if ( sslErr ) fprintf(stderr, "%s\n", ERR_error_string(sslErr, 0));
        exit(EXIT_FAILURE);
    }

    unsigned char digest[SHA_DIGEST_LENGTH];
    unsigned int len;

    // from https://zakird.com/2013/10/13/certificate-parsing-with-openssl/
    int rc = X509_digest(cert, EVP_sha1(), digest, &len);
    if (rc == 0 || len != SHA_DIGEST_LENGTH) {
        perror("X509_digest\n");
        exit(EXIT_FAILURE);
    }
    int i;
    printf("printing digest before EVP\n");
    for (i = 0; i < (int)len; i++) {
        printf("%02x", digest[i]);
    }
    printf("\n");
    printf("length: %i\n",(int)len);
    if(!EVP_VerifyUpdate( evp_md_ctx, digest, sizeof(digest))){
       printf("EVP_VerifyUpdate error. \n");
       exit(EXIT_FAILURE);
    }
    // FILE *sigfile = fopen("siiiiig", "w");
    unsigned char *signature = cert->signature->data;
    // fwrite(signature, sizeof(signature), cert->signature->length, sigfile);
    // fclose(sigfile);
    
    for (i = 0; i < cert->signature->length; i++) {
        printf("%02x", signature[i]);
    }
    printf("\n%i\n", cert->signature->length);


    char *shahash = cert->name;
    printf("%s\n", shahash);

    // check if signature decrypted by pubKey matches digest in evp_md_ctx
    vr = EVP_VerifyFinal( evp_md_ctx, signature, cert->signature->length, pubKey);

    EVP_MD_CTX_destroy( evp_md_ctx );
    EVP_PKEY_free( pubKey );
    ERR_free_strings();
    return vr;
}

/* Verify file with certain certificate 
 * Params: 
 *      signatorYCertName: string name of signer's certificate
 *      clearText:  string name of clear text file
 * http://openssl.6102.n7.nabble.com/EVP-VerifyFinal-fail-use-RSA-public-key-openssl-1-0-0d-win32-vc2008sp1-td9539.html
 * http://stackoverflow.com/questions/15032338/extract-public-key-of-a-der-encoded-certificate-in-c
 */
int verifySig(char *signatoryCertName, const char *clearText){
    char *sig_name = NULL;
    sig_name = malloc(MAXSIZE);
    if (isNameCertFile(clearText)) {
        sprintf( sig_name, "%s/%s_%s.sig", SERVER_CERT_DIR, clearText, signatoryCertName );
    } else {
        sprintf( sig_name, "%s/%s_%s.sig", SERVER_SIG_DIR, clearText, signatoryCertName );
    }
    printf("-----start verify-----\n");
    EVP_PKEY *evpKey;
    //RSA *rsa;
    unsigned char *shaValue = NULL;
    shaValue = malloc(SHA_DIGEST_LENGTH);
    char clear_text_loc[MAXSIZE];
    if (isNameCertFile(clearText)) {
        sprintf(clear_text_loc, "%s/%s", SERVER_CERT_DIR, clearText);
    } else {
        sprintf(clear_text_loc, "%s/%s", SERVER_FILE_DIR, clearText);
    }
    hashFile(shaValue, clear_text_loc);
    printf("SHA:");
    for(int i = 0; i < SHA_DIGEST_LENGTH; i++) printf("%02x", shaValue[i]);
    printf("\n");
    if ( (evpKey = EVP_PKEY_new()) == 0 ) {
        fprintf( stderr, "Couldn't create new EVP_PKEY object.\n" );
        unsigned long sslErr = ERR_get_error();
        if ( sslErr ) fprintf(stderr, "%s\n", ERR_error_string(sslErr, 0));
        return -1;
    }

    /* get private key file */
    //rsa = getRsaPubFp( signatoryCertName );
    int vsigLen=128;
    //int vsigLen = sigLength(signatoryCertName,clearText);
    int vr;
    unsigned char *sig2 = NULL;
    if((sig2 = readSig(sig2, sig_name)) == (unsigned char *)' '){
        return 0;
    }
    for(int i = 0; i < vsigLen; i++) printf("%02x", sig2[i]);
        printf("\n");
    printf( "Length: '%i'\n", vsigLen );
    //printf("%s\n",certificate);
    //printf("%s\n",signatoryCertName);

    /*****************************************************/

    char *certificate = NULL;
    certificate = malloc(MAXSIZE);
    sprintf(certificate,"%s/%s", SERVER_CERT_DIR, signatoryCertName);
    // printf("certloc: %s\n", certificate);
    FILE* fp;
    fp = fopen( certificate, "r" );
    if ( fp == 0 ) {
        fprintf( stderr, "Couldn't open RSA public key: '%s'. %s\n",certificate, strerror(errno) );
        return -1;
    }
    X509 * xcert = PEM_read_X509(fp, NULL, NULL, NULL);
    if (!xcert) {
        fprintf(stderr, "Could not read X509 from pem\n");
        exit(EXIT_FAILURE);
    }
    evpKey = X509_get_pubkey(xcert);


    /*create evp_ctx */
    EVP_MD_CTX *evp_ctx;
    if ( (evp_ctx = EVP_MD_CTX_create()) == 0 ) {
        fprintf( stderr, "Couldn't create EVP context.\n" );
        unsigned long sslErr = ERR_get_error();
        if ( sslErr ) fprintf(stderr, "%s\n", ERR_error_string(sslErr, 0));
        return -1;
    }


    if ( EVP_VerifyInit(evp_ctx, EVP_sha1()) == 0 ) {
        fprintf( stderr, "Couldn't exec EVP_VerifyInit.\n" );
        unsigned long sslErr = ERR_get_error();
        if ( sslErr ) fprintf(stderr, "%s\n", ERR_error_string(sslErr, 0));
        return -1;
    }

    if(!EVP_VerifyUpdate( evp_ctx, (const char *)shaValue, sizeof(shaValue))){
       printf("EVP_VerifyUpdate error. \n");
       return -1;
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
    //RSA_free( rsa );
    EVP_PKEY_free( evpKey );
    ERR_free_strings();
    // free(shaValue);
    // free(sig2);
    return 1;
}

/* vouch file */
int vouchFile(char *signatorysCertName, const char *clearText, SSL *ssl){
    int num;
    unsigned char *shaValue = NULL;
    shaValue = malloc(SHA_DIGEST_LENGTH);
    hashFile(shaValue, clearText);
    unsigned char *sig = NULL;
    sig = malloc(128);
    sig[MAXSIZE] = (unsigned char) '\0';
    //printf("MD5:");
    //for(int i = 0; i < SHA_DIGEST_LENGTH; i++) printf("%02x", shaValue[i]);
    //printf("\n");
    SSL_write(ssl,shaValue,sizeof(shaValue)*2);
    num = SSL_read(ssl, sig, 128);
    if ( num <= 0 )
    {
            printf("Either Connection Closed or Error\n");
            //Break from the While
            exit(EXIT_FAILURE);
    }

    //for(int i = 0; i < (int)sigLen; i++) printf("%02x", sig[i]);
    //    printf("\n");
    //printf( "Length: '%i'\n", sigLen );
    int ws = 0;
    char *sig_name = NULL;
    //memset(sig_name, 0, MAXSIZE);
    sig_name = malloc(MAXSIZE);
    sprintf( sig_name, "%s_%s.sig",  clearText, signatorysCertName);
    ws = writeSig(sig,sig_name);
    if(ws != 0){
        fprintf( stderr, "Couldn't write signature to file.\n" );
        exit(1);
    }
    else{
        printf("Signature file successfully written : %s\n", sig_name);
    }
    SSL_write(ssl,"From Server : Vouching File Succeeded",strlen("From Server : Vouching File Succeeded"));
    // free(shaValue);
    // free(sig);
    return 0;
}

/* Open file and calculate its sha hash 
 * http://stackoverflow.com/questions/10324611/how-to-calculate-the-md5-hash-of-a-large-file-in-c
 */
int hashFile(unsigned char* c, const char *fileName){
    char *filename= (char *)fileName;
    FILE *fp = fopen (filename, "rb");
    SHA_CTX shaContext;
    int bytes;
    unsigned char data[1024];

    if (fp == NULL) {
        printf ("%s can't be opened.\n", filename);
        exit(EXIT_FAILURE);
    }

    SHA1_Init (&shaContext);
    while ((bytes = fread (data, 1, 1024, fp)) != 0)
    SHA1_Update (&shaContext, data, bytes);
    SHA1_Final (c,&shaContext);
    //for(i = 0; i < SHA_DIGEST_LENGTH; i++) printf("%02x", c[i]);
    //printf (" %s\n", filename);
    fclose (fp);
    return 0;
}

/* return 1 if file exists, 0 otherwise */
int check_if_file_exists(const char *file_name) {
    struct stat st;
    int ret = stat(file_name, &st);
    return ret == 0;
}

/**
 * Check if this sig file is for your clear text file (filename)
 *     naming convention is: filename_signingCertName.sig
 */
int checkSigFileName(char *fileName, char *sigFileName) {
    if (strlen(fileName) > strlen(sigFileName)) return 0;

    char *fileNamePortionOfSigName = malloc(strlen(fileName) + 1);
    strncpy(fileNamePortionOfSigName, sigFileName, strlen(fileName));
    fileNamePortionOfSigName[strlen(fileName)] = '\0';
    if (strcmp(fileName, fileNamePortionOfSigName) == 0) return 1;
    else return 0;
}


/* Find issuer's certificate name of certificateName
 * https://zakird.com/2013/10/13/certificate-parsing-with-openssl/
 * http://stackoverflow.com/questions/1271064/how-do-i-loop-through-all-files-in-a-folder-using-c
 */
 int findIssuer(char *certificateName, char ***issuerNames, int *numIssuers){
    *issuerNames = malloc(sizeof(char **));
    *numIssuers = 0;
    // char **issuerNameInd = issuerNames;
    char certificateLoc[MAXSIZE];
    sprintf(certificateLoc,"%s/%s", SERVER_CERT_DIR, certificateName);
    FILE *startCertFp = fopen(certificateLoc, "r");
    if (!startCertFp) {
        fprintf(stderr, "unable to open: %s\n", certificateLoc);
        return 1;
    }
    
    X509 *startCert = PEM_read_X509(startCertFp, NULL, NULL, NULL);
    if (!startCert) {
        fprintf(stderr, "unable to parse certificate in: %s\n", certificateLoc);
        fclose(startCertFp);
        return 1;
    }
    //loop through the directory
    struct dirent *dp;
    DIR *dfd;

    char dir[MAXSIZE];
    sprintf(dir, SERVER_CERT_DIR);

    if ((dfd = opendir(dir)) == NULL)
    {
        fprintf(stderr, "Can't open %s\n", dir);
        return 1;
    }

    //start looping the certs in the directory
    while((dp = readdir(dfd)) != NULL){ //need to be changed
        char curCertName[MAXSIZE];
        sprintf(curCertName, "%s/%s", SERVER_CERT_DIR, dp->d_name);
        struct stat stbuf ;
        if( stat(curCertName,&stbuf ) == -1 )
        {
            printf("Unable to stat file: %s\n",curCertName) ;
            continue ;
        }

        // skip sub directories
        if (S_ISDIR(stbuf.st_mode))
        {
            continue;
        }
        // skip non .pem files
        if( !*curCertName 
            || strlen(curCertName) <4 
            || curCertName[strlen(curCertName)-1] != 'm' 
            || curCertName[strlen(curCertName)-2] != 'e'
            || curCertName[strlen(curCertName)-3] != 'p'){
            continue;
        }

        FILE *curCertFP = fopen(curCertName, "r");
        if (!curCertFP) {
            fprintf(stderr, "unable to open: %s\n", curCertName);
            return 1;
        }

        // open current cert (from list) as issuer
        X509 *curCert = PEM_read_X509(curCertFP, NULL, NULL, NULL);

	if (!curCert) {
		fprintf(stderr, "Couldn't read certificat: %s\n", curCertName);
		exit(EXIT_FAILURE);
	}

        if(strcmp(certificateName, curCertName) != 0
            && X509_check_issued(curCert, startCert) == X509_V_OK) {
            (*numIssuers)++;
            *issuerNames = realloc(*issuerNames, sizeof(*issuerNames) * (*numIssuers) + 1);
	    if (!(*issuerNames)) {
	   	fprintf(stderr, "Couldn't allocate for issuerNames\n"); 
		exit(EXIT_FAILURE);
	    }
            // issuerNameInd++;
            // issuerNameInd = issuerNames + *numIssuers - 1;
            (*issuerNames)[*numIssuers - 1] = malloc(strlen(curCertName));
            //printf("%s\n", curCertName);
            strcpy((*issuerNames)[*numIssuers - 1], curCertName);
            // return 1;
        }
        fclose(curCertFP);
        X509_free(curCert);
    }
    X509_free(startCert);
    fclose(startCertFp);
    if (*numIssuers > 0) return 1;
    return -1; // didn't find an issuer
 }

 #define SERVER_INDEX_FILE "index"

typedef struct CertInd {
    char certName[MAXSIZE];
    int i;
} CertInd;

int getIndexOf(char *certName, CertInd *certIndexMap[], int numCerts) {
    int i;
    for (i = 0; i < numCerts; i++) {
        if (strcmp(certName, certIndexMap[i]->certName) == 0) 
            return certIndexMap[i]->i;
    }
    return -1;
}

char * getNameOfCert(int certNum, CertInd *certIndexMap[], int numCerts) {
    int i;
    for (i = 0; i < numCerts; i++) {
        if (certIndexMap[i]->i == certNum) 
            return certIndexMap[i]->certName;
    }
    return "";
}

/* Count number of certificates in dir, based on .pem naming convention */
int getNumCertsInDir(char *dir) {
    struct dirent *dp;
    DIR *dfd;

    if ((dfd = opendir(dir)) == NULL)
    {
        fprintf(stderr, "[getNumCerts] Can't open %s\n", dir);
        return 1;
    }

    int count = 0;
    // skip sub directories
    // if ( ( stbuf.st_mode & S_IFMT ) == S_IFDIR )
    // first get file count
    while ((dp = readdir(dfd)) != NULL) {
        struct stat stbuf ;
	char entryLoc[MAXSIZE];
	sprintf(entryLoc, "%s/%s", SERVER_CERT_DIR, dp->d_name);
	    if( stat(entryLoc,&stbuf) == -1 )
	    {
		printf("Unable to stat file: %s\n",entryLoc) ;
		continue ;
	    }

	    if (S_ISDIR(stbuf.st_mode)) continue;
        
          if (isNameCertFile(dp->d_name)) count++;
    }
    return count;
}

// to find longest cycle: 
//      find deepest node that signed root node
void dfs(int v, int ***adj, int *visited[], int startCertInd, int numCerts, int **cycle, int *cycleLength, int depth, int **parents, int *deepestNode) {
    // for longest, maybe only set visited[v] = 1 if v != startCertInd, so we can visit startCertInd again.
    //      but we should only be able to visit startCertInd again if it is the final node... (not sure)
    (*visited)[v] = 1;
    (*cycleLength)++;
    (*cycle)[*cycleLength - 1] = v;

    if (depth > *deepestNode && (*adj)[v][startCertInd] && v != startCertInd) {
        *deepestNode = v;
    }
    int i;
    for (i = 0; i < numCerts; i++) {
        if ((*adj)[v][i] > 0 && (*visited)[i] == 0) {
            (*parents)[i] = v;

            dfs(i, adj, visited, startCertInd, numCerts, cycle, cycleLength, depth + 1, parents, deepestNode);
        }
    }
    return;
}

/*
 * Get protection rating of a file based on the longest ring of trust
 * its signatory belongs to.
 *
 * File is regarded as protected if max(ringOfTrust(fileName)) > requested circumference
 */
int getProtectionRating(char *fileName) {
    // find file's signatures
    // do ringOfTrust on each signature's certificate
    // return max ringOfTrust
    
    //loop through signature directory directory
    struct dirent *dp;
    DIR *dfd;
    char dir[MAXSIZE];
    sprintf(dir, SERVER_SIG_DIR);

    if ((dfd = opendir(dir)) == NULL)
    {
        fprintf(stderr, "Can't open %s\n", dir);
        return 1;
    }

    int maxRingOfTrust = 0;

    while((dp = readdir(dfd)) != NULL){
        // if this is a signature of fileName
        if (checkSigFileName(fileName, dp->d_name)) {
            // get ring of trust on sig's certificate
            int certNameStrLen = strlen(dp->d_name) - strlen(fileName) - 5;
            char *certName = malloc(certNameStrLen + 1);

            // extract certificate name portion of sigfile name
            //      (e.g. fileName_certificate.pem.sig -> certificate.pem)
            strncpy(certName, dp->d_name + strlen(fileName) + 1, 
                certNameStrLen);
            certName[certNameStrLen] = '\0';
            int certsROT = ringOfTrust(certName);
            printf("Ring of trust for: %s signed by %s is %i\n", fileName, certName, certsROT);
            maxRingOfTrust = maxRingOfTrust <= certsROT ? certsROT : maxRingOfTrust;
        }
    }
    return maxRingOfTrust;
}

// /* get the certificate of a sig*/
// int getCertName(char **certName, char* sigName){
//     //loop through the directory
//     char **ref;
//     ref=certName;
//     struct dirent *dp;
//     DIR *dfd;
//     int i = 0;

//     char dir[MAXSIZE];
//     sprintf(dir, SERVER_CERT_DIR);

//     if ((dfd = opendir(dir)) == NULL)
//     {
//         fprintf(stderr, "Can't open %s\n", dir);
//         return 1;
//     }
//     while((dp = readdir(dfd)) != NULL)){
//         if(verifySig(dp->d_name,sigName)){
//             *certName = malloc(MAXSIZE);
//             *certName = dp->d_name;
//             certName++;
//             //sprintf(certName,"%s",dp->d_name);
//         }
//     }
//     return 0;
// }

// /* find longest ring a file has */
// int findLongestRing(char *fileName){
//     int longestLenght = 0;
//     char **certName[];


/* return circumference of certificate chain, 
 * else return -1 if ring is not complete 
 */
int ringOfTrust(char *startCertificate) {
    char *checkCert = NULL;
    checkCert = malloc(MAXSIZE);
    sprintf(checkCert,"%s/%s",SERVER_CERT_DIR,startCertificate);
    FILE* fp;
    fp = fopen( checkCert, "r" );
    if ( fp == 0 ) {
        fprintf( stderr, "Couldn't open certificate: %s. %s\n",checkCert, strerror(errno) );
        return 1;
    }
    //loop through the directory
    struct dirent *dp;
    DIR *dfd;

    char dir[MAXSIZE];
    sprintf(dir, SERVER_CERT_DIR);

    if ((dfd = opendir(dir)) == NULL)
    {
        fprintf(stderr, "Can't open %s\n", dir);
        return 1;
    }
    int numberCerts = getNumCertsInDir(dir);
    printf("Number certificates: %i\n", numberCerts);

    CertInd *certIndexMap[numberCerts];

    int **adj;
    int cc;
    adj = malloc(numberCerts * sizeof(int*));
    for (cc = 0; cc < numberCerts; cc++) {
        adj[cc] = malloc(sizeof(int) * numberCerts);
        int ccc;
        for (ccc = 0; ccc < numberCerts; ccc++) {
            adj[cc][ccc] = 0;
        }
    }

    int i; 
    i = 0;

    //loop through the certs in the directory to build unique cert indexes
    while((dp = readdir(dfd)) != NULL){
        char curCertName[MAXSIZE];
        sprintf(curCertName, "%s/%s", SERVER_CERT_DIR, dp->d_name);
        struct stat stbuf ;
        if( stat(curCertName,&stbuf ) == -1 )
        {
            printf("Unable to stat file: %s\n",curCertName) ;
            continue ;
        }

        // skip sub directories
        // if ( ( stbuf.st_mode & S_IFMT ) == S_IFDIR )
        if (S_ISDIR(stbuf.st_mode))
        {
            continue;
        }
        // skip non .pem files
        if( !isNameCertFile(curCertName)){
            continue;
        }
        CertInd *ci = malloc(sizeof(CertInd));
        strcpy(ci->certName, dp->d_name);
        ci->i = i;
        certIndexMap[i] = ci;
        i++;
    }
    // print mapping for debugging
//    printf("Indexing Schematic:\n");
//    for (i = 0; i < numberCerts; i++) {
//         printf("%s --> %i\n", certIndexMap[i]->certName, certIndexMap[i]->i);
//    }

//     printf("\nBuilding signatory graph:\n");

    // build adjacency matrix
    for (i = 0; i < numberCerts; i++) {
        char cert[MAXSIZE];
        strcpy(cert, certIndexMap[i]->certName);
        char **issuers;
        int numIssuers = 0;

        // Find issuer of cert, and get all certificates this issuer owns
        // because we trust ANY higher issuer that signed any of our issuer's
        // certs (we trust every cert owned by issuer)
        if (findIssuer(cert, &issuers, &numIssuers)) {
            int j;
            for (j = 0; j < numIssuers; j++) {
                char *issuer = issuers[j];
                char issue_noDirStr[MAXSIZE];
                strncpy(issue_noDirStr, issuer + strlen(SERVER_CERT_DIR) + 1, strlen(issuer) - strlen(SERVER_CERT_DIR) + 1);

                // at the moment skip self signed certs - not sure if this is correct though
                if (strcmp(cert, issue_noDirStr) == 0) continue;
                int ci = getIndexOf(cert, certIndexMap, numberCerts); // child cert
                int pi = getIndexOf(issue_noDirStr, certIndexMap, numberCerts); // parent cert
                adj[ci][pi] = 1;  
 //               printf("\t%s --issued--> %s (%i ---> %i)\n", issue_noDirStr, cert, pi, ci);          
            }
        }
    }

    int *visited;
    visited = malloc(sizeof(int *) * numberCerts);
    int *cycle;
    cycle = malloc(sizeof(int *) * numberCerts);
    int *parents;
    parents = malloc(sizeof(int) * numberCerts);
    for (i = 0; i < numberCerts; i++) {
        cycle[i] = 0;
        visited[i] = 0;
        parents[i] = -1;
    }

    int cycleLength = 0;
    int deepestNode = -1;

    int startCertInd = getIndexOf(startCertificate, certIndexMap, numberCerts);
    // search algorithm for cycle commence here
    printf("Begin DFS\n");
    dfs(startCertInd, &adj, &visited, startCertInd, numberCerts, &cycle, &cycleLength, 0, &parents, &deepestNode);
    if (deepestNode == -1) return 0;
    // for (i = 0; i < cycleLength; i++) {
    int vert = deepestNode;
    int cycycy = 0;
    printf("DeepestNode: %s\n", getNameOfCert(vert, certIndexMap, numberCerts));
    while (vert != -1) {
         printf("%s(%i) --> ", getNameOfCert(vert, certIndexMap, numberCerts), vert);
        cycycy++;
        vert = parents[vert];
    }

    // for ()
    // while

    // check for complete cycle
    // if (adj[cycle[cycleLength - 1]][startCertInd]) {
    if (adj[deepestNode][startCertInd]) {
        // printf("%s(%i)", getNameOfCert(startCertInd, certIndexMap, numberCerts), startCertInd); cycleLength++;
    } else { // there's no cycle!
        cycycy = 0;
    }

    printf("\nEnd DFS\n");
    printf("Ring of trust circumference: %i\n", cycycy);
    fclose(fp);
    return cycycy;
}

 /*
 * Check if file name is certificate based on .pem naming convention
 */
int isNameCertFile(const char *name) {
    int len = strlen(name);
    return  !(len < 4 
        || name[len - 1] != 'm'
        || name[len - 2] != 'e' 
        || name[len - 3] != 'p'
        || name[len - 4] != '.');
}

 /*
 * Check if file name is signature based on .sig naming convention
 */
int isNameSigFile(const char *name) {
    int len = strlen(name);
    return  !(len < 4 
        || name[len - 1] != 'g'
        || name[len - 2] != 'i' 
        || name[len - 3] != 's'
        || name[len - 4] != '.');
}
