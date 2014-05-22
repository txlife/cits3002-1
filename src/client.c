#include "trustcloud.h"
#define h_addr h_addr_list[0] /* for backward compatibility */
//static int verify_callback(int ok, X509_STORE_CTX *ctx);

void shutdown_connections(SSL_CTX *ctx, SSL *ssl, int socket_fd) {
    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    close(socket_fd);
}

void parse_host_port(char *arg, char *hostname, int *port) {
    char *arg_p = arg;
    char *h_p = hostname;
    while (*arg_p != ':' && *arg_p != '\0') {
        *h_p = *arg_p;
        h_p++;
        arg_p++;
    }
    if (*arg_p == '\0') {
        fprintf(stderr, "Usage: -h address:port\n");
        exit(EXIT_FAILURE);
    }
    arg_p++;
    *port = atoi(arg_p);
}

int main(int argc, char *argv[])
{
    struct sockaddr_in server_info;
    struct hostent *he;
    int socket_fd,num;
    char buffer[1024];
    // char *hostname = NULL;
    char hostname[MAXSIZE];
    // char port_str[MAXSIZE];
    int port_no;
    char buff[1024];
    SSL_CTX *ctx;
    SSL *ssl;
    header h;
    //X509            *server_cert;
    //EVP_PKEY        *pkey;

    /* check arguments */
    if (argc < 2) {
        return help();
    }

    char *file_name = NULL;
    char *certificate = NULL;
    int send_flag = 0;
    int list_flag = 0;
    int fetch_flag = 0;
    int vouch_flag = 0;
    int verify_flag = 0;
    int up_cert_flag = 0;
    int findissuer_flag = 0;
    int test_ringoftrust = 0; // remove later
    int c;
    int circumference = 0;
    opterr = 0;

    /**
     *  args left to implement:
     *      -h hostname:port    provide the remote address hosting the trustcloud server
     *      -c number   provide the required circumference (length) of a ring of trust
     *      -f filename fetch an existing file from the trustcloud server (simply sent to stdout)
     *      -l  list all stored files and how they are protected
     *      -u certificate  upload a certificate to the trustcloud server
     *      -v filename certificate vouch for the authenticity of an existing file in the trustcloud server using the indicated certificate
     */
    while ((c = getopt(argc, argv,"h:a:lf:v:y:i:u:t:c:")) != -1) {
        switch(c) {
            case 'h':
                // hostname = optarg;
                parse_host_port(optarg, hostname, &port_no);
                printf("%s:%i\n", hostname, port_no);
                break;
            case 'a':
                file_name = optarg;
                send_flag = 1;
                break;
            case 'f':
                file_name = optarg;
                fetch_flag = 1;
                break;
	        case 'l':
            	list_flag = 1;
		        break;
            case 'v':
                vouch_flag = 1;
                optind--;
                file_name = argv[optind];
                certificate = argv[++optind];
                break;
            case 'y':
                verify_flag = 1;
                optind--;
                file_name = argv[optind];
                certificate = argv[++optind];
                break;
            case 'c':
                if (!isdigit(optarg[0])) {
                    fprintf(stderr, "Invalid argument for -c, please use number");
                    exit(EXIT_FAILURE);
                }
                circumference = atoi(optarg);
                break;
            case 'u':
                file_name = optarg;
                up_cert_flag = 1;
                break;
            case 'i':
                findissuer_flag = 1;
                certificate = optarg;
                break;
            case 't':
                test_ringoftrust = 1;
                file_name = optarg;
                break;
            default:
                fprintf(stderr, "Flag not recognized.\n");
                exit(EXIT_FAILURE);
        }
    }

    /* SSL libraries init 
     * http://mooon.blog.51cto.com/1246491/909932
     */
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    ctx=SSL_CTX_new(SSLv23_client_method());
    if(ctx == NULL){
        ERR_print_errors_fp(stdout);
        exit(EXIT_FAILURE);
    }

    /* Load the RSA CA certificate into the SSL_CTX structure */
    /* This will allow this client to verify the server's     */
    /* certificate.                                           */
    if (!SSL_CTX_load_verify_locations(ctx, RSA_CLIENT_CA_CERT, NULL)) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    } 

    if ((he = gethostbyname(hostname))==NULL) {
        fprintf(stderr, "Cannot get host name\n");
        exit(EXIT_FAILURE);
    }

    /* Create a socket for tcp communication */
    if ((socket_fd = socket(AF_INET, SOCK_STREAM, 0))== -1) {
        fprintf(stderr, "Socket Failure!!\n");
        exit(EXIT_FAILURE);
    }

    /* Set flag in context to require peer (server) certificate */
    /* verification */
    //SSL_CTX_set_verify(ctx,SSL_VERIFY_PEER,NULL);
    //SSL_CTX_set_verify_depth(ctx,1);
    /* Initialize Server address and port */
    memset(&server_info, 0, sizeof(server_info));
    server_info.sin_family = AF_INET;
    server_info.sin_port = htons(port_no);
    server_info.sin_addr = *((struct in_addr *)he->h_addr);

    /* Connect Server */
    if (connect(socket_fd, (struct sockaddr *)&server_info, sizeof(struct sockaddr))<0) {
        //fprintf(stderr, "Connection Failure\n");
        perror("connect");
        exit(EXIT_FAILURE);
    }
    /* Create a new SSL based on ctx */
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl,socket_fd);
    /* Build up SSL connection */
    if(SSL_connect(ssl) == -1){
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    else{
        printf("Connected with %s encryption\n", SSL_get_cipher(ssl));
        ShowCerts(ssl);
    }

    /* Start Data Processing */
    //printf("Client: Enter Data for Server:\n");
    // fgets(buffer,MAXSIZE-1,stdin);
    /**Sending File **/
    if (send_flag) {
        // printf("%s\n", strcat(client_dir, file_name));
        char target[1024];
        sprintf(target, "%s/%s", CLIENT_FILE_DIR, file_name);
        printf("%s\n", target);
        FILE *fp;
        if ((fp = fopen(target, "r"))){
            h.action = ADD_FILE;
            h.file_size = get_file_size(fp);
            h.file_name = file_name;
            h.certificate = "ssss";
            h.circ = circumference;
            send_header(ssl, h);
            send_file(ssl, fp);
        } else {
            h.action = FAIL_ERROR;
            h.file_size = 0;
            h.file_name = file_name;
            h.certificate = "ssss";
            h.circ = 0;
            send_header(ssl, h);
            perror("fopen");
            exit(EXIT_FAILURE);
        }
    } else if (fetch_flag) {
        header h_send;
        h_send.action = FETCH_FILE;
        h_send.file_name = file_name;
        h_send.file_size = -1;
        h_send.certificate = "bbbb";
        h_send.circ = circumference;
        header h_recv;
        send_header(ssl, h_send);
        char head_buf[HEADER_SIZE];
        int len = HEADER_SIZE;
        // get header from server with file size
        if (recv_all(ssl, (unsigned char *)head_buf, &len) == -1) {
            perror("recv");
            exit(EXIT_FAILURE);
        }
        if (len < HEADER_SIZE) {
            fprintf(stderr, "[CLIENT] Did not receive full header\n");
            exit(EXIT_FAILURE);
        }     
        if (unpack_header_string(ssl, head_buf, &h_recv) == -1) {
            fprintf(stderr, "[CLIENT] Could not unpack header information from client\n");
            exit(EXIT_FAILURE);
        }

        if (h_recv.action == FAIL_ERROR) {
            printf("Server reported protection rating for %s less than the requested %i\n", file_name, circumference);
            exit(EXIT_FAILURE);
        }
        char target[MAXSIZE];
        sprintf(target,"%s/%s", CLIENT_FILE_DIR, h_recv.file_name);            
        printf("Here\n");
        receive_file(ssl, target, h_recv.file_size);
    } 

    else if (up_cert_flag) { // upload public certificate to server
        char target[MAXSIZE];
        sprintf(target, "%s/%s_crt.pem", CLIENT_CERT_DIR, file_name);

        FILE *fp;
        if ((fp = fopen(target, "r"))){
            h.action = UPLOAD_CERT;
            h.file_size = get_file_size(fp);
            h.file_name = file_name;
            h.certificate = " ";
            h.circ = circumference;
            send_header(ssl, h);
            send_file(ssl, fp);
        } else {
            h.action = FAIL_ERROR;
            h.file_size = 0;
            h.file_name = file_name;
            h.certificate = "ssss";
            h.circ = 0;
            send_header(ssl, h);
            perror("fopen");
            exit(EXIT_FAILURE);
        }
    }

    /** List Files **/
    else if(list_flag){
        h.action = LIST_FILE;
        h.file_size = 0;
        h.file_name = " ";
        h.certificate = " ";
        h.circ = circumference;
        send_header(ssl, h);
    	while(1){
    		memset(buffer, 0, sizeof(buffer));
    		//num = recv(socket_fd, buffer, sizeof(buffer),0);
            num = SSL_read(ssl, buffer, sizeof(buffer));
			if ( num <= 0 )
			{
					printf("Either Connection Closed or Error\n");
					//Break from the While
					break;
			}

			buff[num] = '\0';
			printf("%s\n",buffer);
    	}
    }

    /* Vouch File */
    else if(vouch_flag){
        h.action = VOUCH_FILE;
        h.file_size = 0;
        h.file_name = file_name;
        h.circ = 0;
        char certName[MAXSIZE];
        sprintf(certName, "%s_crt.pem", certificate);
        h.certificate = certName;
        unsigned char *md5Value = NULL;
        md5Value = malloc(MD5_DIGEST_LENGTH);
        // char *privateKeyFileName = RSA_CLIENT_KEY; // client's private key file name
        char privateKeyFileName[MAXSIZE];
        sprintf(privateKeyFileName, "%s/%s_key.pem", CLIENT_CERT_DIR, certificate);
        // privateKeyFileName = malloc(MAXSIZE);
        // sprintf( privateKeyFileName, "%s", h.certificate );
        send_header(ssl, h);
        // get hash of file from server 
        num = SSL_read(ssl, md5Value, MD5_DIGEST_LENGTH);
        if ( num <= 0 )
        {
                printf("Either Connection Closed or Error\n");
                //Break from the While
                shutdown_connections(ctx, ssl, socket_fd);
                return 0;
                // break;
        }
        //printf("MD5:");
        //for(int i = 0; i < MD5_DIGEST_LENGTH; i++) printf("%02x", md5Value[i]);
        //printf("\n");
        EVP_PKEY *evpKey;
        if ( (evpKey = EVP_PKEY_new()) == 0 ) {
            fprintf( stderr, "Couldn't create new EVP_PKEY object.\n" );
            unsigned long sslErr = ERR_get_error();
            if ( sslErr ) fprintf(stderr, "%s\n", ERR_error_string(sslErr, 0));
            exit(1);
        }

        // read private key (rsa) from client's private key pem
        RSA *rsa;
        rsa = getRsaFp( privateKeyFileName );
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
         
        // add hash to evp ctx to later be encrypted
        if ( EVP_SignUpdate( evp_ctx, (const char *)md5Value, sizeof(md5Value) ) == 0 ) {
            fprintf( stderr, "Couldn't calculate hash of message.\n" );
            unsigned long sslErr = ERR_get_error();
            if ( sslErr ) fprintf(stderr, "%s\n", ERR_error_string(sslErr, 0));
            exit(1);
        }

        unsigned char *sig1 = NULL;
        unsigned int sigLen = 0;
        //memset(sig, 0, MAXSIZE+1024);
        sig1 = malloc(EVP_PKEY_size(evpKey));

        // Not sure if this is necessary -- encrypted hash might
        // be just binary data so not valid to add a null byte.
        // If this is just to use strlen later to get sig size, 
        // then we should use another way 
        sig1[EVP_PKEY_size(evpKey)] = (unsigned char) '\0';
        /* encrypt hash with client's private key */
        if ( EVP_SignFinal( evp_ctx, sig1, &sigLen, evpKey ) == 0 ) {
            fprintf( stderr, "Couldn't calculate signature.\n" );
            unsigned long sslErr = ERR_get_error();
            if ( sslErr ) fprintf(stderr, "%s\n", ERR_error_string(sslErr, 0));
            exit(1);
        }
        //printf("SIGNATURE:");
        //for(int i = 0; i < (int)sigLen; i++) printf("%02x", sig1[i]);
        //printf("\n");
        //printf("SigLen: %i\n", (int)sigLen);
        //printf("got sig1 : %s\nlength: %i\n",sig1, sigLen);
        // send sig back - use header to notify server of file size?
        SSL_write(ssl,sig1,sigLen);
        EVP_MD_CTX_destroy( evp_ctx );
        RSA_free( rsa );
        EVP_PKEY_free( evpKey );
        ERR_free_strings();
        // free(md5Value);
        // free(sig1);
        while(1){
            //memset(buffer, 0, sizeof(buffer));
            //num = recv(socket_fd, buffer, sizeof(buffer),0);
            num = SSL_read(ssl, buffer, sizeof(buffer));
            if ( num <= 0 )
            {
                    printf("Either Connection Closed or Error\n");
                    //Break from the While
                    break;
            }

            buff[num] = '\0';
            printf("%s\n",buffer);
        }
        free(md5Value);
        free(sig1);
    }
    // vouchFile()
    // sign hash and send back to server (with cert??)

    else if (verify_flag){
        h.action = VERIFY_FILE;
        h.file_size = 0;
        h.file_name = file_name;
        h.circ = 0;
        h.certificate = certificate;
        send_header(ssl, h);
        while(1){
            memset(buffer, 0, sizeof(buffer));
            //num = recv(socket_fd, buffer, sizeof(buffer),0);
            num = SSL_read(ssl, buffer, sizeof(buffer));
            if ( num <= 0 )
            {
                    printf("Either Connection Closed or Error\n");
                    //Break from the While
                    break;
            }

            buff[num] = '\0';
            printf("%s\n",buffer);
        }
    }  else if (findissuer_flag){
        h.action = FIND_ISSUER;
        h.file_size = 0;
        h.file_name = " ";
        h.certificate = certificate;
        send_header(ssl, h);
    }  else if (test_ringoftrust) {
        h.action = TEST_RINGOFTRUST;
        h.file_name = file_name;
        // char certName[MAXSIZE];
        // sprintf(certName, "%s_crt.pem", certificate);
        h.certificate = " ";
        h.circ = circumference;
        send_header(ssl, h);
    }
    /* Close connections */
    shutdown_connections(ctx, ssl, socket_fd);
}//End of main
