#include "trustcloud.h"
#define h_addr h_addr_list[0] /* for backward compatibility */
//static int verify_callback(int ok, X509_STORE_CTX *ctx);

int main(int argc, char *argv[])
{
    struct sockaddr_in server_info;
    struct hostent *he;
    int socket_fd,num;
    char buffer[1024];
    char *hostname = NULL;
    char buff[1024];
    SSL_CTX *ctx;
    SSL *ssl;
    //X509            *server_cert;
    //EVP_PKEY        *pkey;

    /* check arguments */
    if (argc < 2) {
        return help();
    }

    char *file_name = NULL;
    int send_flag = 0;
    int list_flag = 0;
    int fetch_flag = 0;
    int c;
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
    while ((c = getopt(argc, argv,"h:a:lf:")) != -1) {
        switch(c) {
            case 'h':
                hostname = optarg;
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
                file_name = "no filename";
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


    if(VERIFY_CLIENT == ON){
        /* Load the client certificate into the SSL_CTX structure */
        if (SSL_CTX_use_certificate_file(ctx, RSA_CLIENT_CERT, SSL_FILETYPE_PEM) <= 0) {
            ERR_print_errors_fp(stderr);
            exit(EXIT_FAILURE);
        }
        /* Load the private-key corresponding to the client certificate */
        if (SSL_CTX_use_PrivateKey_file(ctx, RSA_CLIENT_KEY, SSL_FILETYPE_PEM) <= 0) {
            ERR_print_errors_fp(stderr);
            exit(EXIT_FAILURE);
        }
        /* Check if the client certificate and private-key matches */
        if (!SSL_CTX_check_private_key(ctx)) {
            fprintf(stderr,"Private key does not match the certificate public key\n");
            exit(EXIT_FAILURE);
        }
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
    server_info.sin_port = htons(PORT);
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
	while(1) {
        // printf("Client: Enter Data for Server:\n");
        // fgets(buffer,MAXSIZE-1,stdin);
	    /**Sending File **/
        if (send_flag) {
            char client_dir[] = "client_files";
            // printf("%s\n", strcat(client_dir, file_name));
            char target[1024];
            sprintf(target, "%s/%s", client_dir, file_name);
            printf("%s\n", target);
            FILE *fp;
            if ((fp = fopen(target, "r"))){
                header h;
                h.action = ADD_FILE;
                h.file_size = get_file_size(fp);
                h.file_name = file_name;
                send_header(socket_fd, h);
                // recv(socket_fd, NULL, 1, 0);
                send_file(socket_fd, fp);
            } else {
                perror("fopen");
                exit(EXIT_FAILURE);
            }
            break;
        } else if (fetch_flag) {
            header h_send;
            h_send.action = FETCH_FILE;
            h_send.file_name = file_name;
            h_send.file_size = -1;
            header h_recv;
            send_header(socket_fd, h_send);
            char head_buf[HEADER_SIZE];
            int len = HEADER_SIZE;
            // get header from server with file size
            if (recv_all(socket_fd, (unsigned char *)head_buf, &len) == -1) {
                perror("recv");
                exit(EXIT_FAILURE);
            }
            if (len < HEADER_SIZE) {
                fprintf(stderr, "[CLIENT] Did not receive full header\n");
                exit(EXIT_FAILURE);
            }     
            if (unpack_header_string(head_buf, &h_recv) == -1) {
                fprintf(stderr, "[CLIENT] Could not unpack header information from client\n");
                exit(EXIT_FAILURE);
            }
            char *client_dir = "client_files";
            char target[1024];
            sprintf(target,"%s/%s", client_dir, h_recv.file_name);            
            receive_file(socket_fd, target, h_recv.file_size);
            break;
        }
	
	    /** List Files **/
	    else if(list_flag){
            header h;
            h.action = LIST_FILE;
            h.file_size = 0;
            h.file_name = file_name;
            send_header(socket_fd, h);
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
        	break;
        } else {
            printf("Unrecognised request\n");
            close(socket_fd);
            exit(EXIT_FAILURE);
        }
    }
    /* Close connections */
    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    close(socket_fd);

}//End of main
