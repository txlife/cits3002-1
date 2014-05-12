#include "trustcloud.h"

int main()
{
    struct sockaddr_in server;
    struct sockaddr_in dest;
    int socket_fd, client_fd,num;
    socklen_t size;
    SSL_CTX *ctx;

    /*******  START SSL ***************/
    /* http://mooon.blog.51cto.com/1246491/909932 */
    /* SSL Libraries Init */
    SSL_library_init();
    /* add all SSL algorithms */
    OpenSSL_add_all_algorithms();
    /* add all SSL ciphers */
    OpenSSL_add_all_ciphers();
    /* add all digests */
    OpenSSL_add_all_digests();
    /* load all SSL errors */
    SSL_load_error_strings();
    /* Build SSL_CTX  -> SSL Content Text 
     * SSLv2_server_method() or SSLv3_server_method() relative to SSL V2
     * and SSL V3
     */
    ctx = SSL_CTX_new(SSLv23_server_method());
    if(ctx == NULL){
        ERR_print_errors_fp(stdout);
        exit(EXIT_FAILURE);
    }
    /* Load the server certificate into the SSL_CTX structure */
    if(SSL_CTX_use_certificate_file(ctx,RSA_SERVER_CERT,SSL_FILETYPE_PEM) <= 0){
        ERR_print_errors_fp(stdout);
        exit(EXIT_FAILURE);
    } 
    /* Load the private-key corresponding to the server certificate */
    if(SSL_CTX_use_PrivateKey_file(ctx,RSA_SERVER_KEY,SSL_FILETYPE_PEM) <= 0){
        ERR_print_errors_fp(stdout);
        exit(EXIT_FAILURE);
    }
    /* Check if the server certificate and private-key matches */
    if(!SSL_CTX_check_private_key(ctx)){
        ERR_print_errors_fp(stdout);
        exit(EXIT_FAILURE);
    }

    /*********** END SSL ****************/

    int yes =1;

    /* Open a socket to listen */
    if ((socket_fd = socket(AF_INET, SOCK_STREAM, 0))== -1) {
        fprintf(stderr, "Socket failure!!\n");
        exit(EXIT_FAILURE);
    }

    if (setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }
    /* init memory for server and dest */
    memset(&server, 0, sizeof(server));
    memset(&dest,0,sizeof(dest));
    server.sin_family = AF_INET; //same to PF_INET
    server.sin_port = htons(PORT);
    server.sin_addr.s_addr = INADDR_ANY; 


    /* BIND SOCKET */
    if ((bind(socket_fd, (struct sockaddr *)&server, sizeof(struct sockaddr )))== -1)    { //sizeof(struct sockaddr) 
        fprintf(stderr, "Binding Failure\n");
        exit(EXIT_FAILURE);
    }

    /* START LISTENING */
    if ((listen(socket_fd, BACKLOG))== -1){
        fprintf(stderr, "Listening Failure\n");
        exit(EXIT_FAILURE);
    }
    while(1) {

        SSL *ssl;
        size = sizeof(struct sockaddr_in);

        /* Waiting for client to connect */
        if ((client_fd = accept(socket_fd, (struct sockaddr *)&dest, &size))==-1 ) {
            perror("accept");
            exit(EXIT_FAILURE);
        }
        else{
            printf("Server got connection from client %s, port %d, socket %d\n", inet_ntoa(dest.sin_addr),ntohs(dest.sin_port),client_fd);
        }
        /* /connection complete */

        /* create a new ssl based on ctx */
        ssl = SSL_new(ctx);
        /* add socket : client_fd to SSL */
        SSL_set_fd(ssl,client_fd);
        /* Build up SSL connection */
        if(SSL_accept(ssl) == -1){
            perror("accept");
            close(client_fd);
            exit(EXIT_FAILURE);
        }


        /******* START PROCESSING DATA *************/

        /* read header - then do action based on header parsing */
        char header_buf[HEADER_SIZE];
        int len = HEADER_SIZE;
        if ((num = recv_all(ssl, (unsigned char *)header_buf, &len))== -1) {
                perror("recv");
                exit(EXIT_FAILURE);
        }
        /* unpack header string */
        header h;
        if (unpack_header_string(header_buf, &h) == -1) {
            fprintf(stderr, "[SERVER] Could not unpack header information from client\n");
            exit(EXIT_FAILURE);
        }
		// header part end
        while(1) {
		    // if client requests to uplaod file
        	if (h.action == ADD_FILE) {
        		char *serv_dir = "server_files";
        		char target[BLOCK_SIZE];
        		sprintf(target, "%s/%s", serv_dir, h.file_name);
        		printf("[SERVER] Adding file %s\n", target);
        		receive_file(ssl, target, h.file_size);
                // add directory for certificates which have signed
                // for (i.e. vouched for) this file
                char dir_name[BLOCK_SIZE];
                
                sprintf(dir_name, "%s/%s_CAs", serv_dir, h.file_name);
                
                // if (mkdir(dir_name, S_IRWXU) < 0) {
                //     perror("mkdir");
                //     exit(EXIT_FAILURE);
                // }
                // write_cert(h.certificate);
                close(client_fd);
                break;
        	} else if (h.action == FETCH_FILE) {
                char *serv_dir = "server_files";
                char target[BLOCK_SIZE];
                sprintf(target, "%s/%s", serv_dir, h.file_name);
                printf("[SERVER] Fetching file %s\n", target);
                FILE *fp;
                if (!(fp = fopen(target, "r"))) {
                    perror("fopen");
                    exit(EXIT_FAILURE);
                }
                header h_send;
                h_send.action = ADD_FILE;
                h_send.file_size = get_file_size(fp);
                h_send.file_name = h.file_name;
                h_send.certificate = " ";
                send_header(ssl, h_send);
                send_file(ssl, fp);
                break;
            } // if client requests to list files
		    else if (h.action == LIST_FILE) {
        		char **files;
        		size_t count;
        		unsigned int i;
        		count = file_list("./server_files/", &files);
        		printf("There are %zu files in the directory,transmitting file list.\n", count);
        		for (i = 0; i < count; i++) {
        			// SSL_write(ssl,files[i],strlen(files[i]));
                    char send_str[MAXSIZE];

                    // if (file verified)
                    sprintf(send_str, "Verified (c = 3): %s", files[i]);
                    // else (file not verified)
                    // sprintf(send_str, "Not Verified (c = 3): %s", files[i]);

                    send_message(ssl, send_str);
        			// sleep(1);
        		}
        		printf("File list transmitting completed.\n");
        		close(client_fd);
        		printf("Client connection closed.\n");
                break;
		    }

            /* if client requires to vouch a file
             * https://gitorious.org/random_play/random_play/source/b9f19d4d9e8d4a9ba0ef55a6b0e2113d1c6a5587:openssl_sign.c
             */
            else if (h.action == VOUCH_FILE){
                // char *rsaprivKeyPath = NULL;
                // rsaprivKeyPath = malloc(MAXSIZE);
                // sprintf( rsaprivKeyPath, "%s", h.certificate );
                //*rsaprivKeyPath = h.certificate;
                const char *clearText = h.file_name;
                char target[BLOCK_SIZE];
                sprintf(target, "server_files/%s", h.file_name);
                unsigned char *md5Value = NULL;
                md5Value = malloc(MD5_DIGEST_LENGTH);
                hashFile(md5Value, (const char *)target);
                send_message(ssl, (char *)md5Value);
                // vouchFile(rsaprivKeyPath,clearText, ssl);
                
                //verifySig(rsaprivKeyPath,clearText);

                break;
            }

            else if (h.action == VERIFY_FILE){
                char *rsaprivKeyPath = NULL;
                rsaprivKeyPath = malloc(MAXSIZE);
                sprintf( rsaprivKeyPath, "%s", h.certificate );
                //*rsaprivKeyPath = h.certificate;
                const char *clearText = h.file_name;
                //vouchFile(rsaprivKeyPath,clearText, ssl);
                
                if(verifySig(rsaprivKeyPath,clearText) == 1){
                    printf("Verify failed\n");
                }

                break;
            }

        } //End of Inner While...
        /********** END DATA PROCESSING **************/

        /* Close SSL Connection */
        SSL_shutdown(ssl);
        /* Release SSL */
        SSL_free(ssl);
        //Close Connection Socket
        close(client_fd);
    } //Outer While

    /* Close listening socket */
    close(socket_fd);
    /* Release CTX */
    SSL_CTX_free(ctx);
    return 0;
} //End of main
