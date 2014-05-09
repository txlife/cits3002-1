#include "trustcloud.h"

int main()
{
    struct sockaddr_in server;
    struct sockaddr_in dest;
    int socket_fd, client_fd,num;
    socklen_t size;
    SSL_CTX *ctx;
    X509            *client_cert = NULL;
    char    *str;

    //if (argc < 2) {
    //    fprintf(stderr, "Usage: server cacert.pem privkey.pem\n");
    //    return 0;
    //}

    /*******  START SSL ***************/
    /* http://mooon.blog.51cto.com/1246491/909932 */
    /* SSL Libraries Init */
    SSL_library_init();
    /* add all SSL algorithms */
    OpenSSL_add_all_algorithms();
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
    if(VERIFY_CLIENT == ON){
        /* Load the RSA CA certificate into the SSL_CTX structure */
        if (!SSL_CTX_load_verify_locations(ctx, RSA_SERVER_CA_CERT, NULL)) {
           ERR_print_errors_fp(stderr);
                exit(1);
        }
 
        /* Set to require peer (client) certificate verification */
        SSL_CTX_set_verify(ctx,SSL_VERIFY_PEER,NULL);
 
        /* Set the verification depth to 1 */
        SSL_CTX_set_verify_depth(ctx,1); 
    }
    /*********** END SSL ****************/


    //char buffer[1024];
    //char *buff;

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
        if (VERIFY_CLIENT == ON){
            /* Get the client's certificate (optional) */
            client_cert = SSL_get_peer_certificate(ssl);
            if (client_cert != NULL) {
                printf ("Client certificate:\n");     
                str = X509_NAME_oneline(X509_get_subject_name(client_cert), 0, 0);
                if ((str)==NULL){
                    exit(EXIT_FAILURE);
                }
                printf ("\t subject: %s\n", str);
                free (str);
                str = X509_NAME_oneline(X509_get_issuer_name(client_cert), 0, 0);
                if ((str)==NULL){
                    exit(EXIT_FAILURE);
                }
                printf ("\t issuer: %s\n", str);
                free (str);
                X509_free(client_cert);
            } 
            else{
                printf("The SSL client does not have certificate.\n");
                exit(EXIT_FAILURE);
            }
        }

        /******* START PROCESSING DATA *************/

        /* read header - then do action based on header parsing */
        char header_buf[1024];
        if ((num = recv(client_fd, header_buf, 1024,0))== -1) {
                perror("recv");
                exit(EXIT_FAILURE);
        }
        else if (num == 0) {
                printf("No header received. Connection closed\n");
                //So I can now wait for another client
                continue;
        } 
        header h;
        if (unpack_header_string(header_buf, &h) == -1) {
            fprintf(stderr, "[SERVER] Could not unpack header information from client\n");
            exit(EXIT_FAILURE);
        }
        printf("[Header]:\n");
        printf("\t%d\n", h.action);
        printf("\t%d\n", h.file_size);
        printf("\t%s\n", h.file_name);
        /* header part end */

        while(1) {
		// if client requests to uplaod file
        	if (h.action == ADD_FILE) {
            		char *serv_dir = "server_files";
            		// char *file_name = "written.txt";
            		// TODO get file_name from header
            		char target[1024];
            		sprintf(target, "%s/%s", serv_dir, h.file_name);
            		printf("[SERVER] Adding file %s\n", target);
            		receive_file(client_fd, target, h.file_size);
                    close(client_fd);
                    break;
        	}
		
		// if client requests to list files
		    else if (h.action == LIST_FILE) {
        		char **files;
        		size_t count;
        		unsigned int i;
        		count = file_list("./", &files);
        		printf("There are %zu files in the directory,transmitting file list.\n", count);
        		for (i = 0; i < count; i++) {
        			SSL_write(ssl,files[i],strlen(files[i]));
        			sleep(1);
        		}
        		printf("File list transmitting completed.\n");
        		close(client_fd);
        		printf("Client connection closed.\n");
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
