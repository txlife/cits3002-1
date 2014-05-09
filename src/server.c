#include "trustcloud.h"

int main()
{
    struct sockaddr_in server;
    struct sockaddr_in dest;
    int socket_fd, client_fd,num;
    socklen_t size;

    int yes =1;

    if ((socket_fd = socket(AF_INET, SOCK_STREAM, 0))== -1) {
        fprintf(stderr, "Socket failure!!\n");
        exit(EXIT_FAILURE);
    }

    if (setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }
    memset(&server, 0, sizeof(server));
    memset(&dest,0,sizeof(dest));
    server.sin_family = AF_INET;
    server.sin_port = htons(PORT);
    server.sin_addr.s_addr = INADDR_ANY; 
    if ((bind(socket_fd, (struct sockaddr *)&server, sizeof(struct sockaddr )))== -1)    { //sizeof(struct sockaddr) 
        fprintf(stderr, "Binding Failure\n");
        exit(EXIT_FAILURE);
    }

    if ((listen(socket_fd, BACKLOG))== -1){
        fprintf(stderr, "Listening Failure\n");
        exit(EXIT_FAILURE);
    }

    while(1) {

        size = sizeof(struct sockaddr_in);

        if ((client_fd = accept(socket_fd, (struct sockaddr *)&dest, &size))==-1 ) {
            perror("accept");
            exit(EXIT_FAILURE);
        }
        printf("Server got connection from client %s\n", inet_ntoa(dest.sin_addr));

        char header_buf[BLOCK_SIZE];
        // read header - then do action based on header parsing
        int len = HEADER_SIZE;
        if ((num = recv_all(client_fd, (unsigned char *)header_buf, &len))== -1) {
                perror("recv");
                exit(EXIT_FAILURE);
        }
        // unpack header string
        header h;
        if (unpack_header_string(header_buf, &h) == -1) {
            fprintf(stderr, "[SERVER] Could not unpack header information from client\n");
            exit(EXIT_FAILURE);
        }

        while(1) {
		// if client requests to upload file
        	if (h.action == ADD_FILE) {
        		char *serv_dir = "server_files";
        		char target[BLOCK_SIZE];
        		sprintf(target, "%s/%s", serv_dir, h.file_name);
        		printf("[SERVER] Adding file %s\n", target);
        		receive_file(client_fd, target, h.file_size);
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
                send_header(client_fd, h_send);
                send_file(client_fd, fp);
                break;
            } // if client requests to list files
		    else if (h.action == LIST_FILE) {
        		char **files;
        		size_t count;
        		unsigned int i;
        		count = file_list("./", &files);
        		printf("There are %zu files in the directory,transmitting file list.\n", count);
        		for (i = 0; i < count; i++) {
        			send_message(client_fd,files[i]);
        			sleep(1);
        		}
        		printf("File list transmitting completed.\n");
        		close(client_fd);
        		printf("Client connection closed.\n");
                break;
		    }

        } //End of Inner While...
        //Close Connection Socket
        close(client_fd);
    } //Outer While

    close(socket_fd);
    return 0;
} //End of main
