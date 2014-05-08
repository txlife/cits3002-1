#include "trustcloud.h"

int main()
{
    struct sockaddr_in server;
    struct sockaddr_in dest;
    int socket_fd, client_fd,num;
    socklen_t size;

    //char buffer[1024];
    //char *buff;
//  memset(buffer,0,sizeof(buffer));
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

        char header_buf[1024];
        // read header - then do action based on header parsing
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
