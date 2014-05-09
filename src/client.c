#include "trustcloud.h"
#define h_addr h_addr_list[0] /* for backward compatibility */

int main(int argc, char *argv[])
{
    struct sockaddr_in server_info;
    struct hostent *he;
    int socket_fd,num;
    char buffer[1024];
    char *hostname = NULL;

    char buff[1024];

    if (argc < 2) {
        fprintf(stderr, "Usage: client -h hostname [-a add_file_name]\n");
        exit(EXIT_FAILURE);
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

    if ((he = gethostbyname(hostname))==NULL) {
        fprintf(stderr, "Cannot get host name\n");
        exit(EXIT_FAILURE);
    }

    if ((socket_fd = socket(AF_INET, SOCK_STREAM, 0))== -1) {
        fprintf(stderr, "Socket Failure!!\n");
        exit(EXIT_FAILURE);
    }

    memset(&server_info, 0, sizeof(server_info));
    server_info.sin_family = AF_INET;
    server_info.sin_port = htons(PORT);
    server_info.sin_addr = *((struct in_addr *)he->h_addr);
    if (connect(socket_fd, (struct sockaddr *)&server_info, sizeof(struct sockaddr))<0) {
        //fprintf(stderr, "Connection Failure\n");
        perror("connect");
        exit(EXIT_FAILURE);
    }

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
        		num = recv(socket_fd, buffer, sizeof(buffer),0);
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
    close(socket_fd);

}//End of main
