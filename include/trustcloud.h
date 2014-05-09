#ifndef _TRUSTCLOUD_H_
#define _TRUSTCLOUD_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <errno.h>
#include <netdb.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <math.h>

#include <dirent.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/crypto.h>


/** Operation Header Action Descriptor Flag Definitions **/
#define ADD_FILE 0
#define FETCH_FILE 1
#define	LIST_FILE 2

#define PORT 3490
#define MAXSIZE 1024
#define BACKLOG 1024

#define RSA_CLIENT_CERT       "client.crt"
#define RSA_CLIENT_KEY  "client.key"
 
#define RSA_CLIENT_CA_CERT      "client_ca.crt"
#define RSA_CLIENT_CA_PATH      "./client_ca.crt"

#define RSA_SERVER_CERT     "server.crt"
#define RSA_SERVER_KEY          "server.key"
 
#define RSA_SERVER_CA_CERT "server_ca.crt"
#define RSA_SERVER_CA_PATH   "./server_ca.crt"

#define ON   1
#define OFF        0

#define BLOCK_SIZE 1024
#define HEADER_SIZE 1024

#define VERIFY_CLIENT  OFF

/**
 *	Header to send to server requesting operation. Each communication to the
 * 		server should be initiated with a header request. 
 */ 
typedef struct header {
	/* Describes operation */ 
	short action;
	/* Size of file */ 
	int file_size;
	/* Name of file - limited to 59 characters*/	
	char *file_name;
} header;

#define NUM_HEAD_FIELDS 3

/**
 * Function Declarations 
 *
 */
/** Receive file, providing file name to store file as **/ 
void receive_file	(int, char *, int);

/** Receive all data from the queue  
 *    (recv not guaranteed to get all data in one go)
 ***/ 
int recv_all(int , unsigned char *, int *);

/** Send file that has been opened successfully to server/client **/
void send_file 	 	(int, FILE *);

/** Send short message (generally string) **/ 
void send_message 	(int, char *);

/** list files**/
size_t file_list	(const char *,char ***);

/** send header message to server/client indication action
 *      to be taken and include other relevant information (file size, 
 *      file name etc.)
 **/
void send_header	(int,header);

/** get file size **/
int get_file_size	(FILE *);

/** unpack header **/
int unpack_header_string	(char *, header *);
/** show certificate **/
void ShowCerts	(SSL *);
/** command line options **/
int help	();
/* 
 * From Beej's Guide to Network Programming, Hall B.J., 2009
 * 		Keeps sending until all data in buffer is sent. 
 */
int sendall 		(int, unsigned char *, int *);

#endif
