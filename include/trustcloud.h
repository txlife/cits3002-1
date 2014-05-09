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
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>


/** Operation Header Action Descriptor Flag Definitions **/
#define ADD_FILE 0
#define FETCH_FILE 1
#define	LIST_FILE 2
#define VOUCH_FILE 3

#define PORT 3490
#define MAXSIZE 1024
#define BACKLOG 1024

#define RSA_CLIENT_CERT       "client.pem"
#define RSA_CLIENT_KEY  "client.pem"
 
#define RSA_CLIENT_CA_CERT      "client.pem"
#define RSA_CLIENT_CA_PATH      "./client.pem"

#define RSA_SERVER_CERT     "server.pem"
#define RSA_SERVER_KEY          "server.pem"
 
#define RSA_SERVER_CA_CERT "server_ca.pem"
#define RSA_SERVER_CA_PATH   "./server_ca.pem"

#define ON   1
#define OFF        0

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
	/* Name of certificate */
	char *certificate;
} header;

#define NUM_HEAD_FIELDS 4

/**
 * Function Declarations 
 *
 */
/** Receive file, providing file name to store file as **/ 
void receive_file	(int, char *, int);
int recv_all(int , char *, int *);
/** Send file that has been opened succesfully to server/client **/
void send_file 	 	(int, FILE *);
/** Send short message (generally string) **/ 
void send_message 	(int, char *);
/** list files**/
size_t file_list	(const char *,char ***);
/** send header **/
void send_header	(int,header);
/** get file size **/
int get_file_size	(FILE *);
/** unpack header **/
int unpack_header_string	(char *, header *);
/** show certificate **/
void ShowCerts	(SSL *);
/** command line options **/
int help	();
/** get password for cert, vouch file **/
int pass_cb		( char *, int, int, void *);
/** get cert file, vouch file **/
RSA* getRsaFp	( const char*);
/* store signature to file */
int writeSig	(unsigned char *, char *);
/* 
 * From Beej's Guide to Network Programming, Hall B.J., 2009
 * 		Keeps sending until all data in buffer is sent. 
 */
int sendall 		(int, char *, int *);

#endif
