#ifndef _TRUSTCLOUD_H_
#define _TRUSTCLOUD_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <errno.h>
#include <netdb.h>
#include <ctype.h>
#include <sys/stat.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
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
#include <openssl/md5.h>
#include <openssl/x509v3.h>
#include <openssl/bn.h>
#include <openssl/asn1.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/bio.h>

/** Operation Header Action Descriptor Flag Definitions **/
#define ADD_FILE 0
#define FETCH_FILE 1
#define	LIST_FILE 2
#define VOUCH_FILE 3
#define VERIFY_FILE 4
#define UPLOAD_CERT 5
#define FIND_ISSUER 6
#define TEST_RINGOFTRUST 7

#define PORT 3490
#define MAXSIZE 1024
#define BACKLOG 1024

#define SERVER_FILE_DIR "server_files"
#define CLIENT_FILE_DIR "client_files"

#define SERVER_SIG_DIR "server_sigs"

#define SERVER_CERT_DIR "server_certs"
#define CLIENT_CERT_DIR "client_certs"

#define RSA_CLIENT_CERT       "client.pem"
#define RSA_CLIENT_KEY  "client.pem"
 
#define RSA_CLIENT_CA_CERT      "client.pem"
#define RSA_CLIENT_CA_PATH      "./client.pem"

#define RSA_SERVER_CERT     "server.pem"
#define RSA_SERVER_KEY          "server.pem"
 
#define RSA_SERVER_CA_CERT "server.pem"
#define RSA_SERVER_CA_PATH   "./server.pem"

#define ON   1
#define OFF  0

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
	/* Name of certificate */
	char *certificate;
	/* Circumference (length) of a ring of trust */
	int circ;
} header;

#define NUM_HEAD_FIELDS 5

/**
 * Function Declarations 
 *
 */
/** Receive file, providing file name to store file as **/ 
void receive_file	(SSL *, char *, int);

/** Receive all data from the queue  
 *    (recv not guaranteed to get all data in one go)
 ***/ 
int recv_all(SSL * , unsigned char *, int *);

/** Send file that has been opened successfully to server/client **/
void send_file 	 	(SSL *, FILE *);

/** Send short message (generally string) **/ 
void send_message 	(SSL *, char *);

/* 
 * From Beej's Guide to Network Programming, Hall B.J., 2009
 *    Keeps sending until all data in buffer is sent. 
 */
int sendall     (SSL *, unsigned char *, int *);

/** list files**/
size_t file_list	(const char *,char ***);

/** send header message to server/client indication action
 *      to be taken and include other relevant information (file size, 
 *      file name etc.)
 **/
void send_header	(SSL *,header);

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
int verifySig	(char *, const char *);
unsigned char * 	readSig(unsigned char *, char *);
int vouchFile 	(char *, const char *, SSL *);
int hashFile	(unsigned char *,const char *);
RSA* getRsaPubFp	(const char*);
int findIssuer(char *, char ***, int *);
int ringOfTrust(char *);
int check_if_file_exists(const char *);
int isNameCertFile(const char *);
int isNameSigFile(const char *);
int isSignedBy(X509 *, X509 *);

#endif
