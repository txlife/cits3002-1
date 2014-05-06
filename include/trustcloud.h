#ifndef _TRUSTCLOUD_H_
#define _TRUSTCLOUD_H_

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <math.h>

/** Operation Header Action Descriptor Flag Definitions **/
#define SEND_FILE 0
#define RECV_FILE 1

#define PORT 3490
#define MAXSIZE 1024
#define BACKLOG 10

/**
 *	Header to send to server requesting operation. Each communication to the
 * 		server should be initiated with a header request. 
 */ 
struct header {
	/* Describes operation */ 
	const short action;
	/* Size of file */ 
	const int file_size;
	/* Name of file - limited to 59 characters*/	
	const char file_name[59];
};

/**
 * Function Declarations 
 *
 */
/** Receive file, providing file name to store file as **/ 
void receive_file	(int, char *);
/** Send file that has been opened succesfully to server/client **/
void send_file 	 	(int, FILE *);
/** Send short message (generally string) **/ 
void send_message 	(int, char *);
/* 
 * From Beej's Guide to Network Programming, Hall B.J., 2009
 * 		Keeps sending until all data in buffer is sent. 
 */
int sendall 		(int, char *, int *);

#endif
