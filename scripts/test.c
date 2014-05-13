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

int main(int argc, char *argv[]) {
  char *issuer_cert_name = argv[1];
  FILE *fp;
  fp = fopen(issuer_cert_name, "rw");
  if (!fp) {
    perror("fopen");
    exit(EXIT_FAILURE);
  }


  X509 *cert;
  cert = PEM_read_X509(fp, NULL, NULL, NULL);

  X509_NAME *name = X509_get_subject_name(cert);

  if (!name) {
    perror("get name");
    exit(EXIT_FAILURE);
  } else {
    
  }
  // char *signing_cert_name = argv[2];
  // FILE *signing_cert_fp = fopen(signing_cert_name, "wr");
  // X509 *signing_cert;
  // signing_cert = PEM_read_X509(signing_cert_fp, NULL, NULL, NULL);

  // EVP_PKEY *private_key;
  // private_key = EVP_PKEY_new();

  // FILE *issuer_cert_fp = fopen(issuer_cert_name, "r");
  
  // RSA *rsa;
  // rsa = RSA_new();

  // rsa = PEM_read_RSAPrivateKey(issuer_cert_fp, NULL, NULL, NULL); 

  // EVP_PKEY_set1_RSA(private_key, rsa);

  // X509_sign(signing_cert, private_key, EVP_md5());
  
  // PEM_write_X509(signing_cert_fp, signing_cert);

  
  return 0;
}
