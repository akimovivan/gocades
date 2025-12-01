#ifndef SIGNER_H
#define SIGNER_H

#include "cades.h"
#include <stdint.h>

#define MY_ENCODING_TYPE (PKCS_7_ASN_ENCODING | X509_ASN_ENCODING)

// NOTE: Errors
typedef enum {
  SUCCESS,
  FAILURE,
  ERR_OPEN_STORE,
  ERR_NO_DATA,
  ERR_CADES_VERIFY,
  ERR_CADES_FREE_VERIFICATION_INFO,
  ERR_CADES_FREE_BLOB,

} SIGNER_ERR;

// NOTE: structs
typedef struct {
  unsigned char *cert_data;     // Certificate encoded data
  unsigned int cert_length;     // Length of certificate data
  unsigned char *subject_name;  // Subject name (as UTF-8)
  unsigned int subject_length;  // Length of subject name
  int has_private_key;          // 1 if has private key, 0 otherwise
  unsigned char *serial_number; // serial number
  unsigned int serial_length;   // length of serial number
  char *signing_algo;           // signing algorithm of the certificate
  unsigned int algo_length;     // Length of signing_algo string
} GoCertInfo;

#ifdef __cplusplus
extern "C" {
#endif

SIGNER_ERR sign_simple(const unsigned char *data, DWORD data_size,
                       unsigned char **signed_data, DWORD *signed_data_size);

SIGNER_ERR verify_signature(const unsigned char *signed_data,
                            size_t signed_data_size, GoCertInfo *cert_info,
                            uint *verification_status);

int encrypt(unsigned char *pbContent, int cbContent,
            unsigned char **pbEncryptedBlob, int *out_len);


int decrypt(unsigned char *pbEncryptedBlob, unsigned int cbEncryptedBlob,
            unsigned char **pbDecryptedBlob,
            unsigned int *out_len); 


// initialize_certificates populates static array of pointers to PCCERT_CONTEXT
// with privateKey
SIGNER_ERR initialize_certificates();

// clear_certificates frees memory that is populated by certificates
void clear_certificates();

// count_certificates return amount of found certificates with private key
// should be used only after initialization
int count_certificates();

SIGNER_ERR get_certificate_by_id(int id, GoCertInfo *cert_info);

#ifdef __cplusplus
}
#endif

#endif // SIGNER_H
