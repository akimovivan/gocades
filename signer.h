#ifndef SIGNER_H
#define SIGNER_H

#include <cades.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Signer information structure
typedef struct {
    int certificate_count;
    int has_private_key;
} SignerInfo;

// Main signing function with options
int cades_sign_with_options(const char* data, int data_len, 
                           const char* store_name, const char* hash_alg,
                           unsigned char** out_sig, int* out_len);

// Get information about available signers
int get_signer_info(SignerInfo* info);

// Simple signing function (backward compatibility)
int cades_sign_simple(const char* data, int data_len, 
                     unsigned char** out_sig, int* out_len);

typedef struct {
    int verified;
    int status;
    char* error_message;
} VerificationResult;

int cades_verify_message(const char* signed_message, VerificationResult* result);
void free_verification_result(VerificationResult* result);

// Simple verification function (returns 0 on success, error code on failure)
int sign_verify(const char* signed_message);

#ifdef __cplusplus
}
#endif

#endif // SIGNER_H
