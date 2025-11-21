#ifndef LIBSIGNER_H
#define LIBSIGNER_H

#ifdef __cplusplus
extern "C" {
#endif

// C-compatible function signature
int sign_simple_wrapper(const unsigned char* data, int data_len, 
                       unsigned char** out_signed_data, int* out_len);

#ifdef __cplusplus
}
#endif

#endif
