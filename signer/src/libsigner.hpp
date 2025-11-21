#ifndef SIGNER_HPP
#define SIGNER_HPP

#include <vector>

// Function declaration
int sign_simple(const std::vector<unsigned char>& data,
                std::vector<unsigned char>* signed_data);

#endif
