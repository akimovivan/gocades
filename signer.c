#include "signer.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int cades_sign_with_options(const char* data, int data_len, 
                           const char* store_name, const char* hash_alg,
                           unsigned char** out_sig, int* out_len) {
    if (!data || data_len <= 0 || !store_name || !hash_alg) {
        return -1;
    }

    HCERTSTORE hStore = CertOpenSystemStoreA(0, store_name);
    if (!hStore) {
        printf("Failed to open certificate store: %s\n", store_name);
        return -2;
    }

    PCCERT_CONTEXT pCertContext = NULL;
    int certCount = 0;
    PCCERT_CONTEXT foundCert = NULL;

    // Find certificate with private key
    while ((pCertContext = CertEnumCertificatesInStore(hStore, pCertContext)) != NULL) {
        certCount++;
        CRYPT_KEY_PROV_INFO* pKeyInfo = NULL;
        DWORD dwKeyProvInfoSize = 0;

        if (CertGetCertificateContextProperty(pCertContext, CERT_KEY_PROV_INFO_PROP_ID, NULL, &dwKeyProvInfoSize)) {
            pKeyInfo = (CRYPT_KEY_PROV_INFO*)malloc(dwKeyProvInfoSize);
            if (pKeyInfo && CertGetCertificateContextProperty(pCertContext, CERT_KEY_PROV_INFO_PROP_ID, pKeyInfo, &dwKeyProvInfoSize)) {
                FILETIME ftSystemTime;
                GetSystemTimeAsFileTime(&ftSystemTime);
                if (CertVerifyTimeValidity(&ftSystemTime, pCertContext->pCertInfo) == 0) {
                    HCRYPTPROV hCryptProv = 0;
                    DWORD dwKeySpec = 0;
                    BOOL fCallerFreeProv = FALSE;

                    if (CryptAcquireCertificatePrivateKey(pCertContext,
                        CRYPT_ACQUIRE_COMPARE_KEY_FLAG | CRYPT_ACQUIRE_SILENT_FLAG,
                        NULL,
                        &hCryptProv,
                        &dwKeySpec,
                        &fCallerFreeProv)) {
                        printf("Found certificate with private key at position %d\n", certCount);
                        foundCert = CertDuplicateCertificateContext(pCertContext);
                        CryptReleaseContext(hCryptProv, 0);
                        break;
                    }
                }
            }
            if (pKeyInfo) free(pKeyInfo);
        }
    }

    if (!foundCert) {
        CertCloseStore(hStore, 0);
        printf("No certificate with private key found in store: %s\n", store_name);
        return -3;
    }

    // Setup signing parameters
    CRYPT_SIGN_MESSAGE_PARA signPara = { sizeof(signPara) };
    signPara.dwMsgEncodingType = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;
    signPara.pSigningCert = foundCert;
    signPara.HashAlgorithm.pszObjId = (char*)hash_alg;

    // Get required size first
    PCRYPT_DATA_BLOB pSignedBlob = malloc(sizeof(CRYPT_DATA_BLOB));
    if (!pSignedBlob) {
        CertFreeCertificateContext(foundCert);
        CertCloseStore(hStore, 0);
        return -5;
    }
    
    pSignedBlob->pbData = NULL;
    pSignedBlob->cbData = 0;

    const BYTE *pbToBeSigned[] = { (BYTE*)data };
    DWORD cbToBeSigned[] = { (DWORD)data_len };

    if (!CryptSignMessage(&signPara, FALSE, 1, pbToBeSigned, cbToBeSigned, NULL, &pSignedBlob->cbData)) {
        DWORD err = GetLastError();
        printf("CryptSignMessage size query failed, error: 0x%08X\n", (unsigned int)err);
        CertFreeCertificateContext(foundCert);
        CertCloseStore(hStore, 0);
        free(pSignedBlob);
        return -4;
    }

    printf("Need %d bytes for signature\n", (int)pSignedBlob->cbData);

    pSignedBlob->pbData = malloc(pSignedBlob->cbData);
    if (!pSignedBlob->pbData) {
        CertFreeCertificateContext(foundCert);
        CertCloseStore(hStore, 0);
        free(pSignedBlob);
        return -5;
    }

    if (!CryptSignMessage(&signPara, FALSE, 1, pbToBeSigned, cbToBeSigned, pSignedBlob->pbData, &pSignedBlob->cbData)) {
        DWORD err = GetLastError();
        printf("CryptSignMessage actual signing failed, error: 0x%08X\n", (unsigned int)err);
        free(pSignedBlob->pbData);
        free(pSignedBlob);
        CertFreeCertificateContext(foundCert);
        CertCloseStore(hStore, 0);
        return -6;
    }

    printf("CAdES signature created successfully using store: %s\n", store_name);

    // Copy result to output
    *out_sig = malloc(pSignedBlob->cbData);
    if (!*out_sig) {
        free(pSignedBlob->pbData);
        free(pSignedBlob);
        CertFreeCertificateContext(foundCert);
        CertCloseStore(hStore, 0);
        return -7;
    }

    memcpy(*out_sig, pSignedBlob->pbData, pSignedBlob->cbData);
    *out_len = pSignedBlob->cbData;

    // Cleanup
    free(pSignedBlob->pbData);
    free(pSignedBlob);
    CertFreeCertificateContext(foundCert);
    CertCloseStore(hStore, 0);

    return 0;
}

// Simple signing function (uses defaults)
int cades_sign_simple(const char* data, int data_len, unsigned char** out_sig, int* out_len) {
    return cades_sign_with_options(data, data_len, "MY", "1.3.14.3.2.26", out_sig, out_len);
}

// Get signer information
int get_signer_info(SignerInfo* info) {
    if (!info) return -1;

    HCERTSTORE hStore = CertOpenSystemStoreA(0, "MY");
    if (!hStore) return -2;

    PCCERT_CONTEXT pCertContext = NULL;
    int certCount = 0;
    int hasPrivateKey = 0;

    while ((pCertContext = CertEnumCertificatesInStore(hStore, pCertContext)) != NULL) {
        certCount++;
        
        DWORD dwKeyProvInfoSize = 0;
        if (CertGetCertificateContextProperty(pCertContext, CERT_KEY_PROV_INFO_PROP_ID, NULL, &dwKeyProvInfoSize)) {
            hasPrivateKey = 1;
            break; // Found at least one certificate with private key
        }
    }

    info->certificate_count = certCount;
    info->has_private_key = hasPrivateKey;

    CertCloseStore(hStore, 0);
    return 0;
}

int cades_verify_message(const char* signed_message, VerificationResult* result) {
    if (!signed_message || !result) {
        return -1;
    }

    // Initialize result structure
    result->verified = 0;
    result->status = 0;
    result->error_message = NULL;

    CRYPT_VERIFY_MESSAGE_PARA cryptVerifyPara = { sizeof(cryptVerifyPara) };
    cryptVerifyPara.dwMsgAndCertEncodingType = 
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;

    CADES_VERIFY_MESSAGE_PARA verifyPara = { sizeof(verifyPara) };
    verifyPara.pVerifyMessagePara = &cryptVerifyPara;

    PCADES_VERIFICATION_INFO pVerifyInfo = NULL;
    PCRYPT_DATA_BLOB pContent = NULL;

    if (!CadesVerifyMessage(&verifyPara, 0,
        (BYTE*)signed_message, (DWORD)strlen(signed_message), &pContent, &pVerifyInfo)) {
        
        // Try to get error information
        DWORD error = GetLastError();
        result->error_message = malloc(256);
        if (result->error_message) {
            snprintf(result->error_message, 256, "CadesVerifyMessage() failed with error: 0x%08X", (unsigned int)error);
        }
        
        if (pVerifyInfo) CadesFreeVerificationInfo(pVerifyInfo);
        return -2;
    }

    // Store verification status
    result->status = pVerifyInfo->dwStatus;
    result->verified = (pVerifyInfo->dwStatus == CADES_VERIFY_SUCCESS);

    // Cleanup
    if (!CadesFreeVerificationInfo(pVerifyInfo)) {
        CadesFreeBlob(pContent);
        result->error_message = strdup("CadesFreeVerificationInfo() failed");
        return -3;
    }

    if (!CadesFreeBlob(pContent)) {
        result->error_message = strdup("CadesFreeBlob() failed");
        return -4;
    }

    return 0; // Success
}

// Simple verification function (your original function)
int sign_verify(const char* signed_message) {
    if (!signed_message) {
        printf("Null signed message provided\n");
        return 1;
    }

    CRYPT_VERIFY_MESSAGE_PARA cryptVerifyPara = { sizeof(cryptVerifyPara) };
    cryptVerifyPara.dwMsgAndCertEncodingType = 
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;

    CADES_VERIFY_MESSAGE_PARA verifyPara = { sizeof(verifyPara) };
    verifyPara.pVerifyMessagePara = &cryptVerifyPara;

    PCADES_VERIFICATION_INFO pVerifyInfo = NULL;
    PCRYPT_DATA_BLOB pContent = NULL;

    if (!CadesVerifyMessage(&verifyPara, 0,
        (BYTE*)signed_message, (DWORD)strlen(signed_message), &pContent, &pVerifyInfo)) {
        
        DWORD error = GetLastError();
        printf("CadesVerifyMessage() failed with error: 0x%08X\n", (unsigned int)error);
        
        if (pVerifyInfo) CadesFreeVerificationInfo(pVerifyInfo);
        return 1;
    }

    if (pVerifyInfo->dwStatus != CADES_VERIFY_SUCCESS) {
        printf("Message is not verified successfully. Status: %d\n", pVerifyInfo->dwStatus);
    } else {
        printf("Message verified successfully.\n");
    }

    if (!CadesFreeVerificationInfo(pVerifyInfo)) {
        CadesFreeBlob(pContent);
        printf("CadesFreeVerificationInfo() failed\n");
        return 2;
    }

    if (!CadesFreeBlob(pContent)) {
        printf("CadesFreeBlob() failed\n");
        return 3;
    }

    return (pVerifyInfo->dwStatus == CADES_VERIFY_SUCCESS) ? 0 : 4;
}

// Enhanced verification with detailed debugging
int cades_verify_message_debug(const char* signed_message, VerificationResult* result) {
    if (!signed_message || !result) {
        return -1;
    }

    // Initialize result structure
    result->verified = 0;
    result->status = 0;
    result->error_code = 0;
    result->error_message = NULL;
    result->verification_details = NULL;

    printf("Debug: Starting verification\n");
    printf("Debug: Signed message length: %zu\n", strlen(signed_message));
    printf("Debug: First 100 bytes of signature: ");
    for (int i = 0; i < (strlen(signed_message) > 100 ? 100 : strlen(signed_message)); i++) {
        printf("%02X ", (unsigned char)signed_message[i]);
    }
    printf("\n");

    CRYPT_VERIFY_MESSAGE_PARA cryptVerifyPara = {0};
    cryptVerifyPara.cbSize = sizeof(cryptVerifyPara);
    cryptVerifyPara.dwMsgAndCertEncodingType = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;

    CADES_VERIFY_MESSAGE_PARA verifyPara = {0};
    verifyPara.dwSize = sizeof(verifyPara);
    verifyPara.pVerifyMessagePara = &cryptVerifyPara;

    PCADES_VERIFICATION_INFO pVerifyInfo = NULL;
    PCRYPT_DATA_BLOB pContent = NULL;

    printf("Debug: Calling CadesVerifyMessage...\n");

    BOOL verifyResult = CadesVerifyMessage(
        &verifyPara, 
        0, // dwFlags
        (BYTE*)signed_message, 
        (DWORD)strlen(signed_message), 
        &pContent, 
        &pVerifyInfo
    );

    DWORD lastError = GetLastError();
    result->error_code = (int)lastError;

    printf("Debug: CadesVerifyMessage returned: %s\n", verifyResult ? "TRUE" : "FALSE");
    printf("Debug: GetLastError(): 0x%08X\n", (unsigned int)lastError);

    if (!verifyResult) {
        // Try to get detailed error information
        result->error_message = malloc(512);
        if (result->error_message) {
            snprintf(result->error_message, 512, 
                    "CadesVerifyMessage() failed with error: 0x%08X", 
                    (unsigned int)lastError);
        }

        // Additional error details based on common error codes
        result->verification_details = malloc(512);
        if (result->verification_details) {
            switch (lastError) {
                case CRYPT_E_ASN1_BADTAG:
                    snprintf(result->verification_details, 512, "Invalid ASN.1 structure - possibly not a valid PKCS#7 signature");
                    break;
                case CRYPT_E_UNEXPECTED_MSG_TYPE:
                    snprintf(result->verification_details, 512, "Unexpected message type - not a signed message");
                    break;
                case CERT_E_UNTRUSTEDROOT:
                    snprintf(result->verification_details, 512, "Untrusted root certificate");
                    break;
                case CRYPT_E_NO_SIGNER:
                    snprintf(result->verification_details, 512, "No signer certificate found");
                    break;
                case NTE_BAD_SIGNATURE:
                    snprintf(result->verification_details, 512, "Bad signature - data may be corrupted");
                    break;
                case ERROR_INVALID_PARAMETER:
                    snprintf(result->verification_details, 512, "Invalid parameters passed to function");
                    break;
                default:
                    snprintf(result->verification_details, 512, "Unknown verification error");
                    break;
            }
        }

        if (pVerifyInfo) {
            CadesFreeVerificationInfo(pVerifyInfo);
        }
        return -2;
    }

    printf("Debug: CadesVerifyMessage succeeded\n");

    // Store verification status
    if (pVerifyInfo) {
        result->status = pVerifyInfo->dwStatus;
        result->verified = (pVerifyInfo->dwStatus == CADES_VERIFY_SUCCESS);
        
        printf("Debug: Verification status: %d\n", pVerifyInfo->dwStatus);
        printf("Debug: Verification successful: %s\n", result->verified ? "YES" : "NO");

        // Add status description
        if (result->verification_details) {
            free(result->verification_details);
        }
        result->verification_details = malloc(256);
        if (result->verification_details) {
            switch (pVerifyInfo->dwStatus) {
                case CADES_VERIFY_SUCCESS:
                    snprintf(result->verification_details, 256, "Signature verification successful");
                    break;
                case CADES_VERIFY_BAD_SIGNATURE:
                    snprintf(result->verification_details, 256, "Bad signature");
                    break;
                case CADES_VERIFY_SIGNER_NOT_FOUND:
                    snprintf(result->verification_details, 256, "No signer certificate found");
                    break;
                case CADES_VERIFY_END_CERT_REVOCATION:
                    snprintf(result->verification_details, 256, "Certificate revoked");
                    break;
                default:
                    snprintf(result->verification_details, 256, "Unknown verification status: %d", pVerifyInfo->dwStatus);
                    break;
            }
        }
    }

    // Cleanup
    if (pVerifyInfo && !CadesFreeVerificationInfo(pVerifyInfo)) {
        printf("Debug: CadesFreeVerificationInfo failed\n");
        CadesFreeBlob(pContent);
        return -3;
    }

    if (pContent && !CadesFreeBlob(pContent)) {
        printf("Debug: CadesFreeBlob failed\n");
        return -4;
    }

    printf("Debug: Verification completed successfully\n");
    return 0;
}

// Helper function to free verification result memory
void free_verification_result(VerificationResult* result) {
    if (result && result->error_message) {
        free(result->error_message);
        result->error_message = NULL;
    }
}
