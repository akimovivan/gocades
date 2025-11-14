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

// Simple verification function
int sign_verify(const char* signed_message, int signature_len) {
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
        (BYTE*)signed_message, (DWORD)signature_len, &pContent, &pVerifyInfo)) {
        
        DWORD error = GetLastError();
        printf("CadesVerifyMessage() failed with error: 0x%08X\n", (unsigned int)error);
        
        if (pVerifyInfo) CadesFreeVerificationInfo(pVerifyInfo);
        return 2;
    }

    if (pVerifyInfo->dwStatus != CADES_VERIFY_SUCCESS) {
        printf("Message is not verified successfully. Status: %d\n", pVerifyInfo->dwStatus);
    } else {
        printf("Message verified successfully.\n");
    }

    if (!CadesFreeVerificationInfo(pVerifyInfo)) {
        CadesFreeBlob(pContent);
        printf("CadesFreeVerificationInfo() failed\n");
        return 3;
    }

    if (!CadesFreeBlob(pContent)) {
        printf("CadesFreeBlob() failed\n");
        return 4;
    }

    return (pVerifyInfo->dwStatus == CADES_VERIFY_SUCCESS) ? 0 : 5;
}
