#include "signer.h"
#include "CSP_WinCrypt.h"
#include "reader/tchar.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

// helper function (not exported)
PCCERT_CONTEXT GetRecipientCert(HCERTSTORE hCertStore, wchar_t *pSubject);
const char *GetHashOid(PCCERT_CONTEXT pCert);
SIGNER_ERR get_cert_info(PCCERT_CONTEXT pCertContext, GoCertInfo *cert_info);

// main functions
SIGNER_ERR sign_simple(const unsigned char *data, DWORD data_size,
                       unsigned char **signed_data, DWORD *signed_data_size) {
  HCERTSTORE hStoreHandle = NULL;
  PCCERT_CONTEXT context = NULL;
  PCCERT_CHAIN_CONTEXT pChainContext = NULL;
  PCRYPT_DATA_BLOB pSignedMessage = NULL;
  int result = -1;

  // Initialize output parameters
  *signed_data = NULL;
  *signed_data_size = 0;

  hStoreHandle = CertOpenSystemStore(0, _TEXT("MY"));
  if (!hStoreHandle) {
    printf("Store handle was not got\n");
    return ERR_OPEN_STORE;
  }

  wchar_t *wa = NULL;
  context = GetRecipientCert(hStoreHandle, wa);
  if (wa)
    free(wa);

  if (!context) {
    printf("There is no certificate with a CERT_KEY_CONTEXT_PROP_ID\n"
           "property and an AT_KEYEXCHANGE private key available.\n"
           "While the message could be sign, in this case, it could\n"
           "not be verify in this program.\n"
           "For more information, read the documentation "
           "http://cpdn.cryptopro.ru/\n");
    CertCloseStore(hStoreHandle, 0);
    return ERR_OPEN_STORE;
  }

  // Allocate and initialize sign parameters
  CRYPT_SIGN_MESSAGE_PARA *signPara =
      (CRYPT_SIGN_MESSAGE_PARA *)malloc(sizeof(CRYPT_SIGN_MESSAGE_PARA));
  if (!signPara) {
    printf("Memory allocation failed\n");
    goto cleanup;
  }
  ZeroMemory(signPara, sizeof(CRYPT_SIGN_MESSAGE_PARA));
  signPara->cbSize = sizeof(CRYPT_SIGN_MESSAGE_PARA);
  signPara->dwMsgEncodingType = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;
  signPara->pSigningCert = context;
  signPara->HashAlgorithm.pszObjId = (LPSTR)GetHashOid(context);

  CADES_SIGN_PARA *cadesSignPara =
      (CADES_SIGN_PARA *)malloc(sizeof(CADES_SIGN_PARA));
  if (!cadesSignPara) {
    printf("Memory allocation failed\n");
    goto cleanup;
  }
  ZeroMemory(cadesSignPara, sizeof(CADES_SIGN_PARA));
  cadesSignPara->dwSize = sizeof(CADES_SIGN_PARA);
  cadesSignPara->dwCadesType = CADES_BES;

  CADES_SIGN_MESSAGE_PARA *para =
      (CADES_SIGN_MESSAGE_PARA *)malloc(sizeof(CADES_SIGN_MESSAGE_PARA));
  if (!para) {
    printf("Memory allocation failed\n");
    goto cleanup;
  }
  ZeroMemory(para, sizeof(CADES_SIGN_MESSAGE_PARA));
  para->dwSize = sizeof(CADES_SIGN_MESSAGE_PARA);
  para->pSignMessagePara = signPara;
  para->pCadesSignPara = cadesSignPara;

  const BYTE *pbToBeSigned[] = {data};
  DWORD cbToBeSigned[] = {(DWORD)data_size};

  CERT_CHAIN_PARA ChainPara = {sizeof(ChainPara)};

  // Build certificate chain and collect certificates
  PCCERT_CONTEXT *certs = NULL;
  DWORD certCount = 0;

  if (CertGetCertificateChain(NULL, context, NULL, NULL, &ChainPara, 0, NULL,
                              &pChainContext)) {
    if (pChainContext->cChain > 0 && pChainContext->rgpChain[0]->cElement > 1) {
      certCount = pChainContext->rgpChain[0]->cElement - 1;
      certs = (PCCERT_CONTEXT *)malloc(certCount * sizeof(PCCERT_CONTEXT));
      if (certs) {
        for (DWORD i = 0; i < certCount; ++i) {
          certs[i] = pChainContext->rgpChain[0]->rgpElement[i]->pCertContext;
        }
        signPara->cMsgCert = certCount;
        signPara->rgpMsgCert = certs;
      }
    }
  }

  // Sign the message
  if (!CadesSignMessage(para, 0, 1, pbToBeSigned, cbToBeSigned,
                        &pSignedMessage)) {
    printf("CadesSignMessage() failed\n");
    goto cleanup;
  }

  // Copy signed data to output
  *signed_data = (unsigned char *)malloc(pSignedMessage->cbData);
  if (!*signed_data) {
    printf("Memory allocation failed\n");
    goto cleanup;
  }
  memcpy(*signed_data, pSignedMessage->pbData, pSignedMessage->cbData);
  *signed_data_size = pSignedMessage->cbData;

  if (!CadesFreeBlob(pSignedMessage)) {
    printf("CadesFreeBlob() failed\n");
    goto cleanup;
  }

  result = 0;

cleanup:
  if (certs)
    free(certs);
  if (signPara)
    free(signPara);
  if (cadesSignPara)
    free(cadesSignPara);
  if (para)
    free(para);
  if (pChainContext)
    CertFreeCertificateChain(pChainContext);
  if (context)
    CertFreeCertificateContext(context);
  if (hStoreHandle)
    CertCloseStore(hStoreHandle, 0);

  if (result != 0) {
    // Free output data if we failed
    if (*signed_data) {
      free(*signed_data);
      *signed_data = NULL;
      *signed_data_size = 0;
    }
  }

  return SUCCESS;
}

// TODO: change to pointer return of verification
SIGNER_ERR verify_signature(const unsigned char *signed_data,
                            size_t signed_data_size, GoCertInfo *cert_info,
                            uint *verification_status) {
  if (signed_data == NULL || signed_data_size == 0) {
    return ERR_NO_DATA;
  }

  CRYPT_VERIFY_MESSAGE_PARA cryptVerifyPara;
  CADES_VERIFICATION_PARA cadesVerifyPara;
  CADES_VERIFY_MESSAGE_PARA verifyPara;
  PCADES_VERIFICATION_INFO pVerifyInfo = NULL;
  PCRYPT_DATA_BLOB pContent = NULL;

  // Initialize structures
  ZeroMemory(&cryptVerifyPara, sizeof(cryptVerifyPara));
  ZeroMemory(&cadesVerifyPara, sizeof(cadesVerifyPara));
  ZeroMemory(&verifyPara, sizeof(verifyPara));

  cryptVerifyPara.cbSize = sizeof(cryptVerifyPara);
  cryptVerifyPara.dwMsgAndCertEncodingType =
      X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;

  cadesVerifyPara.dwSize = sizeof(cadesVerifyPara);
  cadesVerifyPara.dwCadesType = CADES_BES;

  verifyPara.dwSize = sizeof(verifyPara);
  verifyPara.pVerifyMessagePara = &cryptVerifyPara;
  verifyPara.pCadesVerifyPara = &cadesVerifyPara;

  if (!CadesVerifyMessage(&verifyPara, 0, signed_data, (DWORD)signed_data_size,
                          &pContent, &pVerifyInfo)) {
    printf("CadesVerifyMessage() failed\n");
    if (pVerifyInfo) {
      CadesFreeVerificationInfo(pVerifyInfo);
    }
    return ERR_CADES_VERIFY;
  }

  *verification_status = pVerifyInfo->dwStatus;
  if (*verification_status == CADES_VERIFY_SUCCESS) {
    get_cert_info(pVerifyInfo->pSignerCert, cert_info);
  }

  SIGNER_ERR return_value = SUCCESS;
  // Cleanup
  if (pVerifyInfo) {
    if (!CadesFreeVerificationInfo(pVerifyInfo)) {
      printf("CadesFreeVerificationInfo() failed\n");
      return_value = ERR_CADES_FREE_VERIFICATION_INFO;
    }
  }

  if (pContent) {
    if (!CadesFreeBlob(pContent)) {
      printf("CadesFreeBlob() failed\n");
      return_value = ERR_CADES_FREE_BLOB;
    }
  }

  return return_value;
}

SIGNER_ERR get_cert_info(PCCERT_CONTEXT pCertContext, GoCertInfo *cert_info) {
  // memset(cert_info, 0, sizeof(GoCertInfo));

  // Copy certificate data
  cert_info->cert_data = (unsigned char *)malloc(pCertContext->cbCertEncoded);
  if (cert_info->cert_data) {
    memcpy(cert_info->cert_data, pCertContext->pbCertEncoded,
           pCertContext->cbCertEncoded);
    cert_info->cert_length = pCertContext->cbCertEncoded;
  } else {
    return FAILURE;
  }

  // Copy serial number
  cert_info->serial_number =
      (unsigned char *)malloc(pCertContext->pCertInfo->SerialNumber.cbData);
  if (cert_info->serial_number) {
    memcpy(cert_info->serial_number,
           pCertContext->pCertInfo->SerialNumber.pbData,
           pCertContext->pCertInfo->SerialNumber.cbData);
    cert_info->serial_length = pCertContext->pCertInfo->SerialNumber.cbData;
  } else {
    return FAILURE;
  }

  // Get subject name
  DWORD subject_len = CertGetNameStringA(
      pCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, NULL, 0);

  if (subject_len > 0) {
    cert_info->subject_name =
        (unsigned char *)malloc(subject_len); // Use char* for strings
    if (cert_info->subject_name) {
      CertGetNameStringA(pCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL,
                         (LPSTR)cert_info->subject_name, subject_len);
      cert_info->subject_length = subject_len - 1; // Exclude null terminator
    } else {
      return FAILURE;
    }
  }

  const char *oid = pCertContext->pCertInfo->SignatureAlgorithm.pszObjId;
  if (oid) {
    size_t oid_len = strlen(oid);
    cert_info->signing_algo = (char *)malloc(oid_len);
    if (cert_info->signing_algo) {
      strcpy(cert_info->signing_algo, oid);
      cert_info->algo_length = oid_len;
    }
  }

  int mustFree = 0;
  DWORD dwKeySpec = 0;
  HCRYPTPROV hProv = 0;

  if (CryptAcquireCertificatePrivateKey(pCertContext, 0, 0, &hProv, &dwKeySpec,
                                        &mustFree)) {
    cert_info->has_private_key = 1;
    if (mustFree && hProv) {
      CryptReleaseContext(hProv, 0);
    }
  } else {
    cert_info->has_private_key = 0;
  }

  return SUCCESS;
}

PCCERT_CONTEXT GetRecipientCert(HCERTSTORE hCertStore, wchar_t *pSubject) {
  wchar_t *subject = pSubject;
  PCCERT_CONTEXT pCertContext = NULL;
  DWORD dwSize = 0;
  CRYPT_KEY_PROV_INFO *pKeyInfo = NULL;
  int mustFree;
  DWORD dwKeySpec = 0;
  HCRYPTPROV hProv;

  for (;;) {
    if (subject) {
      pCertContext = CertFindCertificateInStore(
          hCertStore, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0,
          CERT_FIND_SUBJECT_STR_W, subject, pCertContext);
      if (pCertContext)
        return pCertContext;
    } else {
      pCertContext = CertFindCertificateInStore(
          hCertStore, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0, CERT_FIND_ANY,
          NULL, pCertContext);
    }

    if (pCertContext) {
      if (!CryptAcquireCertificatePrivateKey(pCertContext, 0, NULL, &hProv,
                                             &dwKeySpec, &mustFree)) {
        if (mustFree)
          CryptReleaseContext(hProv, 0);
        continue;
      }

      if (!(CertGetCertificateContextProperty(
              pCertContext, CERT_KEY_PROV_INFO_PROP_ID, NULL, &dwSize))) {
        printf("Certificate property was not got\n");
        return NULL;
      }

      if (pKeyInfo)
        free(pKeyInfo);

      pKeyInfo = (CRYPT_KEY_PROV_INFO *)malloc(dwSize);
      if (!pKeyInfo) {
        printf("Error occurred during the time of memory allocating\n");
        return NULL;
      }

      if (!(CertGetCertificateContextProperty(
              pCertContext, CERT_KEY_PROV_INFO_PROP_ID, pKeyInfo, &dwSize))) {
        free(pKeyInfo);
        printf("Certificate property was not got\n");
        return NULL;
      }

      if (mustFree)
        CryptReleaseContext(hProv, 0);
      free(pKeyInfo);
      return pCertContext;
    } else {
      printf("Certificate with private key was not found\n");
      return NULL;
    }
  }
}

const char *GetHashOid(PCCERT_CONTEXT pCert) {
  const char *pKeyAlg =
      pCert->pCertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId;

  if (strcmp(pKeyAlg, szOID_CP_GOST_R3410EL) == 0) {
    return szOID_CP_GOST_R3411;
  } else if (strcmp(pKeyAlg, szOID_CP_GOST_R3410_12_256) == 0) {
    return szOID_CP_GOST_R3411_12_256;
  } else if (strcmp(pKeyAlg, szOID_CP_GOST_R3410_12_512) == 0) {
    return szOID_CP_GOST_R3411_12_512;
  }
  return NULL;
}

// int main() {
//   const unsigned char *data = (const unsigned char *)"sas velik";
//   DWORD data_size = (DWORD)strlen((const char *)data);
//   unsigned char *signed_data = NULL;
//   DWORD signed_data_size = 0;
//   int result = sign_simple(data, data_size, &signed_data, &signed_data_size);
//   if (result != 0) {
//     fprintf(stderr, "failed to sign: %d\n", result);
//     return 1;
//   }
//
//   printf("signed successfully %lu\n", sizeof(signed_data));
//
//   GoCertInfo *cert_info = (GoCertInfo *)malloc(sizeof(GoCertInfo));
//   if (!cert_info) {
//     fprintf(stderr, "failed to allocate memory for cert_info\n");
//     free(signed_data);
//     return 1;
//   }
//
//   // Initialize the structure to zero
//   memset(cert_info, 0, sizeof(GoCertInfo));
//   uint verification_status = 0;
//
//   verify_signature(signed_data, signed_data_size, cert_info,
//                    &verification_status);
//   if (verification_status != 0) {
//     fprintf(stderr, "failed to verify signature: %d\n", verification_status);
//     return 1;
//   }
//
//   if (cert_info) {
//     free(cert_info);
//   }
//
//   printf("verified\n");
//   // FILE *fptr = fopen("sign.dat", "w");
//   // if (!fptr) {
//   //   perror("fopen");
//   //   free(signed_data);
//   //   return 1;
//   // }
//   // if (signed_data_size > 0) {
//   //   size_t written = fwrite(signed_data, 1, (size_t)signed_data_size,
//   // fptr);
//   //   if (written != signed_data_size) {
//   //     fprintf(stderr, "write error: wrote %zu of %lu\n", written,
//   //             (unsigned long)signed_data_size);
//   //   }
//   // }
//   // fclose(fptr);
//   // free(signed_data);
//   return 0;
// }
