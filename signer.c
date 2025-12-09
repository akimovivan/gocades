#include "signer.h"
#include <stdint.h>
#ifdef _WIN32
#include "WinCryptEx.h"
#include <tchar.h>
#else
#include <CSP_WinCrypt.h>
#include <reader/tchar.h>
#endif // headers

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

//
// NOTE: Helper functions definitions (not exported)
//
static const char *GetHashOid(PCCERT_CONTEXT pCert);
static SIGNER_ERR get_cert_info(PCCERT_CONTEXT pCertContext,
                                GoCertInfo *cert_info);
static void HandleError(const char *s);
static BOOL isGostType(DWORD dwProvType) { return IS_GOST_PROV(dwProvType); }
static void GetCertDName(PCERT_NAME_BLOB pNameBlob, char **pszName);
static char *wide_to_utf8(const wchar_t *wide_str);

static PCCERT_CONTEXT *certificates = NULL;
static uint8_t cert_count = 0;
static PCCERT_CONTEXT get_cert_by_id_internal(uint8_t idx);

//
// NOTE: library func
//
SIGNER_ERR sign_simple(const unsigned char *data, DWORD data_size,
                       unsigned char **signed_data, DWORD *signed_data_size,
                       uint8_t cert_idx) {
  HCERTSTORE hStoreHandle = NULL;
  PCCERT_CONTEXT context = NULL;
  PCCERT_CHAIN_CONTEXT pChainContext = NULL;
  PCRYPT_DATA_BLOB pSignedMessage = NULL;
  int result = -1;

  *signed_data = NULL;
  *signed_data_size = 0;

  hStoreHandle = CertOpenSystemStore(0, "MY");
  if (!hStoreHandle) {
    return ERR_OPEN_STORE;
  }

  wchar_t *wa = NULL;
  context = get_cert_by_id_internal(cert_idx);
  if (wa)
    free(wa);

  if (!context) {
    CertCloseStore(hStoreHandle, 0);
    return ERR_OPEN_STORE; /* TODO: update error message */
  }

  CRYPT_SIGN_MESSAGE_PARA *signPara =
      (CRYPT_SIGN_MESSAGE_PARA *)malloc(sizeof(CRYPT_SIGN_MESSAGE_PARA));
  if (!signPara) {
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

SIGNER_ERR verify_signature(const unsigned char *signed_data,
                            DWORD signed_data_size, GoCertInfo *cert_info,
                            BOOL *verification_status) {
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
  cert_info->cert_data = (unsigned char *)malloc(pCertContext->cbCertEncoded);
  if (cert_info->cert_data) {
    memcpy(cert_info->cert_data, pCertContext->pbCertEncoded,
           pCertContext->cbCertEncoded);
    cert_info->cert_length = pCertContext->cbCertEncoded;
  } else {
    return FAILURE;
  }

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

  DWORD subject_len = CertGetNameStringA(
      pCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, NULL, 0);

  // if (subject_len > 0) {
  //   cert_info->subject_name =
  //       (unsigned char *)malloc(subject_len); // Use char* for strings
  //   if (cert_info->subject_name) {
  //     CertGetNameStringA(pCertContext, CERT_NAME_FRIENDLY_DISPLAY_TYPE, 0,
  //     NULL,
  //                        (LPSTR)cert_info->subject_name, subject_len);
  //     cert_info->subject_length = subject_len - 1;
  //   } else {
  //     return FAILURE;
  //   }
  // }

  if (subject_len > 0) {
    wchar_t *wide_subject = (wchar_t *)malloc(subject_len * sizeof(wchar_t));
    if (wide_subject) {
      CertGetNameStringW(pCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL,
                         wide_subject, subject_len);

      char *utf8_subject = wide_to_utf8(wide_subject);
      if (utf8_subject) {
        cert_info->subject_name = (unsigned char *)utf8_subject;
        cert_info->subject_length = strlen(utf8_subject);
      }
      free(wide_subject);
    }
  } else {
    return FAILURE;
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

int encrypt(unsigned char *pbContent, DWORD cbContent,
            unsigned char **pbEncryptedBlob, DWORD *out_len, uint8_t cert_idx) {
  HCRYPTPROV hCryptProv = 0;
  PCCERT_CONTEXT pRecipientCert = NULL;
  char *szDName = NULL;
  // DWORD cbContent = sizeof(*pbContent); // Длина сообщения, включая конечный
  // 0

  CRYPT_ALGORITHM_IDENTIFIER EncryptAlgorithm;
  CRYPT_ENCRYPT_MESSAGE_PARA EncryptParams;

  DWORD cbEncryptedBlob;

  // Получение дескриптора криптографического провайдера.
  if (!CryptAcquireContext(
          &hCryptProv, // Адрес возврашаемого дескриптора.
          0,    // Используется имя текущего зарегестрированного пользователя.
          NULL, // Используется провайдер по умолчанию.
          PROV_GOST_2012_256,   // Необходимо для зашифрования и подписи.
          CRYPT_VERIFYCONTEXT)) // Никакие флаги не нужны.
  {
    HandleError("Cryptographic context could not be acquired.");
  }
  printf("CSP has been acquired. \n");

  pRecipientCert = get_cert_by_id_internal(cert_idx);

  if (!pRecipientCert) {
    return -3;
  }

  GetCertDName(&pRecipientCert->pCertInfo->Subject, &szDName);

  ZeroMemory(&EncryptAlgorithm, sizeof(CRYPT_ALGORITHM_IDENTIFIER));
  EncryptAlgorithm.pszObjId = (LPSTR)szOID_CP_GOST_28147;

  // Инициализация структуры CRYPT_ENCRYPT_MESSAGE_PARA.
  memset(&EncryptParams, 0, sizeof(CRYPT_ENCRYPT_MESSAGE_PARA));
  EncryptParams.cbSize = sizeof(CRYPT_ENCRYPT_MESSAGE_PARA);
  EncryptParams.dwMsgEncodingType = MY_ENCODING_TYPE;
  EncryptParams.hCryptProv = hCryptProv;
  EncryptParams.ContentEncryptionAlgorithm = EncryptAlgorithm;

  // Вызов функции CryptEncryptMessage.
  if (!CryptEncryptMessage(&EncryptParams, 1, &pRecipientCert, pbContent,
                           cbContent, NULL, &cbEncryptedBlob)) {
    return -4;
  }
  *out_len = cbEncryptedBlob;

  *pbEncryptedBlob = (BYTE *)malloc(cbEncryptedBlob);

  if (!pbEncryptedBlob) {
    return -5;
  }

  if (!CryptEncryptMessage(&EncryptParams, 1, &pRecipientCert, pbContent,
                           cbContent, *pbEncryptedBlob, &cbEncryptedBlob)) {
    return -6;
  }

  if (pRecipientCert) {
    CertFreeCertificateContext(pRecipientCert);
  }

  return 0;
}

int decrypt(unsigned char *pbEncryptedBlob, DWORD cbEncryptedBlob,
            unsigned char **pbDecryptedBlob, DWORD *out_len) {
  HCRYPTPROV hCryptProv = 0;
  HCERTSTORE hStoreHandle = 0;

  CRYPT_DECRYPT_MESSAGE_PARA decryptParams;

  if (!CryptAcquireContext(
          &hCryptProv, // Адрес возврашаемого дескриптора.
          0,    // Используется имя текущего зарегестрированного пользователя.
          NULL, // Используется провайдер по умолчанию.
          PROV_GOST_2012_256,   // Необходимо для зашифрования и подписи.
          CRYPT_VERIFYCONTEXT)) // Никакие флаги не нужны.
  {
    HandleError("Cryptographic context could not be acquired.");
  }
  printf("CSP has been acquired. \n");

  // Открытие системного хранилища сертификатов.
  hStoreHandle = CertOpenSystemStore(hCryptProv, "MY");

  if (!hStoreHandle) {
    HandleError("Error getting store handle.");
  }
  printf("The MY store is open. \n");

  ZeroMemory(&decryptParams, sizeof(CRYPT_DECRYPT_MESSAGE_PARA));
  decryptParams.cbSize = sizeof(CRYPT_DECRYPT_MESSAGE_PARA);
  decryptParams.dwMsgAndCertEncodingType = MY_ENCODING_TYPE;
  decryptParams.cCertStore = 1;
  decryptParams.rghCertStore = &hStoreHandle;

  DWORD tempCbDecryptedBlob = 0;
  if (!CryptDecryptMessage(&decryptParams, pbEncryptedBlob, cbEncryptedBlob,
                           NULL, &tempCbDecryptedBlob, NULL)) {
    return -1;
  }
  *pbDecryptedBlob = (BYTE *)malloc(tempCbDecryptedBlob);
  if (!(*pbDecryptedBlob)) {
    HandleError("Memory allocation error while decrypting");
    return -2;
  }

  if (!CryptDecryptMessage(&decryptParams, pbEncryptedBlob, cbEncryptedBlob,
                           *pbDecryptedBlob, &tempCbDecryptedBlob, NULL)) {
    free(*pbDecryptedBlob);
    *pbDecryptedBlob = NULL;
    return -3;
  }
  *out_len = tempCbDecryptedBlob;

  return 0;
}

uint8_t count_certificates() { return cert_count; }

SIGNER_ERR initialize_certificates() {
  cert_count = 0;
  certificates = malloc(sizeof(PCCERT_CONTEXT));

  HCERTSTORE hCertStore = CertOpenSystemStore(0, _TEXT("MY"));
  if (!hCertStore) {
    printf("Failed to open certificate store");
    return ERR_OPEN_STORE;
  }

  PCCERT_CONTEXT pCertContext = NULL;
  DWORD dwSize = 0;
  CRYPT_KEY_PROV_INFO *pKeyInfo = NULL;

  while ((pCertContext = CertFindCertificateInStore(
              hCertStore, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0,
              CERT_FIND_ANY, 0, pCertContext))) {
    int mustFree = 0;
    DWORD dwKeySpec = 0;
    HCRYPTPROV hProv = 0;
    if (CryptAcquireCertificatePrivateKey(pCertContext, 0, 0, &hProv,
                                          &dwKeySpec, &mustFree)) {
      dwSize = 0;
      if (CertGetCertificateContextProperty(
              pCertContext, CERT_KEY_PROV_INFO_PROP_ID, 0, &dwSize)) {
        pKeyInfo = (CRYPT_KEY_PROV_INFO *)malloc(dwSize);
        if (pKeyInfo) {
          if (CertGetCertificateContextProperty(pCertContext,
                                                CERT_KEY_PROV_INFO_PROP_ID,
                                                pKeyInfo, &dwSize)) {
            // Reallocate to make room for one more certificate
            PCCERT_CONTEXT *temp = realloc(
                certificates, (cert_count + 1) * sizeof(PCCERT_CONTEXT));
            if (temp == NULL) {
              // realloc failed, free the old pointer and clean up
              free(certificates);
              certificates = NULL;
              free(pKeyInfo);
              if (mustFree && hProv) {
                CryptReleaseContext(hProv, 0);
              }
              CertCloseStore(hCertStore, 0);
              return FAILURE; // or appropriate error code
            }
            certificates = temp;

            // Duplicate the certificate context so it remains valid after store
            // is closed
            certificates[cert_count] =
                CertDuplicateCertificateContext(pCertContext);
            if (certificates[cert_count] != NULL) {
              cert_count++;
            }
          }
          free(pKeyInfo);
          pKeyInfo = NULL;
        }
      }

      if (mustFree && hProv)
        CryptReleaseContext(hProv, 0);
    }
    // If CryptAcquireCertificatePrivateKey fails, continue to next cert
  }

  CertCloseStore(hCertStore, 0);

  if (cert_count == 0) {
    free(certificates);
  }

  return SUCCESS;
}

SIGNER_ERR get_certificate_by_id(uint8_t idx, GoCertInfo *cert_info) {
  if (idx < 0 || idx >= cert_count) {
    return FAILURE;
  }
  return get_cert_info(certificates[idx], cert_info);
}

void clear_certificates() {
  if (certificates) {
    for (int i = 0; i < cert_count; i++) {
      if (certificates[i]) {
        CertFreeCertificateContext(certificates[i]);
      }
    }
    free(certificates);
    certificates = NULL;
    cert_count = 0;
  }
}

//
// NOTE: Helper functions implementations
//
static const char *GetHashOid(PCCERT_CONTEXT pCert) {
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

static void HandleError(const char *s) {
  printf("An error occurred in running the program.\n");
  printf("%s\n", s);
  DWORD err = GetLastError();
  printf("Error number %x\n.", err);
  printf("Program terminating.\n");
  exit(1);
}

static void GetCertDName(PCERT_NAME_BLOB pNameBlob, char **pszName) {
  DWORD cbName;

  cbName =
      CertNameToStr(X509_ASN_ENCODING, pNameBlob,
                    CERT_X500_NAME_STR | CERT_NAME_STR_NO_PLUS_FLAG, NULL, 0);
  if (cbName == 1)
    HandleError("CertNameToStr(NULL)");

  *pszName = (char *)malloc(cbName * sizeof(char));
  if (!*pszName)
    HandleError("Out of memory.");

  cbName = CertNameToStrA(X509_ASN_ENCODING, pNameBlob,
                          CERT_X500_NAME_STR | CERT_NAME_STR_NO_PLUS_FLAG,
                          *pszName, cbName);
  if (cbName == 1)
    HandleError("CertNameToStr(pbData)");
}

static PCCERT_CONTEXT get_cert_by_id_internal(uint8_t idx) {
  if (idx < 0 || idx >= cert_count) {
    return NULL;
  }
  return certificates[idx];
}

static char *wide_to_utf8(const wchar_t *wide_str) {
  if (!wide_str)
    return NULL;

  int utf8_len =
      WideCharToMultiByte(CP_UTF8, 0, wide_str, -1, NULL, 0, NULL, NULL);
  if (utf8_len <= 0)
    return NULL;

  char *utf8_str = (char *)malloc(utf8_len);
  if (!utf8_str)
    return NULL;

  WideCharToMultiByte(CP_UTF8, 0, wide_str, -1, utf8_str, utf8_len, NULL, NULL);
  return utf8_str;
}
