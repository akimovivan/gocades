#include "signer.h"
#include "CSP_WinCrypt.h"
#include "reader/tchar.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

//
// NOTE: Helper functions definitions (not exported)
//
static PCCERT_CONTEXT GetRecipientCert(HCERTSTORE hCertStore,
                                       wchar_t *pSubject);
static const char *GetHashOid(PCCERT_CONTEXT pCert);
static SIGNER_ERR get_cert_info(PCCERT_CONTEXT pCertContext,
                                GoCertInfo *cert_info);
static void HandleError(const char *s);
static PCCERT_CONTEXT GetRecipientCertExchange(HCERTSTORE hCertStore);
static BOOL isGostType(DWORD dwProvType) { return IS_GOST_PROV(dwProvType); }
static void GetCertDName(PCERT_NAME_BLOB pNameBlob, char **pszName);

static PCCERT_CONTEXT *certificates = NULL;
static int cert_count = 0;

//
// NOTE: library func
//
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

  hStoreHandle = CertOpenSystemStore(0, "MY");
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

int encrypt(unsigned char *pbContent, int cbContent,
            unsigned char **pbEncryptedBlob, int *out_len) {
  HCRYPTPROV hCryptProv = 0;
  HCERTSTORE hStoreHandle = 0;
  PCCERT_CONTEXT pRecipientCert = NULL;
  char *szDName = NULL;
  // DWORD cbContent = sizeof(*pbContent); // Длина сообщения, включая конечный
  // 0

  CRYPT_ALGORITHM_IDENTIFIER EncryptAlgorithm;
  CRYPT_ENCRYPT_MESSAGE_PARA EncryptParams;

  DWORD cbEncryptedBlob;

  printf("source message: %s\n", pbContent);
  printf("message length: %d bytes \n", cbContent);

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

  // Открытие системного хранилища сертификатов.
  hStoreHandle = CertOpenSystemStore(hCryptProv, "MY");

  if (!hStoreHandle) {
    HandleError("Error getting store handle.");
  }
  printf("The MY store is open. \n");

  // Получение указателя на сертификат получателя с помощью
  // функции GetRecipientCert.
  pRecipientCert = GetRecipientCertExchange(hStoreHandle);

  if (!pRecipientCert) {
    printf("No certificate with a CERT_KEY_CONTEXT_PROP_ID \n");
    printf("property and an AT_KEYEXCHANGE private key available. \n");
    printf("While the message could be encrypted, in this case, \n");
    printf("it could not be decrypted in this program. \n");
    printf("For more information, see the documentation for \n");
    printf("CryptEncryptMessage and CryptDecryptMessage.\n\n");
    HandleError("No Certificate with AT_KEYEXCHANGE key in store.");
  }
  GetCertDName(&pRecipientCert->pCertInfo->Subject, &szDName);
  printf("A recipient's certificate has been acquired: %s\n", szDName);

  // Инициализация структуры с нулем.
  memset(&EncryptAlgorithm, 0, sizeof(CRYPT_ALGORITHM_IDENTIFIER));
  // EncryptAlgorithm.pszObjId = OID_CipherVar_Default;
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
    HandleError("Getting EncrypBlob size failed.");
  }
  printf("The encrypted message is %d bytes. \n", cbEncryptedBlob);
  *out_len = cbEncryptedBlob;

  // Распределение памяти под возвращаемый BLOB.
  *pbEncryptedBlob = (BYTE *)malloc(cbEncryptedBlob);

  if (!pbEncryptedBlob)
    HandleError("Memory allocation error while encrypting.");

  // Повторный вызов функции CryptEncryptMessage для зашифрования содержимого.
  if (!CryptEncryptMessage(&EncryptParams, 1, &pRecipientCert, pbContent,
                           cbContent, *pbEncryptedBlob, &cbEncryptedBlob)) {
    HandleError("Encryption failed.");
  }
  printf("Encryption succeeded. \n");

  if (pRecipientCert) {
    CertFreeCertificateContext(pRecipientCert);
  }

  return 0;
}

int decrypt(unsigned char *pbEncryptedBlob, unsigned int cbEncryptedBlob,
            unsigned char **pbDecryptedBlob,
            unsigned int *out_len) { // Changed cbDecryptedBlob to pointer

  HCRYPTPROV hCryptProv = 0;
  HCERTSTORE hStoreHandle = 0; // This handle needs to be valid for decryption

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

  // Initialize structure
  memset(&decryptParams, 0, sizeof(CRYPT_DECRYPT_MESSAGE_PARA));
  decryptParams.cbSize = sizeof(CRYPT_DECRYPT_MESSAGE_PARA);
  decryptParams.dwMsgAndCertEncodingType = MY_ENCODING_TYPE;
  decryptParams.cCertStore = 1;
  decryptParams.rghCertStore = &hStoreHandle;

  DWORD tempCbDecryptedBlob = 0; // Use a temp variable for the size
  if (!CryptDecryptMessage(&decryptParams, pbEncryptedBlob, cbEncryptedBlob,
                           NULL, &tempCbDecryptedBlob, NULL)) {
    HandleError("Error getting decrypted message size");
    return -1;
  }
  printf("The size for the decrypted message is: %u.\n", tempCbDecryptedBlob);

  // Allocate memory for the decrypted data in C
  *pbDecryptedBlob = (BYTE *)malloc(tempCbDecryptedBlob);
  if (!(*pbDecryptedBlob)) { // Check the dereferenced pointer
    // DO NOT free pbEncryptedBlob here - it's managed by Go
    HandleError("Memory allocation error while decrypting");
    return -2;
  }

  // Call CryptDecryptMessage again to get the actual decrypted data
  if (!CryptDecryptMessage(&decryptParams, pbEncryptedBlob, cbEncryptedBlob,
                           *pbDecryptedBlob, &tempCbDecryptedBlob, NULL)) {
    free(*pbDecryptedBlob);  // Free the allocated buffer, not the
                             // pointer-to-pointer
    *pbDecryptedBlob = NULL; // Set it to NULL to signal failure
    // DO NOT free pbEncryptedBlob here - it's managed by Go
    HandleError("Error decrypting the message");
    return -3;
  }

  // Update the output size parameter
  *out_len = tempCbDecryptedBlob;

  printf("Message Decrypted Successfully. \n");
  // Be cautious with %s if the decrypted data might not be null-terminated or
  // is binary printf("The decrypted string is: %.*s\n", tempCbDecryptedBlob,
  // (char*)*pbDecryptedBlob);

  // DO NOT free pbEncryptedBlob here - it's managed by Go
  // The caller (Go) is responsible for freeing pbEncryptedBlob
  // The caller (Go) is also responsible for freeing *pbDecryptedBlob after use

  return 0;
}

int count_certificates() {
  return cert_count;
}

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
            PCCERT_CONTEXT *temp = realloc(certificates, 
                                          (cert_count + 1) * sizeof(PCCERT_CONTEXT));
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
            
            // Duplicate the certificate context so it remains valid after store is closed
            certificates[cert_count] = CertDuplicateCertificateContext(pCertContext);
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

SIGNER_ERR get_certificate_by_id(int idx, GoCertInfo *cert_info) {
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

void HandleError(const char *s) {
  printf("An error occurred in running the program.\n");
  printf("%s\n", s);
  DWORD err = GetLastError();
  printf("Error number %x\n.", err);
  printf("Program terminating.\n");
  exit(1);
}

PCCERT_CONTEXT GetRecipientCertExchange(HCERTSTORE hCertStore) {
  PCCERT_CONTEXT pCertContext = NULL;
  BOOL bCertNotFind = TRUE;
  DWORD dwSize = 0;
  CRYPT_KEY_PROV_INFO *pKeyInfo = NULL;
  DWORD PropId = CERT_KEY_PROV_INFO_PROP_ID;
  HCRYPTPROV hProv = 0;
  DWORD dwKeySpec = 0;
  BOOL fFreeProv = FALSE;

  if (!hCertStore)
    return NULL;

  do {
    // Поиск сертификатов в хранилище до тех пор, пока не будет достигнут
    // конец хранилища, или сертификат с ключем AT_KEYEXCHANGE не будет найден.
    pCertContext = CertFindCertificateInStore(
        hCertStore, // Дескриптор хранилища, в котором будет осуществлен поиск.
        MY_ENCODING_TYPE, 0, CERT_FIND_PROPERTY, &PropId, pCertContext);
    if (!pCertContext)
      break;

    // Для простоты в этом коде реализован только поиск первого
    // вхождения ключа AT_KEYEXCHANGE. Во многих случаях, помимо
    // поиска типа ключа, осуществляется также поиск определенного
    // имени субъекта.

    // Однократный вызов функции CertGetCertificateContextProperty
    // для получения возврашенного размера структуры.
    if (!(CertGetCertificateContextProperty(
            pCertContext, CERT_KEY_PROV_INFO_PROP_ID, NULL, &dwSize))) {
      printf("Error getting key property.\n");
      return NULL;
    }

    //--------------------------------------------------------------
    // распределение памяти под возвращенную структуру.

    free(pKeyInfo);

    pKeyInfo = (CRYPT_KEY_PROV_INFO *)malloc(dwSize);

    if (!pKeyInfo) {
      HandleError("Error allocating memory for pKeyInfo.");
    }

    //--------------------------------------------------------------
    // Получение структуры информации о ключе.

    if (!(CertGetCertificateContextProperty(
            pCertContext, CERT_KEY_PROV_INFO_PROP_ID, pKeyInfo, &dwSize))) {
      HandleError("The second call to the function failed.");
    }

    //-------------------------------------------
    // Проверка члена dwKeySpec на расширенный ключ и типа провайдера
    if (pKeyInfo->dwKeySpec == AT_KEYEXCHANGE &&
        isGostType(pKeyInfo->dwProvType)) {
      //-------------------------------------------
      // попробуем открыть провайдер
      fFreeProv = FALSE;
      if (CryptAcquireCertificatePrivateKey(
              pCertContext,
              CRYPT_ACQUIRE_COMPARE_KEY_FLAG | CRYPT_ACQUIRE_SILENT_FLAG, NULL,
              &hProv, &dwKeySpec, &fFreeProv)) {
        HCRYPTKEY hKey = 0;
        if (CryptGetUserKey(hProv, dwKeySpec, &hKey)) {
          bCertNotFind = FALSE;
          CryptDestroyKey(hKey);
        }
        if (fFreeProv)
          CryptReleaseContext(hProv, 0);
      }
    }
  } while (bCertNotFind && pCertContext);

  free(pKeyInfo);

  if (bCertNotFind)
    return NULL;
  else
    return (pCertContext);
}

void GetCertDName(PCERT_NAME_BLOB pNameBlob, char **pszName) {
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

// left it here for testing directly in c
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

// int main() {
//   SIGNER_ERR err = initialize_certificates();
//   if (err != SUCCESS) {
//     fprintf(stderr, "failed to initialize certificates\n");
//     return 1;
//   }
//
//   GoCertInfo *cert_info = (GoCertInfo *)malloc(sizeof(GoCertInfo));
//   if (!cert_info) {
//     fprintf(stderr, "failed to allocate memory for cert_info\n");
//     return 1;
//   }
//
//   // Initialize the structure to zero
//   memset(cert_info, 0, sizeof(GoCertInfo));
//
//   err = get_cert_info(certificates[0], cert_info);
//   if (err != SUCCESS) {
//     fprintf(stderr, "failed to get certificate info\n");
//     return 2;
//   }
//
//   printf("Certificate info:\n\tcert_len: %d\n\tsubject_name: %s\n",
//          cert_info->cert_length, cert_info->subject_name);
//
//   free(certificates);
//   free(cert_info);
//
//   return 0;
// }
