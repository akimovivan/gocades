#pragma once

#define SERVICE_URL_2001 L"http://subca-1/tsp_root/tsp.srf"
#define SERVICE_URL_2012 L"http://pki2012/tsp_root/tsp.srf"

PCCERT_CONTEXT GetRecipientCert(HCERTSTORE hCertStore, wchar_t *pSubject) {
  wchar_t *subject(pSubject);
  PCCERT_CONTEXT pCertContext(0);
  DWORD dwSize(0);
  CRYPT_KEY_PROV_INFO *pKeyInfo(0);

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
          0, pCertContext);
    }

    if (pCertContext) {
      if (!CryptAcquireCertificatePrivateKey(pCertContext, 0, 0, &hProv,
                                             &dwKeySpec, &mustFree)) {
        if (mustFree)
          CryptReleaseContext(hProv, 0);
        continue;
      }

      if (!(CertGetCertificateContextProperty(
              pCertContext, CERT_KEY_PROV_INFO_PROP_ID, 0, &dwSize))) {
        std::cout << "Certificate property was not got" << std::endl;
        return 0;
      }

      if (pKeyInfo)
        free(pKeyInfo);

      pKeyInfo = (CRYPT_KEY_PROV_INFO *)malloc(dwSize);

      if (!pKeyInfo) {
        std::cout << "Error occured during the time of memory allocating" << std::endl;
        return 0;
      }

      if (!(CertGetCertificateContextProperty(
              pCertContext, CERT_KEY_PROV_INFO_PROP_ID, pKeyInfo, &dwSize))) {
        free(pKeyInfo);
        std::cout << "Certificate property was not got" << std::endl;
        return 0;
      }

      if (mustFree)
        CryptReleaseContext(hProv, 0);
      free(pKeyInfo);
      return pCertContext;

    } else {
      std::cout << "Certificate with private key was not found" << std::endl;
      return 0;
    }
  }
}

template <typename T>
int SaveVectorToFile(const char *filename, std::vector<T> &buffer) {
  if (buffer.empty()) {
    std::cout << "There is nothing to save" << std::endl;
    return -1;
  }

  FILE *f = fopen(filename, "wb");
  if (!f) {
    std::cout << "Opening file " << filename << " failed" << std::endl;
    return -1;
  }

  size_t count = fwrite(&buffer[0], sizeof(T), buffer.size(), f);
  fclose(f);
  if (count != buffer.size()) {
    std::cout << "Error occured during saving to file " << filename << std::endl;
    return -1;
  }
  return 0;
}

int ReadFileToVector(const char *filename, std::vector<unsigned char> &buffer) {
  enum { bytesSize = 512 };

  unsigned long bytesRead(1);
  char buf[bytesSize];

  FILE *f = fopen(filename, "r+b");

  if (!f) {
    std::cout << "Opening file " << filename << " failed" << std::endl;
    return -1;
  }

  while (!feof(f)) {
    bytesRead = (unsigned long)fread(buf, 1, bytesSize, f);

    if (bytesSize != bytesRead && ferror(f)) {
      fclose(f);
      return -1;
    }
    std::copy(buf, buf + bytesRead, std::back_inserter(buffer));
  }
  fclose(f);

  return 0;
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
