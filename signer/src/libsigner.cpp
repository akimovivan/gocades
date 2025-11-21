#ifdef _WIN32
#include <tchar.h>
#else
#include "reader/tchar.h"
#include <cstdio>
#endif

#include "cades.h"
#include <cstring>
#include <cstdlib>
#include <iostream>
#include <vector>
#include "../samples_util.h"
#include <wchar.h>
#include "libsigner.hpp"

int sign_simple(const std::vector<unsigned char>& data,
                std::vector<unsigned char>* signed_data) {
    if (!signed_data) {
        std::cerr << "Error: signed_data pointer is null." << std::endl;
        return -1;
    }

    signed_data->clear();

    HCERTSTORE hStoreHandle = CertOpenSystemStore(0, _TEXT("MY"));

    if (!hStoreHandle) {
        std::cout << "Store handle was not got" << std::endl;
        return -1;
    }

    wchar_t *wa = NULL;
    PCCERT_CONTEXT context = GetRecipientCert(hStoreHandle, wa);
    if (wa)
        delete[] wa;

    if (!context) {
        std::cout << "There is no certificate with a CERT_KEY_CONTEXT_PROP_ID "
                  << std::endl
                  << "property and an AT_KEYEXCHANGE private key available."
                  << std::endl
                  << "While the message could be sign, in this case, it could"
                  << std::endl
                  << "not be verify in this program." << std::endl
                  << "For more information, read the documentation "
                     "http://cpdn.cryptopro.ru/"
                  << std::endl;
        CertCloseStore(hStoreHandle, 0);
        return -1;
    }

    CRYPT_SIGN_MESSAGE_PARA signPara = {sizeof(signPara)};
    signPara.dwMsgEncodingType = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;
    signPara.pSigningCert = context;
    signPara.HashAlgorithm.pszObjId = (LPSTR)GetHashOid(context);

    CADES_SIGN_PARA cadesSignPara = {sizeof(cadesSignPara)};
    cadesSignPara.dwCadesType = CADES_BES;

    CADES_SIGN_MESSAGE_PARA para = {sizeof(para)};
    para.pSignMessagePara = &signPara;
    para.pCadesSignPara = &cadesSignPara;

    const unsigned char *pbToBeSigned[] = {data.data()};
    DWORD cbToBeSigned[] = {(DWORD)data.size()};

    CERT_CHAIN_PARA ChainPara = {sizeof(ChainPara)};
    PCCERT_CHAIN_CONTEXT pChainContext = NULL;

    std::vector<PCCERT_CONTEXT> certs;

    if (CertGetCertificateChain(NULL, context, NULL, NULL, &ChainPara, 0, NULL,
                                &pChainContext)) {

        for (DWORD i = 0; i < pChainContext->rgpChain[0]->cElement - 1; ++i) {
            certs.push_back(pChainContext->rgpChain[0]->rgpElement[i]->pCertContext);
        }
    }
    if (certs.size() > 0) {
        signPara.cMsgCert = (DWORD)certs.size();
        signPara.rgpMsgCert = certs.data();
    }

    PCRYPT_DATA_BLOB pSignedMessage = 0;
    if (!CadesSignMessage(&para, 0, 1, pbToBeSigned, cbToBeSigned,
                          &pSignedMessage)) {
        std::cout << "CadesSignMessage() failed" << std::endl;
        if (pChainContext) CertFreeCertificateChain(pChainContext);
        CertFreeCertificateContext(context);
        CertCloseStore(hStoreHandle, 0);
        return -1;
    }
    if (pChainContext)
        CertFreeCertificateChain(pChainContext);

    signed_data->assign(pSignedMessage->pbData,
                        pSignedMessage->pbData + pSignedMessage->cbData);

    if (!CadesFreeBlob(pSignedMessage)) {
        std::cout << "CadesFreeBlob() failed" << std::endl;
        CertFreeCertificateContext(context);
        CertCloseStore(hStoreHandle, 0);
        return -1;
    }

    if (!CertCloseStore(hStoreHandle, 0)) {
        std::cout << "Certificate store handle was not closed." << std::endl;
        CertFreeCertificateContext(context);
        return -1;
    }

    if (context)
        CertFreeCertificateContext(context);

    return 0;
}

extern "C" {
    int sign_simple_wrapper(const unsigned char* data, int data_len, 
                           unsigned char** out_signed_data, int* out_len) {
        if (!data || !out_signed_data || !out_len || data_len <= 0) {
            return -1;
        }

        std::vector<unsigned char> input_data(data, data + data_len);
        std::vector<unsigned char> signed_data;

        int result = sign_simple(input_data, &signed_data);
        
        if (result == 0 && !signed_data.empty()) {
            *out_signed_data = (unsigned char*)malloc(signed_data.size());
            if (*out_signed_data) {
                memcpy(*out_signed_data, signed_data.data(), signed_data.size());
                *out_len = (int)signed_data.size();
            } else {
                return -1;
            }
        } else {
            *out_signed_data = nullptr;
            *out_len = 0;
        }

        return result;
    }
}
