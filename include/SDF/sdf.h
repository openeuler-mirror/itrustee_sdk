/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: to ta operator
 * Create: 2025-04-08
 */
#ifndef SDF_H
#define SDF_H
#include<stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SDR_OK                  0x0
#define SDR_BASE                0x01000000
#define SDR_UNKNOWERR           (SDR_BASE + 0x00000001)
#define SDR_NOTSUPPORT          (SDR_BASE + 0x00000002)
#define SDR_COMMFAIL            (SDR_BASE + 0x00000003)
#define SDR_HARDFAIL            (SDR_BASE + 0x00000004)
#define SDR_OPENDEVICE          (SDR_BASE + 0x00000005)
#define SDR_OPENSESSION         (SDR_BASE + 0x00000006)
#define SDR_PARDENY             (SDR_BASE + 0x00000007)
#define SDR_KEYNOTEXIST         (SDR_BASE + 0x00000008)
#define SDR_ALGNOTSUPPORT       (SDR_BASE + 0x00000009)
#define SDR_ALGMODNOTSUPPORT    (SDR_BASE + 0x0000000A)
#define SDR_PKOPERR             (SDR_BASE + 0x0000000B)
#define SDR_SKOPERR             (SDR_BASE + 0x0000000C)
#define SDR_SIGNERR             (SDR_BASE + 0x0000000D)
#define SDR_VERIFYERR           (SDR_BASE + 0x0000000E)
#define SDR_SYMOPERR            (SDR_BASE + 0x0000000F)
#define SDR_STEPERR             (SDR_BASE + 0x00000010)
#define SDR_FILESIZEERR         (SDR_BASE + 0x00000011)
#define SDR_FILENOEXIST         (SDR_BASE + 0x00000012)
#define SDR_FILEOFSERR          (SDR_BASE + 0x00000013)
#define SDR_KEYTYPEERR          (SDR_BASE + 0x00000014)
#define SDR_KEYERR              (SDR_BASE + 0x00000015)
#define SDR_ENCDATAERR          (SDR_BASE + 0x00000016)
#define SDR_RANDERR             (SDR_BASE + 0x00000017)
#define SDR_PRKRERR             (SDR_BASE + 0x00000018)
#define SDR_MACERR              (SDR_BASE + 0x00000019)
#define SDR_FILEEXSITS          (SDR_BASE + 0x0000001A)
#define SDR_FILEWERR            (SDR_BASE + 0x0000001B)
#define SDR_NOBUFFER            (SDR_BASE + 0x0000001C)
#define SDR_INARGERR            (SDR_BASE + 0x0000001D)
#define SDR_OUTARGERR           (SDR_BASE + 0x0000001E)
#define SDR_GENERIC             (SDR_BASE + 0x0000001F)
#define SDR_PASSWDERR           (SDR_BASE + 0x00000020)
#define SDR_SHORT_BUFFER        (SDR_BASE + 0x00000021)
#define SDR_SELFTESTERR         (SDR_BASE + 0x00000022)
#define SDR_BUSY                (SDR_BASE + 0x10000001)
#define SDR_DUPLIPWD            (SDR_BASE + 0x00A00001)


#define MAX_SDF_DEVICE_NUM 50
#define MAX_SDFSession_NUM 1000
#define MAX_SDF_AGREEMENT_KEY_LENGTH 128
#define MAX_SDF_SPONSOR_ID_LENGTH 128
#define MAX_SDF_RESPONSE_ID_LENGTH 128
#define AGREEMENT_ID_MAX_LEN 64
#define PASSWORD_LEN 128
#define ECCref_MAX_LEN 64
#define SM2_KEY_BYTES 32
#define SM4_KEY_BYTES 16
#define ISSUER_NAME_LENGTH 40
#define DEVICE_NAME_LENGTH 16
#define DEVICE_SERIAL_LENGTH 16
#define ASYM_ALG_ABILITY_LENGTH 2
#define M_LENGTH 32
#define CRYPT_COORDINATE_LENGTH 32
#define CRYPT_KEY_LENGTH 16
#define IV_LENGTH 16
#define TAG_LENGTH 16
#define NONCE_LENGTH 64
#define PASSWORD_MAX_LEN 128
#define STRONG_PASSWORD_COUNT 2
#define PASSWORD_MIN_LEN 8
#define PASSWORD_PBKDF2_LEN 32
#define ITERATIONS 10000
#define MAX_USERNAME_LEN 256

#define MAX_KEYS 1000
#define MAX_PASSWORD_LENGTH 128
#define KEY_INFO_LEN 8
#define KEY_SHIFT_BITS 4
#define KEY_FILENAME_LEN 12
#define SALT_LEN 16
#define MAX_CA_PATH 256
#define CA_INFO_LEN 32


typedef struct KeyHandle_st {
    unsigned char *KeyName;
} KeyHandle;

typedef struct ECCrefPublicKey_st {
    unsigned int bits;
    unsigned char x[ECCref_MAX_LEN];
    unsigned char y[ECCref_MAX_LEN];
} ECCrefPublicKey;

typedef struct ECCrefPrivateKey_st {
    unsigned int bits;
    unsigned char K[ECCref_MAX_LEN];
} ECCrefPrivateKey;

typedef struct ECCrefKey_st {
    unsigned int bits;
    unsigned int Valid;
    ECCrefPublicKey PubKey;
    ECCrefPrivateKey PrivateKey;
} ECCrefKey;

typedef struct ECCCipher_st {
    unsigned char x[ECCref_MAX_LEN];
    unsigned char y[ECCref_MAX_LEN];
    unsigned char M[M_LENGTH];
    unsigned int L;
    unsigned char C[];
} ECCCipher;

typedef struct ECCSignature_st {
    unsigned char r[ECCref_MAX_LEN];
    unsigned char s[ECCref_MAX_LEN];
} ECCSignature;

typedef struct {
    unsigned int keyIndex;
    unsigned int DerivedKeySize;
    unsigned char SelfID[AGREEMENT_ID_MAX_LEN];
    unsigned int SelfIDLen;
    ECCrefPublicKey SelfPubKey;
    ECCrefPublicKey SelfTempPubKey;
    unsigned int SelfTempEccKeyID;
} AgreementSelfInfo;

typedef struct {
    unsigned char peerID[AGREEMENT_ID_MAX_LEN];
    unsigned int peerIDLen;
    ECCrefPublicKey peerPubKey;
    ECCrefPublicKey peerTempPubKey;
} AgreementPeerInfo;

typedef struct {
    unsigned char IssuerName[ISSUER_NAME_LENGTH];
    unsigned char DeviceName[DEVICE_NAME_LENGTH];
    unsigned char DeviceSerial[DEVICE_SERIAL_LENGTH];
    unsigned int DeviceVersion;
    unsigned int StandardVersion;
    unsigned int AsymAlgAbility[ASYM_ALG_ABILITY_LENGTH];
    unsigned int SymAlgAbility;
    unsigned int HashAlgAbility;
    unsigned int BufferSize;
} DEVICEINFO;

typedef struct {
    unsigned int keyHandleID;
    unsigned int keySize;   // bytes
} SDFKeyHandle;

typedef struct {
    unsigned int uiKeyIndex;
    unsigned char pucPassword[PASSWORD_PBKDF2_LEN];
    unsigned int uiPwdLength;   // bytes
} SDFPrivateKeyAccessInfo;

struct CryptKeyHandle {
    uint32_t keyID;
    uint32_t algType;
    uint32_t keyBitSize;
    uint32_t mode;
    uint32_t keyHandleID;
    uint32_t tagLen;
    uint32_t nonceLen;
    uint8_t x[CRYPT_COORDINATE_LENGTH];
    uint8_t y[CRYPT_COORDINATE_LENGTH];
    uint8_t k[CRYPT_COORDINATE_LENGTH];
    uint8_t cryptKey[CRYPT_KEY_LENGTH];
    uint8_t IV[IV_LENGTH];
    uint8_t tag[TAG_LENGTH];
    uint8_t nonce[NONCE_LENGTH];
};

enum GmKeyAlgorithm {
    SGD_SM4_ECB       = 0x00000401,
    SGD_SM4_CBC       = 0x00000402,
    SGD_SM4_MAC       = 0x00000410,
    SGD_SM4_GCM       = 0x02000400,
    SGD_SM2_1         = 0x00020200,
    SGD_SM2_VERIFY    = 0x00020201,
    SGD_SM2_3         = 0x00020800,
    SGD_SM2_DECRYPT    = 0x00020801,
    SGD_SM3           = 0x00000001,
    SGD_SM3_MAC       = 0x00100001,
    SGD_SM2           = 0x00020100,
};

enum SDFAlgorithm {
    SDF_INVALID  = 0x00000000,
    SDF_SM2_SIGN = 0x00000800,
    SDF_SM2_ENC  = 0x00000000,
    SDF_SM4      = 0x00000003,
};

#define RSAref_MAX_BITS 2048
#define RSAref_MAX_LEN    ((RSAref_MAX_BITS + 7) / 8)
#define RSAref_MAX_PBITS  ((RSAref_MAX_BITS + 1) / 2)
#define RSAref_MAX_PLEN   ((RSAref_MAX_PBITS + 7) / 8)
typedef struct RSArefPublicKey_st {
    unsigned int bits;
    unsigned char m[RSAref_MAX_LEN];
    unsigned char e[RSAref_MAX_LEN];
} RSArefPublicKey;

typedef struct RSArefPrivateKey_st {
    unsigned int bits;
    unsigned char m[RSAref_MAX_LEN];
    unsigned char e[RSAref_MAX_LEN];
    unsigned char d[RSAref_MAX_LEN];
    unsigned char prime[2][RSAref_MAX_PLEN];
    unsigned char pexp[2][RSAref_MAX_PLEN];
    unsigned char coef[RSAref_MAX_PLEN];
}RSArefPrivateKey;

int SDF_OpenDevice(void **phDeviceHandle);

int SDF_CloseDevice(void *hDeviceHandle);

int SDF_OpenSession(void *hDeviceHandle, void **phSessionHandle);

int SDF_CloseSession(void *hSessionHandle);

int SDF_GetDeviceInfo(void *hSessionHandle, DEVICEINFO *pstDeviceInfo);

int SDF_GenerateRandom(void *hSessionHandle, unsigned int uiLength, unsigned char *pucRandom);

int SDF_GetPrivateKeyAccessRight(void *hSessionHandle, unsigned int uiKeyIndex, unsigned char *pucPassword,
    unsigned int uiPwdLength);

int SDF_ReleasePrivateKeyAccessRight(void *hSessionHandle, unsigned int uiKeyIndex);

int SDF_CreateFile(void *hSessionHandle, unsigned char *pucFileName, unsigned int uiNameLen, unsigned int uiFileSize);

int SDF_ReadFile(void *hSessionHandle, unsigned char *pucFileName, unsigned int uiNameLen, unsigned int uiOffset,
    unsigned int *puiFileLength, unsigned char *pucBuffer);

int SDF_WriteFile(void *hSessionHandle, unsigned char *pucFileName, unsigned int uiNameLen, unsigned int uiOffset,
    unsigned int uiFileLength, unsigned char *pucBuffer);

int SDF_DeleteFile(void *hSessionHandle, unsigned char *pucFileName, unsigned int uiNameLen);

int SDF_GenerateAgreementDataWithECC(void *hSessionHandle, unsigned int uiISKIndex, unsigned int uiKeyBits,
                                     unsigned char *pucSponsorID, unsigned int uiSponsorIDLength,
                                     ECCrefPublicKey *pucSponsorPublicKey, ECCrefPublicKey *pucSponsorTmpPublicKey,
                                     void **phAgreementHandle);

int SDF_GenerateKeyWithECC(void *hSessionHandle, unsigned char *pucResponseID, unsigned int uiResponseIDLength,
                           ECCrefPublicKey *pucResponsePublicKey, ECCrefPublicKey *pucResponseTmpPublicKey,
                           void *hAgreementHandle, void **phKeyHandle);

int SDF_GenerateAgreementDataAndKeyWithECC(void *hSessionHandle, unsigned int uiISKIndex, unsigned int uiKeyBits,
                                           unsigned char *pucResponseID, unsigned int uiResponseIDLength,
                                           unsigned char *pucSponsorID, unsigned int uiSponsorIDLength,
                                           ECCrefPublicKey *pucSponsorPublicKey,
                                           ECCrefPublicKey *pucSponsorTmpPublicKey,
                                           ECCrefPublicKey *pucResponsePublicKey,
                                           ECCrefPublicKey *pucResponseTmpPublicKey,
                                           void **phKeyHandle);

int SDF_ExportSignPublicKey_ECC(void *hSessionHandle, unsigned int uiKeyIndex, ECCrefPublicKey *pucPublicKey);

int SDF_ExportEncPublicKey_ECC(void *hSessionHandle, unsigned int uiKeyIndex, ECCrefPublicKey *pucPublicKey);

int SDF_GenerateKeyPair_ECC(void *hSessionHandle, unsigned int uiAlgID, unsigned int uiKeyBits,
    ECCrefPublicKey *pucPublicKey, ECCrefPrivateKey *pucPrivateKey);

int SDF_GenerateKeyWithIPK_ECC(void *hSessionHandle, unsigned int uiIPKIndex, unsigned int uiKeyBits,
    ECCCipher *pucKey, void **phKeyHandle);

int SDF_GenerateKeyWithEPK_ECC(void *hSessionHandle, unsigned int uiKeyBits, unsigned int uiAlgID,
    ECCrefPublicKey *pucPublicKey, ECCCipher *pucKey, void **phKeyHandle);

int SDF_ImportKeyWithISK_ECC(void *hSessionHandle, unsigned int uiISKIndex, ECCCipher *pucKey, void **phKeyHandle);

int SDF_ExchangeDigitEnvelopeBaseOnECC(void *hSessionHandle, unsigned int uiKeyIndex, unsigned int uiAlgID,
    ECCrefPublicKey *pucPublicKey, ECCCipher *pucEncDataIn, ECCCipher *pucEncDataOut);

int SDF_GenerateKeyWithKEK(void *hSessionHandle, unsigned int uiKeyBits, unsigned int uiAlgID, unsigned int uiKEKIndex,
    unsigned char *pucKey, unsigned int *puiKeyLength, void **phKeyHandle);

int SDF_ImportKeyWithKEK(void *hSessionHandle, unsigned int uiAlgID, unsigned int uiKEKIndex,
    unsigned char *pucKey, unsigned int puiKeyLength, void **phKeyHandle);

int SDF_Encrypt(void *hSessionHandle, void *hKeyHandle, unsigned int uiAlgID, unsigned char *pucIV,
    unsigned char *pucData, unsigned int uiDataLength, unsigned char *pucEncData, unsigned int *puiEncDataLength);

int SDF_Decrypt(void *hSessionHandle, void *hKeyHandle, unsigned int uiAlgID, unsigned char *pucIV,
    unsigned char *pucEncData, unsigned int uiEncDataLength, unsigned char *pucData, unsigned int *puiDataLength);

int SDF_CalculateMAC(void *hSessionHandle, void *hKeyHandle, unsigned int uiAlgID, unsigned char *pucIV,
    unsigned char *pucData, unsigned int uiDataLength, unsigned char *pucMAC, unsigned int *puiMACLength);

int SDF_InternalSign_ECC(void *hSessionHandle, unsigned int uiISKIndex, unsigned char *pucData,
    unsigned int uiDataLength, ECCSignature *pucSignature);

int SDF_InternalVerify_ECC(void *hSessionHandle, unsigned int uiISKIndex, unsigned char *pucData,
    unsigned int uiDataLength, ECCSignature *pucSignature);

int SDF_InternalEncrypt_ECC(void *hSessionHandle, unsigned int uiISKIndex, unsigned char *pucData,
    unsigned int uiDataLength, ECCCipher *pucEncData);

int SDF_InternalDecrypt_ECC(void *hSessionHandle, unsigned int uiISKIndex, unsigned int ECCKeyType,
    ECCCipher *pucEncData, unsigned char *pucData, unsigned int *puiDataLength);

int SDF_ExternalSign_ECC(void *hSessionHandle, unsigned int uiAlgID, ECCrefPrivateKey *pucPrivateKey,
    unsigned char *pucData, unsigned int uiDataLength, ECCSignature *pucSignature);

int SDF_ExternalVerify_ECC(void *hSessionHandle, unsigned int uiAlgID, ECCrefPublicKey *pucPublicKey,
    unsigned char *pucDataInput, unsigned int uiInputLength, ECCSignature *pucSignature);

int SDF_HashInit(void *hSessionHandle, unsigned int uiAlgID, ECCrefPublicKey *pucPublicKey,
    unsigned char *pucID, unsigned int uiIDLength);

int SDF_HashUpdate(void *hSessionHandle, unsigned char *pucData, unsigned int uiDataLength);

int SDF_HashFinal(void *hSessionHandle, unsigned char *pucHash, unsigned int *puiHashLength);

int SDF_ExternalDecrypt_ECC(void *hSessionHandle, unsigned int uiAlgID, ECCrefPrivateKey *pucPrivateKey,
    ECCCipher *pucEncData, unsigned char *pucData, unsigned int *puiDataLength);

int SDF_ExternalEncrypt_ECC(void *hSessionHandle, unsigned int uiAlgID, ECCrefPublicKey *pucPublicKey,
    unsigned char *pucData, unsigned int uiDataLength, ECCCipher *pucEncature);

int SDF_ImportKey(void *hSessionHandle, unsigned char *pucKey, unsigned int uiKeyLength, void **phKeyHandle);

int SDF_DestroyKey(void *hSessionHandle, void *hKeyHandle);

int SDF_ExportSignPublicKey_RSA(void *hSessionHandle, unsigned int uiKeyIndex, RSArefPublicKey *pucPublicKey);

int SDF_ExportEncPublicKey_RSA(void *hSessionHandle, unsigned int uiKeyIndex, RSArefPublicKey *pucPublicKey);

int SDF_ExchangeDigitEnvelopeBaseOnRSA(void *hSessionHandle, unsigned int uiKeyIndex, RSArefPublicKey *pucPublicKey,
    unsigned char *pucDEInput, unsigned int uiDELength, unsigned char *pucDEOutput, unsigned int *puiDELength);

int SDF_ExternalPublicKeyOperation_RSA(void *hSessionHandle, RSArefPublicKey *pucPublicKey,
    unsigned char *pucDataInput, unsigned int uiInputLength, unsigned char *pucDataOutput,
    unsigned int *puiOutputLength);

int SDF_GenerateKeyWithIPK_RSA(void *hSessionHandle, unsigned int uiIPKIndex, unsigned int uiKeyBits,
    unsigned char *pucKey, unsigned int *puiKeyLength, void **phKeyHandle);

int SDF_GenerateKeyWithEPK_RSA(void *hSessionHandle, unsigned int uiKeyBits, RSArefPublicKey *pucPublicKey,
    unsigned char *pucKey, unsigned int *puiKeyLenghth, void **phKeyHandle);

int SDF_ImportKeyWithISK_RSA(void *hSessionHandle, unsigned int uiISKIndex, unsigned char *pucKey,
    unsigned int puiKeyLength, void **phKeyHandle);

int SDF_ExternalPrivateKeyOperation_RSA(void *hSessionHandle, RSArefPrivateKey *pucPrivateKey,
    unsigned char *pucDataInput, unsigned int uiInputLength, unsigned char *pucDataOutput,
    unsigned int *puiOutputLength);

int SDF_InternalPublicKeyOperation_RSA(void *hSessionHandle, unsigned int uiKeyIndex, unsigned char *pucDataInput,
    unsigned int uiInputLength, unsigned char *pucDataOutput, unsigned int *puiOutputLength);

int SDF_InternalPrivateKeyOperation_RSA(void *hSessionHandle, unsigned int uiKeyIndex, unsigned char *pucDataInput,
    unsigned int uiInputLength, unsigned char *pucDataOutput, unsigned int *puiOutputLength);

int SDF_GenerateKeyPair_RSA(void *hSessionHandle, unsigned int uiKeyBits, RSArefPublicKey *pucPublicKey,
    RSArefPrivateKey *pucPrivateKey);
    
int ECM_OpenSession(void *hDeviceHandle, void **phSessionHandle);

int ECM_GenerateKey(void *hSessionHandle, unsigned int uiKeyIndex,
    unsigned char *pucPassword, unsigned int uiPwdLength);

int ECM_DeleteKey(void *hSessionHandle, unsigned int uiKeyIndex);

int ECM_QueryKey(void *hSessionHandle, unsigned int uiKeyIndex, unsigned int *uiKeyInfo);

int ECM_ChangePassword(void *hSessionHandle, unsigned int uiKeyIndex,
    unsigned char *prePassword, unsigned int prePasswordLen,
    unsigned char *newPassword, unsigned int newPasswordLen);

int ECM_ExportKey(void *hSessionHandle, unsigned int uiKeyIndex,
    unsigned char *keyFileBuffer, unsigned int *keyBufferLength, unsigned char *keySalt);

int ECM_ImportKey(void *hSessionHandle, unsigned int uiKeyIndex,
    unsigned char *keyFileBuffer, unsigned int keyBufferLength, unsigned char *keySalt);

int ECM_SetAccessRight(void *hSessionHandle, unsigned int uiKeyIndex, unsigned char *pucAccessInfo,
    unsigned char *pucPassword, unsigned int uiPwdLength);

int ECM_DelAccessRight(void *hSessionHandle, unsigned int uiKeyIndex, unsigned char *pucAccessInfo,
    unsigned char *pucPassword, unsigned int uiPwdLength);

int ECM_FactoryReset();
int SDF_AuthEnc(void *hSessionHandle, void *hKeyHandle, unsigned int uiAlgID, unsigned char *pucStartVar,
    unsigned int uiStartVarLength, unsigned char *pucAad, unsigned int uiAadLength, unsigned char *pucData,
    unsigned int uiDataLength, unsigned char *pucEncData, unsigned int *puiEncDataLength,
    unsigned char *pucAuthData, unsigned int *uiAuthDataLength);
int SDF_AuthDec(void *hSessionHandle, void *hKeyHandle, unsigned int uiAlgID, unsigned char *pucStartVar,
    unsigned int uiStartVarLength, unsigned char *pucAad, unsigned int uiAadLength, unsigned char *pucAuthData,
    unsigned int *puiAuthDataLength, unsigned char *pucEncData, unsigned int uiEncDataLength,
    unsigned char *pucData, unsigned int *puiDataLength);
#ifdef __cplusplus
}
#endif
#endif
