/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * iTrustee licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: Yaodongdong
 * Create: 2019-05-29
 * Description: soft engine in boringssl
 */
#ifndef __CRYPTO_WRAPPER_H__
#define __CRYPTO_WRAPPER_H__

#include <type.h>
#include <tee_defines.h>
#include <sre_chinadrm.h>

#define SHA256_LEN  32
#define OEM_KEY_LEN 16

#define ECC_P256_PRIV_LEN            64
#define ECC_P256_PUB_LEN             32
#define RSA_PUB_LEN                  1024
#define RSA_PRIV_LEN                 512
#define ATTEST_TBS_MAXSIZE           512
#define ATTESTATION_KEY_USAGE_OFFSET 16
#define EC_FIX_BUFFER_LEN            66
#define SHA256_HASH_LEN              32
#define ECC_PRIV_LEN                 66
#define ECC_PUB_LEN                  66

/* macro in tomcrypto start */
/* ECC domain id */
#define NIST_P192 0
#define NIST_P224 1
#define NIST_P256 2
#define NIST_P384 3
#define NIST_P521 4

#define SHA1_HASH   1
#define SHA224_HASH 2
#define SHA256_HASH 3
#define SHA384_HASH 4
#define SHA512_HASH 5
/* Algorithm id */
#define RSA_ALG 0
#define ECC_ALG 1
/* macro in tomcrypto end */
#define DIR_ENC 0
#define DIR_DEC 1

#define CRYPTO_NUMBER_TWO      2
#define CRYPTO_NUMBER_THREE    3
#define CRYPTO_NUMBER_FOUR     4
#define CRYPTO_NUMBER_FIVE     5
#define CRYPTO_NUMBER_SIX      6
#define CRYPTO_NUMBER_SEVEN    7
#define CRYPTO_NUMBER_EIGHT    8
#define VALIDITY_TIME_SIZE     13
#define SECRET_KEY_MAX_LEN     64
#define CER_PUBLIC_KEY_MAX_LEN 300
#define VALIDITY_FIX_LEN       32
#define KEY_USAGE_FIX_LEN      41
#define ITEM_THREE_ADD_LEN     12
#define ITEM_THREE_MOVE_LEN    27
#define ITEM_TWO_ADD_LEN       23

/* table struct for match convert */
typedef struct {
    uint32_t src;
    uint32_t dest;
} crypto_u2u;

#define VALIDITY_TIME_SIZE 13
typedef struct {
    uint8_t start[VALIDITY_TIME_SIZE];
    uint8_t end[VALIDITY_TIME_SIZE];
} validity_period_t;

typedef struct {
    uint32_t domain;
    uint8_t x[ECC_PUB_LEN];
    uint32_t x_len;
    uint8_t y[ECC_PUB_LEN];
    uint32_t y_len;
} ecc_pub_key_t;

typedef struct {
    uint32_t domain;
    uint8_t r[ECC_PRIV_LEN];
    uint32_t r_len;
} ecc_priv_key_t;

typedef struct {
    uint8_t e[RSA_PUB_LEN];
    uint32_t e_len;
    uint8_t n[RSA_PUB_LEN];
    uint32_t n_len;
} rsa_pub_key_t;

typedef struct {
    uint8_t e[RSA_PUB_LEN];
    uint32_t e_len;
    uint8_t n[RSA_PUB_LEN];
    uint32_t n_len;
    uint8_t d[RSA_PUB_LEN];
    uint32_t d_len;
    uint8_t p[RSA_PRIV_LEN];
    uint32_t p_len;
    uint8_t q[RSA_PRIV_LEN];
    uint32_t q_len;
    uint8_t dp[RSA_PRIV_LEN];
    uint32_t dp_len;
    uint8_t dq[RSA_PRIV_LEN];
    uint32_t dq_len;
    uint8_t qinv[RSA_PRIV_LEN];
    uint32_t qinv_len;
} rsa_priv_key_t;

typedef struct {
    unsigned char *ou;
    unsigned char *o;
    unsigned char *c;
    unsigned char *cn;
} dn_name_t;

struct ec_pub_info {
    uint8_t *x;
    uint32_t x_len;
    uint8_t *y;
    uint32_t y_len;
};

struct ec_priv_info {
    uint32_t nid;
    uint8_t *r;
    uint32_t r_len;
};

/*
 * Convert the ecc public key passed in by the user into the ecc_pub_key_t structure.
 *
 * @param pub   [OUT] The ecc public key structure
 * @param in    [IN]  The ecc public key buffer
 * @param inlen [IN]  The length of ecc public key buffer
 *
 * @return  1: Import ecc public key success
 * @return -1: Import ecc public key failed
 */
int32_t ecc_import_pub(ecc_pub_key_t *pub, const uint8_t *in, uint32_t inlen);

/*
 * Convert the ecc_pub_key_t structure passed in by the user into ecc public key buffer.
 *
 * @param out    [OUT]    The ecc public key buffer
 * @param outlen [IN/OUT] The length of ecc public key buffer
 * @param pub    [IN]     The ecc public key structure
 *
 * @return -1: Export ecc public key failed
 * @return  others: The real size of out buffer
 */
int32_t ecc_export_pub(uint8_t *out, uint32_t out_size, ecc_pub_key_t *pub);

/*
 * Read next TLV (Type-Length-Value) from ASN1 buffer.
 *
 * @param type        [OUT] Type of TLV
 * @param header_len  [OUT] Length of TLV
 * @param buf         [IN]  Input TLV
 * @param buf_len     [IN]  Length of buf in bytes
 *
 * @return -1: Get next TLV failed
 * @return  others: Length of next TLV
 */
int32_t get_next_tlv(uint32_t *type, uint32_t *header_len, const uint8_t *buf, uint32_t buf_len);

/*
 * Convert the ecc private key passed in by the user into the ecc_priv_key_t structure.
 *
 * @param priv  [OUT] The ecc private key structure
 * @param in    [IN]  The ecc private key buffer
 * @param inlen [IN]  The length of ecc private key buffer
 *
 * @return -1: Import ecc private key failed
 * @return  others: The width of  ecc private key
 */
int32_t ecc_import_priv(ecc_priv_key_t *priv, const uint8_t *in, uint32_t inlen);

/*
 * Use ECC algorithm to sign user data.
 *
 * @param signature  [OUT]    The signature of input data
 * @param sig_siz    [IN/OUT] The length of signature
 * @param in         [IN]     The data to be sign
 * @param in_len     [IN]     The length of input data
 * @param priv       [IN]     The ecc private key structure
 *
 * @return -1: Sign input buffer use ecc failed
 * @return  others: The length of signature
 */
int32_t ecc_sign_digest(uint8_t *signature, uint32_t sig_size, uint8_t *in, uint32_t in_len, ecc_priv_key_t *priv);

/*
 * Verify the data with ECC algorithm.
 *
 * @param signature  [IN]  The signature of input data
 * @param sig_len    [IN]  The length of signature
 * @param in         [IN]  The input data
 * @param in_len     [IN]  The length of input data
 * @param pub        [IN]  The ecc public key structure
 *
 * @return  1: Verify digest success
 * @return -1: Verify digest failed
 */
int32_t ecc_verify_digest(const uint8_t *signature, uint32_t sig_len, uint8_t *in, uint32_t in_len, ecc_pub_key_t *pub);

/*
 * Generate rsa key pair.
 * @param priv      [OUT] The rsa private key structure
 * @param pub       [OUT] The rsa public key structure
 * @param e         [IN]  The exponent of rsa key
 * @param key_size  [IN]  The size of rsa key
 *
 * @return  0: Generate rsa keypair success
 * @return -1: Generate rsa keypair failed
 */
int32_t rsa_generate_keypair(rsa_priv_key_t *priv, rsa_pub_key_t *pub, uint32_t e, uint32_t key_size);

/*
 * Do rsa encryption.
 *
 * @param dest_data [OUT]    The dest data buffer
 * @param dest_len  [IN/OUT] The length of dest data
 * @param src_data  [IN]     The src data buffer
 * @param src_len   [IN]     The length of src data
 * @param pub       [IN]     The rsa public key structure
 * @param padding   [IN]     The padding type of encryption
 * @param hash_nid  [IN]     The hash_nid of encryption
 *
 * @return  0: Do rsa encryption success
 * @return -1: Do rsa encryption failed
 */
int32_t rsa_encrypt(uint8_t *dest_data, uint32_t *dest_len, uint8_t *src_data, uint32_t src_len, rsa_pub_key_t *pub,
                    int32_t padding, int32_t hash_nid);

/*
 * Do rsa decryption.
 *
 * @param dest_data [OUT]    The dest data buffer
 * @param dest_len  [IN/OUT] The length of dest data
 * @param src_data  [IN]     The src data buffer
 * @param src_len   [IN]     The length of src data
 * @param priv      [IN]     THE rsa private key structure
 * @param padding   [IN]     The padding type of encryption
 * @param hash_nid  [IN]     The hash_nid of encryption
 *
 * @return  0: Do rsa decryption success
 * @return -1: Do rsa decryption failed
 */
int32_t rsa_decrypt(uint8_t *dest_data, uint32_t *dest_len, uint8_t *src_data, uint32_t src_len, rsa_priv_key_t *priv,
                    uint32_t padding, int32_t hash_nid);

/*
 * Do rsa Sign digest.
 *
 * @param signature  [OUT]    The signature of input data
 * @param sig_size   [IN/OUT] The length of signature
 * @param in         [IN]     The input data
 * @param in_len     [IN]     The length of input data
 * @param priv       [IN]     The rsa  private key structure
 * @param salt_len   [IN]     The length of salt
 * @param hash_nid   [IN]     The hash_nid of encryption
 * @param padding    [IN]     The padding type of encryption
 *
 * @return  0: Do rsa sign digest success
 * @return -1: Do rsa Sign digest failed
 */
int32_t rsa_sign_digest(uint8_t *signature, uint32_t *sig_size, uint8_t *in, uint32_t in_len, rsa_priv_key_t *priv,
                        uint32_t salt_len, int32_t hash_nid, int32_t padding);

/*
 * Do rsa Verify digest.
 *
 * @param signature  [IN]  The signature of input data
 * @param sig_size   [IN]  The length of signature
 * @param in         [IN]  The input data
 * @param in_len     [IN]  The length of input data
 * @param pub        [IN]  The rsa public key structure
 * @param salt_len   [IN]  The length of salt
 * @param hash_nid   [IN]  The hash_nid of encryption
 * @param padding    [IN]  The padding type of encryption
 *
 * @return  0: Do rsa verify success
 * @return -1: Do rsa verify failed
 */
int32_t rsa_verify_digest(uint8_t *signature, uint32_t sig_size, uint8_t *in, uint32_t in_len, const rsa_pub_key_t *pub,
                          uint32_t salt_len, int32_t hash_nid, int32_t padding);

/*
 * Convert the rsa private key passed in by the user into the rsa_priv_key_t structure.
 *
 * @param priv  [OUT] The rsa private key structure
 * @param in    [IN]  The rsa private key buffer
 * @param inlen [IN]  The length of rsa private key buffer
 *
 * @return -1: Import rsa private key failed
 * @return  0: Import rsa private key success
 */
int rsa_import_priv(rsa_priv_key_t *priv, const uint8_t *in, uint32_t in_len);

/*
 * Check the certificate revocation list.
 *
 * @param cert            [IN] The crl buffer
 * @param cert_len        [IN] The length of crl buffer
 * @param parent_key      [IN] The public key to verify the crl
 * @param parent_key_len  [IN] The length of public key
 *
 * @return  1: Check the crl success
 * @return  others: Check the crl failed
 */
int x509_crl_validate(uint8_t *cert, uint32_t cert_len, uint8_t *parent_key, uint32_t parent_key_len);

/*
 * Check the x509 certificate.
 *
 * @param cert            [IN] The certificate buffer
 * @param cert_len        [IN] The length of certificate buffer
 * @param parent_key      [IN] The public key to verify the crl
 * @param parent_key_len  [IN] The length of public key
 *
 * @return  1: Check the cert success
 * @return  others: Check the cert failed
 */
int x509_cert_validate(uint8_t *cert, uint32_t cert_len, uint8_t *parent_key, uint32_t parent_key_len);

/*
 * Get public key from certificate.
 *
 * @param pub      [OUT] The public key struct
 * @param in       [IN]  The certificate buffer
 * @param inlen    [IN]  The length of certificate buffer
 *
 * @return  0: Get public key success
 * @return -1: Get public key failed
 */
int import_pub_from_sp(void *pub, const uint8_t *in, uint32_t inlen);

/*
 * Get public key from certificate.
 *
 * @param pub      [OUT] The public key buffer
 * @param cert     [IN]  The certificate buffer
 * @param cert_len [IN]  The length of certificate buffer
 *
 * @return -1: Get public key failed
 * @return  others: The length of public key buffer
 */
int get_subject_public_key(uint8_t *pub, const uint8_t *cert, uint32_t cert_len);

/*
 * Get public key from certificate.
 *
 * @param pub      [OUT]    The public key buffer
 * @param pub_size [IN/OUT] The length of public key buffer
 * @param cert     [IN]     The certificate buffer
 * @param cert_len [IN]     The length of certificate buffer
 *
 * @return -1: Get public key failed
 * @return  others: The length of public key buffer
 */
int get_subject_public_key_new(uint8_t *pub, uint32_t pub_size, const uint8_t *cert, uint32_t cert_len);

/*
 * Get valid date from certificate.
 *
 * @param vd       [OUT] The valid data structure
 * @param cert     [IN]  The certificate buffer
 * @param cert_len [IN]  The length of certificate buffer
 *
 * @return  0: Get valid date success
 * @return -1: Get valid data failed
 */
int get_validity_from_cert(validity_period_t *vd, uint8_t *cert, uint32_t cert_len);

/*
 * Get common name from certificate.
 *
 * @param name      [OUT]    The common name buffer
 * @param name_size [IN/OUT] The length of common name buffer
 * @param cert      [IN]     The certificate buffer
 * @param cert_len  [IN]     The length of certificate buffer
 *
 * @return -1: Get common name failed
 * @return  others: Get common name success
 */
int get_subject_CN(uint8_t *name, uint32_t name_size, const uint8_t *cert, uint32_t cert_len);

/*
 * Get organization name from certificate.
 *
 * @param name      [OUT]    The organization name buffer
 * @param name_size [IN/OUT] The length of organization name buffer
 * @param cert      [IN]     The certificate buffer
 * @param cert_len  [IN]     The length of certificate buffer
 *
 * @return -1: Get organization name failed
 * @return  others: Get organization name success
 */
int get_subject_OU(uint8_t *name, uint32_t name_size, const uint8_t *cert, uint32_t cert_len);

/*
 * Get serial number from certificate.
 *
 * @param serial_number      [OUT]    The serial number buffer
 * @param serial_number_size [IN/OUT] The length of serial number buffer
 * @param cert               [IN]     The certificate buffer
 * @param cert_len           [IN]     The length of certificate buffer
 *
 * @return -1: Get serial number failed
 * @return  others: Get serial number success
 */
int get_serial_number_from_cert(uint8_t *serial_number, uint32_t serial_number_size, uint8_t *cert, uint32_t cert_len);

/*
 * Get issuer from certificate.
 *
 * @param issuer      [OUT]    The issuer buffer
 * @param issuer_size [IN/OUT] The length of issuer buffer
 * @param cert        [IN]     The certificate buffer
 * @param cert_len    [IN]     The length of certificate buffer
 *
 * @return -1: Get serial number failed
 * @return  others: Get serial number success
 */
int get_issuer_from_cert(uint8_t *issuer, uint32_t issuer_size, uint8_t *crl, uint32_t crl_len);

/*
 * Get element number from certificate.
 *
 * @param elem     [OUT] The element with elem_id
 * @param elem_id  [IN]  The index of element
 * @param cert     [IN]  The certificate buffer
 * @param cert_len [IN]  The length of certificate buffer
 *
 * @return -1: Get element failed
 * @return  others: The length of element
 */
int32_t get_tbs_element(uint8_t **elem, uint32_t elem_id, const uint8_t *cert, uint32_t cert_len);

/*
 * Recover the root certificate.
 *
 * @param cert     [OUT]    The certificate buffer
 * @param cert_len [IN/OUT] The length of certificate buffer
 * @param priv     [IN]     The private key structure
 * @param keytype  [IN]     The keytype of private key
 *
 * @return -1: Recover root certificate failed
 * @return others: Recover root certificate success
 */
int32_t recover_root_cert(uint8_t *cert, uint32_t cert_len, const void *priv, uint32_t keytype);

/*
 * Convert the rsa_pub_key_t structure passed in by the user into rsa public key buffer.
 *
 * @param out    [OUT] The rsa public key buffer
 * @param outlen [IN]  The length of rsa public key buffer
 * @param pub    [IN]  The rsa public key structure
 *
 * @return -1: Export rsa public key failed
 * @return  others: The real size of out buffer
 */
int32_t rsa_export_pub_sp(uint8_t *out, uint32_t out_size, rsa_pub_key_t *pub);

/*
 * Sign the pkcs10 certificate.
 *
 * @param cert          [OUT]    The certificate buffer
 * @param cert_len      [IN]     The length of certificate buffer
 * @param csr           [IN]     The certificate signing request buffer
 * @param csr_len       [IN]     The length of certificate signing request buffer
 * @param valid         [IN]     The valid date buffer
 * @param serial_number [IN]     The serial number buffer
 * @param serial_length [IN]     The length of serial number buffer
 * @param priv          [IN]     The private key structure
 * @param keytype       [IN]     The keytype of private key
 *
 * @return -1: Sign the pkcs10 certificate failed
 * @return others: The real size of certificate
 */
int32_t sign_pkcs10(uint8_t *cert, uint32_t cert_len,
                    const uint8_t *csr, uint32_t csr_len, const validity_period_t *valid,
                    const uint8_t *serial_number, uint32_t serial_length, const void *priv, uint32_t keytype);

/*
 * Create attestation certificate with input params.
 *
 * @param cert                   [OUT] The certificate buffer
 * @param cert_len               [IN]  The length of certificate buffer
 * @param valid                  [IN]  The valid date buffer
 * @param issuer_tlv             [IN]  The issuer buffer
 * @param issuer_tlv_len         [IN]  The length of issuer buffer
 * @param subject_public_key     [IN]  The subject public key buffer
 * @param subject_public_key_len [IN]  The length of subject public key buffer
 * @param attestation_ext        [IN]  The attestation extrol infor buffer
 * @param attestation_ext_len    [IN]  The length of attestation extrol infor buffer
 * @param priv_sign              [IN]  The private key buffer
 * @param key_usage_sign_bit     [IN]  The usage sign falg
 * @param key_usage_encrypt_bit  [IN]  The usage encrypt flag
 * @param keytype                [IN]  The keytype of private key
 * @param hash                   [IN]  The hash func of digest
 *
 * @return -1: Create attestation certificate failed
 * @return others: The real size of certificate
 */
int32_t create_attestation_cert(uint8_t *cert, uint32_t cert_len, const validity_period_t *valid,
                                const uint8_t *issuer_tlv, uint32_t issuer_tlv_len,
                                const uint8_t *subject_public_key, uint32_t subject_public_key_len,
                                const uint8_t *attestation_ext, uint32_t attestation_ext_len, void *priv_sign,
                                uint32_t key_usage_sign_bit, uint32_t key_usage_encrypt_bit, uint32_t key_type,
                                uint32_t hash);

/*
 * Get oem huk.
 *
 * @param huk      [OUT] The oem huk buffer
 * @param key      [IN]  The hmac key buffer
 * @param key_size [IN]  The length of hmac key buffer
 *
 * @return  0: Get oem huk success
 * @return -1: Get oem huk failed
 */
int get_class_oem_huk(uint8_t *huk, const uint8_t *key, uint32_t key_size);

/*
 * Derive ecc public key from private key.
 *
 * @param priv_info  [IN]  The ecc_priv_key_t structure
 * @param pub_info   [OUT] The ecc_pub_key_t structure
 *
 * @return  0: Derive ecc public key success
 * @return -1: Derive ecc public key failed
 */
int ecc_derive_public_key(ecc_priv_key_t *priv_info, ecc_pub_key_t *pub_info);

/*
 * Derive ecc private key from huk.
 *
 * @param priv     [OUT] The ecc_priv_key_t structure
 * @param secret   [IN]  The huk buffer
 * @param sec_len  [IN]  The length of huk buffer
 *
 * @return  0: Derive ecc private key success
 * @return -1: Derive ecc private key failed
 */
int derive_ecc_private_key_from_huk(ecc_priv_key_t *priv, const uint8_t *secret, uint32_t sec_len);

/*
 * Do aes key wrap operation.
 * @param params [IN/OUT] The cdrm_params structure contains key/iv/input/output info
 *
 * @return  TEE_SUCCESS: Do aes key wrap operation success
 * @return       others: Do aes key wrap operation failed
 */
TEE_Result aes_key_wrap(struct cdrm_params *params);

/*
 * Do aes key unwrap operation.
 *
 * @param params [IN/OUT] The cdrm_params structure contains key/iv/input/output info
 *
 * @return  TEE_SUCCESS: Do aes key unwrap operation success
 * @return       others: Do aes key unwrap operation failed
 */
TEE_Result aes_key_unwrap(struct cdrm_params *params);

#endif
