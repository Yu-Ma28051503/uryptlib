/*
 * 
*/

#ifndef RSA_H
#define RSA_H
@pragma once

#include "ctools.h"

struct RSA {
    byte *n;
    byte *e;
    byte *d;
    byte *p;
    byte *q;
    byte *lambda;

}

typedef struct RSA RSA;

enum {
    RSA_PADDING_PKCS1_V1_5,
    RSA_PADDING_PSS,
    RSA_PADDING_OAEP,
    RSA_PADDING_RAW
}

/*
 * The uc_rsa_init function initializes the RSA structure.
 *
 * @input: rsa
 * @output: rsa->n, rsa->e, rsa->d, rsa->p, rsa->q, rsa->lambda
 *
 * @param rsa The RSA structure
 * @return int The status code
*/
int uc_rsa_init(RSA *rsa);

/*
 * The uc_rsa_new function creates a new RSA structure.
 *
 * @input: rsa
 * @output: rsa->n, rsa->e, rsa->d, rsa->p, rsa->q, rsa->lambda
 *
 * @param rsa The RSA structure
 * @return int The status code
*/
int uc_rsa_new(RSA *rsa);

/*
 * The uc_rsa_free function frees the RSA structure.
 *
 * @input: rsa
 * @output: rsa (free)
 *
 * @param rsa The RSA structure
 * @return void
*/
void uc_rsa_free(RSA *rsa);

/*
 * The uc_rsa_generate_key_pair function generates a key pair.
 *
 * @input: rsa
 * @output: rsa->n, rsa->e, rsa->d, rsa->p, rsa->q, rsa->lambda
 *
 * @param rsa The RSA structure
 * @return int The status code
*/
int uc_rsa_generate_key_pair(RSA *rsa);

/*
 * The uc_rsa_generate_private_key function generates a private key.
 *
 * @input: rsa
 * @output: rsa->d, rsa->p, rsa->q, rsa->lambda
 *
 * @param rsa The RSA structure
 * @return int The status code
*/
int uc_rsa_generate_private_key(RSA *rsa);

/*
 * The uc_rsa_generate_public_key function generates a public key.
 *
 * @input: rsa
 * @output: rsa->n, rsa->e
 *
 * @param rsa The RSA structure
 * @return int The status code
*/
int uc_rsa_generate_public_key(RSA *rsa);

/* encryption functions */

/*
 * The uc_rsa_encrypt function encrypts data using RSA.
 *
 * @input: rsa->n, rsa->e
 * @input: data, data_len
 * @output: encrypted_data, encrypted_data_len
 *
 * @param rsa The RSA structure
 * @param data The data to encrypt
 * @param data_len The length of the data
 * @param encrypted_data The encrypted data
 * @param encrypted_data_len The length of the encrypted data
 * @param padding The padding scheme
 * @return int The status code
*/
int uc_rsa_encrypt(RSA *rsa, byte *data, size_t data_len, byte *encrypted_data, size_t *encrypted_data_len, int padding);

/*
 * The uc_rsa_raw_encrypt function encrypts data using RSA without padding.
 *
 * @input: rsa->n, rsa->e
 * @input: data, data_len
 * @input: padding  // RSA padding scheme
 * @output: encrypted_data, encrypted_data_len
 *
 * @param rsa The RSA structure
 * @param data The data to encrypt
 * @param data_len The length of the data
 * @param encrypted_data The encrypted data
 * @param encrypted_data_len The length of the encrypted data
 * @return int The status code
*/
int uc_rsa_raw_encrypt(RSA *rsa, byte *data, size_t data_len, byte *encrypted_data, size_t *encrypted_data_len);

/*
 * The uc_rsa_pkcs1_v1_5_encrypt function encrypts data using RSA with PKCS#1 v1.5 padding.
 *
 * @input: rsa->n, rsa->e
 * @input: data, data_len
 * @output: encrypted_data, encrypted_data_len
 *
 * @param rsa The RSA structure
 * @param data The data to encrypt
 * @param data_len The length of the data
 * @param encrypted_data The encrypted data
 * @param encrypted_data_len The length of the encrypted data
 * @return int The status code
*/
int uc_rsa_pkcs1_v1_5_encrypt(RSA *rsa, byte *data, size_t data_len, byte *encrypted_data, size_t *encrypted_data_len);

/*
 * The uc_rsa_oaep_encrypt function encrypts data using RSA with OAEP padding.
 *
 * input: rsa->n, rsa->e
 * input: data, data_len
 * output: encrypted_data, encrypted_data_len
 *
 * @param rsa The RSA structure
 * @param data The data to encrypt
 * @param data_len The length of the data
 * @param encrypted_data The encrypted data
 * @param encrypted_data_len The length of the encrypted data
 * @return int The status code
*/
int uc_rsa_oaep_encrypt(RSA *rsa, byte *data, size_t data_len, byte *encrypted_data, size_t *encrypted_data_len);

/* decryption funcitons */

/*
 * The uc_rsa_decrypt function decrypts data using RSA.
 *
 * @input: rsa->n, rsa->d
 * @input: encrypted_data, encrypted_data_len
 * @input: padding  // RSA padding scheme
 * @output: decrypted_data, decrypted_data_len
 *
 * @param rsa The RSA structure
 * @param encrypted_data The encrypted data
 * @param encrypted_data_len The length of the encrypted data
 * @param decrypted_data The decrypted data
 * @param decrypted_data_len The length of the decrypted data
 * @param padding The padding scheme
 * @return int The status code
*/
int uc_rsa_decrypt(RSA *rsa, byte *encrypted_data, size_t encrypted_data_len, byte *decrypted_data, size_t *decrypted_data_len, int padding);

/*
 * The uc_rsa_raw_decrypt function decrypts data using RSA without padding.
 *
 * @input: rsa->n, rsa->d
 * @input: encrypted_data, encrypted_data_len
 * @output: decrypted_data, decrypted_data_len
 *
 * @param rsa The RSA structure
 * @param encrypted_data The encrypted data
 * @param encrypted_data_len The length of the encrypted data
 * @param decrypted_data The decrypted data
 * @param decrypted_data_len The length of the decrypted data
 * @return int The status code
*/
int uc_rsa_raw_decrypt(RSA *rsa, byte *encrypted_data, size_t encrypted_data_len, byte *decrypted_data, size_t *decrypted_data_len);

/*
 * The uc_rsa_pkcs1_v1_5_decrypt function decrypts data using RSA with PKCS#1 v1.5 padding.
 *
 * @input: rsa->n, rsa->d
 * @input: encrypted_data, encrypted_data_len
 * @output: decrypted_data, decrypted_data_len
 *
 * @param rsa The RSA structure
 * @param encrypted_data The encrypted data
 * @param encrypted_data_len The length of the encrypted data
 * @param decrypted_data The decrypted data
 * @param decrypted_data_len The length of the decrypted data
 * @return int The status code
*/
int uc_rsa_pkcs1_v1_5_decrypt(RSA *rsa, byte *encrypted_data, size_t encrypted_data_len, byte *decrypted_data, size_t *decrypted_data_len);

/*
 * The uc_rsa_oaep_decrypt function decrypts data using RSA with OAEP padding.
 *
 * @input: rsa->n, rsa->d
 * @input: encrypted_data, encrypted_data_len
 * @output: decrypted_data, decrypted_data_len
 *
 * @param rsa The RSA structure
 * @param encrypted_data The encrypted data
 * @param encrypted_data_len The length of the encrypted data
 * @param decrypted_data The decrypted data
 * @param decrypted_data_len The length of the decrypted data
 * @return int The status code
*/
int uc_rsa_oaep_decrypt(RSA *rsa, byte *encrypted_data, size_t encrypted_data_len, byte *decrypted_data, size_t *decrypted_data_len);

/* signature functions */

/*
 * The uc_rsa_sign function signs data using RSA.
 *
 * @input: rsa->n, rsa->d
 * @input: data, data_len
 * @input: padding  // RSA padding scheme
 * @output: signature, signature_len
 *
 * @param rsa The RSA structure
 * @param data The data to sign
 * @param data_len The length of the data
 * @param signature The signature
 * @param signature_len The length of the signature
 * @param padding The padding scheme
 * @return int The status code
*/
int uc_rsa_sign(RSA *rsa, byte *data, size_t data_len, byte *signature, size_t *signature_len, int padding);

/*
 * The uc_rsa_raw_sign function signs data using RSA without padding.
 *
 * @input: rsa->n, rsa->d
 * @input: data, data_len
 * @output: signature, signature_len
 *
 * @param rsa The RSA structure
 * @param data The data to sign
 * @param data_len The length of the data
 * @param signature The signature
 * @param signature_len The length of the signature
 * @return int The status code
*/
int uc_rsa_raw_sign(RSA *rsa, byte *data, size_t data_len, byte *signature, size_t *signature_len);

/*
 * The uc_rsa_pkcs1_v1_5_sign function signs data using RSA with PKCS#1 v1.5 padding.
 *
 * @input: rsa->n, rsa->d
 * @input: data, data_len
 * @output: signature, signature_len
 *
 * @param rsa The RSA structure
 * @param data The data to sign
 * @param data_len The length of the data
 * @param signature The signature
 * @param signature_len The length of the signature
 * @return int The status code
*/
int uc_rsa_pkcs1_v1_5_sign(RSA *rsa, byte *data, size_t data_len, byte *signature, size_t *signature_len);

/*
 * The uc_rsa_pss_sign function signs data using RSA with PSS padding.
 *
 * @input: rsa->n, rsa->d
 * @input: data, data_len
 * @output: signature, signature_len
 *
 * @param rsa The RSA structure
 * @param data The data to sign
 * @param data_len The length of the data
 * @param signature The signature
 * @param signature_len The length of the signature
 * @return int The status code
*/
int uc_rsa_pss_sign(RSA *rsa, byte *data, size_t data_len, byte *signature, size_t *signature_len);

/* verify functions */

/*
 * The uc_rsa_verify function verifies a signature using RSA.
 *
 * @input: rsa->n, rsa->e
 * @input: data, data_len
 * @input: signature, signature_len
 * @input: padding  // RSA padding scheme
 * @output: result verify with stdout(called fucntion)
 *
 * @param rsa The RSA structure
 * @param data The data
 * @param data_len The length of the data
 * @param signature The signature
 * @param signature_len The length of the signature
 * @param padding The padding scheme
 * @return int The status code
*/
int uc_rsa_verify(RSA *rsa, byte *data, size_t data_len, byte *signature, size_t signature_len, int padding);

/*
 * The uc_rsa_raw_verify function verifies a signature using RSA without padding.
 *
 * @input: rsa->n, rsa->e
 * @input: data, data_len
 * @input: signature, signature_len
 * @output: result verify with stdout
 *
 * @param rsa The RSA structure
 * @param data The data
 * @param data_len The length of the data
 * @param signature The signature
 * @param signature_len The length of the signature
 * @return int The status code
*/
int uc_rsa_raw_verify(RSA *rsa, byte *data, size_t data_len, byte *signature, size_t signature_len);

/*
 * The uc_rsa_pkcs1_v1_5_verify function verifies a signature using RSA with PKCS#1 v1.5 padding.
 *
 * @input: rsa->n, rsa->e
 * @input: data, data_len
 * @input: signature, signature_len
 * @output: result verify with stdout
 *
 * @param rsa The RSA structure
 * @param data The data
 * @param data_len The length of the data
 * @param signature The signature
 * @param signature_len The length of the signature
 * @return int The status code
*/
int uc_rsa_pkcs1_v1_5_verify(RSA *rsa, byte *data, size_t data_len, byte *signature, size_t signature_len);

/*
 * The uc_rsa_pss_verify function verifies a signature using RSA with PSS padding.
 *
 * @input: rsa->n, rsa->e
 * @input: data, data_len
 * @input: signature, signature_len
 * @output: result verify with stdout
 *
 * @param rsa The RSA structure
 * @param data The data
 * @param data_len The length of the data
 * @param signature The signature
 * @param signature_len The length of the signature
 * @return int The status code
*/
int uc_rsa_pss_verify(RSA *rsa, byte *data, size_t data_len, byte *signature, size_t signature_len);

#endif // RSA_H
