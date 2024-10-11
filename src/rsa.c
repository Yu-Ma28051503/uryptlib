/*
 *
*/

#include "rsa.h"

/*
 * The uc_rsa_init function initializes the RSA structure.
 *
 * @input: rsa
 * @output: rsa->n, rsa->e, rsa->d, rsa->p, rsa->q, rsa->lambda
 *
 * @param rsa The RSA structure
 * @return int The status code
*/
int uc_rsa_init(RSA *rsa)
{
    ret = UC_SUCCESS;

    if (rsa == NULL) {
        ret = uc_rsa_new(rsa);
        if (ret != UC_SUCCESS) {
            uc_eprint("Failed to initialize RSA\n");
            return ret;
        }
    }

    return ret;
}

/*
 * The uc_rsa_new function creates a new RSA structure.
 *
 * @input: rsa
 * @output: rsa->n, rsa->e, rsa->d, rsa->p, rsa->q, rsa->lambda
 *
 * @param rsa The RSA structure
 * @return int The status code
*/
int uc_rsa_new(RSA *rsa)
{
    ret = UC_SUCCESS;

    if (rsa == NULL) {
        rsa = (RSA *)malloc(sizeof(RSA));
        if (rsa == NULL) {
            uc_eprint("Failed to allocate memory for RSA\n");
            ret = UC_FAILURE;
        }
    }

    if (rsa != NULL && ret == UC_SUCCESS) {
        rsa->n = NULL;
        rsa->e = NULL;
        rsa->d = NULL;
        rsa->p = NULL;
        rsa->q = NULL;
        rsa->lambda = NULL;
    }
    

    return ret;
}

/*
 * The uc_rsa_free function frees the RSA structure.
 *
 * @input: rsa
 * @output: rsa (free)
 *
 * @param rsa The RSA structure
 * @return void
*/
void rsa_free(RSA *rsa)
{
    if (rsa != NULL) {
        free(rsa);
    }
}

/*
 * The uc_rsa_generate_key_pair function generates a key pair.
 *
 * @input: rsa
 * @output: rsa->n, rsa->e, rsa->d, rsa->p, rsa->q, rsa->lambda
 *
 * @param rsa The RSA structure
 * @return int The status code
*/
int uc_rsa_generate_key_pair(RSA *rsa)
{
    ret = UC_SUCCESS;

    ret = uc_rsa_generate_private_key(rsa);
    if (ret != UC_SUCCESS) {

        return ret;
    }

    return ret;
}

/*
 * The uc_rsa_generate_private_key function generates a private key.
 *
 * @input: rsa
 * @output: rsa->d, rsa->p, rsa->q, rsa->lambda
 *
 * @param rsa The RSA structure
 * @return int The status code
*/
int uc_rsa_generate_private_key(RSA *rsa)
{
    ret = UC_SUCCESS;

    return ret;
}

/*
 * The uc_rsa_generate_public_key function generates a public key.
 *
 * @input: rsa
 * @output: rsa->n, rsa->e
 *
 * @param rsa The RSA structure
 * @return int The status code
*/
int uc_rsa_generate_public_key(RSA *rsa)
{
    ret = UC_SUCCESS;

    return ret;
}

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
int uc_rsa_encrypt(RSA *rsa, byte *data, size_t data_len, byte *encrypted_data, size_t *encrypted_data_len, int padding)
{
    ret = UC_SUCCESS;

    /* Check function arguments */
    if (rsa == NULL || data == NULL || data_len == 0 || encrypted_data != NULL || encrypted_data_len == NULL) {
        uc_eprint("BAD FUNCTION ARGUMENTS\n");
        ret = UC_FAILURE;
    }

    /* Check RSA seted values n and e */
    if (ret == UC_SUCCESS) {
        if (rsa->n == NULL || rsa->e == NULL) {
            uc_eprint("RSA public key is not set\n");
            ret = UC_FAILURE;
        }
    }

    switch (padding) {
    case RSA_PADDING_RAW:
        ret = uc_rsa_raw_encrypt(rsa, data, data_len, encrypted_data, encrypted_data_len);
        break;
    case RSA_PADDING_PKCS1_V1_5:
        ret = uc_rsa_pkcs1_v1_5_encrypt(rsa, data, data_len, encrypted_data, encrypted_data_len);
        break;
    case RSA_PADDING_OAEP:
        ret = uc_rsa_oaep_encrypt(rsa, data, data_len, encrypted_data, encrypted_data_len);
        break;
    default:
        uc_eprint("Invalid padding\n");
        ret = UC_FAILURE;
        break;
    }

    return ret;
}

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
int uc_rsa_raw_encrypt(RSA *rsa, byte *data, size_t data_len, byte *encrypted_data, size_t *encrypted_data_len)
{
    ret = UC_SUCCESS;

    

    /* Allocate encrypted data */
    if (ret == UC_SUCCESS) {
        encrypted_data = (byte *)malloc(data_len);
        if (encrypted_data == NULL) {
            uc_eprint("Failed to allocate memory for encrypted data\n");
            ret = UC_FAILURE;
        }
    }

    /* Encrypt data */
    if (ret == UC_SUCCESS) {
    }

    return ret;
}

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
int uc_rsa_pkcs1_v1_5_encrypt(RSA *rsa, byte *data, size_t data_len, byte *encrypted_data, size_t *encrypted_data_len)
{
    ret = UC_SUCCESS;

    /* Allocate encrypted data */
    if (ret == UC_SUCCESS) {
        encrypted_data = (byte *)malloc(data_len);
        if (encrypted_data == NULL) {
            uc_eprint("Failed to allocate memory for encrypted data\n");
            ret = UC_FAILURE;
        }
    }

    /* Encrypt data */
    if (ret == UC_SUCCESS) {
    }

    return ret;
}

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
int uc_rsa_oaep_encrypt(RSA *rsa, byte *data, size_t data_len, byte *encrypted_data, size_t *encrypted_data_len)
{
    ret = UC_SUCCESS;

    /* Allocate encrypted data */
    if (ret == UC_SUCCESS) {
        encrypted_data = (byte *)malloc(data_len);
        if (encrypted_data == NULL) {
            uc_eprint("Failed to allocate memory for encrypted data\n");
            ret = UC_FAILURE;
        }
    }

    /* Encrypt data */
    if (ret == UC_SUCCESS) {
    }

    return ret;
}

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
int uc_rsa_decrypt(RSA *rsa, byte *encrypted_data, size_t encrypted_data_len, byte *decrypted_data, size_t *decrypted_data_len, int padding)
{
    ret = UC_SUCCESS;

    /* Check function arguments */
    if (rsa == NULL || encrypted_data == NULL || encrypted_data_len == 0 || decrypted_data != NULL || decrypted_data_len == NULL) {
        uc_eprint("BAD FUNCTION ARGUMENTS\n");
        ret = UC_FAILURE;
    }

    /* Check RSA seted values n and d */
    if (ret == UC_SUCCESS) {
        if (rsa->n == NULL || rsa->d == NULL) {
            uc_eprint("RSA private key is not set\n");
            ret = UC_FAILURE;
        }
    }

    if (ret == UC_SUCCESS) {
        switch (padding) {
            case RSA_PADDING_RAW:
                ret = uc_rsa_raw_decrypt(rsa, encrypted_data, encrypted_data_len, decrypted_data, decrypted_data_len);
                break;
            case RSA_PADDING_PKCS1_V1_5:
                ret = uc_rsa_pkcs1_v1_5_decrypt(rsa, encrypted_data, encrypted_data_len, decrypted_data, decrypted_data_len);
                break;
            case RSA_PADDING_OAEP:
                ret = uc_rsa_oaep_decrypt(rsa, encrypted_data, encrypted_data_len, decrypted_data, decrypted_data_len);
                break;
            default:
                uc_eprint("Invalid padding\n");
                ret = UC_FAILURE;
                break;
        }
    }

    return ret;
}

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
int uc_rsa_raw_decrypt(RSA *rsa, byte *encrypted_data, size_t encrypted_data_len, byte *decrypted_data, size_t *decrypted_data_len)
{
    ret = UC_SUCCESS;

    /* Allocate decrypted data */
    if (ret == UC_SUCCESS) {
        decrypted_data = (byte *)malloc(encrypted_data_len);
        if (decrypted_data == NULL) {
            uc_eprint("Failed to allocate memory for decrypted data\n");
            ret = UC_FAILURE;
        }
    }
    /* Decrypt data */
    if (ret == UC_SUCCESS) {
    }

    return ret;
}

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
int uc_rsa_pkcs1_v1_5_decrypt(RSA *rsa, byte *encrypted_data, size_t encrypted_data_len, byte *decrypted_data, size_t *decrypted_data_len)
{
    ret = UC_SUCCESS;

    /* Allocate decrypted data */
    if (ret == UC_SUCCESS) {
        decrypted_data = (byte *)malloc(encrypted_data_len);
        if (decrypted_data == NULL) {
            uc_eprint("Failed to allocate memory for decrypted data\n");
            ret = UC_FAILURE;
        }
    }

    /* Decrypt data */
    if (ret == UC_SUCCESS) {
    }

    return ret;
}

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
int uc_rsa_oaep_decrypt(RSA *rsa, byte *encrypted_data, size_t encrypted_data_len, byte *decrypted_data, size_t *decrypted_data_len)
{
    ret = UC_SUCCESS;

    /* Allocate decrypted data */
    if (ret == UC_SUCCESS) {
        decrypted_data = (byte *)malloc(encrypted_data_len);
        if (decrypted_data == NULL) {
            uc_eprint("Failed to allocate memory for decrypted data\n");
            ret = UC_FAILURE;
        }
    }

    /* Decrypt data */
    if (ret == UC_SUCCESS) {
    }

    return ret;
}

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
int uc_rsa_sign(RSA *rsa, byte *data, size_t data_len, byte *signature, size_t *signature_len, int padding)
{
    ret = UC_SUCCESS;

    /* Check function arguments */
    if (rsa == NULL || data == NULL || data_len == 0 || signature != NULL || signature_len == NULL) {
        uc_eprint("BAD FUNCTION ARGUMENTS\n");
        ret = UC_FAILURE;
    }

    /* Check RSA seted values n and d */
    if (ret == UC_SUCCESS) {
        if (rsa->n == NULL || rsa->d == NULL) {
            uc_eprint("RSA private key is not set\n");
            ret = UC_FAILURE;
        }
    }

    if (ret == UC_SUCCESS) {
        switch (padding) {
            case RSA_PADDING_RAW:
                ret = uc_rsa_raw_sign(rsa, data, data_len, signature, signature_len);
                break;
            case RSA_PADDING_PKCS1_V1_5:
                ret = uc_rsa_pkcs1_v1_5_sign(rsa, data, data_len, signature, signature_len);
                break;
            case RSA_PADDING_PSS:
                ret = uc_rsa_pss_sign(rsa, data, data_len, signature, signature_len);
                break;
            default:
                uc_eprint("Invalid padding\n");
                ret = UC_FAILURE;
                break;
        }
    }

    return ret;
}

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
int uc_rsa_raw_sign(RSA *rsa, byte *data, size_t data_len, byte *signature, size_t *signature_len)
{
    ret = UC_SUCCESS;

    /* Allocate signature */
    if (ret == UC_SUCCESS) {
        signature = (byte *)malloc(data_len);
        if (signature == NULL) {
            uc_eprint("Failed to allocate memory for signature\n");
            ret = UC_FAILURE;
        }
    }

    /* Sign data */
    if (ret == UC_SUCCESS) {
    }

    return ret;
}

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
int uc_rsa_pkcs1_v1_5_sign(RSA *rsa, byte *data, size_t data_len, byte *signature, size_t *signature_len)
{
    ret = UC_SUCCESS;

    /* Allocate signature */
    if (ret == UC_SUCCESS) {
        signature = (byte *)malloc(data_len);
        if (signature == NULL) {
            uc_eprint("Failed to allocate memory for signature\n");
            ret = UC_FAILURE;
        }
    }

    /* Sign data */
    if (ret == UC_SUCCESS) {
    }

    return ret;
}

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
int uc_rsa_pss_sign(RSA *rsa, byte *data, size_t data_len, byte *signature, size_t *signature_len)
{
    ret = UC_SUCCESS;

    /* Allocate signature */
    if (ret == UC_SUCCESS) {
        signature = (byte *)malloc(data_len);
        if (signature == NULL) {
            uc_eprint("Failed to allocate memory for signature\n");
            ret = UC_FAILURE;
        }
    }

    /* Sign data */
    if (ret == UC_SUCCESS) {
    }

    return ret;
}

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
int uc_rsa_verify(RSA *rsa, byte *data, size_t data_len, byte *signature, size_t signature_len, int padding)
{
    ret = UC_SUCCESS;

    /* Check function arguments */
    if (rsa == NULL || data == NULL || data_len == 0 || signature == NULL || signature_len == 0) {
        uc_eprint("BAD FUNCTION ARGUMENTS\n");
        ret = UC_FAILURE;
    }

    /* Check RSA seted values n and e */
    if (ret == UC_SUCCESS) {
        if (rsa->n == NULL || rsa->e == NULL) {
            uc_eprint("RSA public key is not set\n");
            ret = UC_FAILURE;
        }
    }

    if (ret == UC_SUCCESS) {
        switch (padding) {
            case RSA_PADDING_RAW:
                ret = uc_rsa_raw_verify(rsa, data, data_len, signature, signature_len);
                break;
            case RSA_PADDING_PKCS1_V1_5:
                ret = uc_rsa_pkcs1_v1_5_verify(rsa, data, data_len, signature, signature_len);
                break;
            case RSA_PADDING_PSS:
                ret = uc_rsa_pss_verify(rsa, data, data_len, signature, signature_len);
                break;
            default:
                uc_eprint("Invalid padding\n");
                ret = UC_FAILURE;
                break;
        }
    }

    return ret;
}

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
int uc_rsa_raw_verify(RSA *rsa, byte *data, size_t data_len, byte *signature, size_t signature_len)
{
    ret = UC_SUCCESS;

    

    /* Verify signature */
    if (ret == UC_SUCCESS) {
    }

    return ret;
}

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
int uc_rsa_pkcs1_v1_5_verify(RSA *rsa, byte *data, size_t data_len, byte *signature, size_t signature_len)
{
    ret = UC_SUCCESS;

    /* Verify signature */
    if (ret == UC_SUCCESS) {
    }

    return ret;
}

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
int uc_rsa_pss_verify(RSA *rsa, byte *data, size_t data_len, byte *signature, size_t signature_len)
{
    ret = UC_SUCCESS;

    /* Verify signature */
    if (ret == UC_SUCCESS) {
    }

    return ret;
}
