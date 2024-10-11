/*
 *
*/

#include "rsa.h"

int uc_rsa_new(RSA *rsa)
{
    ret = SUCCESS;

    return ret;
}

void rsa_free(RSA *rsa)
{
    if (rsa != NULL)
    {
        free(rsa);
    }
}

int uc_rsa_generate_key_pair(RSA *rsa)
{
    ret = SUCCESS;

    ret = uc_rsa_generate_private_key(rsa);
    if (ret != SUCCESS)
    {
        
        return ret;
    }

    return ret;
}

int uc_rsa_generate_private_key(RSA *rsa)
{
    ret = SUCCESS;

    return ret;
}

int uc_rsa_generate_public_key(RSA *rsa)
{
    ret = SUCCESS;

    return ret;
}

int uc_rsa_encrypt(RSA *rsa)
{
    ret = SUCCESS;

    return ret;
}

int uc_rsa_decrypt(RSA *rsa)
{
    ret = SUCCESS;

    return ret;
}

int uc_rsa_sign(RSA *rsa)
{
    ret = SUCCESS;

    return ret;
}

int uc_rsa_verify(RSA *rsa)
{
    ret = SUCCESS;

    return ret;
}

