/*
 *
*/

#include "rsa.h"

int uc_rsa_init(RSA *rsa)
{
    ret = UC_SUCCESS;

    if (rsa == NULL)
    {
        ret = uc_rsa_new(rsa);
        if (ret != UC_SUCCESS)
        {
            uc_eprint("Failed to initialize RSA\n");
            return ret;
        }
    }

    return ret;
}

int uc_rsa_new(RSA *rsa)
{
    ret = UC_SUCCESS;

    if (rsa == NULL)
    {
        rsa = (RSA *)malloc(sizeof(RSA));
        if (rsa == NULL)
        {
            uc_eprint("Failed to allocate memory for RSA\n");
            ret = UC_FAILURE;
        }
    }

    if (rsa != NULL && ret == UC_SUCCESS)
    {
        rsa->n = NULL;
        rsa->e = NULL;
        rsa->d = NULL;
        rsa->p = NULL;
        rsa->q = NULL;
        rsa->lambda = NULL;
    }
    

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
    ret = UC_SUCCESS;

    ret = uc_rsa_generate_private_key(rsa);
    if (ret != UC_SUCCESS)
    {

        return ret;
    }

    return ret;
}

int uc_rsa_generate_private_key(RSA *rsa)
{
    ret = UC_SUCCESS;

    return ret;
}

int uc_rsa_generate_public_key(RSA *rsa)
{
    ret = UC_SUCCESS;

    return ret;
}

int uc_rsa_encrypt(RSA *rsa)
{
    ret = UC_SUCCESS;

    return ret;
}

int uc_rsa_decrypt(RSA *rsa)
{
    ret = UC_SUCCESS;

    return ret;
}

int uc_rsa_sign(RSA *rsa)
{
    ret = UC_SUCCESS;

    return ret;
}

int uc_rsa_verify(RSA *rsa)
{
    ret = UC_SUCCESS;

    return ret;
}

