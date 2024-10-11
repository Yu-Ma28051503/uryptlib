/*
 * 
*/

#ifndef RSA_H
#define RSA_H

#include "ctools.h"

struct RSA {
    
}

typedef struct RSA RSA;

/*
 *
*/
int rsa_new(RSA *rsa);

/*
 *
*/
void rsa_free(RSA *rsa);

/*
 *
*/
int uc_rsa_encrypt();

/*
 *
*/
int uc_rsa_decrypt();

/*
 *
*/
int uc_rsa_sign();

/*
 *
*/
int uc_rsa_verify();



#endif // RSA_H
