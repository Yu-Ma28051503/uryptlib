/*
 * 
*/

#ifndef RSA_H
#define RSA_H

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
int uc_rsa_encrypt(RSA *rsa);

/*
 *
*/
int uc_rsa_decrypt(RSA *rsa);

/*
 *
*/
int uc_rsa_sign(RSA *rsa);

/*
 *
*/
int uc_rsa_verify(RSA *rsa);



#endif // RSA_H
