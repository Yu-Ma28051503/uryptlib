/*
 *
*/

#ifndef CTOOLS_H
#define CTOOLS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdarg.h>

#define UC_SUCCESS 0
#define UC_FAILURE 1

typedef uint8_t byte;

/* functions */
/*
 * The uc_print function prints formatted output to the standard output stream.
 * @param format The format string
 * @param ... The variable argument list
 * @return void
*/
void uc_print(const char *format, ...);

/*
 * The uc_eprint function prints formatted output to the standard error stream.
 * @param format The format string
 * @param ... The variable argument list
 * @return void
*/
void uc_eprint(const char *format, ...);

/*
 * The uc_ext_GCD function calculates the greatest common divisor of two integers using the extended Euclidean algorithm.
*/
int uc_ext_GCD(int a, int b, int *x, int *y);

#endif // CTOOLS_H
