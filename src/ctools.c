/*
 *
*/

#include "ctools.h"

/*
 * The uc_print function prints formatted output to the standard output stream.
 * @param format The format string
 * @param ... The variable argument list
 * @return void
*/
void uc_print(const char *format, ...)
{
    va_list args;  // Variable argument list

    va_start(args, format);  // Initialize variable argument list
    vprintf(stdout, format, args);  // Print formatted output
    va_end(args);  // End using variable argument list
}

/*
 * The uc_eprint function prints formatted output to the standard error stream.
 * @param format The format string
 * @param ... The variable argument list
 * @return void
*/
void uc_eprint(const char *format, ...)
{
    va_list args;  // Variable argument list

    va_start(args, format);  // Initialize variable argument list
    vfprintf(stderr, format, args);  // Print formatted output
    va_end(args);  // End using variable argument list
}

/*
 * The uc_ext_GCD function calculates the greatest common divisor of two integers using the extended Euclidean algorithm.
*/
int uc_ext_GCD(int a, int b, int *x, int *y)
{
    int x1, y1, x2, y2, q, r;

    if (b == 0) {
        *x = 1;
        *y = 0;
        return a;
    }

    x2 = 1;
    x1 = 0;
    y2 = 0;
    y1 = 1;

    while (b > 0) {
        q = a / b;
        r = a - q * b;
        *x = x2 - q * x1;
        *y = y2 - q * y1;
        a = b;
        b = r;
        x2 = x1;
        x1 = *x;
        y2 = y1;
        y1 = *y;
    }

    *x = x2;
    *y = y2;

    return a;
}
