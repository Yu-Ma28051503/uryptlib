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
