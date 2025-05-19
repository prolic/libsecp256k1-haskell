#include <secp256k1.h>

/* Returns the adress of the library's built-in context */
const secp256k1_context* hs_secp256k1_content_static(void)
{
    return secp256k1_context_static;
}
