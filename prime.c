#include "prime.h"

int isPrime(size_t n)
{
    mpz_t c, res;
    mpz_init(c);
    mpz_init(res);

    mpz_set_ui(c, n);
    return mpz_probab_prime_p(c, 7);
}

size_t nextPrime(size_t op)
{
    mpz_t c, res;
    mpz_init(c);
    mpz_init(res);

    mpz_set_ui(c, op);
    mpz_nextprime(res, c);

    return mpz_get_ui(res);
}