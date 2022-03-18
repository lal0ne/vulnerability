#include <openssl/bn.h>


int main() {
    BN_CTX *ctx;
    ctx = BN_CTX_new();
    BIGNUM *res, *a, *p;
    res = BN_CTX_get(ctx);
    a = BN_CTX_get(ctx);
    p = BN_CTX_get(ctx);

    BN_dec2bn(&p, "697");
    BN_dec2bn(&a, "696");

    printf("p = %s\n", BN_bn2dec(p));
    printf("a = %s\n", BN_bn2dec(a));

    BIGNUM* check = BN_mod_sqrt(res, a, p, ctx);
    printf("%s\n", BN_bn2dec(res));

    return 0;
}
