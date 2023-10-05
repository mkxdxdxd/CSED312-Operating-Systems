#include <stdint.h>
/*for shift*/
#define f (1 << 14)
/*convert n to fixed point*/
#define int_to_fixed(n) (n * f)
/*convert x to integer (rounding toward zero)*/
#define fixed_to_int_round_to_zero(x) (x / f)
/*convert x to integer (rounding toward nearest)*/
#define fixed_to_int(x) (x >= 0) ? ((x + f / 2) / f) \
                                 : ((x - f / 2) / f)
/*add x and y*/
#define fixed_plus_fixed(x, y) (x + y)
/*subtract y from x*/
#define fixed_minus_fixed(x, y) (x - y)
/*add x and n*/
#define fixed_plus_int(x, n) (x + n * f)
/*subtract n from x*/
#define fixed_minus_int(x, n) (x - n * f)
/*multiply x by y*/
#define fixed_mul_fixed(x, y) (int)((int64_t)x * y / f)
/*multiply x by n*/
#define fixed_mul_int(x, n) (x * n)
/*divide x by y*/
#define fixed_div_fixed(x, y) (int)((int64_t)x * f / y)
/*divide x by n*/
#define fixed_div_int(x, n) (x / n)