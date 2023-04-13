#ifndef FIXED_POINT
#define FIXED_POINT


typedef int fixed_point_t;

//2^16
#define FP_F_SHIFT 14

#define FP_CONVERT_N_TO_FP(n) (fixed_point_t)(n << FP_F_SHIFT)

#define FP_CONVERT_X_TO_INT_ZERO(x) (int)(x >> FP_F_SHIFT)

#define FP_CONVERT_X_TO_INT_NEAREST(x) (int)((x >= 0) ? ((x + (1 << (FP_F_SHIFT - 1))) >> FP_F_SHIFT) : ((x - (1 << (FP_F_SHIFT - 1))) >> FP_F_SHIFT))

#define FP_ADD_X_Y(x, y) (x + y)

#define FP_SUB_X_Y(x, y) (x - y)

#define FP_ADD_X_N(x, n) (x + (n << FP_F_SHIFT))

#define FP_SUB_X_N(x, n) (x - (n << FP_F_SHIFT))

#define FP_MUL_X_Y(x, y) ((fixed_point_t)(((int64_t)x) * y >> FP_F_SHIFT))

#define FP_MUL_X_N(x, n) (x * n)

#define FP_DIV_X_Y(x, y) ((fixed_point_t)((((int64_t)x) << FP_F_SHIFT) / y))

#define FP_DIV_X_N(x, n) (x / n)







#endif