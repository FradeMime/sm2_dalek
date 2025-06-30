#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sm2/error.h>
#include <sm2/mem.h>
#include <sm2/ghash.h>
#include <sm2/sm2_z256.h>


// 常规加法
uint64_t ffi_sm2_z256_add(uint64_t *value, const uint64_t *a, const uint64_t *b) {
    return sm2_z256_add(value, a, b);
}

// 常规减法
uint64_t ffi_sm2_z256_sub(uint64_t *value, const uint64_t *a, const uint64_t *b)
{
    return sm2_z256_sub(value, a, b);
}

// 常规减法
uint64_t ffi_sm2_z256_mul(uint64_t *value, const uint64_t *a, const uint64_t *b)
{
    return sm2_z256_sub(value, a, b);
}

// 模加
void ffi_sm2_z256_modp_add(uint64_t *value, const uint64_t *a, const uint64_t *b) {
    sm2_z256_modp_add(value, a, b);
}

// 模倍加
void ffi_sm2_z256_modp_dbl_add(uint64_t *value, const uint64_t *a) {
    sm2_z256_modp_dbl(value, a);
}

// 模三倍加
void ffi_sm2_z256_modp_tri_add(uint64_t *value, const uint64_t *a) {
    sm2_z256_modp_tri(value, a);
}

// 模减
void ffi_sm2_z256_modp_sub(uint64_t *value, const uint64_t *a, const uint64_t *b) {
    sm2_z256_modp_sub(value, a, b);
}

// 模反(加法逆元)
void ffi_sm2_z256_modp_neg(uint64_t *value, const uint64_t *a) {
    sm2_z256_modp_neg(value, a);
}

// 模除以二
void ffi_sm2_z256_modp_haf(uint64_t *value, const uint64_t *a) {
    sm2_z256_modp_haf(value, a);
}

// 常规整数转蒙哥马利域中形式
void ffi_sm2_z256_modp_to_mont(uint64_t *r, const uint64_t *a) {
    sm2_z256_modp_to_mont(a, r);
}

// 蒙哥马利域中表示的参数转常规整数
void ffi_sm2_z256_modp_from_mont(uint64_t *r, const uint64_t *a) {
    sm2_z256_modp_from_mont(r, a);
}

void ffi_sm2_z256_modp_mont_mul(uint64_t *r, const uint64_t *a, const uint64_t *b) {
    sm2_z256_modp_mont_mul(r, a, b);
}


