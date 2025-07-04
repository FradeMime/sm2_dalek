#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sm2/error.h>
#include <sm2/mem.h>
#include <sm2/ghash.h>
#include <sm2/sm2_z256.h>

// 字节转域
void func_sm2_z256_from_bytes(uint64_t *value, const uint8_t *a){
    sm2_z256_from_bytes(value, a);
}

// 域转字节
void func_sm2_z256_to_bytes(uint8_t *value, const uint64_t *a){
    sm2_z256_to_bytes(a, value);
}


// 常规加法
uint64_t func_sm2_z256_add(uint64_t *value, const uint64_t *a, const uint64_t *b) {
    return sm2_z256_add(value, a, b);
}

// 常规减法
uint64_t func_sm2_z256_sub(uint64_t *value, const uint64_t *a, const uint64_t *b)
{
    return sm2_z256_sub(value, a, b);
}

// 常规乘法
uint64_t func_sm2_z256_mul(uint64_t *value, const uint64_t *a, const uint64_t *b)
{
    return sm2_z256_mul(value, a, b);
}

// 模加
void func_sm2_z256_modp_add(uint64_t *value, const uint64_t *a, const uint64_t *b) {
    sm2_z256_modp_add(value, a, b);
}

// 模倍加
void func_sm2_z256_modp_dbl_add(uint64_t *value, const uint64_t *a) {
    sm2_z256_modp_dbl(value, a);
}

// 模三倍加
void func_sm2_z256_modp_tri_add(uint64_t *value, const uint64_t *a) {
    sm2_z256_modp_tri(value, a);
}

// 模减
void func_sm2_z256_modp_sub(uint64_t *value, const uint64_t *a, const uint64_t *b) {
    sm2_z256_modp_sub(value, a, b);
}

// 模反(加法逆元)
void func_sm2_z256_modp_neg(uint64_t *value, const uint64_t *a) {
    sm2_z256_modp_neg(value, a);
}

// 模除以二
void func_sm2_z256_modp_haf(uint64_t *value, const uint64_t *a) {
    sm2_z256_modp_haf(value, a);
}



// 常规整数转蒙哥马利域中形式
void func_sm2_z256_modp_to_mont(uint64_t *value, const uint64_t *a) {
    sm2_z256_modp_to_mont(a, value);
}

// 蒙哥马利域中表示的参数转常规整数
void func_sm2_z256_modp_from_mont(uint64_t *value, const uint64_t *a) {
    sm2_z256_modp_from_mont(value, a);
}

// 模乘
void func_sm2_z256_modp_mont_mul(uint64_t *value, const uint64_t *a, const uint64_t *b) {
    sm2_z256_modp_mont_mul(value, a, b);
}

// 模平方
void func_sm2_z256_modp_mont_sqr(uint64_t *value, const uint64_t *a) {
    sm2_z256_modp_mont_sqr(value, a);
}

// 模幂
void func_sm2_z256_modp_mont_exp(uint64_t *value, const uint64_t *a, const uint64_t *b) {
    sm2_z256_modp_mont_exp(value, a, b);
}

// 模逆元
void func_sm2_z256_modp_mont_inv(uint64_t *value, const uint64_t *a) {
    sm2_z256_modp_mont_inv(value, a);
}

// 模平方根
void func_sm2_z256_modp_mont_sqrt(uint64_t *value, const uint64_t *a) {
    sm2_z256_modp_mont_sqrt(value, a);
}


// 标量模加
void func_sm2_z256_modn_add(uint64_t *value, const uint64_t *a, const uint64_t *b){
    sm2_z256_modn_add(value, a, b);
}

// 标量模减
void func_sm2_z256_modn_sub(uint64_t *value, const uint64_t *a, const uint64_t *b){
    sm2_z256_modn_sub(value, a, b);
}

// 标量模取反
void func_sm2_z256_modn_neg(uint64_t *value, const uint64_t *a){
    sm2_z256_modn_neg(value, a);
}

// 标量模乘
void func_sm2_z256_modn_mul(uint64_t *value, const uint64_t *a, const uint64_t *b){
    sm2_z256_modn_mul(value, a, b);
}

// 标量模平方
void func_sm2_z256_modn_sqr(uint64_t *value, const uint64_t *a){
    sm2_z256_modn_sqr(value, a);
}

// 标量 进蒙哥马利
void func_sm2_z256_modn_to_mont(uint64_t *value, const uint64_t *a) {
    sm2_z256_modn_to_mont(a, value);
}

// 标量 出蒙哥马利
void func_sm2_z256_modn_from_mont(uint64_t *value, const uint64_t *a) {
    sm2_z256_modn_from_mont(value, a);
}

// 标量 蒙哥马利模乘
void func_sm2_z256_modn_mont_mul(uint64_t *value, const uint64_t *a, const uint64_t *b) {
    sm2_z256_modn_mont_mul(value, a, b);
}

// 标量 蒙哥马利模平方
void func_sm2_z256_modn_mont_sqr(uint64_t *value, const uint64_t *a) {
    sm2_z256_modn_mont_sqr(value, a);
}

// 标量 蒙哥马利模逆
void func_sm2_z256_modn_mont_inv(uint64_t *value, const uint64_t *a) {
    sm2_z256_modn_mont_inv(value, a);
}


// 点 转 字节
void func_sm2_z256_point_to_bytes(
    uint8_t *value, 
    const SM2_Z256_POINT *point) {
    sm2_z256_point_to_bytes(point, value);
}

// 字节数据 转 点
// 压缩/非压缩都可以用
void func_sm2_z256_point_from_octets(SM2_Z256_POINT *point, const uint8_t *buf, const size_t inlen) {
    sm2_z256_point_from_octets(point, buf, inlen);
}

// 点 压缩为 33字节
void func_sm2_z256_point_to_compressed_octets(uint8_t *value, const SM2_Z256_POINT *point) {
    sm2_z256_point_to_compressed_octets(point, value);
}


// 两倍点
void func_sm2_z256_point_dbl(SM2_Z256_POINT *dbl_point, const SM2_Z256_POINT *point) {
    sm2_z256_point_dbl(dbl_point, point);
}