use libc::{c_int, c_uchar, size_t};

extern "C" {
    // 常规加法
    fn ffi_sm2_z256_add(value: *mut c_uchar, a: *mut c_uchar, b: *mut c_uchar) -> u64;
    // 常规减法
    fn ffi_sm2_z256_sub(value: *mut c_uchar, a: *mut c_uchar, b: *mut c_uchar) -> u64;
    // 常规乘法
    fn ffi_sm2_z256_mul(value: *mut c_uchar, a: *mut c_uchar, b: *mut c_uchar) -> void;

    // 模加
    fn ffi_sm2_z256_modp_add(value: *mut c_uchar, a: *mut c_uchar, b: *mut c_uchar) -> void;
    // 模减
    fn ffi_sm2_z256_modp_sub(value: *mut c_uchar, a: *mut c_uchar, b: *mut c_uchar) -> void;
    // 模乘
    fn 
}

// 常规加法
pub fn sm2_z256_add(a: &[u8; 32], b: &[u8; 32]) -> Result<[u8; 65], String> {
    let mut value = [0u8; 32];
    unsafe {
        ffi_sm2_z256_add(&value, a, b)
    }
    Ok(value)
}

// 常规减法
pub fn sm2_z256_sub(a: &[u8; 32], b: &[u8; 32]) -> Result<[u8; 65], String> {
    let mut value = [0u8; 32];
    unsafe {
        ffi_sm2_z256_sub(&value, a, b)
    }
    Ok(value)
}

// 常规乘法
pub fn sm2_z256_mul(a: &[u8; 32], b: &[u8; 32]) -> Result<[u8; 65], String> {
    let mut value = [0u8; 32];
    unsafe {
        ffi_sm2_z256_mul(&value, a, b)
    }
    Ok(value)
}