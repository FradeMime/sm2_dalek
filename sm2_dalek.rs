use libc::{c_int, c_uchar, size_t};


#[repr(C)]
pub struct SM2_Z256_POINT {
    pub X: [u64; 4],
    pub Y: [u64; 4],
    pub Z: [u64; 4],
}

extern "C" {

    // 字节数组转域
    fn func_sm2_z256_from_bytes(value: *mut u64, a: *const u8);
    // 域转字节数组
    fn func_sm2_z256_to_bytes(value: *mut u64, a: *const u64);

    // 常规加法
    fn func_sm2_z256_add(value: *mut u64, a: *const u64, b: *const u64) -> u64;
    // 常规减法
    fn func_sm2_z256_sub(value: *mut u64, a: *const u64, b: *const u64) -> u64;
    // 常规乘法
    fn func_sm2_z256_mul(value: *mut u64, a: *const u64, b: *const u64) -> u64;

    // 模加
    fn func_sm2_z256_modp_add(value: *mut u64, a: *const u64, b: *const u64);
    // 模减
    fn func_sm2_z256_modp_sub(value: *mut u64, a: *const u64, b: *const u64);
    // 模双倍加
    fn func_sm2_z256_modp_dbl(value: *mut u64, a: *const u64);
    // 模三倍加
    fn func_sm2_z256_modp_tri(value: *mut u64, a: *const u64);
    // 模反
    fn func_sm2_z256_modp_neg(value: *mut u64, a: *const u64);
    // 模除以二
    fn func_sm2_z256_modp_haf(value: *mut u64, a: *const u64);

    // 进蒙哥马利
    fn func_sm2_z256_modp_to_mont(value: *mut u64, a: *const u64);
    // 出蒙哥马利
    fn func_sm2_z256_modp_from_mont(value: *mut u64, a: *const u64);
    // 模乘
    fn func_sm2_z256_modp_mont_mul(value: *mut u64, a: *const u64, b: *const u64);
    // 模平方
    fn func_sm2_z256_modp_mont_sqr(value: *mut u64, a: *const u64);
    // 模幂
    fn func_sm2_z256_modp_mont_exp(value: *mut u64, a: *const u64, b: *const u64);
    // 模逆元
    fn func_sm2_z256_modp_mont_inv(value: *mut u64, a: *const u64);
    // 模平方根
    fn func_sm2_z256_modp_mont_sqrt(value: *mut u64, a: *const u64);

    // 标量模加
    fn func_sm2_z256_modn_add(value: *mut u64, a: *const u64, b: *const u64);
    // 标量模减
    fn func_sm2_z256_modn_sub(value: *mut u64, a: *const u64, b: *const u64);
    // 标量模取反
    fn func_sm2_z256_modn_neg(value: *mut u64, a: *const u64);
    // 标量模乘
    fn func_sm2_z256_modn_mul(value: *mut u64, a: *const u64, b: *const u64);
    // 标量模平方
    fn func_sm2_z256_modn_sqr(value: *mut u64, a: *const u64);
    // 标量 进蒙哥马利
    fn func_sm2_z256_modn_to_mont(value: *mut u64, a: *const u64);
    // 标量 出蒙哥马利
    fn func_sm2_z256_modn_from_mont(value: *mut u64, a: *const u64);
    // 标量 蒙哥马利模乘
    fn func_sm2_z256_modn_mont_mul(value: *mut u64, a: *const u64, b: *const u64);
    // 标量 蒙哥马利模平方
    fn func_sm2_z256_modn_mont_sqr(value: *mut u64, a: *const u64);
    // 标量 蒙哥马利模逆
    fn func_sm2_z256_modn_mont_inv(value: *mut u64, a: *const u64);


    // 点转字节 64字节
    fn func_sm2_z256_point_to_bytes(value: *mut u8, point: *const SM2_Z256_POINT);
    // 字节转点 任意
    fn func_sm2_z256_point_from_octets(point: *mut SM2_Z256_POINT, buf: *const u8, inlen: const usize);
    // SM2点压缩 33字节
    fn func_sm2_z256_point_to_compressed_octets(value: *mut u8, point: *const SM2_Z256_POINT);
    // 两倍点
    fn func_sm2_z256_point_dbl(dbl_point: *mut SM2_Z256_POINT, point: *const SM2_Z256_POINT);

}

// 字节数组转域
pub fn ffi_sm2_z256_from_bytes(a: &[u64; 4]) -> Result<[u64; 4], String> {
    let mut value = [0u64; 4];
    unsafe {
        func_sm2_z256_from_bytes(value.as_mut_ptr(), a.as_ptr())
    }
    Ok(value)
}

// 域转字节数组
pub fn ffi_sm2_z256_to_bytes(a: &[u64; 4]) -> Result<[u64; 4], String> {
    let mut value = [0u64; 4];
    unsafe {
        func_sm2_z256_to_bytes(value.as_mut_ptr(), a.as_ptr())
    }
    Ok(value)
}

// 常规加法
pub fn ffi_sm2_z256_add(a: &[u64; 4], b: &[u64; 4]) -> Result<[u64; 4], String> {
    let mut value = [0u64; 4];
    unsafe {
        func_sm2_z256_add(value.as_mut_ptr(), a.as_ptr(), b.as_ptr())
    }
    Ok(value)
}

// 常规减法
pub fn ffi_sm2_z256_sub(a: &[u64; 4], b: &[u64; 4]) -> Result<[u64; 4], String> {
    let mut value = [0u64; 4];
    unsafe {
        func_sm2_z256_sub(value.as_mut_ptr(), a.as_ptr(), b.as_ptr())
    }
    Ok(value)
}

// 常规乘法
pub fn ffi_sm2_z256_mul(a: &[u64; 4], b: &[u64; 4]) -> Result<[u64; 4], String> {
    let mut value = [0u64; 4];
    unsafe {
        func_sm2_z256_mul(value.as_mut_ptr(), a.as_ptr(), b.as_ptr())
    }
    Ok(value)
}

// 模加
pub fn ffi_sm2_z256_modp_add(a: &[u64; 4], b: &[u64; 4]) -> Result<[u64; 4], String> {
    let mut value = [0u64; 4];
    unsafe {
        func_sm2_z256_modp_add(value.as_mut_ptr(), a.as_ptr(), b.as_ptr())
    }
    Ok(value)
}

// 模减
pub fn ffi_sm2_z256_modp_sub(a: &[u64; 4], b: &[u64; 4]) -> Result<[u64; 4], String> {
    let mut value = [0u64; 4];
    unsafe {
        func_sm2_z256_modp_sub(value.as_mut_ptr(), a.as_ptr(), b.as_ptr())
    }
    Ok(value)
}

// 模双倍加
pub fn ffi_sm2_z256_modp_dbl(a: &[u64; 4]) -> Result<[u64; 4], String> {
    let mut value = [0u64; 4];
    unsafe {
        func_sm2_z256_modp_dbl(value.as_mut_ptr(), a.as_ptr())
    }
    Ok(value)
}

// 模三倍加
pub fn ffi_sm2_z256_modp_tri(a: &[u64; 4]) -> Result<[u64; 4], String> {
    let mut value = [0u64; 4];
    unsafe {
        func_sm2_z256_modp_tri(value.as_mut_ptr(), a.as_ptr())
    }
    Ok(value)
}

// 模反(加法逆元)
pub fn ffi_sm2_z256_modp_neg(a: &[u64; 4]) -> Result<[u64; 4], String> {
    let mut value = [0u64; 4];
    unsafe {
        func_sm2_z256_modp_neg(value.as_mut_ptr(), a.as_ptr())
    }
    Ok(value)
}

// 模除以二
pub fn ffi_sm2_z256_modp_haf(a: &[u64; 4]) -> Result<[u64; 4], String> {
    let mut value = [0u64; 4];
    unsafe {
        func_sm2_z256_modp_haf(value.as_mut_ptr(), a.as_ptr())
    }
    Ok(value)
}

// 模整数转蒙哥马利域中形式
pub fn ffi_sm2_z256_modp_to_mont(a: &[u64; 4]) -> Result<[u64; 4], String> {
    let mut value = [0u64; 4];
    unsafe {
        func_sm2_z256_modp_to_mont(value.as_mut_ptr(), a.as_ptr())
    }
    Ok(value)
}

// 蒙哥马利域中表示的参数转常规整数
pub fn ffi_sm2_z256_modp_from_mont(a: &[u64; 4]) -> Result<[u64; 4], String> {
    let mut value = [0u64; 4];
    unsafe {
        func_sm2_z256_modp_from_mont(value.as_mut_ptr(), a.as_ptr())
    }
    Ok(value)
}

// 模乘
pub fn ffi_sm2_z256_modp_mont_mul(a: &[u64; 4], b: &[u64; 4]) -> Result<[u64; 4], String> {
    let mut value = [0u64; 4];
    unsafe {
        func_sm2_z256_modp_mont_mul(value.as_mut_ptr(), a.as_ptr(), b.as_ptr())
    }
    Ok(value)
}

// 模平方
pub fn ffi_sm2_z256_modp_mont_sqr(a: &[u64; 4]) -> Result<[u64; 4], String> {
    let mut value = [0u64; 4];
    unsafe {
        func_sm2_z256_modp_mont_sqr(value.as_mut_ptr(), a.as_ptr())
    }
    Ok(value)
}

// 模幂
pub fn ffi_sm2_z256_modp_mont_exp(a: &[u64; 4], b: &[u64; 4]) -> Result<[u64; 4], String> {
    let mut value = [0u64; 4];
    unsafe {
        func_sm2_z256_modp_mont_exp(value.as_mut_ptr(), a.as_ptr(), b.as_ptr())
    }
    Ok(value)
}

// 模逆元
pub fn ffi_sm2_z256_modp_mont_inv(a: &[u64; 4]) -> Result<[u64; 4], String> {
    let mut value = [0u64; 4];
    unsafe {
        func_sm2_z256_modp_mont_inv(value.as_mut_ptr(), a.as_ptr())
    }
    Ok(value)
}

// 模平方根
pub fn ffi_sm2_z256_modp_mont_sqrt(a: &[u64; 4]) -> Result<[u64; 4], String> {
    let mut value = [0u64; 4];
    unsafe {
        func_sm2_z256_modp_mont_sqrt(value.as_mut_ptr(), a.as_ptr())
    }
    Ok(value)
}




// 标量模加
pub fn ffi_sm2_z256_modn_add(a: &[u64; 4], b: &[u64; 4]) -> Result<[u64; 4], String> {
    let mut value = [0u64; 4];
    unsafe {
        func_sm2_z256_modn_add(value.as_mut_ptr(), a.as_ptr(), b.as_ptr())
    }
    Ok(value)
}

// 标量模减
pub fn ffi_sm2_z256_modn_sub(a: &[u64; 4], b: &[u64; 4]) -> Result<[u64; 4], String> {
    let mut value = [0u64; 4];
    unsafe {
        func_sm2_z256_modn_sub(value.as_mut_ptr(), a.as_ptr(), b.as_ptr())
    }
    Ok(value)
}

// 标量模取反
pub fn ffi_sm2_z256_modn_neg(a: &[u64; 4]) -> Result<[u64; 4], String> {
    let mut value = [0u64; 4];
    unsafe {
        func_sm2_z256_modn_neg(value.as_mut_ptr(), a.as_ptr())
    }
    Ok(value)
}

// 标量模乘
pub fn ffi_sm2_z256_modn_mul(a: &[u64; 4], b: &[u64; 4]) -> Result<[u64; 4], String> {
    let mut value = [0u64; 4];
    unsafe {
        func_sm2_z256_modn_mul(value.as_mut_ptr(), a.as_ptr(), b.as_ptr())
    }
    Ok(value)
}

// 标量模平方
pub fn ffi_sm2_z256_modn_sqr(a: &[u64; 4]) -> Result<[u64; 4], String> {
    let mut value = [0u64; 4];
    unsafe {
        func_sm2_z256_modn_sqr(value.as_mut_ptr(), a.as_ptr())
    }
    Ok(value)
}

// 标量 进蒙哥马利
pub fn ffi_sm2_z256_modn_to_mont(a: &[u64; 4]) -> Result<[u64; 4], String> {
    let mut value = [0u64; 4];
    unsafe {
        func_sm2_z256_modn_to_mont(value.as_mut_ptr(), a.as_ptr())
    }
    Ok(value)
}

// 标量 出蒙哥马利
pub fn ffi_sm2_z256_modn_from_mont(a: &[u64; 4]) -> Result<[u64; 4], String> {
    let mut value = [0u64; 4];
    unsafe {
        func_sm2_z256_modn_from_mont(value.as_mut_ptr(), a.as_ptr())
    }
    Ok(value)
}

// 标量 蒙哥马利模乘
pub fn ffi_sm2_z256_modn_mont_mul(a: &[u64; 4], b: &[u64; 4]) -> Result<[u64; 4], String> {
    let mut value = [0u64; 4];
    unsafe {
        func_sm2_z256_modn_mont_mul(value.as_mut_ptr(), a.as_ptr(), b.as_ptr())
    }
    Ok(value)
}

// 标量 蒙哥马利模平方
pub fn ffi_sm2_z256_modn_mont_sqr(a: &[u64; 4]) -> Result<[u64; 4], String> {
    let mut value = [0u64; 4];
    unsafe {
        func_sm2_z256_modn_mont_sqr(value.as_mut_ptr(), a.as_ptr())
    }
    Ok(value)
}

// 标量 蒙哥马利模逆
pub fn ffi_sm2_z256_modn_mont_inv(a: &[u64; 4]) -> Result<[u64; 4], String> {
    let mut value = [0u64; 4];
    unsafe {
        func_sm2_z256_modn_mont_inv(value.as_mut_ptr(), a.as_ptr())
    }
    Ok(value)
}


// 点 转 字节 64字节
pub fn ffi_sm2_z256_point_to_bytes(point: &EdwardsPoint) -> Result<[u8; 64], String> {
    let mut value = [0u8; 64];

    // 手动构造C层兼容结构
    let c_point = SM2_Z256_POINT {
        X: point.X.0,
        Y: point.Y.0,
        Z: point.Z.0,
    };

    unsafe {
        func_sm2_z256_point_to_bytes(value.as_mut_ptr(), &c_point as *const SM2_Z256_POINT);
    }
    Ok(value)
}

// 字节 转 点
// 任意
pub fn ffi_sm2_z256_point_from_octets(buf: &[u8], inlen: &usize) -> Result<EdwardsPoint, String> {
    // 安全拷贝到中间 Vec 缓冲区
    let mut in_buf = Vec::with_capacity(inlen);
    in_buf.extend_from_slice(&buf[..inlen]);

    let mut c_point = SM2_Z256_POINT {
        X: [0u64; 4],
        Y: [0u64; 4],
        Z: [0u64; 4],
    };
    unsafe {
        func_sm2_z256_point_from_octets(&mut c_point as *mut SM2_Z256_POINT, buf.as_ptr(), inlen)
    }
    Ok(point)
}

// 点 压缩 33字节
pub fn ffi_sm2_z256_point_to_compressed_octets(point: &EdwardsPoint) -> Result<[u8; 33], String> {
    let mut value = [0u8; 33];

    // 手动构造C层兼容结构
    let c_point = SM2_Z256_POINT {
        X: point.X.0,
        Y: point.Y.0,
        Z: point.Z.0,
    };

    unsafe {
        func_sm2_z256_point_to_compressed_octets(value.as_mut_ptr(), &c_point as *const SM2_Z256_POINT);
    }
    Ok(value)
}

// 两倍点
pub fn ffi_sm2_z256_point_dbl(point: &EdwardsPoint) -> Result<EdwardsPoint, String> {

    let c_point = SM2_Z256_POINT {
        X: point.X.0,
        Y: point.Y.0,
        Z: point.Z.0,
    };

    let dbl_point = SM2_Z256_POINT {
        X: [0u64; 4],
        Y: [0u64; 4],
        Z: [0u64; 4],
    };
    
    unsafe {
        func_sm2_z256_point_dbl(&mut dbl_point as *mut SM2_Z256_POINT, &c_point as *const SM2_Z256_POINT);
    }
    let result = EdwardsPoint {
        X: FieldElement(dbl_point.X),
        Y: FieldElement(dbl_point.Y),
        Z: FieldElement(dbl_point.Z),
    };

    Ok(result)
}