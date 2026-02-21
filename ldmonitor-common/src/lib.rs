#![no_std]

/// 最大路径长度
pub const MAX_PATH_LEN: usize = 256;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct DlopenEvent {
    pub pid: u32,
    pub uid: u32,
    pub path_len: u32,
    pub path: [u8; MAX_PATH_LEN],
}

impl DlopenEvent {
    /// 获取路径字符串（用户空间使用）
    #[cfg(feature = "user")]
    pub fn path_str(&self) -> &str {
        let len = (self.path_len as usize).min(MAX_PATH_LEN);
        // 查找第一个 null 字节或使用 path_len
        let actual_len = self.path[..len].iter().position(|&b| b == 0).unwrap_or(len);
        core::str::from_utf8(&self.path[..actual_len]).unwrap_or("")
    }
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for DlopenEvent {}
