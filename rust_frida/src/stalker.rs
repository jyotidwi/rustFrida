/* This example is in the public domain */
use std::collections::HashMap;
use std::ffi::c_void;
use std::fmt::format;
use std::io::{Write, Read, Seek, SeekFrom};
use std::thread;
use std::sync::Mutex;
use std::fs::{OpenOptions, File};
use frida_gum as gum;
use frida_gum::stalker::{Event, EventMask, EventSink, Stalker, Transformer};
use lazy_static::lazy_static;
use crossbeam_channel::{bounded, Sender};
use frida_gum::{Module, NativePointer, Process};
use crate::GLOBAL_STREAM;
use prost::Message;
use frida_gum::interceptor::{Interceptor, InvocationContext, InvocationListener};

// 寄存器变化记录（只记录有变化的寄存器）
#[derive(Clone, PartialEq, Message)]
struct RegChange {
    #[prost(uint32, tag = "1")]
    reg_num: u32,        // 寄存器编号 (0-28 对应 X0-X28)
    #[prost(uint64, tag = "2")]
    value: u64,          // 寄存器值
}

// 原始指令消息（在通道中传输，包含完整寄存器）
#[derive(Clone)]
struct RawInstrMessage {
    addr: u64,
    bytes: Vec<u8>,
    module: String,
    regs: [u64; 32],     // 完整的寄存器值（X0-X28 + FP + LR + SP，用于后台比对）
}

// 定义指令跟踪消息（最终写入文件的 protobuf 格式）
#[derive(Clone, PartialEq, Message)]
struct InstrMessage {
    #[prost(uint64, tag = "1")]
    addr: u64,
    #[prost(bytes, tag = "2")]
    bytes: Vec<u8>,      // ARM64 指令字节码（4字节）
    #[prost(message, repeated, tag = "3")]
    ctx: Vec<RegChange>, // 只记录变化的寄存器
}

// 内存区域信息
#[derive(Clone, PartialEq, Message)]
struct MemoryRegion {
    #[prost(uint64, tag = "1")]
    start_addr: u64,
    #[prost(uint64, tag = "2")]
    end_addr: u64,
    #[prost(string, tag = "3")]
    permissions: String,
    #[prost(uint64, tag = "4")]
    offset: u64,
    #[prost(string, tag = "5")]
    dev: String,
    #[prost(uint64, tag = "6")]
    inode: u64,
    #[prost(string, tag = "7")]
    pathname: String,
    #[prost(bytes, tag = "8")]
    data: Vec<u8>,
}

// 内存快照
#[derive(Clone, PartialEq, Message)]
struct MemorySnapshot {
    #[prost(uint64, tag = "1")]
    timestamp: u64,
    #[prost(uint32, tag = "2")]
    pid: u32,
    #[prost(message, repeated, tag = "3")]
    regions: Vec<MemoryRegion>,
}


lazy_static! {
    static ref GUM: gum::Gum = unsafe { gum::Gum::obtain() };

    // 全局 map: 存储基本块地址 -> 指令数量的映射
    static ref BLOCK_COUNT_MAP: Mutex<HashMap<u64, usize>> = Mutex::new(HashMap::new());

    // 创建有界通道（限制内存占用，容量 10000 条消息，约 2.5MB）
    static ref INSTR_SENDER: Sender<RawInstrMessage> = {
        let (sender, receiver) = bounded::<RawInstrMessage>(100000);

        // 启动后台工作线程
        thread::spawn(move || {
            // 打开或创建日志文件
            let log_path = "/data/data/com.example.tracersample/files/trace.log";
            let mut log_file = match OpenOptions::new()
                .create(true)
                .append(true)
                .open(log_path)
            {
                Ok(f) => f,
                Err(e) => {
                    eprintln!("无法打开日志文件 {}: {}", log_path, e);
                    return;
                }
            };

            // 后台线程的寄存器状态（用于比对）
            let mut prev_regs = [0u64; 32];

            while let Ok(raw_msg) = receiver.recv() {
                // 在后台线程中比对寄存器变化
                let mut changes = Vec::new();
                for i in 0..32 {
                    if raw_msg.regs[i] != prev_regs[i] {
                        changes.push(RegChange {
                            reg_num: i as u32,
                            value: raw_msg.regs[i],
                        });
                        prev_regs[i] = raw_msg.regs[i];
                    }
                }

                // 构造最终的 InstrMessage
                let msg = InstrMessage {
                    addr: raw_msg.addr,
                    bytes: raw_msg.bytes.clone(),
                    ctx: changes,
                };

                // 使用 protobuf 的 length-delimited 编码（变长编码）
                let mut buf = Vec::new();
                if let Err(e) = msg.encode_length_delimited(&mut buf) {
                    eprintln!("Protobuf 编码失败: {}", e);
                    continue;
                }

                // 写入日志文件（protobuf 自带长度前缀）
                if let Err(e) = log_file.write_all(&buf) {
                    eprintln!("写入 protobuf 数据失败: {}", e);
                    continue;
                }

                // 可选：同时输出可读格式到控制台
                unsafe {
                    if let Some(mut stream) = GLOBAL_STREAM.get() {
                        let output = format!(
                            "0x{:x}: [{:02x} {:02x} {:02x} {:02x}] {} (changed: {} regs)\n",
                            raw_msg.addr,
                            raw_msg.bytes.get(0).unwrap_or(&0),
                            raw_msg.bytes.get(1).unwrap_or(&0),
                            raw_msg.bytes.get(2).unwrap_or(&0),
                            raw_msg.bytes.get(3).unwrap_or(&0),
                            raw_msg.module,
                            msg.ctx.len()
                        );
                        let _ = stream.write_all(output.as_bytes());
                    }
                }
            }
        });

        sender
    };
}

// 解析 /proc/self/maps 中的单行
fn parse_maps_line(line: &str) -> Option<(u64, u64, String, u64, String, u64, String)> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 5 {
        return None;
    }

    // 解析地址范围
    let addr_range: Vec<&str> = parts[0].split('-').collect();
    if addr_range.len() != 2 {
        return None;
    }
    let start_addr = u64::from_str_radix(addr_range[0], 16).ok()?;
    let end_addr = u64::from_str_radix(addr_range[1], 16).ok()?;

    // 权限
    let permissions = parts[1].to_string();

    // 偏移
    let offset = u64::from_str_radix(parts[2], 16).ok()?;

    // 设备号
    let dev = parts[3].to_string();

    // inode
    let inode = parts[4].parse::<u64>().ok()?;

    // 路径名（可能不存在）
    let pathname = if parts.len() > 5 {
        parts[5..].join(" ")
    } else {
        String::new()
    };

    Some((start_addr, end_addr, permissions, offset, dev, inode, pathname))
}

// 从 /proc/self/mem 读取指定地址范围的内存
fn read_memory_region(mem_file: &mut File, start_addr: u64, size: usize) -> std::io::Result<Vec<u8>> {
    let mut buffer = vec![0u8; size];
    mem_file.seek(SeekFrom::Start(start_addr))?;
    mem_file.read_exact(&mut buffer)?;
    Ok(buffer)
}

// Dump 内存快照到文件
fn dump_memory_snapshot(output_path: &str) -> std::io::Result<()> {
    // 读取 /proc/self/maps
    let maps_content = std::fs::read_to_string("/proc/self/maps")?;

    // 打开 /proc/self/mem
    let mut mem_file = File::open("/proc/self/mem")?;

    let mut regions = Vec::new();

    // 获取当前时间戳
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // 获取当前进程 PID
    let pid = std::process::id();

    // 解析每一行
    for line in maps_content.lines() {
        if let Some((start_addr, end_addr, permissions, offset, dev, inode, pathname)) = parse_maps_line(line) {
            // 只 dump 可读的内存区域
            if !permissions.starts_with('r') {
                continue;
            }

            let size = (end_addr - start_addr) as usize;

            // 读取内存数据（可能失败，例如某些特殊区域）
            let data = match read_memory_region(&mut mem_file, start_addr, size) {
                Ok(d) => d,
                Err(e) => {
                    eprintln!("无法读取内存区域 0x{:x}-0x{:x}: {}", start_addr, end_addr, e);
                    Vec::new() // 失败时使用空数据
                }
            };

            regions.push(MemoryRegion {
                start_addr,
                end_addr,
                permissions,
                offset,
                dev,
                inode,
                pathname,
                data,
            });
        }
    }

    // 创建内存快照
    let snapshot = MemorySnapshot {
        timestamp,
        pid,
        regions,
    };

    // 编码为 protobuf
    let mut buf = Vec::new();
    snapshot.encode(&mut buf).map_err(|e| {
        std::io::Error::new(std::io::ErrorKind::Other, format!("Protobuf 编码失败: {}", e))
    })?;

    // 写入文件
    let mut output_file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(output_path)?;

    output_file.write_all(&buf)?;

    Ok(())
}

struct SampleEventSink;

impl EventSink for SampleEventSink {
    fn query_mask(&mut self) -> EventMask {
        EventMask::None
    }

    fn start(&mut self) {
        println!("start");
    }

    fn process(&mut self, _event: &Event) {
        println!("process");
    }

    fn flush(&mut self) {
        println!("flush");
    }

    fn stop(&mut self) {
        println!("stop");
    }
}

pub fn follow(tid:usize) {
    // 在开始追踪前先 dump 内存快照
    let snapshot_path = "/data/data/com.zhenxi.hunter/files/memory_snapshot.pb";
    match dump_memory_snapshot(snapshot_path) {
        Ok(_) => {
            unsafe {
                if let Some(mut stream) = GLOBAL_STREAM.get() {
                    let _ = stream.write_all(format!("内存快照已保存到: {}\n", snapshot_path).as_bytes());
                }
            }
        }
        Err(e) => {
            unsafe {
                if let Some(mut stream) = GLOBAL_STREAM.get() {
                    let _ = stream.write_all(format!("内存快照保存失败: {}\n", e).as_bytes());
                }
            }
        }
    }

    let mut stalker = Stalker::new(&GUM);

    let mut proc = Process::obtain(&GUM);

    // 存储模块信息：base -> (size, path, name)
    // let mut modules: BTreeMap<usize, (usize, String, String)> = BTreeMap::new();
    // for md in proc.enumerate_modules(){
    //     modules.insert(
    //         md.range().base_address().0 as usize,
    //         (md.range().size(), md.path(), md.name())
    //     );
    // }
    // let mut log_file = OpenOptions::new()
    //     .create(true)
    //     .append(true)
    //     .open("/data/data/com.example.tracersample/files/wwb.log")
    //     .expect("Failed to open log file");

    let transformer = Transformer::from_callback(&GUM,  |mut basic_block, _output| {

        // 迭代 basic_block 并计数
        // let mut count = 0;
        // let mut first_addr = 0u64;


        // let mut first = true;
        //
        // for instr in basic_block {
        //
        //
        //     if first {
        //         let addr = instr.instr().address();  // addr 从 instr 获取
        //         first = false;
        //         // first_addr = addr;
        //
        //         // 在第一条指令处设置 callout
        //         instr.put_callout(move |cpu_context: CpuContext| {
        //             // 直接发送地址，不复制指令
        //             let _ = INSTR_SENDER.send(InstrMessage {
        //                 addr,
        //             });
        //         });
        //     }
        //
        //     // count += 1;
        //     instr.keep();
        // }

        // 将基本块起始地址和指令数量存入全局 map
        // if count > 0 {
        //     BLOCK_COUNT_MAP.lock().unwrap().insert(first_addr, count);
        // }



        for instr in basic_block {
            let addr = instr.instr().address();

            // 获取指令字节码（ARM64 指令固定 4 字节）
            let instr_bytes = instr.instr().bytes();
            let bytes = instr_bytes[0..4].to_vec();

            // 获取模块信息
            let (md_path, md_name) = match proc.find_module_by_address(addr as usize) {
                Some(m) => {
                    (m.path().to_string(), format!("{}+0x{:x}", m.name(), addr - m.range().base_address().0 as u64))
                },
                None => {
                    ("unknown".to_string(), "unknown".to_string())
                }
            };

            // 过滤系统模块
            if !(md_path.contains("apex") || md_path.contains("system") || md_path.contains("unknown")) {
                unsafe {
                    instr.put_callout(move |_cpu_context| {
                        // 直接读取寄存器值，不做任何比对（比对在后台线程进行）
                        let mut regs = [0u64; 32];
                        // 复制 X0-X28
                        regs[0..29].copy_from_slice(&(*_cpu_context.cpu_context).x);
                        // 添加 FP, LR, SP (索引 29, 30, 31)
                        regs[29] = _cpu_context.fp();
                        regs[30] = _cpu_context.lr();
                        regs[31] = _cpu_context.sp();

                        // 发送原始消息，使用 try_send 避免阻塞
                        // 如果通道满了，丢弃消息（牺牲完整性换取性能）
                        let _ = INSTR_SENDER.try_send(RawInstrMessage {
                            addr,
                            bytes: bytes.clone(),
                            module: md_name.clone(),
                            regs,
                        });
                    });
                }
            }
            instr.keep();
        }
    });

    // let mut event_sink = SampleEventSink;
    stalker.follow(tid,&transformer, Some(&mut SampleEventSink));
}

struct OpenListener;

impl InvocationListener for OpenListener {
    fn on_enter(&mut self, _context: InvocationContext) {
        GLOBAL_STREAM.get().unwrap().write_all(format!("begin trace {}",_context.thread_id()).as_bytes());
        follow(_context.thread_id() as usize);
    }

    fn on_leave(&mut self, _context: InvocationContext) {
        GLOBAL_STREAM.get().unwrap().write_all("end trace".as_bytes());
        Stalker::new(&GUM).unfollow(_context.thread_id() as usize);
    }
}

pub fn hfollow(lib:String,addr:usize) {
    let proc = Process::obtain(&GUM);
    let md = proc.find_module_by_name(lib.as_str()).unwrap();
    let target = md.range().base_address().0 as u64 + addr as u64;
    let mut listener = OpenListener {};
    let mut interceptor = Interceptor::obtain(&GUM);
    interceptor.attach(NativePointer(target as *mut c_void),&mut listener).unwrap();

}


