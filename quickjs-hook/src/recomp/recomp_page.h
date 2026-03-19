/*
 * recompiler.h - ARM64 页级代码重编译器
 *
 * 将一页 ARM64 代码从 orig_base 重编译到 recomp_base，保持 1:1 偏移映射。
 * PC 相对指令自动调整立即数；超出范围的指令通过跳板(trampoline)处理。
 *
 * 设计原则：
 *   - 重编译页中每条指令与原始页保持相同偏移（内核直接 PC += delta）
 *   - 页内分支（B/BL/B.cond/CBZ 等目标在同页内）直接复制（偏移不变）
 *   - 页外 PC 相对引用（ADR/ADRP/LDR literal）始终指向原始地址
 *   - 超出立即数范围的指令替换为 B/BL 跳转到跳板区
 */

#ifndef RECOMP_PAGE_H
#define RECOMP_PAGE_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define RECOMP_PAGE_SIZE  4096
#define RECOMP_INSN_COUNT (RECOMP_PAGE_SIZE / 4)

/* 重编译统计 */
typedef struct {
    int num_copied;         /* 非 PC 相对指令，直接复制 */
    int num_intra_page;     /* 页内分支，直接复制 */
    int num_direct_reloc;   /* PC 相对指令，直接调整立即数 */
    int num_trampolines;    /* 需要跳板的指令 */
    int error;              /* 非零表示出错 */
    char error_msg[256];    /* 错误信息 */
} RecompileStats;

/*
 * 重编译一页 ARM64 代码
 *
 * @param orig_code     原始页数据的可读副本（RECOMP_PAGE_SIZE 字节）
 * @param orig_base     原始页在目标进程的虚拟地址（页对齐）
 * @param recomp_buf    输出：重编译代码缓冲区（RECOMP_PAGE_SIZE 字节，可写）
 * @param recomp_base   重编译页将被映射到的虚拟地址（页对齐）
 * @param tramp_buf     输出：跳板代码缓冲区（可写）
 * @param tramp_base    跳板缓冲区的虚拟地址
 * @param tramp_cap     跳板缓冲区容量（字节）
 * @param tramp_used    输出：跳板区已使用字节数
 * @param stats         输出：统计信息（可为 NULL）
 * @return              0 成功，-1 失败
 */
int recompile_page(
    const void* orig_code,
    uint64_t orig_base,
    void* recomp_buf,
    uint64_t recomp_base,
    void* tramp_buf,
    uint64_t tramp_base,
    size_t tramp_cap,
    size_t* tramp_used,
    RecompileStats* stats
);

#ifdef __cplusplus
}
#endif

#endif /* RECOMPILER_H */
