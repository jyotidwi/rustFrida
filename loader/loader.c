#include <stdint.h>
#include <sys/types.h>
#include <dlfcn.h>
#include <pthread.h>

// 定义字符串表结构体，与main.rs中的完全一致
typedef struct {
    uint64_t sym_name;
    uint32_t sym_name_len;

    uint64_t pthread_err;
    uint32_t pthread_err_len;

    uint64_t dlsym_err;
    uint32_t dlsym_err_len;

    uint64_t cmdline;
    uint32_t cmdline_len;

    uint64_t output_path;
    uint32_t output_path_len;
} StringTable;

// 定义与main.rs中相同的结构体（字段顺序必须完全一致）
typedef struct {
    uintptr_t malloc;      // 用于分配内存
    uintptr_t free;        // 用于释放内存
    uintptr_t socketpair;  // 用于创建已连接的套接字对
    uintptr_t write;       // 用于发送数据
    uintptr_t close;       // 用于关闭套接字
    uintptr_t mmap;        // 用于内存映射
    uintptr_t munmap;
    uintptr_t memfd_create; // 用于创建匿名内存文件
    uintptr_t pthread_create; // 用于创建线程
    uintptr_t pthread_detach; // 用于分离线程
    uintptr_t strlen;
} LibcOffsets;

typedef struct {
    uintptr_t dlopen;   // 动态加载
    uintptr_t dlsym;    // 动态符号查找
    uintptr_t dlerror;
    uintptr_t android_dlopen_ext;  // fd-based dlopen (绕过 SELinux path 检查)
} DlOffsets;

// 注入参数结构体（与 Rust AgentArgs 完全一致）
typedef struct {
    uint64_t table;    // *const StringTable（目标进程内地址）
    int32_t  ctrl_fd;  // socketpair fd1（agent 端）
    int32_t  agent_memfd; // 目标进程内的 agent.so memfd
} AgentArgs;

// 定义函数指针类型
typedef void (*free_t)(void*);
typedef ssize_t (*write_t)(int, const void*, size_t);
typedef int (*close_t)(int);

// android_dlopen_ext for fd-based loading (bypasses SELinux path check)
#define ANDROID_DLEXT_USE_LIBRARY_FD 0x10
typedef struct {
    uint64_t flags;
    void*    reserved_addr;
    size_t   reserved_size;
    int      relro_fd;
    int      library_fd;
    off_t    library_fd_offset;
    void*    library_namespace;
} android_dlextinfo;
typedef void* (*android_dlopen_ext_t)(const char*, int, const android_dlextinfo*);

typedef int (*pthread_create_t)(pthread_t*, const pthread_attr_t*, void* (*)(void*), void*);
typedef int (*pthread_detach_t)(pthread_t);
typedef void* (*dlsym_t)(void*, const char*);
typedef char* (*dlerror_t)();
typedef size_t (*strlen_t)(const char *);

int shellcode_entry(LibcOffsets* offsets, DlOffsets* dl, StringTable* table, AgentArgs* agent_args) {
    // 定义函数指针
    free_t free = (free_t)offsets->free;
    write_t write = (write_t)offsets->write;
    close_t close = (close_t)offsets->close;
    android_dlopen_ext_t android_dlopen_ext = (android_dlopen_ext_t)dl->android_dlopen_ext;
    dlsym_t dlsym = (dlsym_t)dl->dlsym;
    dlerror_t dlerror = (dlerror_t)dl->dlerror;
    pthread_create_t pthread_create = (pthread_create_t)offsets->pthread_create;
    pthread_detach_t pthread_detach = (pthread_detach_t)offsets->pthread_detach;
    strlen_t strlen = (strlen_t)offsets->strlen;

    // 获取字符串引用 (现在所有字符串都已经有 NULL 结尾)
    const char* sym_name = (const char*)table->sym_name;
    // 符号名可以直接作为 C 字符串使用，因为已有 NULL 结尾

    const char* pthread_err = (const char*)table->pthread_err;
    size_t pthread_err_len = table->pthread_err_len - 1; // 减去 NULL 结尾

    const char* dlsym_err = (const char*)table->dlsym_err;
    size_t dlsym_err_len = table->dlsym_err_len - 1; // 减去 NULL 结尾

    int ctrl_fd = agent_args->ctrl_fd;
    int memfd = agent_args->agent_memfd;

    // 使用 android_dlopen_ext fd-based 加载，绕过 SELinux path 检查
    // 手动清零 (shellcode 不能调用 memset)
    android_dlextinfo ext_info;
    {
        char *p = (char *)&ext_info;
        for (unsigned i = 0; i < sizeof(ext_info); i++) p[i] = 0;
    }
    ext_info.flags = ANDROID_DLEXT_USE_LIBRARY_FD;
    ext_info.library_fd = memfd;
    ext_info.library_fd_offset = 0;

    // 需要传非NULL文件名，否则 linker 返回主程序 handle
    char lib_name[10];
    lib_name[0] = 'a'; lib_name[1] = 'g'; lib_name[2] = 'e';
    lib_name[3] = 'n'; lib_name[4] = 't'; lib_name[5] = '.';
    lib_name[6] = 's'; lib_name[7] = 'o'; lib_name[8] = '\0';
    void* handle = android_dlopen_ext(lib_name, RTLD_NOW, &ext_info);
    if (!handle) {
        char* msg = dlerror();
        write(ctrl_fd, msg, strlen(msg));
        close(memfd);
        close(ctrl_fd);
        free(offsets);
        free(dl);
        free(table);
        return -5;
    }

    // 查找符号 (sym_name 已有 NULL 结尾，可直接使用)
    void* sym = dlsym(handle, sym_name);

    if (sym) {
        pthread_t tid;
        // 传递 agent_args 作为参数给 hello_entry（包含 table 指针和 ctrl_fd）
        if (pthread_create(&tid, NULL, sym, (void*)agent_args) == 0) {
            pthread_detach(tid);
        } else {
            // 发送线程创建失败消息
            write(ctrl_fd, pthread_err, pthread_err_len);
            close(ctrl_fd);
            close(memfd);
            free(offsets);
            free(dl);
            free(table);
            free(agent_args);
            return -6;
        }
    } else {
        // 发送符号查找失败消息
        write(ctrl_fd, dlsym_err, dlsym_err_len);
        close(ctrl_fd);
        close(memfd);
        free(offsets);
        free(dl);
        free(table);
        free(agent_args);
        return -7;
    }

    close(memfd);
    free(offsets);
    free(dl);
    // 不释放 table 和 agent_args（agent 线程继续使用）
    // 不关闭 ctrl_fd（agent 线程继续使用）
    return 1;
}

