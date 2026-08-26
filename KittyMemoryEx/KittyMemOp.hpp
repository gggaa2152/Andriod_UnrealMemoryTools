#pragma once

#include "KittyUtils.hpp"
#include "KittyIOFile.hpp"

enum EKittyMemOP
{
    EK_MEM_OP_NONE = 0,
    EK_MEM_OP_SYSCALL,
    EK_MEM_OP_IO,
    EK_MEM_OP_DIRECT  // 进程内直读（Hook 注入模式）
};

class IKittyMemOp
{
protected:
    pid_t _pid;

public:
    IKittyMemOp() : _pid(0) {}
    virtual ~IKittyMemOp() = default;

    virtual bool init(pid_t pid) = 0;

    inline pid_t processID() const { return _pid; }

    virtual size_t Read(uintptr_t address, void *buffer, size_t len) const = 0;
    virtual size_t Write(uintptr_t address, void *buffer, size_t len) const = 0;

    std::string ReadStr(uintptr_t address, size_t maxLen);
    bool WriteStr(uintptr_t address, std::string str);
};

class KittyMemSys : public IKittyMemOp
{
public:
    bool init(pid_t pid);

    size_t Read(uintptr_t address, void *buffer, size_t len) const;
    size_t Write(uintptr_t address, void *buffer, size_t len) const;
};

class KittyMemIO : public IKittyMemOp
{
private:
    std::unique_ptr<KittyIOFile> _pMem;

public:
    bool init(pid_t pid);

    size_t Read(uintptr_t address, void *buffer, size_t len) const;
    size_t Write(uintptr_t address, void *buffer, size_t len) const;
};

// ============ 进程内直读（Hook 注入模式专用） ============
// 本模式下工具以 .so 注入到目标游戏进程内部，
// 无需跨进程系统调用，直接对自身地址空间进行读写。
class KittyMemDirect : public IKittyMemOp
{
public:
    bool init(pid_t pid);

    size_t Read(uintptr_t address, void *buffer, size_t len) const;
    size_t Write(uintptr_t address, void *buffer, size_t len) const;
};