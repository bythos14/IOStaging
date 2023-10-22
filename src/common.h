#pragma once

#include <psp2kern/types.h>
#include <psp2kern/kernel/dmac.h>
#include <psp2kern/kernel/debug.h>
#include <psp2kern/kernel/sysmem.h>

#include <string.h>

#define CONFIG_PATH "ur0:data/iostaging.cfg"

#define LOG(msg, ...) ksceKernelPrintf("[IOStaging] - %s: "msg, __FUNCTION__, ##__VA_ARGS__)

#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define MAX(a, b) ((a) > (b) ? (a) : (b))
#define ALIGN(a,b) (((a) + ((b) - 1)) & ~((b) - 1))

#define DEFAULT_SDIF_BUFFER_SIZE (128 * 1024)
#define DEFAULT_MSIF_BUFFER_SIZE (0) //MSIF Staging disabled by default
#define DEFAULT_OVERCLOCK_MSIF (SCE_FALSE) 

#define SDIF_BUFFER_SIZE (config.sdBufSize)
#define MSIF_BUFFER_SIZE (config.msBufSize)
#define OVERCLOCK_MSIF (config.overclockMsif)

typedef struct StagingConfig
{
    SceUInt32 sdBufSize;
    SceUInt32 msBufSize;
    SceBool overclockMsif;
} StagingConfig;

extern StagingConfig config;

#define IO_BUFFER_BLOCK_TYPE (SCE_KERNEL_MEMBLOCK_TYPE_KERNEL_TMP_NC_RW)

typedef struct StagingBuffer
{
    SceUID memBlock;
    void *base;
    SceUIntPtr paddr;
    SceSize size;
} StagingBuffer;

static inline void CopyBuffer(void *dst, const void *src, SceSize len)
{
    if (len < 4096)
        memcpy(dst, src, len);
    else
        ksceDmacMemcpy(dst, src, len);
}

static inline int InitStagingBuffer(StagingBuffer *stagingBuf, SceSize size)
{
    SceKernelAllocMemBlockKernelOpt opt = {0};
    opt.size = sizeof(opt);
    opt.attr = SCE_KERNEL_ALLOC_MEMBLOCK_ATTR_PHYCONT;
    stagingBuf->memBlock = ksceKernelAllocMemBlock("IOStagingBuf", IO_BUFFER_BLOCK_TYPE, ALIGN(size, 4096), &opt);
    if (stagingBuf->memBlock < 0)
    {
        LOG("Failed to allocate staging buffer (0x%08X)\n", stagingBuf->memBlock);
        return -1;
    }

    ksceKernelGetMemBlockBase(stagingBuf->memBlock, &stagingBuf->base);
    ksceKernelVAtoPA(stagingBuf->base, &stagingBuf->paddr);

    stagingBuf->size = size;

    return 0;
}

static inline void TermStagingBuffer(StagingBuffer *stagingBuf)
{
    if (stagingBuf->memBlock > 0)
        ksceKernelFreeMemBlock(stagingBuf->memBlock);

    memset(stagingBuf, 0, sizeof(StagingBuffer));
}

int InitMsifStaging();
void TermMsifStaging();

int InitSdifStaging();
void TermSdifStaging();