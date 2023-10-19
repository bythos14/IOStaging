#pragma once

#include <psp2kern/types.h>
#include <psp2kern/kernel/dmac.h>
#include <psp2kern/kernel/debug.h>
#include <psp2kern/kernel/sysmem.h>
#include <string.h>

#define MIN(a, b) ((a) < (b) ? (a) : (b))

#define SDIF_BUFFER_SIZE (128 * 1024)
#define MSIF_BUFFER_SIZE (128 * 1024)

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
    stagingBuf->memBlock = ksceKernelAllocMemBlock("IOStagingBuf", IO_BUFFER_BLOCK_TYPE, size, &opt);
    if (stagingBuf->memBlock < 0)
    {
        ksceKernelPrintf("InitStagingBuffer: Failed to allocate staging buffer (0x%08X)\n", stagingBuf->memBlock);
        return -1;
    }

    ksceKernelGetMemBlockBase(stagingBuf->memBlock, &stagingBuf->base);
    ksceKernelVAtoPA(stagingBuf->base, &stagingBuf->paddr);

    stagingBuf->size = size;

    return 0;
}