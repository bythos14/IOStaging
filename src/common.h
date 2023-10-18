#pragma once

#include <psp2kern/types.h>
#include <psp2kern/kernel/sysmem/memtype.h>

#define MIN(a, b) ((a) < (b) ? (a) : (b))

#define SDIF_BUFFER_SIZE (128 * 1024)
#define MSIF_BUFFER_SIZE (128 * 1024)

#define IO_BUFFER_BLOCK_TYPE (SCE_KERNEL_MEMBLOCK_TYPE_KERNEL_TMP_NC_RW)

typedef struct StagingContext
{
    SceUID memBlock;
    void *base;
    SceUIntPtr paddr;
} StagingContext;