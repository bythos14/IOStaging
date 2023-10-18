#include <psp2kern/kernel/cpu.h>
#include <psp2kern/kernel/dmac.h>
#include <psp2kern/kernel/modulemgr.h>
#include <psp2kern/kernel/sysmem.h>
#include <psp2kern/kernel/threadmgr.h>
#include <psp2kern/kernel/debug.h>
#include <taihen.h>

#include "common.h"

typedef struct SceSdifAdmaDescriptor
{
    SceUInt16 cmd;
    SceUInt16 size;
    SceUIntPtr addr;
} SceSdifAdmaDescriptor;

typedef struct SdifCommand
{
    SceSize size;
    SceUInt32 flags;
    SceUInt32 cmd;
    SceUInt32 argument;
    SceUInt32 response[4];
    void *buffer;
    SceUInt16 blockSize;
    SceUInt16 blockCount;
    SceUInt32 errorCode;
    SceUInt32 field9_0x2c[13];
    struct SdifCommand *pNext;
    SceUInt32 field11_0x64;
    SceUInt32 commandIndex;
    void *pCallback;
    SceUID evfId;
    struct SdifCommand *pSecondaryCmd;
    void *pContext;
    SceUInt32 descAreaPhyAddr;
    SceSdifAdmaDescriptor defaultDescArea[16];
    void *pDescArea;
    struct SceKernelPARange paRange;
    SceUInt32 unk_0x10c;
    SceUInt32 field22_0x110[29];
    SceUInt32 defaultDescAreaPhyAddr;
    SceUID dmaDescBlock;
    SceUInt32 field25_0x18c[3];
    void *alignedAddr;
    SceUInt32 alignedLength;
    SceUInt32 unalignedHeadLength;
    SceUInt32 unalignedTailLength;
    SceUInt32 unalignedHeadPhyAddr;
    SceUInt32 unalignedTailPhyAddr;
    SceUInt64 timestamp;
    SceUInt32 field33_0x1b8[2];
    SceUInt8 unalignedHeadBuffer[64];
    SceUInt8 unalignedTailBuffer[64];
} SdifCommand;

static tai_hook_ref_t hookRefs[2];
static SceUID hookIds[2];
static SceUID patchIds[2];
static StagingContext stagingBuf;
static void *segmentBase[2];

static int (*FUN_810017E8)(void *sdifContext, SdifCommand *primaryCmd, SdifCommand *secondaryCmd, SceUInt maxRetries, SceUInt unk);

int module_get_offset(SceUID pid, SceUID modid, int segidx, size_t offset, uintptr_t *addr);

uint32_t EncodeBl(uint32_t patch_offset, uint32_t target_offset)
{
#define THUMB_SHUFFLE(x) ((((x)&0xFFFF0000) >> 16) | (((x)&0xFFFF) << 16))

    uint32_t displacement = target_offset - (patch_offset & ~0x1) - 4;
    uint32_t signbit = (displacement >> 31) & 0x1;
    uint32_t i1 = (displacement >> 23) & 0x1;
    uint32_t i2 = (displacement >> 22) & 0x1;
    uint32_t imm10 = (displacement >> 12) & 0x03FF;
    uint32_t imm11 = (displacement >> 1) & 0x07FF;
    uint32_t j1 = i1 ^ (signbit ^ 1);
    uint32_t j2 = i2 ^ (signbit ^ 1);
    uint32_t value = (signbit << 26) | (j1 << 13) | (j2 << 11) | (imm10 << 16) | imm11;
    value |= 0xF000D000; // BL
    return THUMB_SHUFFLE(value);
}

static int _sceSdifReadSectorSd(void *sdifCtx, SceUInt32 sector, void *base, SceUInt32 nSectors)
{
    if (nSectors <= (SDIF_BUFFER_SIZE >> 9))
        return TAI_CONTINUE(int, hookRefs[0], sdifCtx, sector, base, nSectors);

    int ret;
    while (nSectors != 0)
    {
        ret = TAI_CONTINUE(int, hookRefs[0], sdifCtx, sector, base, MIN(nSectors, SDIF_BUFFER_SIZE >> 9));
        if (ret != 0)
            break;

        base += MIN(nSectors << 9, SDIF_BUFFER_SIZE);
        sector += MIN(nSectors, SDIF_BUFFER_SIZE >> 9);
        nSectors -= MIN(nSectors, SDIF_BUFFER_SIZE >> 9);
    }

    return ret;
}

static int _sceSdifWriteSectorSd(void *sdifCtx, SceUInt32 sector, void *base, SceUInt32 nSectors)
{
    if (nSectors <= (SDIF_BUFFER_SIZE >> 9))
        return TAI_CONTINUE(int, hookRefs[1], sdifCtx, sector, base, nSectors);

    int ret;
    while (nSectors != 0)
    {
        ret = TAI_CONTINUE(int, hookRefs[1], sdifCtx, sector, base, MIN(nSectors, SDIF_BUFFER_SIZE >> 9));
        if (ret != 0)
            break;

        base += MIN(nSectors << 9, SDIF_BUFFER_SIZE);
        sector += MIN(nSectors, SDIF_BUFFER_SIZE >> 9);
        nSectors -= MIN(nSectors, SDIF_BUFFER_SIZE >> 9);
    }

    return ret;
}

static void SetupCommands(void *sdifContext, SdifCommand *primaryCmd, SdifCommand *secondaryCmd)
{
    SceSdifAdmaDescriptor *desc;
    SceSize dmaSize, descCount;

    primaryCmd->pContext = sdifContext;
    primaryCmd->evfId = *(SceUID *)(sdifContext + 0x2440);
    primaryCmd->pSecondaryCmd = secondaryCmd;
    primaryCmd->pCallback = segmentBase[0] + 0x85;

    if (primaryCmd->flags & 0x400)
    {
        primaryCmd->flags &= 0xffefffff;
        primaryCmd->unalignedHeadLength = 0;
        primaryCmd->unalignedTailLength = 0;
        primaryCmd->alignedLength = 0;
        primaryCmd->descAreaPhyAddr = primaryCmd->defaultDescAreaPhyAddr;

        desc = &primaryCmd->defaultDescArea[0];
        dmaSize = primaryCmd->blockCount * primaryCmd->blockSize;
        descCount = 0;
        while (dmaSize != 0)
        {
            desc[descCount].addr = stagingBuf.paddr;
            desc[descCount].cmd = 0x21;
            desc[descCount].size = MIN(dmaSize, 0x10000);
            descCount++;
            dmaSize -= MIN(dmaSize, 0x10000);
        }
        desc[descCount - 1].cmd |= 0x2;
        ksceKernelCpuDcacheAndL2WritebackRange(desc, sizeof(SceSdifAdmaDescriptor) * descCount);
    }

    if (secondaryCmd != 0)
    {
        primaryCmd->pCallback = NULL;
        secondaryCmd->pContext = sdifContext;
        secondaryCmd->evfId = *(SceUID *)(sdifContext + 0x2440);
        secondaryCmd->pSecondaryCmd = NULL;
        secondaryCmd->pCallback = segmentBase[0] + 0x85;

        if (secondaryCmd->flags & 0x400)
        {
            secondaryCmd->flags &= 0x3fefffff;
            secondaryCmd->unalignedHeadLength = 0;
            secondaryCmd->unalignedTailLength = 0;
            secondaryCmd->alignedLength = 0;
            secondaryCmd->descAreaPhyAddr = secondaryCmd->defaultDescAreaPhyAddr;

            desc = &secondaryCmd->defaultDescArea[0];
            dmaSize = secondaryCmd->blockCount * secondaryCmd->blockSize;
            descCount = 0;
            while (dmaSize != 0)
            {
                desc[descCount].addr = stagingBuf.paddr;
                desc[descCount].cmd = 0x21;
                desc[descCount].size = MIN(dmaSize, 0x10000);
                descCount++;
                dmaSize -= MIN(dmaSize, 0x10000);
            }
            desc[descCount - 1].cmd |= 0x2;
            ksceKernelCpuDcacheAndL2WritebackRange(desc, sizeof(SceSdifAdmaDescriptor) * descCount);
        }
    }
}

int ReadSectorSd(void *sdifContext, SdifCommand *primaryCmd, SdifCommand *secondaryCmd, SceUInt maxRetries)
{
    int ret;
    if (*(SceUInt8 *)(sdifContext + 0x2425) == 0)
    {
        if ((ret = ksceKernelLockFastMutex((SceKernelFastMutex *)(sdifContext + 0x2444))) < 0)
            return ret;

        ksceKernelLockFastMutex((SceKernelFastMutex *)(sdifContext + 0x2444)); // Double lock, as FUN_810017E8 unlocks it internallly
    }

    SetupCommands(sdifContext, primaryCmd, secondaryCmd);

    ret = FUN_810017E8(sdifContext, primaryCmd, secondaryCmd, maxRetries, 1);
    if (ret < 0)
    {
        ksceKernelUnlockFastMutex((SceKernelFastMutex *)(sdifContext + 0x2444));
        return ret;
    }

    if (primaryCmd->blockCount * primaryCmd->blockSize < 4096) // Safe to assume standard memcpy will be faster for small copies due to DMA overhead
        memcpy(primaryCmd->buffer, stagingBuf.base, primaryCmd->blockCount * primaryCmd->blockSize);
    else
        ksceDmacMemcpy(primaryCmd->buffer, stagingBuf.base, primaryCmd->blockCount * primaryCmd->blockSize);

    ksceKernelUnlockFastMutex((SceKernelFastMutex *)(sdifContext + 0x2444));

    return 0;
}

int WriteSectorSd(void *sdifContext, SdifCommand *primaryCmd, SdifCommand *secondaryCmd, SceUInt maxRetries)
{
    int ret;
    if (*(SceUInt8 *)(sdifContext + 0x2425) == 0)
    {
        if ((ret = ksceKernelLockFastMutex((SceKernelFastMutex *)(sdifContext + 0x2444))) < 0)
            return ret;
    }

    SetupCommands(sdifContext, primaryCmd, secondaryCmd);

    if (primaryCmd->blockCount * primaryCmd->blockSize < 4096)
        memcpy(stagingBuf.base, primaryCmd->buffer, primaryCmd->blockCount * primaryCmd->blockSize);
    else
        ksceDmacMemcpy(stagingBuf.base, primaryCmd->buffer, primaryCmd->blockCount * primaryCmd->blockSize);

    return FUN_810017E8(sdifContext, primaryCmd, secondaryCmd, maxRetries, 1);
}

int InitSdifStaging()
{
    tai_module_info_t moduleInfo = {0};
    SceKernelAllocMemBlockKernelOpt opt = {0};
    uint32_t bl;

    moduleInfo.size = sizeof(moduleInfo);
    taiGetModuleInfoForKernel(KERNEL_PID, "SceSdif", &moduleInfo);

    opt.size = sizeof(opt);
    opt.attr = SCE_KERNEL_ALLOC_MEMBLOCK_ATTR_PHYCONT;
    stagingBuf.memBlock = ksceKernelAllocMemBlock("SdifStagingBuf", IO_BUFFER_BLOCK_TYPE, SDIF_BUFFER_SIZE, &opt);
    if (stagingBuf.memBlock < 0)
    {
        ksceKernelPrintf("[SDIF_STAGING] - Failed to allocate staging buffer (0x%08X)\n", stagingBuf.memBlock);
        return -1;
    }

    ksceKernelGetMemBlockBase(stagingBuf.memBlock, &stagingBuf.base);

    ksceKernelVAtoPA(stagingBuf.base, &stagingBuf.paddr);

    module_get_offset(KERNEL_PID, moduleInfo.modid, 0, 0, (uintptr_t *)&segmentBase[0]);
    module_get_offset(KERNEL_PID, moduleInfo.modid, 1, 0, (uintptr_t *)&segmentBase[1]);

    FUN_810017E8 = segmentBase[0] + 0x17E9;

    hookIds[0] = taiHookFunctionExportForKernel(KERNEL_PID, &hookRefs[0], "SceSdif", 0x96D306FA, 0xB9593652, _sceSdifReadSectorSd);
    hookIds[1] = taiHookFunctionExportForKernel(KERNEL_PID, &hookRefs[1], "SceSdif", 0x96D306FA, 0xE0781171, _sceSdifWriteSectorSd);

    bl = EncodeBl((uintptr_t)segmentBase[0] + 0x6E54, (uintptr_t)&ReadSectorSd);
    patchIds[0] = taiInjectDataForKernel(KERNEL_PID, moduleInfo.modid, 0, 0x6E54, &bl, 4);

    bl = EncodeBl((uintptr_t)segmentBase[0] + 0x6F3E, (uintptr_t)&WriteSectorSd);
    patchIds[1] = taiInjectDataForKernel(KERNEL_PID, moduleInfo.modid, 0, 0x6F3E, &bl, 4);

    return 0;
}