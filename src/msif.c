#include <psp2kern/kernel/cpu.h>
#include <psp2kern/kernel/dmac.h>
#include <psp2kern/kernel/modulemgr.h>
#include <psp2kern/kernel/sysmem.h>
#include <psp2kern/kernel/threadmgr.h>
#include <psp2kern/kernel/debug.h>
#include <taihen.h>

#include "common.h"

typedef struct SceMsifAdmaDescriptor
{
    SceUIntPtr addr;
    SceUIntPtr next;
    uint16_t size;
    uint16_t attr;
} SceMsifAdmaDescriptor;

typedef struct MsifStagingBuffer
{
    StagingBuffer head;
    void *dmaBuf;
    SceSize dmaSize;
    SceBool dmaBypass;
    SceMsifAdmaDescriptor *descArea;
    SceUIntPtr descAreaPAddr;
    uint32_t *alignSizes;
} MsifStagingBuffer;

static tai_hook_ref_t hookRefs[6];
static SceUID hookIds[6];
static MsifStagingBuffer stagingBuf;

int module_get_offset(SceUID pid, SceUID modid, int segidx, size_t offset, uintptr_t *addr);

static int _sceMsifReadSector(SceUInt32 sector, void *base, SceUInt32 nSectors)
{
    if (nSectors <= (MSIF_BUFFER_SIZE >> 9))
        return TAI_CONTINUE(int, hookRefs[0], sector, base, nSectors);

    int ret;
    while (nSectors != 0)
    {
        ret = TAI_CONTINUE(int, hookRefs[0], sector, base, MIN(nSectors, MSIF_BUFFER_SIZE >> 9));
        if (ret != 0)
            break;

        base += MIN(nSectors << 9, MSIF_BUFFER_SIZE);
        sector += MIN(nSectors, MSIF_BUFFER_SIZE >> 9);
        nSectors -= MIN(nSectors, MSIF_BUFFER_SIZE >> 9);
    }

    return ret;
}

static int _sceMsifWriteSector(SceUInt32 sector, void *base, SceUInt32 nSectors)
{
    if (nSectors <= (MSIF_BUFFER_SIZE >> 9))
        return TAI_CONTINUE(int, hookRefs[1], sector, base, nSectors);

    int ret;
    while (nSectors != 0)
    {
        ret = TAI_CONTINUE(int, hookRefs[1], sector, base, MIN(nSectors, MSIF_BUFFER_SIZE >> 9));
        if (ret != 0)
            break;

        base += MIN(nSectors << 9, MSIF_BUFFER_SIZE);
        sector += MIN(nSectors, MSIF_BUFFER_SIZE >> 9);
        nSectors -= MIN(nSectors, MSIF_BUFFER_SIZE >> 9);
    }

    return ret;
}

static int _sceMsifPrepareDmaTable(void *base, SceSize len, SceBool write)
{
    SceMsifAdmaDescriptor *desc = stagingBuf.descArea;
    SceUIntPtr dmaAddr = stagingBuf.head.paddr, descAddr = stagingBuf.descAreaPAddr;
    SceSize dmaSize, descCount = 0;

    stagingBuf.dmaBuf = base;
    stagingBuf.dmaSize = len;
    stagingBuf.dmaBypass = SCE_TRUE;

    while (len != 0)
    {
        dmaSize = MIN(len, 0x40000);

        if (descCount != 0)
            desc[descCount - 1].next = descAddr + (sizeof(SceMsifAdmaDescriptor) * descCount);

        desc[descCount].addr = dmaAddr;
        desc[descCount].next = 0;
        desc[descCount].size = dmaSize >> 2;
        desc[descCount].attr = 0xC000;

        if ((dmaSize & 0x3f) == 0)
            desc[descCount].attr |= 0x7; // 64 bytes aligned
        else if ((dmaSize & 0x1f) == 0)
            desc[descCount].attr |= 0x5; // 32 bytes aligned
        else if ((dmaSize & 0xf) == 0)
            desc[descCount].attr |= 0x3; // 16 bytes aligned

        dmaAddr += dmaSize;
        len -= dmaSize;
        descCount++;
    }

    if (descCount != 0)
        desc[descCount - 1].attr &= ~0x4000;

    ksceKernelDcacheCleanRange(desc, descCount * sizeof(SceMsifAdmaDescriptor));

    stagingBuf.alignSizes[0] = 0;
    stagingBuf.alignSizes[1] = 0;
    stagingBuf.alignSizes[2] = 0;

    return 0;
}

static int _msproal_read_sectors(void *pCtx, SceUInt32 sector, SceUInt32 count, SceMsifAdmaDescriptor *descriptorBase)
{
    int ret = TAI_CONTINUE(int, hookRefs[3], pCtx, sector, count, descriptorBase);

    if (stagingBuf.dmaBypass && ret == 0)
    {
        CopyBuffer(stagingBuf.dmaBuf, stagingBuf.head.base, stagingBuf.dmaSize);

        stagingBuf.dmaBypass = SCE_FALSE;
    }

    return ret;
}

static int _msproal_write_sectors(void *pCtx, SceUInt32 sector, SceUInt32 count, SceMsifAdmaDescriptor *descriptorBase)
{
    if (stagingBuf.dmaBypass)
        CopyBuffer(stagingBuf.head.base, stagingBuf.dmaBuf, stagingBuf.dmaSize);

    int ret = TAI_CONTINUE(int, hookRefs[4], pCtx, sector, count, descriptorBase);

    if (ret == 0 && stagingBuf.dmaBypass)
        stagingBuf.dmaBypass = SCE_FALSE;

    return ret;
}

void kscePervasiveMsifSetClock(int clock);
int kscePervasiveRemovableMemoryGetCardInsertState();

static void SetMsifClock(void *pCtx, SceUInt32 unk)
{
    SceUInt16 regValue = *(SceUInt16 *)(*(void **)(pCtx + 0xC00) + 0xC);

    if (unk == 1)
        regValue = (regValue & ~0xC0) | 0x80; // Serial
    else if (unk == 5)
        regValue = (regValue & ~0xC0) | 0x40; // PAR8
    else
        regValue = regValue & ~0xC0;          // PAR4

    *(SceUInt16 *)(*(void **)(pCtx + 0xC00) + 0xC) = regValue;

    if (unk == 1)
        kscePervasiveMsifSetClock(4); // Observed ~16MHz with 8 MB/s speed
    else if (((unk - 2) < 3) && !OVERCLOCK_MSIF)
        kscePervasiveMsifSetClock(5); // Observed ~32MHz with 16 MB/s speed
    else
        kscePervasiveMsifSetClock(6); // Observed ~40MHz with 20 MB/s speed
}

int InitMsifStaging()
{
    SceMsifAdmaDescriptor **descAreaBase;
    void **msifContext;
    tai_module_info_t moduleInfo = {0};

    moduleInfo.size = sizeof(moduleInfo);
    taiGetModuleInfoForKernel(KERNEL_PID, "SceMsif", &moduleInfo);

    if (InitStagingBuffer(&stagingBuf.head, MSIF_BUFFER_SIZE) < 0)
        return -1;

    hookIds[0] = taiHookFunctionExportForKernel(KERNEL_PID, &hookRefs[0], "SceMsif", 0xB706084A, 0x58654AA3, _sceMsifReadSector);
    hookIds[1] = taiHookFunctionExportForKernel(KERNEL_PID, &hookRefs[1], "SceMsif", 0xB706084A, 0x329035EF, _sceMsifWriteSector);
    hookIds[2] = taiHookFunctionOffsetForKernel(KERNEL_PID, &hookRefs[2], moduleInfo.modid, 0, 0x38F0, 1, _sceMsifPrepareDmaTable);
    hookIds[3] = taiHookFunctionOffsetForKernel(KERNEL_PID, &hookRefs[3], moduleInfo.modid, 0, 0xDDC, 1, _msproal_read_sectors);
    hookIds[4] = taiHookFunctionOffsetForKernel(KERNEL_PID, &hookRefs[4], moduleInfo.modid, 0, 0x107C, 1, _msproal_write_sectors);
    hookIds[5] = taiHookFunctionOffsetForKernel(KERNEL_PID, &hookRefs[5], moduleInfo.modid, 0, 0x25C0, 1, SetMsifClock);

    module_get_offset(KERNEL_PID, moduleInfo.modid, 1, 0x14E4, (uintptr_t *)&stagingBuf.alignSizes);
    module_get_offset(KERNEL_PID, moduleInfo.modid, 1, 0x14F8, (uintptr_t *)&descAreaBase);
    stagingBuf.descArea = *descAreaBase;

    ksceKernelVAtoPA(stagingBuf.descArea, &stagingBuf.descAreaPAddr);

    module_get_offset(KERNEL_PID, moduleInfo.modid, 1, 0x0, (uintptr_t *)&msifContext);
    if ((*msifContext != NULL) && (*(SceUInt32 *)(*msifContext + 0xC0C) & 0x1)) // Check to see if memory stick is inserted and mounted already
        kscePervasiveMsifSetClock(6);

    return 0;
}