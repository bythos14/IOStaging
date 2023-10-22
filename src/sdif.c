#include <psp2kern/kernel/cpu.h>
#include <psp2kern/kernel/threadmgr.h>

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

typedef struct SdifStagingBuffer
{
    StagingBuffer head;
    SceSize dmaSizes[2];
} SdifStagingBuffer;

static tai_hook_ref_t hookRefs[3];
static SceUID hookIds[3];
static SdifStagingBuffer stagingBuf;

static int (*_sceSdifSendCmd)(void *sdifContext, SdifCommand *primaryCmd, SdifCommand *secondaryCmd, SceUInt maxRetries, SceUInt unk);
static void (*FUN_81000084)();
static SdifCommand *(*_sceSdifGetCommand)(void *sdifContext);
static int (*_sceSdifSendACmd)(void *sdifContext, SdifCommand *cmd, SceUInt maxRetries);

int module_get_offset(SceUID pid, SceUID modid, int segidx, size_t offset, uintptr_t *addr);

static inline int _SdifLock(void *sdifContext)
{
    if (*(SceUInt8 *)(sdifContext + 0x2425) != 0)
        return 0;

    return ksceKernelLockFastMutex((SceKernelFastMutex *)(sdifContext + 0x2444));
}

static inline int _SdifUnlock(void *sdifContext)
{
    if (*(SceUInt8 *)(sdifContext + 0x2425) != 0)
        return 0;

    return ksceKernelUnlockFastMutex((SceKernelFastMutex *)(sdifContext + 0x2444));
}

static int _sceSdReadSector(void *sdCtx, SceUInt32 sector, void *base, SceUInt32 nSectors)
{
    if (nSectors <= (SDIF_BUFFER_SIZE >> 9))
        return TAI_CONTINUE(int, hookRefs[0], sdCtx, sector, base, nSectors);

    int ret;
    while (nSectors != 0)
    {
        ret = TAI_CONTINUE(int, hookRefs[0], sdCtx, sector, base, MIN(nSectors, SDIF_BUFFER_SIZE >> 9));
        if (ret != 0)
            break;

        base += MIN(nSectors << 9, SDIF_BUFFER_SIZE);
        sector += MIN(nSectors, SDIF_BUFFER_SIZE >> 9);
        nSectors -= MIN(nSectors, SDIF_BUFFER_SIZE >> 9);
    }

    return ret;
}

static int _sceSdWriteSector(void *sdCtx, SceUInt32 sector, void *base, SceUInt32 nSectors)
{
    if (nSectors <= (SDIF_BUFFER_SIZE >> 9))
        return TAI_CONTINUE(int, hookRefs[1], sdCtx, sector, base, nSectors);

    int ret;
    while (nSectors != 0)
    {
        ret = TAI_CONTINUE(int, hookRefs[1], sdCtx, sector, base, MIN(nSectors, SDIF_BUFFER_SIZE >> 9));
        if (ret != 0)
            break;

        base += MIN(nSectors << 9, SDIF_BUFFER_SIZE);
        sector += MIN(nSectors, SDIF_BUFFER_SIZE >> 9);
        nSectors -= MIN(nSectors, SDIF_BUFFER_SIZE >> 9);
    }

    return ret;
}
static void PrepareAdmaTable(SdifCommand *cmd, int secondary)
{
    SceSdifAdmaDescriptor *desc;
    SceUIntPtr dmaAddr;
    SceSize dmaSize, descCount;

    cmd->flags &= (secondary ? 0x3fefffff : 0xffefffff);
    cmd->unalignedHeadLength = 0;
    cmd->unalignedTailLength = 0;
    cmd->alignedLength = 0;
    cmd->descAreaPhyAddr = cmd->defaultDescAreaPhyAddr;

    desc = &cmd->defaultDescArea[0];
    dmaAddr = stagingBuf.head.paddr;
    if (secondary)
        dmaAddr += stagingBuf.dmaSizes[0];
    dmaSize = stagingBuf.dmaSizes[secondary];
    descCount = 0;
    while (dmaSize != 0)
    {
        desc[descCount].addr = dmaAddr;
        desc[descCount].cmd = 0x21;
        desc[descCount].size = MIN(dmaSize, 0x10000);
        descCount++;
        dmaAddr += MIN(dmaSize, 0x10000);
        dmaSize -= MIN(dmaSize, 0x10000);
    }
    if (descCount != 0)
        desc[descCount - 1].cmd |= 0x2;
    ksceKernelDcacheCleanRange(desc, sizeof(SceSdifAdmaDescriptor) * descCount);
}

static int InitCommands(void *sdifContext, SdifCommand *primaryCmd, SdifCommand *secondaryCmd)
{
    if (primaryCmd->flags & 0x400)
        stagingBuf.dmaSizes[0] = MAX(1, primaryCmd->blockCount) * primaryCmd->blockSize;
    else
        stagingBuf.dmaSizes[0] = 0;

    if (secondaryCmd != NULL && secondaryCmd->flags & 0x400)
        stagingBuf.dmaSizes[1] = MAX(1, primaryCmd->blockCount) * secondaryCmd->blockSize;
    else
        stagingBuf.dmaSizes[1] = 0;

    if ((stagingBuf.dmaSizes[0] + stagingBuf.dmaSizes[1]) > stagingBuf.head.size)
        return -1;

    primaryCmd->pContext = sdifContext;
    primaryCmd->evfId = *(SceUID *)(sdifContext + 0x2440);
    primaryCmd->pSecondaryCmd = secondaryCmd;
    primaryCmd->pCallback = FUN_81000084;

    if (primaryCmd->flags & 0x400)
    {
        if (stagingBuf.dmaSizes[0] == 0)
            return -1;
        PrepareAdmaTable(primaryCmd, 0);
    }

    if (secondaryCmd != 0)
    {
        primaryCmd->pCallback = NULL;
        secondaryCmd->pContext = sdifContext;
        secondaryCmd->evfId = *(SceUID *)(sdifContext + 0x2440);
        secondaryCmd->pSecondaryCmd = NULL;
        secondaryCmd->pCallback = FUN_81000084;

        if (secondaryCmd->flags & 0x400)
        {
            if (stagingBuf.dmaSizes[1] == 0)
                return -1;
            PrepareAdmaTable(secondaryCmd, 1);
        }
    }

    return 0;
}

static int ExecuteACMD23(void *sdifContext, SceSize blockCount)
{
    SdifCommand *cmd = _sceSdifGetCommand(sdifContext);
    if (cmd != NULL)
    {
        cmd->size = sizeof(*cmd);
        cmd->cmd = 23;
        cmd->flags = 0x13;
        cmd->argument = blockCount;
        cmd->buffer = NULL;

        return _sceSdifSendACmd(sdifContext, cmd, 3);
    }
    return 0;
}

static int _FUN_81001C10(void *sdifContext, SdifCommand *primaryCmd, SdifCommand *secondaryCmd, SceUInt maxRetries)
{
    int ret, deviceIndex = *(SceInt32 *)(sdifContext + 0x2420), deviceType = *(SceInt32 *)(sdifContext + 0x2410);

    if ((ret = _SdifLock(sdifContext)) < 0)
        return ret;

    /**
     * Race condition fix. TaiHEN seems to install the hook before configuring the hookRef,
     * so if the hooked function is hot, there may be a chance of the function getting
     * executed before it is safe to call TAI_CONTINUE. Seems to only happen to this function.
     */
    {
        static SceBool loaded = SCE_FALSE;
        if (!loaded)
        {
            ksceKernelDelayThread(10);
            loaded = SCE_TRUE;
        }
    }

    // Only SD2VITA
    if ((deviceIndex != 1) || (deviceType != 2))
    {
        _SdifUnlock(sdifContext);
        return TAI_CONTINUE(int, hookRefs[2], sdifContext, primaryCmd, secondaryCmd, maxRetries);
    }

    if (InitCommands(sdifContext, primaryCmd, secondaryCmd) < 0)
    {
        _SdifUnlock(sdifContext);
        return TAI_CONTINUE(int, hookRefs[2], sdifContext, primaryCmd, secondaryCmd, maxRetries);
    }

    if (primaryCmd->cmd == 25) // ACMD23 on multi-block writes for optimal performance
    {
        ExecuteACMD23(sdifContext, primaryCmd->blockCount);
    }

    _SdifLock(sdifContext);

    if ((primaryCmd->flags & 0x600) == 0x600)
        CopyBuffer(stagingBuf.head.base, primaryCmd->buffer, stagingBuf.dmaSizes[0]);
    if ((secondaryCmd != NULL) && (secondaryCmd->flags & 0x600) == 0x600)
        CopyBuffer(stagingBuf.head.base + stagingBuf.dmaSizes[0], secondaryCmd->buffer, stagingBuf.dmaSizes[1]);

    ret = _sceSdifSendCmd(sdifContext, primaryCmd, secondaryCmd, maxRetries, 1);
    if (ret < 0)
    {
        _SdifUnlock(sdifContext);
        return ret;
    }

    if ((primaryCmd->flags & 0x500) == 0x500)
        CopyBuffer(primaryCmd->buffer, stagingBuf.head.base, stagingBuf.dmaSizes[0]);
    if ((secondaryCmd != NULL) && (secondaryCmd->flags & 0x500) == 0x500)
        CopyBuffer(secondaryCmd->buffer, stagingBuf.head.base + stagingBuf.dmaSizes[0], stagingBuf.dmaSizes[1]);

    _SdifUnlock(sdifContext);

    return ret;
}

int InitSdifStaging()
{
    tai_module_info_t moduleInfo = {0};
    moduleInfo.size = sizeof(moduleInfo);
    taiGetModuleInfoForKernel(KERNEL_PID, "SceSdif", &moduleInfo);

    if (SDIF_BUFFER_SIZE == 0) // Buffering disabled
        return 0;

    if (InitStagingBuffer(&stagingBuf.head, SDIF_BUFFER_SIZE) < 0)
        goto fail;

    module_get_offset(KERNEL_PID, moduleInfo.modid, 0, 0x17E9, (uintptr_t *)&_sceSdifSendCmd);
    module_get_offset(KERNEL_PID, moduleInfo.modid, 0, 0x1CE1, (uintptr_t *)&_sceSdifSendACmd);
    module_get_offset(KERNEL_PID, moduleInfo.modid, 0, 0x85, (uintptr_t *)&FUN_81000084);
    module_get_offset(KERNEL_PID, moduleInfo.modid, 0, 0x2E41, (uintptr_t *)&_sceSdifGetCommand);

    hookIds[0] = taiHookFunctionExportForKernel(KERNEL_PID, &hookRefs[0], "SceSdif", 0x96D306FA, 0xB9593652, _sceSdReadSector);
    if (hookIds[0] < 0)
        goto fail;
    hookIds[1] = taiHookFunctionExportForKernel(KERNEL_PID, &hookRefs[1], "SceSdif", 0x96D306FA, 0xE0781171, _sceSdWriteSector);
    if (hookIds[1] < 0)
        goto fail;
    hookIds[2] = taiHookFunctionOffsetForKernel(KERNEL_PID, &hookRefs[2], moduleInfo.modid, 0, 0x1C10, 1, _FUN_81001C10);
    if (hookIds[2] < 0)
        goto fail;

    return 0;
fail:
    LOG("Failed to initialize SDIF I/O staging\n");
    TermSdifStaging();
    return -1;
}

void TermSdifStaging()
{
    if (hookIds[2] > 0)
        taiHookReleaseForKernel(hookIds[2], hookRefs[2]);
    if (hookIds[1] > 0)
        taiHookReleaseForKernel(hookIds[1], hookRefs[1]);
    if (hookIds[0] > 0)
        taiHookReleaseForKernel(hookIds[0], hookRefs[0]);

    TermStagingBuffer(&stagingBuf.head);
}