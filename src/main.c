#include <psp2kern/kernel/cpu.h>
#include <psp2kern/kernel/dmac.h>
#include <psp2kern/kernel/modulemgr.h>
#include <psp2kern/kernel/sysmem.h>
#include <psp2kern/kernel/threadmgr.h>
#include <psp2kern/kernel/debug.h>
#include <taihen.h>

#define STAGING_BUFFER_SIZE (64 * 1024)
#define MIN(a, b) ((a) < (b) ? (a) : (b))

typedef struct SceMsifAdmaDescriptor
{
	SceUIntPtr addr;
	struct SceMsifAdmaDescriptor *next;
	uint16_t size;
	uint16_t attr;
} SceMsifAdmaDescriptor;

static SceBool doDmaBypass;

static tai_hook_ref_t hookRefs[5];
static SceUID hookIds[5];
static void *buf;
static SceSize bufLen;
static uint32_t *unalignedSizes;
static SceMsifAdmaDescriptor *descArea;

struct 
{
	SceUID memBlock;
	void *base;
	SceUIntPtr paddr;
} stagingBuf;

int module_get_offset(SceUID pid, SceUID modid, int segidx, size_t offset, uintptr_t *addr);

int _sceMsifReadSector(SceUInt32 sector, void *base, SceUInt32 nSectors)
{
	if (nSectors <= (STAGING_BUFFER_SIZE >> 9))
		return TAI_CONTINUE(int, hookRefs[0], sector, base, nSectors);

	int ret;
	while (nSectors != 0)
	{
		ret = TAI_CONTINUE(int, hookRefs[0], sector, base, MIN(nSectors, STAGING_BUFFER_SIZE >> 9));
		if (ret != 0)
			break;

		base += MIN(nSectors << 9, STAGING_BUFFER_SIZE);
		sector += MIN(nSectors, STAGING_BUFFER_SIZE >> 9);
		nSectors -= MIN(nSectors, STAGING_BUFFER_SIZE >> 9);
	}

	return ret;
}

int _sceMsifWriteSector(SceUInt32 sector, void *base, SceUInt32 nSectors)
{
	if (nSectors <= (STAGING_BUFFER_SIZE >> 9))
		return TAI_CONTINUE(int, hookRefs[1], sector, base, nSectors);

	int ret;
	while (nSectors != 0)
	{
		ret = TAI_CONTINUE(int, hookRefs[1], sector, base, MIN(nSectors, STAGING_BUFFER_SIZE >> 9));
		if (ret != 0)
			break;

		base += MIN(nSectors << 9, STAGING_BUFFER_SIZE);
		sector += MIN(nSectors, STAGING_BUFFER_SIZE >> 9);
		nSectors -= MIN(nSectors, STAGING_BUFFER_SIZE >> 9);
	}

	return ret;
}

int _sceMsifPrepareDmaTable(void *base, SceSize len, SceBool write)
{
	buf = base;
	bufLen = len;
	doDmaBypass = SCE_TRUE;

	descArea[0].addr = stagingBuf.paddr;
	descArea[0].next = NULL;
	descArea[0].size = len >> 2;
	descArea[0].attr = 0x8000;

	if ((len & 0x3f) == 0)
		descArea[0].attr |= 0x7; // 64 bytes aligned
	else if ((len & 0x1f) == 0)
		descArea[0].attr |= 0x5; // 32 bytes aligned
	else if ((len & 0xf) == 0)
		descArea[0].attr |= 0x3; // 16 bytes aligned

	ksceKernelCpuDcacheAndL2WritebackRange(descArea, sizeof(descArea[0]));

	unalignedSizes[0] = 0;
	unalignedSizes[1] = 0;
	unalignedSizes[2] = 0;

	return 0;
}

int _msproal_read_sectors(void *pCtx, SceUInt32 sector, SceUInt32 count, SceMsifAdmaDescriptor *descriptorBase)
{
	int ret = TAI_CONTINUE(int, hookRefs[3], pCtx, sector, count, descriptorBase);

	if (doDmaBypass && ret == 0)
	{
		if (bufLen < 4096) // Safe to assume standard memcpy will be faster for small copies due to DMA overhead
			memcpy(buf, stagingBuf.base, bufLen);
		else
			ksceDmacMemcpy(buf, stagingBuf.base, bufLen);

		doDmaBypass = SCE_FALSE;
	}

	return ret;
}

int _msproal_write_sectors(void *pCtx, SceUInt32 sector, SceUInt32 count, SceMsifAdmaDescriptor *descriptorBase)
{
	if (doDmaBypass)
	{
		// if (bufLen < 4096)
			memcpy(stagingBuf.base, buf, bufLen); // Standard memcpy is faster for Cached to Uncached. TODO: Implement checks for cache regions
		// else
		// 	ksceDmacMemcpy(stagingBuf.base, buf, bufLen);
	}

	int ret = TAI_CONTINUE(int, hookRefs[4], pCtx, sector, count, descriptorBase);

	if (ret == 0 && doDmaBypass)
		doDmaBypass = SCE_FALSE;

	return ret;
}

void _start() __attribute__((weak, alias("module_start")));
int module_start(SceSize args, void *argp)
{
	SceMsifAdmaDescriptor **descAreaBase;
	tai_module_info_t moduleInfo = {0};
	SceKernelAllocMemBlockKernelOpt opt = {0};

	moduleInfo.size = sizeof(moduleInfo);
	taiGetModuleInfoForKernel(KERNEL_PID, "SceMsif", &moduleInfo);

	opt.size = sizeof(opt);
	opt.attr = SCE_KERNEL_ALLOC_MEMBLOCK_ATTR_PHYCONT;
	stagingBuf.memBlock = ksceKernelAllocMemBlock("MsifStagingBuf", SCE_KERNEL_MEMBLOCK_TYPE_KERNEL_TMP_NC_RW, STAGING_BUFFER_SIZE, &opt);

	ksceKernelGetMemBlockBase(stagingBuf.memBlock, &stagingBuf.base);

	ksceKernelVAtoPA(stagingBuf.base, &stagingBuf.paddr);

	hookIds[0] = taiHookFunctionExportForKernel(KERNEL_PID, &hookRefs[0], "SceMsif", 0xB706084A, 0x58654AA3, _sceMsifReadSector);
	hookIds[1] = taiHookFunctionExportForKernel(KERNEL_PID, &hookRefs[1], "SceMsif", 0xB706084A, 0x329035EF, _sceMsifWriteSector);
	hookIds[2] = taiHookFunctionOffsetForKernel(KERNEL_PID, &hookRefs[2], moduleInfo.modid, 0, 0x38F0, 1, _sceMsifPrepareDmaTable);
	hookIds[3] = taiHookFunctionOffsetForKernel(KERNEL_PID, &hookRefs[3], moduleInfo.modid, 0, 0xDDC, 1, _msproal_read_sectors);
	hookIds[4] = taiHookFunctionOffsetForKernel(KERNEL_PID, &hookRefs[4], moduleInfo.modid, 0, 0x107C, 1, _msproal_write_sectors);

	module_get_offset(KERNEL_PID, moduleInfo.modid, 1, 0x14E4, (uintptr_t *)&unalignedSizes);
	module_get_offset(KERNEL_PID, moduleInfo.modid, 1, 0x14F8, (uintptr_t *)&descAreaBase);
	descArea = *descAreaBase;

	return SCE_KERNEL_START_SUCCESS;
}

int module_stop(SceSize args, void *argp)
{
	return SCE_KERNEL_STOP_SUCCESS;
}
