#include <psp2kern/kernel/cpu.h>
#include <psp2kern/kernel/dmac.h>
#include <psp2kern/kernel/modulemgr.h>
#include <psp2kern/kernel/sysmem.h>
#include <psp2kern/kernel/threadmgr.h>
#include <psp2kern/kernel/debug.h>
#include <taihen.h>

#define STAGING_BUFFER_SIZE (256 * 1024)
#define MIN(a, b) (a < b ? a : b)

typedef struct SceMsifAdmaDescriptor
{
	SceUIntPtr addr;
	struct SceMsifAdmaDescriptor *next;
	uint16_t size;
	uint16_t attr;
} SceMsifAdmaDescriptor;

static SceBool doDmaBypass = 0, *dummyReadBug;

static tai_hook_ref_t hookRefs[4];
static SceUID hookIds[4];
static SceKernelDmaOpId dmaOp;
static void *buf;
static SceSize bufLen;
static uint32_t *unalignedSizes;
static SceMsifAdmaDescriptor *descArea;

int (*msproal_read_sectors)(void *pCtx, SceUInt32 sector, SceUInt32 count, SceMsifAdmaDescriptor *descriptorBase);

struct 
{
	SceUID memBlock;
	void *base;
	SceUIntPtr paddr;
} stagingBuf;

int module_get_offset(SceUID pid, SceUID modid, int segidx, size_t offset, uintptr_t *addr);

void _ksceKernelCpuDcacheAndL2WritebackInvalidateRange(void *base, SceSize len)
{
	SceKernelSysClock start, end, _len = len;
	start = ksceKernelGetSystemTimeWide();

	if ((uintptr_t)(base)&0x1F)
	{
		ksceKernelCpuDcacheAndL2WritebackInvalidateRange((void *)((uintptr_t)(base) & ~0x1F), 0x20);
		len -= 0x20 - ((uintptr_t)(base)&0x1F);
		base = (void *)(((uintptr_t)(base) & ~0x1F) + 0x20);
	}

	ksceKernelCpuDcacheAndL2InvalidateRange(base, len & ~0x1F);
	base = (void *)((uintptr_t)(base) + (len & ~0x1F));
	len &= 0x1F;

	if (len != 0)
	{
		ksceKernelCpuDcacheAndL2WritebackInvalidateRange(base, len);
	}

	end = ksceKernelGetSystemTimeWide();

	ksceKernelPrintf("Took %llu us to invalidate %llu bytes\n", end - start, _len);
}

int _sceMsifPrepareDmaTable(void *base, SceSize len, SceBool write)
{
	// if (write == SCE_TRUE)
		// return TAI_CONTINUE(int, hookRefs[1], base, len, write);

	buf = base;
	bufLen = len;
	doDmaBypass = SCE_TRUE;

	unalignedSizes[0] = 0;
	unalignedSizes[1] = 0;
	unalignedSizes[2] = 0;

	return 0;
}

int _msproal_read_sectors(void *pCtx, SceUInt32 sector, SceUInt32 count, SceMsifAdmaDescriptor *descriptorBase)
{
	if (!doDmaBypass)
		return TAI_CONTINUE(int, hookRefs[2], pCtx, sector, count, descriptorBase);

	ksceKernelPrintf("Reading %u bytes from sector %u\n", bufLen, sector);

	while (bufLen != 0)
	{
		SceSize transferSize = MIN(bufLen, STAGING_BUFFER_SIZE);
		SceUInt32 sectorCount = transferSize >> 9;

		SceMsifAdmaDescriptor *descArea = descriptorBase;
		descArea[0].addr = stagingBuf.paddr;
		descArea[0].next = NULL;
		descArea[0].size = transferSize >> 2;
		descArea[0].attr = 0x8000;

		if ((transferSize & 0x3f) == 0)
			descArea[0].attr |= 0x7; // 64 bytes aligned
		else if ((transferSize & 0x1f) == 0)
			descArea[0].attr |= 0x5; // 32 bytes aligned
		else if ((transferSize & 0xf) == 0)
			descArea[0].attr |= 0x3; // 16 bytes aligned

		ksceKernelCpuDcacheAndL2WritebackInvalidateRange(descArea, sizeof(descArea[0]));

		int ret = TAI_CONTINUE(int, hookRefs[2], pCtx, sector, sectorCount, descArea);
		if (ret != 0)
		{
			ksceKernelPrintf("Sector read failed\n");
			doDmaBypass = SCE_FALSE;
			return ret;
		}

		if (transferSize < 4096)
			memcpy(buf, stagingBuf.base, transferSize);
		else
			ksceDmacMemcpy(buf, stagingBuf.base, transferSize);

		sector += sectorCount;
		bufLen -= transferSize;
		buf += transferSize;
	}

	doDmaBypass = SCE_FALSE;

	return 0;
}

int _msproal_write_sectors(void *pCtx, SceUInt32 sector, SceUInt32 count, SceMsifAdmaDescriptor *descriptorBase)
{
	// if (!doDmaBypass)
		return TAI_CONTINUE(int, hookRefs[3], pCtx, sector, count, descriptorBase);

	ksceKernelPrintf("Writing %u bytes to sector %u\n", bufLen, sector);

	while (bufLen != 0)
	{
		SceSize transferSize = MIN(bufLen, STAGING_BUFFER_SIZE);
		SceUInt32 sectorCount = transferSize >> 9;

		SceMsifAdmaDescriptor *descArea = descriptorBase;
		descArea[0].addr = stagingBuf.paddr;
		descArea[0].next = NULL;
		descArea[0].size = transferSize >> 2;
		descArea[0].attr = 0x8000;

		if ((transferSize & 0x3f) == 0)
			descArea[0].attr |= 0x7; // 64 bytes aligned
		else if ((transferSize & 0x1f) == 0)
			descArea[0].attr |= 0x5; // 32 bytes aligned
		else if ((transferSize & 0xf) == 0)
			descArea[0].attr |= 0x3; // 16 bytes aligned

		ksceKernelCpuDcacheAndL2WritebackRange(descArea, sizeof(descArea[0]));

		if (transferSize < 4096)
			memcpy(stagingBuf.base, buf, transferSize);
		else
			ksceDmacMemcpy(stagingBuf.base, buf, transferSize);

		int ret = TAI_CONTINUE(int, hookRefs[3], pCtx, sector, sectorCount, descArea);
		if (ret != 0)
		{
			ksceKernelPrintf("Sector write failed\n");
			doDmaBypass = SCE_FALSE;
			return ret;
		}

		if (*dummyReadBug)
		{
			descArea->size = 0x200 >> 2;
			ksceKernelCpuDcacheAndL2WritebackRange(descArea, sizeof(descArea[0]));
			doDmaBypass = SCE_FALSE;
			msproal_read_sectors(pCtx, 0xC0, 1, descArea);
			doDmaBypass = SCE_TRUE;
		}

		sector += sectorCount;
		bufLen -= transferSize;
		buf += transferSize;
	}

	doDmaBypass = SCE_FALSE;

	return 0;
}

void _start() __attribute__((weak, alias("module_start")));
int module_start(SceSize args, void *argp)
{
	tai_module_info_t moduleInfo = {0};
	moduleInfo.size = sizeof(moduleInfo);
	taiGetModuleInfoForKernel(KERNEL_PID, "SceMsif", &moduleInfo);

	hookIds[0] = taiHookFunctionImportForKernel(KERNEL_PID, &hookRefs[0], "SceMsif", 0x40ECDB0E, 0x364E68A4, _ksceKernelCpuDcacheAndL2WritebackInvalidateRange);
	hookIds[1] = taiHookFunctionOffsetForKernel(KERNEL_PID, &hookRefs[1], moduleInfo.modid, 0, 0x38F0, 1, _sceMsifPrepareDmaTable);
	hookIds[2] = taiHookFunctionOffsetForKernel(KERNEL_PID, &hookRefs[2], moduleInfo.modid, 0, 0xDDC, 1, _msproal_read_sectors);
	hookIds[3] = taiHookFunctionOffsetForKernel(KERNEL_PID, &hookRefs[3], moduleInfo.modid, 0, 0x107C, 1, _msproal_write_sectors);

	module_get_offset(KERNEL_PID, moduleInfo.modid, 1, 0x14E4, (uintptr_t *)&unalignedSizes);
	module_get_offset(KERNEL_PID, moduleInfo.modid, 1, 0x14DC, (uintptr_t *)&dummyReadBug);
	module_get_offset(KERNEL_PID, moduleInfo.modid, 0, 0xDDD, (uintptr_t *)&msproal_read_sectors);
	SceMsifAdmaDescriptor **descAreaBase;
	module_get_offset(KERNEL_PID, moduleInfo.modid, 0, 0x14F8, (uintptr_t *)&descAreaBase);
	descArea = *descAreaBase;

	SceKernelAllocMemBlockKernelOpt opt = {0};
	opt.size = sizeof(opt);
	opt.attr = SCE_KERNEL_ALLOC_MEMBLOCK_ATTR_PHYCONT;
	stagingBuf.memBlock = ksceKernelAllocMemBlock("MsifStagingBuf", SCE_KERNEL_MEMBLOCK_TYPE_KERNEL_ROOT_GAME_RW, STAGING_BUFFER_SIZE, &opt);

	ksceKernelGetMemBlockBase(stagingBuf.memBlock, &stagingBuf.base);

	ksceKernelVAtoPA(stagingBuf.base, &stagingBuf.paddr);

	return SCE_KERNEL_START_SUCCESS;
}

int module_stop(SceSize args, void *argp)
{
	return SCE_KERNEL_STOP_SUCCESS;
}
