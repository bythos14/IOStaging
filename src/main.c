#include <psp2kern/kernel/cpu.h>
#include <psp2kern/kernel/dmac.h>
#include <psp2kern/kernel/modulemgr.h>
#include <psp2kern/kernel/sysmem.h>
#include <psp2kern/kernel/threadmgr.h>
#include <psp2kern/kernel/debug.h>
#include <taihen.h>

int InitMsifStaging();
int InitSdifStaging();

void _start() __attribute__((weak, alias("module_start")));
int module_start(SceSize args, void *argp)
{
	if (InitMsifStaging() < 0)
		return SCE_KERNEL_START_FAILED;
	if (InitSdifStaging() < 0)
		return SCE_KERNEL_START_FAILED;

	return SCE_KERNEL_START_SUCCESS;
}

int module_stop(SceSize args, void *argp)
{
	return SCE_KERNEL_STOP_SUCCESS;
}
