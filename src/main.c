#include <psp2kern/kernel/modulemgr.h>
#include <psp2kern/io/fcntl.h>

#include <taihen.h>

#include "common.h"

int InitMsifStaging();
int InitSdifStaging();

StagingConfig config = 
{
	.sdBufSize = DEFAULT_SDIF_BUFFER_SIZE, 
	.msBufSize = DEFAULT_MSIF_BUFFER_SIZE,
	.overclockMsif = DEFAULT_OVERCLOCK_MSIF
};

static void LoadConfig()
{
	SceUID fd;
	int size;
	
	fd = ksceIoOpen(CONFIG_PATH, SCE_O_RDONLY, 0666);
	if (fd < 0)
		return;

	size = ksceIoPread(fd, &config, sizeof(config), 0);
	
	if (size != sizeof(config))
	{
		config.sdBufSize = DEFAULT_SDIF_BUFFER_SIZE;
		config.msBufSize = DEFAULT_MSIF_BUFFER_SIZE;
		config.overclockMsif = SCE_FALSE;

		LOG("Config file is too small");
	}

	ksceIoClose(fd);
}

void _start() __attribute__((weak, alias("module_start")));
int module_start(SceSize args, void *argp)
{
	int msifStat, sdifStat;

	LoadConfig();

	msifStat = InitMsifStaging();
	sdifStat = InitSdifStaging();

	if ((msifStat < 0) && (sdifStat < 0))
		return SCE_KERNEL_START_FAILED;

	return SCE_KERNEL_START_SUCCESS;
}

int module_stop(SceSize args, void *argp)
{
	TermMsifStaging();
	TermSdifStaging();

	return SCE_KERNEL_STOP_SUCCESS;
}
