#include <dlfcn.h>
#include "loader.h"

bool lib_loader(void *handle)
{
	Initialize = dlsym(handle, "Initialize");
	GetModuleCount = dlsym(handle, "GetModuleCount");
	GetModuleInfo = dlsym(handle, "GetModuleInfoA");
	SwitchModule = dlsym(handle, "SwitchModule");
	GetParam_DWord = dlsym(handle, "GetParamA");
	GetParam_Pointer = dlsym(handle, "GetParamA");
	GetParam_Bool = dlsym(handle, "GetParamA");
	PrepareRouter = dlsym(handle, "PrepareRouter");
	ScanRouter = dlsym(handle, "ScanRouter");
	FreeRouter = dlsym(handle, "FreeRouter");
	StopRouter = dlsym(handle, "StopRouter");
	IsRouterStopping = dlsym(handle, "IsRouterStopping");
	SetParam_Word = dlsym(handle, "SetParamA");
	SetParam_Pointer = dlsym(handle, "SetParamA");
}

bool SetParam_Bool(dword st, bool value)
{
	return SetParam_Word(st, (word) value);
}
