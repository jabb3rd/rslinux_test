#ifndef __LOADER_H
#define __LOADER_H

/* Some basic definitions */
#define FALSE 0
#define TRUE !FALSE

typedef int bool;
typedef unsigned char byte;
typedef unsigned int word;
typedef unsigned long dword;

/* A module description structure */
typedef struct {
        bool enabled;
        char name[16];
        char desc[32];
} t_module_desc;

/* GetParam/SetParam parameters */
enum _st_enum {
	stEnableDebug,
	stDebugVerbosity,
	stWriteLogCallback,
	stSetTableDataCallback,
	stUserAgent,
	stUseCustomPage,
	stDualAuthCheck,
	stPairsBasic,
	stPairsDigest,
	stProxyType,
	stProxyIP,
	stProxyPort,
	stUseCredentials,
	stCredentialsUsername,
	stCredentialsPassword,
	stPairsForm,
	stFilterRules,
	stProxyUseAuth,
	stProxyUser,
	stProxyPass
};

/* Shared library loader */
bool lib_loader(void *handle);

/* Functions' declaration */
typedef bool (*Initialize_t)(void);

typedef bool (*GetModuleCount_t)(dword *count);
typedef bool (*GetModuleInfo_t)(dword index, t_module_desc *description);
typedef bool (*SwitchModule_t)(dword index, bool enabled);

typedef bool (*PrepareRouter_t)(dword row, dword ip, word port, void *hrouter);
typedef bool (*ScanRouter_t)(void *hrouter);
typedef bool (*FreeRouter_t)(void *hrouter);
typedef bool (*StopRouter_t)(void *hrouter);
typedef bool (*IsRouterStopping_t)(void *hrouter);

typedef bool (*GetParam_DWord_t)(dword st, dword *value, dword size, dword *out_length);
typedef bool (*GetParam_Pointer_t)(dword st, void *pointer, dword size, dword *out_length);
typedef bool (*GetParam_Bool_t)(dword st, bool *value, dword size, dword *out_length);

typedef bool (*SetParam_Word_t)(dword st, word value);
typedef bool (*SetParam_Pointer_t)(dword st, void *pointer);

Initialize_t Initialize;
GetModuleCount_t GetModuleCount;
GetModuleInfo_t GetModuleInfo;
SwitchModule_t SwitchModule;
PrepareRouter_t PrepareRouter;
ScanRouter_t ScanRouter;
FreeRouter_t FreeRouter;
StopRouter_t StopRouter;
IsRouterStopping_t IsRouterStopping;

GetParam_DWord_t GetParam_DWord;
GetParam_Pointer_t GetParam_Pointer;
GetParam_Bool_t GetParam_Bool;
SetParam_Word_t SetParam_Word;
SetParam_Pointer_t SetParam_Pointer;

bool SetParam_Bool(dword st, bool value);

#endif
