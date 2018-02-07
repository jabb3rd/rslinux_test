#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include "loader.h"

void set_callback(dword row, char *name, char *value)
{
	printf("#%lu: '%s' = '%s'\n", row, name, value);
}

int main()
{
	void *handle = dlopen("liblibrouter.so", RTLD_LAZY);
	if (!handle) {
		fprintf(stderr, "%s\n", dlerror());
		return -1;
	} else
		dlerror();

	/* Shared library import here */
	lib_loader(handle);

	if (!Initialize()) {
		fprintf(stderr, "[-] Initialize()\n");
		dlclose(handle);
		return -1;
	} else
		fprintf(stderr, "[+] Initialize()\n");

	dword count = 0;

	if (!GetModuleCount(&count))
		fprintf(stderr, "GetModuleCount() FAILED!\n");
	else
		printf("count = %lu\n", count);

	for (dword i = 0; i < count; i++) {
		t_module_desc desc;
		if (!GetModuleInfo(i, &desc))
			fprintf(stderr, "GetModuleInfo() FAILED\n");
		else
			printf("enabled = %s, name = '%s', desc = '%s'\n", desc.enabled == 0 ? "FALSE" : "TRUE", desc.name, desc.desc);
	}

	dword *router = NULL;
	int False = FALSE;
	int True = TRUE;
	bool result;

	char *creds = "test\ttest\r\n";
	char *user = "test";
	char *pass = "test";

	char buf[4096];
	dword bytes;

	fprintf(stderr, "[%s] SetParam(stProxyType)\n", SetParam_Word(stProxyType, 0) ? "+": "-");
	fprintf(stderr, "[%s] SetParam(stUserAgent)\n", SetParam_Pointer(stUserAgent, "Mozilla/5.0 (Windows NT 5.1; rv:9.0.1) Gecko/20100101 Firefox/9.0.1") ? "+": "-");
	fprintf(stderr, "[%s] SetParam(stUseCustomPage)\n", SetParam_Pointer(stUseCustomPage, &False) ? "+": "-");
	fprintf(stderr, "[%s] SetParam(stDualAuthCheck)\n", SetParam_Pointer(stDualAuthCheck, &False) ? "+": "-");


	fprintf(stderr, "[%s] SetParam(stPairsBasic)\n", SetParam_Pointer(stPairsBasic, creds) ? "+": "-");
	fprintf(stderr, "[%s] SetParam(stPairsDigest)\n", SetParam_Pointer(stPairsDigest, creds) ? "+": "-");
        fprintf(stderr, "[%s] SetParam(stPairsForm)\n", SetParam_Pointer(stPairsForm, creds) ? "+": "-");
	fprintf(stderr, "[%s] SetParam(stCredentialsUsername)\n", SetParam_Pointer(stCredentialsUsername, user) ? "+": "-");
	fprintf(stderr, "[%s] SetParam(stCredentialsPassword)\n", SetParam_Pointer(stCredentialsPassword, pass) ? "+": "-");
	fprintf(stderr, "[%s] PrepareRouter\n", PrepareRouter(123, 0xac1c006e, 80, &router) ? "+": "-");

	bytes = 0;
	result = GetParam_Pointer(stCredentialsPassword, &buf, 4096, &bytes);
	fprintf(stderr, "[%s] size = %lu value = '%s'\n", result ? "+": "-", bytes, buf);
	bytes = 0;
	GetParam_Pointer(stCredentialsUsername, &buf, 4096, &bytes);
	fprintf(stderr, "[%s] size = %lu value = '%s'\n", result ? "+": "-", bytes, buf);

	fprintf(stderr, "[%s] SetParam(stSetTableDataCallback)\n", SetParam_Pointer(stSetTableDataCallback, &set_callback) ? "+": "-");

	ScanRouter(router);
	FreeRouter(router);

	dlclose(handle);
	return 0;
}
