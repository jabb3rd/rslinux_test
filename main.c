#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <arpa/inet.h>
#include <dlfcn.h>
#include "loader.h"

void set_callback(dword row, char *name, char *value)
{
	printf("#%u:>>> '%s' = '%s'\n", row, name, value);
}

void write_log_callback(char *str, byte verbosity)
{
	fprintf(stderr, "LOG(%d): %s\n", (int) verbosity, str);
}

int main(int argc, char *argv[])
{
    globalArgs.inputWordList = "./auth_basic.txt";
    globalArgs.target_ip = "192.168.0.1";

    struct in_addr target;

    int opt = 0;

    opt = getopt( argc, argv, optString );
    while ( opt != -1 ) { /* Last exit code is -1 */
        switch( opt ) {
            case 'w':
                globalArgs.inputWordList = optarg;
                printf("bla");
                break;
            case 't':
                globalArgs.target_ip = optarg;
                inet_aton(globalArgs.target_ip, &target);
                fprintf(stderr, "Target IP: %s\n", globalArgs.target_ip);
                break;
            case 'h':
            case '?':
                fprintf(stderr, "Usage: ./rs.bin -t 192.168.0.1 <-w ~/path/to/wordlist.txt>");
                break;
            default:
                fprintf(stderr, "Wtf?");
                exit(10);
        }
        opt = getopt(argc, argv, optString);
    }

    /* Load Router Scan library you need to ask Stas'M about it */
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
		printf("count = %u\n", count);

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
	dword result_dw;
	int ResultCode;
	char *creds = "test\ttest\r\n";
	char *user = "admin";
	char *pass = "test";

	char buf[4096];
	dword bytes;

	fprintf(stderr, "[%s] SetParam(stEnableDebug)\n", SetParam_Bool(stEnableDebug, TRUE) ? "+": "-");
	fprintf(stderr, "[%s] GetParam(stEnableDebug)\n", GetParam_Bool(stEnableDebug, &result, sizeof(result), &bytes) ? "+": "-");
	printf("stEnableDebug = %s (%u bytes)\n", result ? "TRUE": "FALSE", bytes);

	fprintf(stderr, "[%s] SetParam(stDebugVerbosity)\n", SetParam_Word(stDebugVerbosity, 1) ? "+": "-");
	fprintf(stderr, "[%s] GetParam(stDebugVerbosity)\n", GetParam_DWord(stDebugVerbosity, &result_dw, sizeof(result_dw), &bytes) ? "+": "-");
	printf("stDebugVerbosity = %u (%u bytes)\n", result_dw, bytes);

	fprintf(stderr, "[%s] SetParam(stProxyType)\n", SetParam_Word(stProxyType, 0) ? "+": "-");
	fprintf(stderr, "[%s] SetParam(stUserAgent)\n", SetParam_Pointer(stUserAgent, "Mozilla/5.0 (Windows NT 5.1; rv:9.0.1) Gecko/20100101 Firefox/9.0.1") ? "+": "-");
	fprintf(stderr, "[%s] SetParam(stUseCustomPage)\n", SetParam_Pointer(stUseCustomPage, &False) ? "+": "-");
	fprintf(stderr, "[%s] SetParam(stDualAuthCheck)\n", SetParam_Pointer(stDualAuthCheck, &False) ? "+": "-");

	//fprintf(stderr, "[%s] SetParam(stPairsBasic)\n", SetParam_Pointer(stPairsBasic, creds) ? "+": "-");
	//fprintf(stderr, "[%s] SetParam(stPairsDigest)\n", SetParam_Pointer(stPairsDigest, creds) ? "+": "-");
	fprintf(stderr, "[%s] SetParam(stPairsForm)\n", SetParam_Pointer(stPairsForm, creds) ? "+": "-");
	fprintf(stderr, "[%s] SetParam(stCredentialsUsername)\n", SetParam_Pointer(stCredentialsUsername, user) ? "+": "-");
	fprintf(stderr, "[%s] SetParam(stCredentialsPassword)\n", SetParam_Pointer(stCredentialsPassword, pass) ? "+": "-");
	fprintf(stderr, "[%s] SetParam(stUseCredentials)\n", SetParam_Pointer(stUseCredentials, creds) ? "+": "-");

    unsigned int target_hex_ip = 0xc0a80001;
    char * s_ip;
    s_ip = inet_ntoa(*(struct in_addr *) &target.s_addr);
    target_hex_ip = ntohl(target.s_addr);
    int row = 1;
    fprintf(stderr, "[%s] PrepareRouter %s\n", PrepareRouter(row, target_hex_ip, 80, &router) ? "+": "-", s_ip);

	bytes = 0;
	result = GetParam_Pointer(stCredentialsPassword, &buf, sizeof(buf), &bytes);
	fprintf(stderr, "[%s] GetParam(stCredentialsPassword): size = %u value = '%s'\n", result ? "+": "-", bytes, buf);
	bytes = 0;
	result = GetParam_Pointer(stCredentialsUsername, &buf, sizeof(buf), &bytes);
	fprintf(stderr, "[%s] GetParam(stCredentialsUsername): size = %u value = '%s'\n", result ? "+": "-", bytes, buf);

	fprintf(stderr, "[%s] SetParam(stSetTableDataCallback)\n", SetParam_Pointer(stSetTableDataCallback, &set_callback) ? "+": "-");
	fprintf(stderr, "[%s] SetParam(stWriteLogCallback)\n", SetParam_Pointer(stWriteLogCallback, &write_log_callback) ? "+": "-");

	ScanRouter(router);
	FreeRouter(router);

	dlclose(handle);
	return 0;
}
