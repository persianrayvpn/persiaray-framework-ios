#pragma once

#include <stdint.h>
#include "libusque.h"
#include "liburnetwork.h"

#ifdef __cplusplus
extern "C" {
#endif

char *AwgStart(char *configJSON);
char *AwgStop(void);
char *AwgSetHopInner(char *endpoint);
char *AwgPing(char *requestJSON);
long long AwgAdBlockTake(void);
void AwgFree(char *p);
int AwgIsStub(void);

char *CGoInvoke(char *requestJSON);
void CGoFree(char *value);
int LibXrayIsStub(void);

char *PRPsiphonStart(char *configJSON, char *embeddedServerList);
void PRPsiphonStop(void);
char *PRPsiphonNoticePoll(void);
int PRPsiphonSocksPort(void);
int PRPsiphonHTTPPort(void);
int PRPsiphonIsConnected(void);
void PRPsiphonFree(char *value);
int PRPsiphonIsStub(void);

#ifdef __cplusplus
}
#endif
