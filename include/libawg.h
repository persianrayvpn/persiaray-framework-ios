#pragma once

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
char *PRTravelPick(char *requestJSON);
char *PRTravelLogTake(void);
void PRTravelFree(char *p);

#ifdef __cplusplus
}
#endif
