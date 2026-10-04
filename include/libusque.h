#pragma once

#ifdef __cplusplus
extern "C" {
#endif

/* Returned JSON strings are owned by Go and must be released with PRUsqueFree. */
char *PRUsqueInvoke(char *requestJSON);
char *PRUsqueRegister(char *requestJSON);
char *PRUsqueStart(char *requestJSON);
char *PRUsqueStop(char *sessionID);
char *PRUsqueStopAll(void);
char *PRUsqueStatus(char *sessionID);
int PRUsqueIsReady(char *sessionID);
char *PRUsqueLastError(char *sessionID);
char *PRUsqueProbe(char *requestJSON);
void PRUsqueFree(char *value);
int PRUsqueIsStub(void);

#ifdef __cplusplus
}
#endif
