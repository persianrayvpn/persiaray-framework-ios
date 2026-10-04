#pragma once

#ifdef __cplusplus
extern "C" {
#endif

char *CGoInvoke(char *requestJSON);
void CGoFree(char *value);
int LibXrayIsStub(void);

#ifdef __cplusplus
}
#endif
