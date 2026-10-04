#pragma once

#ifdef __cplusplus
extern "C" {
#endif

/* Returned JSON is owned by Go and must be released with PRUrFree.
   PRUrStart blocks until a provider is up and the loopback SOCKS port listens.
   Request: data_dir, network_jwt, client_jwt, country, strong, post_quantum,
   upstream_socks, socks_port, device_model, version, instance_id. */
char *PRUrStart(char *requestJSON);
char *PRUrStop(void);
void PRUrFree(char *value);
int PRUrIsStub(void);

#ifdef __cplusplus
}
#endif
