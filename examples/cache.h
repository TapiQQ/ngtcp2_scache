#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <gdbm.h>

struct ssl_scinfo_t;

int ssl_scache_store(SSL_SESSION *sess, int timeout);
SSL_SESSION *ssl_scache_retrieve(unsigned char *id, int idlen);
void ssl_scache_remove(SSL_SESSION *sess);
void ssl_scache_expire(time_t now);

int ssl_scache_dbm_store(struct ssl_scinfo_t *SCI, char* file);
void ssl_scache_dbm_retrieve(struct ssl_scinfo_t *SCI);
void ssl_scache_dbm_remove(struct ssl_scinfo_t *SCI);
void ssl_scache_dbm_expire(time_t tNow);

#ifdef __cplusplus
}
#endif
