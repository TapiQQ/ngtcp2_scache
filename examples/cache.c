
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <gdbm.h>
#include "cache.h"

struct ssl_scinfo_t {
	const unsigned char  *ucaKey;
   	unsigned int  nKey;
   	unsigned char  *ucaData;
   	int   nData;
   	int   tExpiresAt;
};


int ssl_scache_store(SSL_SESSION *sess, int timeout){
	struct ssl_scinfo_t SCI;
	unsigned char buf[1024*20];
	unsigned char *b;
	int rc = 0;
	unsigned int *max_session_id_length;
	unsigned int var = 32;

	max_session_id_length = &var;


	SCI.ucaKey = SSL_SESSION_get_id(sess, max_session_id_length);
	SCI.nKey = var;

	SCI.ucaData = b = buf;
	SCI.nData = i2d_SSL_SESSION(sess, &b);
	SCI.tExpiresAt = timeout;

	ssl_scache_dbm_store(&SCI, "/home/quic/cache/cache.gdbm");


	//Store to neighbour's databases as well
	int max_neighbours;
	char fn[26] = "/home/quic/mnt1/cache.gdbm";
	FILE *file;

	for(int i = 1; i < max_neighbours; i++){
		fn[14] = i+'0';
		if(access(fn, F_OK) != -1){
			ssl_scache_dbm_store(&SCI, fn);
		}
	}

	return 1;
}

SSL_SESSION *ssl_scache_retrieve(unsigned char *id, int idlen){
	SSL_SESSION *sess;
	struct ssl_scinfo_t SCI;
	time_t tNow;

	//Current time
	tNow = time(NULL);

	//Create cache query
	SCI.ucaKey = id;
	SCI.nKey = idlen;
	SCI.ucaData = NULL;
	SCI.nData = 0;
	SCI.tExpiresAt = 0;

	//query
	ssl_scache_dbm_retrieve(&SCI);


	//Return if not found
	if(SCI.ucaData == NULL){
		return NULL;
	}

	//no expiration implementation yet

	sess = d2i_SSL_SESSION(NULL, (const unsigned char **)&SCI.ucaData, SCI.nData);
	return sess;
}


int ssl_scache_dbm_store(struct ssl_scinfo_t *SCI, char* file){
	GDBM_FILE gdbm;
	datum dbmkey;
	datum dbmval;
	int err;
	const unsigned char* id = malloc(sizeof(const unsigned char *));


	//Don't try to store too much
	if ((SCI->nKey + SCI->nData) >= 950 /* at least less than approx. 1KB */)
        return 0;

	//Create DBM key
	dbmkey.dptr = (char *)(SCI->ucaKey);
	dbmkey.dsize = SCI->nKey;

	//Create DBM value
	dbmval.dsize = sizeof(time_t) + SCI->nData;
	dbmval.dptr  = (char *)malloc(dbmval.dsize);
	if (dbmval.dptr == NULL){
        	return 0;
	}
	memcpy((char *)dbmval.dptr, &SCI->tExpiresAt, sizeof(time_t));
	memcpy((char *)dbmval.dptr+sizeof(time_t), SCI->ucaData, SCI->nData);


	//Store to DBM file
	gdbm = gdbm_open(file, 0, GDBM_WRITER, 777, NULL);
	err = gdbm_store(gdbm, dbmkey, dbmval, GDBM_INSERT);
	if(err != 0){
		printf("error: %i\n", err);
		return 0;
	}
	gdbm_close(gdbm);




	free(dbmval.dptr);

	//printf("ssl_scache_dbm_store successful on %s\n", file);
	return 1;
}

void ssl_scache_dbm_retrieve(struct ssl_scinfo_t *SCI){
	GDBM_FILE gdbm;
	GDBM_FILE gdbm_ext;
	datum dbmkey;
	datum dbmval;
	datum dbmkey_ext;
	datum dbmval_ext;
	int err;

	//Initialize result
	SCI->ucaData = NULL;
	SCI->nData = 0;
	SCI->tExpiresAt = 0;

	//Create DBM key and values
	dbmkey.dptr = (char *)(SCI->ucaKey);
	dbmkey.dsize = SCI->nKey;


	//fetch it from the DBM file
	gdbm = gdbm_open("/home/quic/cache/cache.gdbm", 0, GDBM_READER, 777, NULL);
	dbmval = gdbm_fetch(gdbm, dbmkey);
	gdbm_close(gdbm);


	//Return if not found
	if(dbmval.dptr == NULL || dbmval.dsize <= sizeof(time_t)){
		printf("Retrieved session was NULL\n");
		return;
	}


	//Copy over the information to the SCI
	SCI->nData = dbmval.dsize-sizeof(time_t);
	SCI->ucaData = (unsigned char *)malloc(SCI->nData);
	if (SCI->ucaData == NULL){
        	SCI->nData = 0;
		return;
    	}
	memcpy(SCI->ucaData, (char *)dbmval.dptr+sizeof(time_t), SCI->nData);
	memcpy(&SCI->tExpiresAt, dbmval.dptr, sizeof(time_t));

	return;

	//ToDo: Record expiration
}
