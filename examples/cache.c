
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

	//Add the key
	SCI.ucaKey = SSL_SESSION_get_id(sess, max_session_id_length);
	SCI.nKey = var;

	//Transform the session into a data stream
	SCI.ucaData = b = buf;
	SCI.nData = i2d_SSL_SESSION(sess, &b);
	SCI.tExpiresAt = timeout;

	//And store it
	ssl_scache_dbm_store(&SCI, "/home/quic/cache/cache.gdbm");

	//Store to neighbour's databases as well
	int max_neighbours = 5;
	char fn[26] = "/home/quic/mnt1/cache.gdbm";
	FILE *file;

	for(int i = 1; i < max_neighbours; i++){
		fn[14] = i+'0';
		if(access(fn, F_OK) != -1){
			ssl_scache_dbm_store(&SCI, fn);
		}
	}

	//Allow the regular expiring to occur
	ssl_scache_expire(time(NULL));

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

	//Perform query
	ssl_scache_dbm_retrieve(&SCI);


	//Return if not found
	if(SCI.ucaData == NULL){
		return NULL;
	}

	//check for expire time
	if(SCI.tExpiresAt <= tNow){
		printf("Retrieved session was expired\n");
		ssl_scache_dbm_remove(&SCI);
		return NULL;
	}

	sess = d2i_SSL_SESSION(NULL, (const unsigned char **)&SCI.ucaData, SCI.nData);
	return sess;
}

void ssl_scache_remove(SSL_SESSION *sess){
	struct ssl_scinfo_t SCI;
	unsigned int *max_session_id_length;
	unsigned int var = 32;

	max_session_id_length = &var;

	//create cache query
	SCI.ucaKey = SSL_SESSION_get_id(sess, max_session_id_length);
	SCI.nKey = var;
	SCI.ucaData = NULL;
	SCI.nData = 0;
	SCI.tExpiresAt = 0;

	//perform removal
	ssl_scache_dbm_remove(&SCI);

	return;
}

void ssl_scache_expire(time_t now){
	static time_t last = 0;

	/* Expiration should only be done from time to time
	   Need an implementation for this propably */

	/*Perform expiration
	printf("Trying to perform expiration\n");
	ssl_scache_dbm_expire(now);
	*/

	return;
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
}

void ssl_scache_dbm_remove(struct ssl_scinfo_t *SCI){
	GDBM_FILE gdbm;
	datum dbmkey;
	int err;

	//Create GDBM key and value
	dbmkey.dptr = (char *)(SCI->ucaKey);
	dbmkey.dsize = SCI->nKey;

	//Delete it from the GDBM file
	gdbm = gdbm_open("/home/quic/cache/cache.gdbm", 0, GDBM_WRITER, 777, NULL);
	err = gdbm_delete(gdbm, dbmkey);
	if(err == 0){
		printf("Entry successfully removed\n");
	}
	gdbm_close(gdbm);

	return;
}

void ssl_scache_dbm_expire(time_t tNow){
	GDBM_FILE gdbm;
	datum dbmkey;
	datum dbmval;
	time_t tExpiresAt;
	int nElements = 0;
	int nDeleted = 0;
	int bDelete;
	datum *keylist;
	int keyidx;
	int i;
	int j;


	#define KEYMAX 32

		//loop 2: scan DBM database
		keyidx = 0;
		gdbm = gdbm_open("/home/quic/cache/cache.gdbm", 0, GDBM_WRITER, 777, NULL);
		dbmkey = gdbm_firstkey(gdbm);
		while(dbmkey.dptr != NULL){
			nElements++;
			bDelete = 0;
			dbmval = gdbm_fetch(gdbm, dbmkey);
			if(dbmval.dsize <= sizeof(time_t) || dbmval.dptr == NULL){
				bDelete = 1;
			}
			else{
				memcpy(&tExpiresAt, dbmval.dptr, sizeof(time_t));
				if(tExpiresAt <= tNow){
					bDelete = 1;
				}
			}
			if(bDelete){
				if((keylist[keyidx].dptr = malloc(dbmkey.dsize)) != NULL){
					memcpy(keylist[keyidx].dptr, dbmkey.dptr, dbmkey.dsize);
					keylist[keyidx].dsize = dbmkey.dsize;
					keyidx++;
					if(keyidx == KEYMAX){
						break;}
				}
			}
			dbmkey = gdbm_nextkey(gdbm, dbmkey);
		}
		gdbm_close(gdbm);


		//loop 2: delete expired elements
		gdbm = gdbm_open("/home/quic/cache/cache.gdbm", 0, GDBM_WRITER, 777, NULL);
		for(i = 0; i < keyidx; i++){
			gdbm_delete(gdbm, keylist[i]);
			nDeleted++;
			printf("Entry successfully deleted\n");
		}
		gdbm_close(gdbm);

		for(j = 0; j < keyidx; j++){
			free(keylist[j].dptr);
		}

	return;
}
