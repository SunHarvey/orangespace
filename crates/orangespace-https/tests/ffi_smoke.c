#include "orangespace_https.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
static uint8_t out[1048576], node[64];
static OsHttpsBytes bytes(const char *s) { OsHttpsBytes b={(const uint8_t*)s,strlen(s)}; return b; }
int main(int argc, char **argv) {
    uint32_t status=999, len=999;
    memset(out,0xa5,sizeof out); memset(node,0xa5,sizeof node);
    assert(os_https_request_v1(NULL,out,sizeof out,&status,node,sizeof node,&len)==-1);
    assert(status==999 && len==999 && out[0]==0xa5 && node[0]==0xa5);
    OsHttpsRequest r={bytes("http://credential-not-allowed"),bytes("invalid ca"),bytes("GET"),bytes("/ok"),bytes("secret-body-never-print"),bytes("secret-token-never-print")};
    assert(os_https_request_v1(&r,out,sizeof out,&status,node,sizeof node,&len)==-1);
    assert(os_https_request_v1(&r,out,sizeof out-1,&status,node,sizeof node,&len)==-1);
    assert(os_https_request_v1(&r,out,sizeof out,&status,node,sizeof node-1,&len)==-1);
    r.origin.ptr=NULL; r.origin.len=1;
    assert(os_https_request_v1(&r,out,sizeof out,&status,node,sizeof node,&len)==-1);
    r.origin.len=(size_t)-1;
    assert(os_https_request_v1(&r,out,sizeof out,&status,node,sizeof node,&len)==-1);
    assert(status==999 && len==999);
    for(size_t i=0;i<sizeof out;i++) assert(out[i]==0xa5);
    for(size_t i=0;i<sizeof node;i++) assert(node[i]==0xa5);
    if(argc==3) {
        FILE *fp=fopen(argv[2],"rb"); assert(fp); uint8_t ca[8192]; size_t n=fread(ca,1,sizeof ca,fp); fclose(fp);
        r.origin=bytes(argv[1]); r.ca_pem=(OsHttpsBytes){ca,n}; r.method=bytes("POST"); r.path=bytes("/status"); r.body=bytes("{\"error\":\"exact\"}"); r.bearer=bytes("");
        int32_t result=os_https_request_v1(&r,out,sizeof out,&status,node,sizeof node,&len);
        assert(result==17 && status==401 && len==43); assert(memcmp(out,"{\"error\":\"exact\"}",17)==0);
        r.path=bytes("/centre");
        result=os_https_request_v1(&r,out,sizeof out,&status,NULL,0,&len);
        assert(result==17 && status==200 && len==0);
    }
    puts("C ABI linked: malformed/caps/atomic error and optional real TLS status/body passed");
    return 0;
}
