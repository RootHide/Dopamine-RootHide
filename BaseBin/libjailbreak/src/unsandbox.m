#include <stdio.h>
#include <unistd.h>
#include <spawn.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/event.h>
#include <sys/syscall.h>

#import <Foundation/Foundation.h>
#import "libjailbreak.h"

#include "vnode.h"

#define LOG JBLogDebug
extern uint64_t unsign_kptr(uint64_t);

struct  namecache {
	TAILQ_ENTRY(namecache)  nc_entry;       /* chain of all entries */
	TAILQ_ENTRY(namecache)  nc_child;       /* chain of ncp's that are children of a vp */
	union {
		LIST_ENTRY(namecache)  nc_link; /* chain of ncp's that 'name' a vp */
		TAILQ_ENTRY(namecache) nc_negentry; /* chain of ncp's that 'name' a vp */
	} nc_un;
	LIST_ENTRY(namecache)   nc_hash;        /* hash chain */
	vnode_t                 nc_dvp;         /* vnode of parent of name */
	vnode_t                 nc_vp;          /* vnode the name refers to */
	unsigned int            nc_hashval;     /* hashval of stringname */
	const char              *nc_name;       /* pointer to segment name in string cache */
};

static unsigned int crc32tab[256];

static void
init_crc32(void)
{
	/*
	 * the CRC-32 generator polynomial is:
	 *   x^32 + x^26 + x^23 + x^22 + x^16 + x^12 + x^10
	 *        + x^8  + x^7  + x^5  + x^4  + x^2  + x + 1
	 */
	unsigned int crc32_polynomial = 0x04c11db7;
	unsigned int i, j;

	/*
	 * pre-calculate the CRC-32 remainder for each possible octet encoding
	 */
	for (i = 0; i < 256; i++) {
		unsigned int crc_rem = i << 24;

		for (j = 0; j < 8; j++) {
			if (crc_rem & 0x80000000) {
				crc_rem = (crc_rem << 1) ^ crc32_polynomial;
			} else {
				crc_rem = (crc_rem << 1);
			}
		}
		crc32tab[i] = crc_rem;
	}
}

unsigned int
hash_string(const char *cp, int len)
{
	unsigned hash = 0;

	if (len) {
		while (len--) {
			hash = crc32tab[((hash >> 24) ^ (unsigned char)*cp++)] ^ hash << 8;
		}
	} else {
		while (*cp != '\0') {
			hash = crc32tab[((hash >> 24) ^ (unsigned char)*cp++)] ^ hash << 8;
		}
	}
	/*
	 * the crc generator can legitimately generate
	 * a 0... however, 0 for us means that we
	 * haven't computed a hash, so use 1 instead
	 */
	if (hash == 0) {
		hash = 1;
	}
	return hash;
}

static void print_nc(uint64_t ncp) 
{
	while(ncp) {

		struct namecache nc={0};
		kreadbuf(ncp, &nc, sizeof(nc));

		char namebuf[128]={0};
		for(int i=0; i<sizeof(namebuf)/sizeof(namebuf[0]); i++)
			if( !(namebuf[i]=kread8((uint64_t)nc.nc_name+i)) ) break;

		LOG("nc %llx hashval=%08x vp=%16llx dvp=%llx name=%llx next=%16llx prev=%llx,%llx %s\n", ncp, nc.nc_hashval, nc.nc_vp, nc.nc_dvp, nc.nc_name, 
				nc.nc_hash.le_next, nc.nc_hash.le_prev, nc.nc_hash.le_prev?kread64((uint64_t) nc.nc_hash.le_prev):0, namebuf);

		ncp = (uint64_t)nc.nc_hash.le_next;
	}
}

static int make_tail_file()
{
    char tail[PATH_MAX];
    snprintf(tail, sizeof(tail), "/tmp/%u", arc4random());
    printf("tail=%s\n", tail);
    int tailfd = open(tail, O_RDWR|O_CREAT, 0666);
    if(tailfd < 0) return -1;
    printf("tailfd=%d\n", tailfd);
    uint64_t tailvp = proc_get_vnode_by_file_descriptor(self_proc(), tailfd);
    if(tailvp == 0) return -1;
    printf("tailvp=%llx\n", tailvp);
	struct vnode tailvnode;
	kreadbuf(tailvp, &tailvnode, sizeof(tailvnode));
    struct namecache tailnc={0};
	uint64_t tailncp = (uint64_t)tailvnode.v_nclinks.lh_first;
    printf("tailncp=%llx\n", tailncp);
	kreadbuf(tailncp, &tailnc, sizeof(tailnc));
    printf("tailnc.nc_entry.tqe_prev=%p\n", tailnc.nc_entry.tqe_prev);
    printf("tailnc.nc_entry.tqe_next=%p\n", tailnc.nc_entry.tqe_next);
    return 0;
}

#include <libgen.h>
 int unsandbox(const char* dir, const char* file)
{
	int ret = 0;
	int filefd=-1,dirfd=-1;

	 dirfd = open(dir, O_RDONLY);
	if(dirfd<0) {
		JBLogError("open dir failed %d,%s", errno, strerror(errno));
		goto failed;
	}

	 filefd = open(file, O_RDONLY);
	if(filefd<0) {
		JBLogError("open file failed %d,%s", errno, strerror(errno));
		goto failed;
	}
		
	/* we need to create a new namecache to add to the tail of nchead 
        after the kernel caches the namecache for "file" to avoid filenc.nc_entry.tqe_next==0 */
    if(make_tail_file() != 0) {
        JBLogError("make_tail_file failed %d,%s", errno, strerror(errno));
        goto failed;
    }

	uint64_t dirvp = proc_get_vnode_by_file_descriptor(self_proc(), dirfd);
	if(!dirvp) {
		JBLogError("get dirvp failed %d,%s", errno, strerror(errno));
		goto failed;
	}

	struct vnode dirvnode;
	kreadbuf(dirvp, &dirvnode, sizeof(dirvnode));
	kwrite32(dirvp+offsetof(struct vnode, v_usecount), dirvnode.v_usecount+1);

	uint64_t filevp = proc_get_vnode_by_file_descriptor(self_proc(), filefd);
	if(!filevp) {
		JBLogError("get filevp failed %d,%s", errno, strerror(errno));
		goto failed;
	}

	struct vnode filevnode;
	kreadbuf(filevp, &filevnode, sizeof(filevnode));

	kwrite32(filevp+offsetof(struct vnode, v_usecount), filevnode.v_usecount+1);


	struct vnode parentvnode;
	uint64_t parentvp = unsign_kptr((uint64_t)filevnode.v_parent);
	kreadbuf(parentvp, &parentvnode, sizeof(parentvnode));
	kwrite32(parentvp+offsetof(struct vnode, v_usecount), parentvnode.v_usecount+1);


	JBLogDebug("filefd=%d filevp=%llx fileid=%lld parent=%llx dirvp=%llx dirid=%lld\n", filefd, filevp, filevnode.v_id, filevnode.v_parent, dirvp, dirvnode.v_id);

	struct namecache filenc={0};
	uint64_t filencp = (uint64_t)filevnode.v_nclinks.lh_first;
	kreadbuf(filencp, &filenc, sizeof(filenc));
	JBLogDebug("filefd=%d filevp=%llx fileid=%lld parent=%llx dirvp=%llx dirid=%lld ncchildren=%llx:%llx->%llx\n", 
		filefd, filevp, filevnode.v_id, filevnode.v_parent, dirvp, dirvnode.v_id, dirvnode.v_ncchildren.tqh_first, dirvnode.v_ncchildren.tqh_last, 
		dirvnode.v_ncchildren.tqh_last?kread64((uint64_t)dirvnode.v_ncchildren.tqh_last):0);

{
	uint64_t ncp=(uint64_t)dirvnode.v_ncchildren.tqh_first;
	while(ncp) {

		struct namecache nc={0};
		kreadbuf(ncp, &nc, sizeof(nc));

		char namebuf[128]={0};
		for(int i=0; i<sizeof(namebuf)/sizeof(namebuf[0]); i++)
			if( !(namebuf[i]=kread8((uint64_t)nc.nc_name+i)) ) break;

		LOG("child %llx hashval=%08x vp=%16llx dvp=%llx name=%llx next=%16llx prev=%llx,%llx %s\n", ncp, nc.nc_hashval, nc.nc_vp, nc.nc_dvp, nc.nc_name, 
				nc.nc_child.tqe_next, nc.nc_child.tqe_prev, nc.nc_child.tqe_prev?kread64((uint64_t) nc.nc_child.tqe_prev):0, namebuf);

		ncp = (uint64_t)nc.nc_child.tqe_next;
	}
}

	init_crc32();
	char fname[PATH_MAX];
	uint32_t hash_val = hash_string(basename_r(file, fname), 0);
	JBLogDebug("hash=%x\n", hash_val);

	uint64_t kernelslide = bootInfo_getUInt64(@"kernelslide");
	JBLogDebug("kernelslide=%llx\n", kernelslide);
	uint64_t nchashtbl = kread64(kernelslide+ bootInfo_getUInt64(@"nchashtbl"));
	uint64_t nchashmask = kread64(kernelslide+ bootInfo_getUInt64(@"nchashmask"));
	JBLogDebug("nchashtbl=%llx nchashmask=%llx\n", nchashtbl, nchashmask);
	// for(int i=0; i<nchashmask; i++) {
	// 	JBLogDebug("hash[%d]=%llx\n", i, kread64(nchashtbl+i*8));
	// }

	uint32_t index = (dirvnode.v_id ^ (hash_val)) & nchashmask; //*********dirv2?
	uint64_t ncpp = nchashtbl + index*8;
	uint64_t ncp = kread64(ncpp);
	JBLogDebug("index=%x ncpp=%llx ncp=%llx\n", index, ncpp, ncp);

	JBLogDebug("dir hash chain\n");
	print_nc(kread64(ncpp));
	

	//return 0; //////////////////////////////////////////////////////////////////////////////////////////////////////////////////


	kwrite64(filencp+offsetof(struct namecache,nc_dvp), dirvp);
	kwrite_ptr(filevp+offsetof(struct vnode, v_parent), (uint64_t)dirvp, 0xF506);


	//LIST_REMOVE(ncp, nc_hash):
	{
		uint64_t ncp = filencp;
		
		if(filenc.nc_hash.le_next) {
			//LIST_NEXT((elm), field)->field.le_prev =(elm)->field.le_prev;
			kwrite64((uint64_t)filenc.nc_hash.le_next+offsetof(struct namecache, nc_hash.le_prev), (uint64_t)filenc.nc_hash.le_prev); //next->prev = prev
		}

		//*(elm)->field.le_prev = LIST_NEXT((elm), field);
		kwrite64((uint64_t)filenc.nc_hash.le_prev, (uint64_t)filenc.nc_hash.le_next);
	}
	//LIST_INSERT_HEAD(ncpp, ncp, nc_hash):
	{
		uint64_t ncp = filencp;

		uint64_t first = kread64(ncpp);
		kwrite64(ncp+offsetof(struct namecache, nc_hash.le_next), first);
		if(first) { //if ((LIST_NEXT((elm), field) = LIST_FIRST((head))) != NULL)
			//LIST_FIRST((head))->field.le_prev = &LIST_NEXT((elm), field);
			kwrite64(first+offsetof(struct namecache, nc_hash.le_prev),  ncp+offsetof(struct namecache, nc_hash.le_next) );
		}
		kwrite64(ncpp, ncp); //LIST_FIRST((head)) = (elm);
		kwrite64(ncp+offsetof(struct namecache, nc_hash.le_prev), ncpp); //(elm)->field.le_prev = &LIST_FIRST((head));
	}

	//TAILQ_REMOVE(&(ncp->nc_dvp->v_ncchildren), ncp, nc_child);
	{	
		uint64_t ncp = filencp;
		if(filenc.nc_child.tqe_next) { //always true for filenc next time
			//TAILQ_NEXT((elm), field)->field.tqe_prev = (elm)->field.tqe_prev;
			kwrite64((uint64_t)filenc.nc_child.tqe_next+offsetof(struct namecache, nc_child.tqe_prev), (uint64_t)filenc.nc_child.tqe_prev);
		} else {
			//(head)->tqh_last = (elm)->field.tqe_prev;
			kwrite64(parentvp+offsetof(struct vnode,v_ncchildren.tqh_last), (uint64_t)filenc.nc_child.tqe_prev);
		}
		//*(elm)->field.tqe_prev = TAILQ_NEXT((elm), field);
		kwrite64((uint64_t)filenc.nc_child.tqe_prev, (uint64_t)filenc.nc_child.tqe_next);

		kwrite64(filencp+offsetof(struct namecache,nc_child.tqe_next), filencp); //TAILQ_CHECK_NEXT
		kwrite64(filencp+offsetof(struct namecache,nc_child.tqe_prev), filencp+offsetof(struct namecache,nc_child.tqe_next)); //TAILQ_CHECK_PREV
	}
	
	//TAILQ_REMOVE(&nchead, ncp, nc_entry);
	{	
		uint64_t ncp = filencp;
		if(filenc.nc_entry.tqe_next) { //always true for filenc next time
			//TAILQ_NEXT((elm), field)->field.tqe_prev = (elm)->field.tqe_prev;
			kwrite64((uint64_t)filenc.nc_entry.tqe_next+offsetof(struct namecache, nc_entry.tqe_prev), (uint64_t)filenc.nc_entry.tqe_prev);
		} else {
			//(head)->tqh_last = (elm)->field.tqe_prev;
			abort();
		}
		//*(elm)->field.tqe_prev = TAILQ_NEXT((elm), field);
		kwrite64((uint64_t)filenc.nc_entry.tqe_prev, (uint64_t)filenc.nc_entry.tqe_next);

		kwrite64(filencp+offsetof(struct namecache,nc_entry.tqe_next), filencp); //TAILQ_CHECK_NEXT
		kwrite64(filencp+offsetof(struct namecache,nc_entry.tqe_prev), filencp+offsetof(struct namecache,nc_entry.tqe_next)); //TAILQ_CHECK_PREV
	}

    //LIST_REMOVE(ncp, nc_un.nc_link);
	{
		uint64_t ncp = filencp;
		
		if(filenc.nc_un.nc_link.le_next) {
			//LIST_NEXT((elm), field)->field.le_prev =(elm)->field.le_prev;
			kwrite64((uint64_t)filenc.nc_hash.le_next+offsetof(struct namecache, nc_un.nc_link.le_prev), (uint64_t)filenc.nc_un.nc_link.le_prev); //next->prev = prev
		}

		//*(elm)->field.le_prev = LIST_NEXT((elm), field);
		kwrite64((uint64_t)filenc.nc_un.nc_link.le_prev, (uint64_t)filenc.nc_un.nc_link.le_next);
	}

	JBLogDebug("final hash chain\n");
	print_nc(kread64(ncpp));


	JBLogDebug("unsandboxed %llx %llx %s %s\n\n", filevp, dirvp, file, dir);

	ret = 0;
	goto success;

failed:
	ret = -1;

success:
	if(dirfd>=0) close(dirfd);
	if(filefd>=0) close(filefd);

	return ret;
}
