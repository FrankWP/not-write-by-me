#ifndef	_LICENSE_FILE_PROCESS_H_
#define	_LICENSE_FILE_PROCESS_H_

#include <stdio.h>
#include <inttypes.h>
#include <syslog.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PROCESS_FILE_NAME       ".liprocess"
#define PROCESS_FILE_PATH       "/etc/.topwalk"   // a folder that save process file

#define SZ_SIGN         16
#define SZ_MACHINE_ID   256
#define VERSION         0x100   // version of license file and process file must be same.

typedef uint32_t        LI_UINT32;
typedef uint64_t        LI_UINT64;
typedef LI_UINT64       LI_TIME;
//typedef LI_UINT32       LI_TIME;

typedef enum
{
    LSS_OK          = 0,	// LicenSe Signature OK.
	LSS_UNKNOWN_BAD	= 1,	// 
    LSS_VER_BAD     = 2,
    LSS_SIGN_BAD    = 3,
}LSIGN_STAT;

/*
typedef enum
{
	LRF_DEFAULT		= 0,
	LRF_RESETTM		= 1,
}LRFLG;	// License Register Flag
*/

typedef struct __license_head
{
	char	    company[256];   // Which company register to.
	LI_TIME     date_create;	// the date of creating license file.
	LI_TIME     sec_last;		// how many seconds did you registered.
	LI_UINT32   num_append_inf; // how many append items are there.
}lihead;

typedef struct __license_append
{
	char        name[32];   // name of data
	LI_UINT32   sz_data;    // data size
	char        *data;      // point to data

	struct __license_append *next;
}liappend;

typedef struct __license_information
{
    char        li_sign[SZ_SIGN];   // sign of license file
    LI_UINT32   version;
	char	    machine_id[SZ_MACHINE_ID];    // machind id register to.
	lihead      lih;
	liappend    *lia;
}license_information;

typedef struct __license_history
{
    LI_UINT32       sz_self;    // total size of this item(in file).  char        md5[16];    // md5 value of license file.
    unsigned char   md5[16];
    lihead          lih;

    struct __license_history *next;
}lihistory;

typedef struct __process_information
{
    char        pr_sign[SZ_SIGN];   // sign of process file.
    LI_UINT32   version;
	LI_TIME		date_reg;		// the latest register date.
    LI_TIME     sec_elapse;    // total seconds of license working.
    LI_TIME     sec_left;      // how many seconds left of license.

    lihead      lih;            // current license head info.
    liappend    *lia;           // current license append info.

    LI_UINT32   num_history;    // how many license history item are there.
    lihistory   *lihis;         // license history, including current license.
}process_information;

///////////////////////////////////////////////////////
// about license running mod

#define REGIST_INTERVAL       0
#define CHECK_INTERVAL        5

struct li_arg
{
	char pro_name[32];
	char li_path[256];
	int exit_code;
	void (*before_exit)(int);
};

struct li_run_status 
{
	//int		is_loaded;
	process_information pro_info;
	char	pro_file_path[512];
	char	pro_file_name[512];
	char	li_path[512];
	int		exit_code;
	void	(*before_exit)(int);
};

void* li_mod(void *p);

#define li_free(ptr) __license_free((void**)(ptr))
void __license_free(void **p);

// license functions
int init_license_information(license_information *li, const char *machine_id, const char *company, LI_TIME date_create, LI_TIME sec_last);
int add_append_information(license_information *li, const char *name, const char *data, size_t sz_data);
int make_license_file(const char *path, license_information *li);

//int parse_license_file(char *path, license_information *li);
int parse_license_file(const char *path, license_information *linf, unsigned char *md5val);
int get_licnese_appendinfo_val_sz(license_information *li, const char *name);	// return 0, if val does not exist, or get failed. else return a int large than 0.
int get_license_appendinfo_val(license_information *li, char *name, char *store, size_t sz_store);
int	get_valid_license(const char *path, license_information *linf, lihistory *lihis, unsigned char *md5val);

void clear_license_information(license_information *li);

// process functions
int init_process_information(process_information *pinf);
int load_process_file(const char *fpath, const char *fname, process_information *pinf);
//int save_process_file(char *path, process_information *pinf);
int save_process_file(const char *fpath, const char *fname, process_information *pinf);

int replace_license(process_information *pinf, license_information *linf, const unsigned char *md5val);
int import_license(const char *licpath, const char *propath, const char *proname, process_information *pinf);
int register_license(license_information *plinf, const unsigned char *md5val, const char *licpath, const char *propath, const char *proname, process_information *pinf);
void clear_process_information(process_information *pinf);
char *get_append_data_by_name(liappend *lia, const char *name, size_t *sz_data);
lihistory *get_licensehistory_by_idx(lihistory *lihis, int idx);

int get_fingerprint(char *str, int len);

#ifdef __cplusplus
}
#endif

#endif	// _LICENSE_FILE_PROCESS_H_

