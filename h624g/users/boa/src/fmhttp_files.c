/*
 * Realtek Semiconductor Corp.
 * 2011/09/09
 *
 * HTTP file server handler routines
 *
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <sys/sysinfo.h>
#include <dirent.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdarg.h>
#include "apmib.h"
#include "boa.h"
#include "asp_page.h"
#include "apform.h"
#include "utility.h"
#include "http_files.h"


#define DOT_OR_DOTDOT(s) ((s)[0] == '.' && (!(s)[1] || ((s)[1] == '.' && !(s)[2])))


// Die with an error message if we can't malloc() enough space and do an
// sprintf() into that space.
char* xasprintf(const char *format, ...)
{
	va_list p;
	int r;
	char *string_ptr;

	// GNU extension
	va_start(p, format);
	r = vasprintf(&string_ptr, format, p);
	va_end(p);


	if (r < 0)
		printf("xasprintf die\n");
	return string_ptr;
}

char* concat_path_file(const char *path, const char *filename)
{
	char *lc;

	if (!path)
		path = "";
	lc = last_char_is(path, '/');
	while (*filename == '/')
		filename++;
	return xasprintf("%s%s%s", path, (lc==NULL ? "/" : ""), filename);
}

char* concat_subpath_file(const char *path, const char *f)
{
	if (f && DOT_OR_DOTDOT(f))
		return NULL;
	return concat_path_file(path, f);
}

int remove_file(const char *path)
{
	struct stat path_stat;

	if (lstat(path, &path_stat) < 0) {
		if (errno != ENOENT) {
			printf("cannot stat '%s'\n", path);
			return -1;
		}
		printf("cannot stat '%s'\n", path);
		return -1;
	}

	if (S_ISDIR(path_stat.st_mode)) {
		DIR *dp;
		struct dirent *d;
		int status = 0;

		
		dp = opendir(path);
		if (dp == NULL) {
			return -1;
		}

		while ((d = readdir(dp)) != NULL) {
			char *new_path;

			new_path = concat_subpath_file(path, d->d_name);
			if (new_path == NULL)
				continue;
			if (remove_file(new_path) < 0)
				status = -1;
			free(new_path);
		}

		if (closedir(dp) < 0) {
			printf("cannot close '%s'\n", path);
			return -1;
		}
		
		if (rmdir(path) < 0) {
			printf("cannot remove '%s'\n", path);
			return -1;
		}

		return status;
	}

	/* !ISDIR */
	

	if (unlink(path) < 0) {
		printf("cannot remove '%s'\n", path);
		return -1;
	}

	return 0;
}
char * strcat_str(char * str, int * len, int * tmplen, const char * s2)
{
	int s2len;
	s2len = (int)strlen(s2);
	if(*tmplen <= (*len + s2len))
	{
		if(s2len < 256)
			*tmplen += 256;
		else
			*tmplen += s2len;
		str = (char *)realloc(str, *tmplen);
	}
	memcpy(str + *len, s2, s2len + 1);
	*len += s2len;
	return str;
}
int rm_url_escape_char2(char *src_str)
{
	int len=0;
	int i=0;
	int hit=0;
	int real_len=0;
	char tmpBuf[4];
	unsigned char key[4];
	char *dest_str;
	
	//printf("%s:src_str=%s\n", __FUNCTION__, src_str);
	if(NULL == src_str)
		return -1;
	dest_str = src_str;
	len=strlen(src_str);
	do
	{
		if (src_str[i] !='%') {
			dest_str[real_len]=src_str[i];
			hit=0;
		}
		else {
			tmpBuf[0] = src_str[i+1];
			tmpBuf[1] = src_str[i+2];
			tmpBuf[2] = 0;
			
			if ( !_is_hex(tmpBuf[0]) || !_is_hex(tmpBuf[1]))
				return -1;
			key[0] = (unsigned char) strtol(tmpBuf, (char**)NULL, 16);
			hit=1;
			dest_str[real_len] = key[0];
		}
		if (hit==0)
			i=i+1;
		else
			i=i+3;
		real_len++;
	} while (i<len);
	dest_str[real_len]='\0';
//	printf("%s:dest_str=%s\n", __FUNCTION__, dest_str);
	return 0;
}

int rm_url_escape_char(char *src_str, char *dest_str)
{
	int len=0;
	int i=0;
	int hit=0;
	int real_len=0;
	char tmpBuf[4];
	unsigned char key[4];
	
	//printf("%s:src_str=%s\n", __FUNCTION__, src_str);
	if(NULL == src_str)
		return -1;
		
	len=strlen(src_str);
	
	do
	{
		if(src_str[i] !='%'){
			 dest_str[real_len]=src_str[i];
			 hit=0;
		}else{
			
			tmpBuf[0] = src_str[i+1];
			tmpBuf[1] = src_str[i+2];
			tmpBuf[2] = 0;
			
			if ( !_is_hex(tmpBuf[0]) || !_is_hex(tmpBuf[1]))
				return -1;
			key[0] = (unsigned char) strtol(tmpBuf, (char**)NULL, 16);
			hit=1;
			dest_str[real_len]=	key[0];
		}
	if(hit==0)
		i=i+1;
	else
		i=i+3;		
		real_len++;
	}while(i<len);
	dest_str[real_len]='\0';
//	printf("%s:dest_str=%s\n", __FUNCTION__, dest_str);
	return 0;
}

char* get_filenPath(char *path)  
{    
		char* ptr = strrchr(path,'/');    
			if( ptr != NULL)        
				ptr++;    
			return ptr;
}


void get_ParentDirectory(char *dest_path, char *src_path, int usage)
{
	char *token=NULL, *savestr1=NULL;
	char arg_buff[200]={0}, tmp_path[200]={0},last_path[200]={0};
	char sub_path[200]={0};
	int path_index=0;
	char *_last_;

	token=NULL;
	savestr1=NULL;	     
	sprintf(arg_buff, "%s", src_path);
	token = strtok_r(arg_buff,"/", &savestr1);
	memset(dest_path, 0x00, sizeof(dest_path));
	do{
			if (token == NULL){/*check if the first arg is NULL*/
				break;
			}else{   
				sprintf(last_path, "/%s", token);
				if(path_index>2){
					sprintf(tmp_path, "/%s", token);
					if(sub_path[0])
						strcat(sub_path, tmp_path);
					else
						sprintf(sub_path, "%s", tmp_path);
				}
			}
			path_index++;
		token = strtok_r(NULL, "/", &savestr1);
	}while(token !=NULL);
	if(usage==1){
		_last_=strstr(sub_path,last_path);
		snprintf(dest_path, _last_-sub_path+1, "%s",sub_path);
		//printf("href path=%s\n", dest_path);
	}else{
		if(sub_path[0])
			sprintf(dest_path, "%s",sub_path);
			//printf("display path=%s\n", dest_path);
	}
	
	return;	
}
static int PathEnrtySort(const void *p1, const void *p2)
{
	PATH_ENTRY_T	*s1=NULL, *s2=NULL;
	int					rc=-1;
	
	s1 = (PATH_ENTRY_T*)p1;
	s2 = (PATH_ENTRY_T*)p2;
	if(s1->type=='N'){
		if(!s1->name[0] || !s2->name[0]){
			return -1;
		}
	
		if(s1->name[0] && s2->name[0]) {
			//printf("s1->name=%s, s2->name=%s\n", s1->name, s2->name);
			rc = strcmp(s1->name, s2->name);
			
			if(s1->order == 'A'){
					if(rc < 0)
						return 1;
					if(rc > 0)
						return -1;	
			}
		}
		return rc; 
	}
	if(s1->type=='M'){
		if(s1->order == 'A'){
			if(s1->mtime > s2->mtime)
					return -1;
			if(s1->mtime < s2->mtime)
					return 1;
		}
		if(s1->order == 'D'){
			if(s1->mtime > s2->mtime)
					return 1;
			if(s1->mtime < s2->mtime)
					return -1;
		}
		return 0;
	}
	if(s1->type=='S'){
		if(s1->order == 'A'){
			if(s1->size > s2->size)
					return -1;
			if(s1->size < s2->size)
					return 1;
		}
		if(s1->order == 'D'){
			if(s1->size > s2->size)
					return 1;
			if(s1->size < s2->size)
					return -1;
		}
		return 0;
	}
	return 0;
}
char* find_Last2F_boundary(char *data, int dlen, char *pattern, int plen, int *result)
{	
	int i;	
	char *end=NULL;	
	
	if (plen > dlen)
		return 0;
	*result = 0;
	for (i=0; i<dlen;i++) {
		if (memcmp(data + i, pattern, plen)!=0) {
			continue;
		}
		else{		
			*result = 1;	
			end = (data + i);
		}
	}  
	return end;
}

char* last_char_is(const char *s, int c)
{
	if (s && *s) {
		size_t sz = strlen(s) - 1;
		s += sz;
		if ( (unsigned char)*s == c)
			return (char*)s;
	}
	return NULL;
}




void create_directory_list(char* Entrypath, int type, int order)
{
	char tmpbuff[1024];
	
	#if defined(ENABLE_LFS)
	struct stat64 sbuf;
	#else
	struct stat sbuf;
	#endif
	
 	DIR *dir=NULL;
	struct dirent *next;
	PATH_ENTRY_Tp FILE_sp;
	PATH_ENTRY_Tp DIR_sp;
	int current_entry=0;
	int FILE_len=0;
	int DIR_len=0;
	dir = opendir(Entrypath);
	if (!dir) {
		printf("Cannot open %s", Entrypath);
		return;
	}
	while ((next = readdir(dir)) != NULL) {
		//printf("create_directory_list:next->d_reclen=%d, next->d_name=%s, next->d_type=%x\n",next->d_reclen, next->d_name,next->d_type);
		/* Must skip ".." */
		if (strcmp(next->d_name, "..") == 0)
			continue;
		if (strcmp(next->d_name, ".") == 0)
			continue;

		if(	current_entry > MAX_PATH_ENTRY)
			continue;

		current_entry++;

		if(next->d_type==0x8){//regular file

			FILE_len = (CurrFILECount + 1) * sizeof(PATH_ENTRY_T);
			if((FileEntryHead = realloc(FileEntryHead, FILE_len)) == NULL) {
				return;
			}
			FILE_sp = &FileEntryHead[CurrFILECount++];
			memset(FILE_sp, 0, sizeof(PATH_ENTRY_T));
			FILE_sp->isDir=next->d_type;
			if(type !=0 && order!=0){
				FILE_sp->type= type;
				FILE_sp->order=order;
			}else{
				FILE_sp->type= 'N';
				FILE_sp->order='D';
			}
			sprintf(FILE_sp->name, "%s", next->d_name);
			if((strlen(Entrypath)+strlen(next->d_name)) < 1024){
				sprintf(tmpbuff, "%s%s", Entrypath, next->d_name);
#if defined(ENABLE_LFS)		
				if (stat64(tmpbuff, &sbuf)==0) {
#else
				if (stat(tmpbuff, &sbuf)==0) {
#endif			
					FILE_sp->size = sbuf.st_size;
					FILE_sp->mtime = sbuf.st_mtime;
				}else{
					FILE_sp->size = 0;
					FILE_sp->mtime = 0;
				}
			}else{
				FILE_sp->size = 0;
				FILE_sp->mtime = 0;
			}
			qsort((void *)FileEntryHead, CurrFILECount, sizeof(PATH_ENTRY_T), PathEnrtySort);
		}
		else if(next->d_type==0x4){//directory

			DIR_len = (CurrDIRCount + 1) * sizeof(PATH_ENTRY_T);
			if((DirEntryHead = realloc(DirEntryHead, DIR_len)) == NULL) {
				return;
			}
			DIR_sp = &DirEntryHead[CurrDIRCount++];
			memset(DIR_sp, 0, sizeof(PATH_ENTRY_T));
			DIR_sp->isDir=next->d_type;
			if(type !=0 && order!=0){
				DIR_sp->type= type;
				DIR_sp->order=order;
			}else{
				DIR_sp->type= 'N';
				DIR_sp->order='D';
			}
			sprintf(DIR_sp->name, "%s", next->d_name);
			if((strlen(Entrypath)+strlen(next->d_name)) < 1024){
				sprintf(tmpbuff, "%s%s", Entrypath, next->d_name);
#if defined(ENABLE_LFS)
				if (stat64(tmpbuff, &sbuf)==0) {
#else
				if (stat(tmpbuff, &sbuf)==0) {
#endif
					DIR_sp->size = sbuf.st_size;
					DIR_sp->mtime = sbuf.st_mtime;
				}else{
					DIR_sp->size = 0;
					DIR_sp->mtime = 0;
				}
			}else{
				DIR_sp->size = 0;
				DIR_sp->mtime = 0;
			}
			qsort((void *)DirEntryHead, CurrDIRCount, sizeof(PATH_ENTRY_T), PathEnrtySort);
		}
		else if(next->d_type==0x0){
			if((strlen(Entrypath)+strlen(next->d_name)) < 1024){
				sprintf(tmpbuff, "%s%s", Entrypath, next->d_name);

#if defined(ENABLE_LFS)		
				if (stat64(tmpbuff, &sbuf)==0) {
#else
				if (stat(tmpbuff, &sbuf)==0) {
#endif
					if(S_ISREG(sbuf.st_mode))
					{
						FILE_len = (CurrFILECount + 1) * sizeof(PATH_ENTRY_T);
						if((FileEntryHead = realloc(FileEntryHead, FILE_len)) == NULL) {
							return;
						}
						FILE_sp = &FileEntryHead[CurrFILECount++];
						memset(FILE_sp, 0, sizeof(PATH_ENTRY_T));
						FILE_sp->isDir=0x8;
						if(type !=0 && order!=0){
							FILE_sp->type= type;
							FILE_sp->order=order;
						}else{
							FILE_sp->type= 'N';
							FILE_sp->order='D';
						}
						sprintf(FILE_sp->name, "%s", next->d_name);

						FILE_sp->size = sbuf.st_size;
						FILE_sp->mtime = sbuf.st_mtime;

						qsort((void *)FileEntryHead, CurrFILECount, sizeof(PATH_ENTRY_T), PathEnrtySort);
					}
					else if(S_ISDIR(sbuf.st_mode))
					{
						DIR_len = (CurrDIRCount + 1) * sizeof(PATH_ENTRY_T);
						if((DirEntryHead = realloc(DirEntryHead, DIR_len)) == NULL) {
							return;
						}
						DIR_sp = &DirEntryHead[CurrDIRCount++];
						memset(DIR_sp, 0, sizeof(PATH_ENTRY_T));
						DIR_sp->isDir=0x4;
						if(type !=0 && order!=0){
							DIR_sp->type= type;
							DIR_sp->order=order;
						}else{
							DIR_sp->type= 'N';
							DIR_sp->order='D';
						}
						sprintf(DIR_sp->name, "%s", next->d_name);

						DIR_sp->size = sbuf.st_size;
						DIR_sp->mtime = sbuf.st_mtime;

						qsort((void *)DirEntryHead, CurrDIRCount, sizeof(PATH_ENTRY_T), PathEnrtySort);
					}
				}
			}
		}
	}
	closedir(dir);
	
	//printf("total alloc DIRCount=%d\n", CurrDIRCount);
	//printf("total alloc FILECount=%d\n", CurrFILECount);
}



