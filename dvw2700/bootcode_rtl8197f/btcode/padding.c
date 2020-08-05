#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

 /* 
 * Return:  0, OK
 *         -1, Fail
 */



 unsigned long int appendFile(char *destFilePath, unsigned long int appendLength)
 {
     unsigned char tmpBuf[1024];
     int i = 0;
     FILE *fp;
     for(i = 0; i < 1024; i++)
     {
         tmpBuf[i] = 0xFF;
     }
     if ((fp = fopen(destFilePath, "ab+"))==NULL)
     {
         printf("Can not open file %s \n", destFilePath);
         return -1;
     }
     
     while(appendLength > 0)
     {
         if (appendLength <= 1024)
         {
             fwrite(tmpBuf, sizeof(char), appendLength, fp);
             appendLength -= appendLength;
         }
         else 
         {
             fwrite(tmpBuf, sizeof(char), 1024, fp);
             appendLength -= 1024;
         }
     }
     fclose(fp);
     return 0;
 }

 void main(void)
 {
 	struct stat buf;
 	unsigned int total_len = 10240;
	unsigned int file_len,appendLength;


    stat("boot_iram.bin", &buf);
	file_len = buf.st_size;

	appendLength= total_len-file_len;
	
    appendFile("boot_iram.bin", appendLength);
 }

