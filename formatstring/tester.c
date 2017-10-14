#include <stdio.h>
#include <string.h>
#include <stdlib.h>

typedef int bool;
#define true 1
#define false 0

#define DEBUG 1
#define FORMATBUFFERSIZE 2048
#define main real_main //Only define this when we're overloading via formatstringtester.c (i.e., comment out for normal build)

// From the linux sprintf man page:
// %n-The number of characters written so far is stored into the integer indicated by the int * (or variant) pointer argument. No argument is converted.

// To build:
// $ gcc -g -m32 -Wno-format-security -fno-stack-protector -z execstack formatstringtester.c -o formatstringtester
//
// To build in Eclipse:
//   cross gcc compiler miscellaneous settings: -m32 -Wno-format-security -fno-stack-protector
//   cross gcc linker miscellaneous settings: -m32 -z execstack
// Debugger useful settings for prompting default arguments: ${string_prompt:My Prompt Text:Default Value}
//
// Before running, disable ASLR: $ echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
// You can turn ASLR back on using: $ echo 2 | sudo tee /proc/sys/kernel/randomize_va_space
//
// If you need to pass script output as a program argument, don't run in eclipse (unless you're smarter than me)
// $ ddd --args Debug/stacksmash $(../shellcode/inputargs)
//
// See the shellcode example project for shellcode that works
//
// To run in Eclipse:
//   Run it in the debugger and pass in shellcode address=ffffb5e0, ret fptr address=ffffb9ec as the arguments (if it doesn't work, see what the address of buf
//     printed out in vuln() is and pass in that value instead)
// To run from shell:
//   The procedure is the similar to above but passes in shellcode address=ffffb5e0, ret fptr address=ffffb9ec as the arguments (if this doesn't work, see above)

#define usagefile "./usagedetails.txt"

// This function provides a remote capability to update the file used as input to the function that provides program usage and instruction details to users.
int updateUsageFile(const char *filename, const char *buffer) {
    int status=0;
    FILE *fp;
    fp=fopen(filename, "w+" );
    printf("\nThe length of buffer is: %d\n", strlen(buffer));
    fwrite(buffer, 1, strlen(buffer), fp);
    fclose(fp);
    return(status);
}

// To facilitate remote updates for program usage and instruction details without recompiling code, a clever developer moved the usage details to a file.
// The file can be updated using the updateUsageFile() function above
int printFormattedUsageFile(const char *filename) {//0xbfffe448 = EBP
    char rawbuf[FORMATBUFFERSIZE] __attribute__ ((aligned (8)));//our shellcode is 25 bytes;
    char printbuf[FORMATBUFFERSIZE] __attribute__ ((aligned (8)));//our shellcode is 25 bytes;
    int status=0;
    int len=0;
    FILE *fp;
#if DEBUG
    register int sp asm ("sp");
    register int ebp asm ("ebp");
    printf("sp=%x, ebp=%x, printbuf(shellcodeaddr)=%x, retaddr=%x, *retaddr=%x\n", sp, ebp, printbuf, (unsigned long *)(ebp+4), *(unsigned long *)(ebp+4));
    printf("opening %s",filename);
#endif
    fp=fopen(filename, "r" );/*open the file*/
    fseek(fp, 0L, SEEK_END);/*peek the file size by setting the pointer to the file's end*/
    len = ftell(fp);/*save the file size*/
    fseek(fp, 0L, SEEK_SET);/*reset the file pointer*/
    fread(rawbuf, 1, len, fp);/*read the file*/
#if DEBUG
    printf("%s\n",rawbuf);/*print the final version*/
#endif
    memset(printbuf,0,sizeof(printbuf));/*clear the printbuf*/
    snprintf(printbuf, len+1, "%s\n", rawbuf);/*formatted print into the printbuf, add 1 to filesize for '\n'*/
    printf(printbuf);/*print the final version*/ /*NOTE: retfptr is smashed here*/
#if DEBUG
    printf("sp=%x, ebp=%x, printbuf(shellcodeaddr)=%x, retaddr=%x, *retaddr=%x\n", sp, ebp, printbuf, (unsigned long *)(ebp+4), *(unsigned long *)(ebp+4));
#endif
    return(status);
}

int main(int argc, char *argv[]) {

    int status=0;

    if (argc!=2) {
        printf("Usage: ./formatstring <newbuffer>\n");
        return(-1);
    }
#if DEBUG
    else {
        printf("argv[0](formatstring)=%s\n",argv[0]);//This binary's name
        printf("argv[1](<newbuffer>)=%s\n",argv[1]);//<newbuffer> to write to usagefile
    }
#endif

    updateUsageFile(usagefile, argv[1]);
    printFormattedUsageFile(usagefile);

    return(0);
}
