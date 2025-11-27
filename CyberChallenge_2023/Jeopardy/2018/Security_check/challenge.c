// gcc -w -m32 -fno-stack-protector -zexecstack -o challenge challenge.c -mpreferred-stack-boundary=2 -g

#include <stdio.h>

#define MAX 4

int security_check = 0;
int debug = 0;

void disable_security_check() {
    security_check = 0;
}

void enable_security_check() {
    security_check = 1;
}

void enable_debug() {
    debug = 1;
}

void print_function(char *src) {
    char dst[230];

    if (debug) {
        printf("dst is at %08x, now checking security\n", &dst);
        printf("security status: %s\n", (security_check ? "enabled" : "disabled"));
    }

    if (security_check) {
        strncpy(dst, src, 229);
        dst[229] = '\0';
        printf("%s\n", dst);
    } else {
        /* Old vulnerable code */
        strcpy(dst, src);
    }
}

void w() {
    system("w");
}

void ls() {
    system("ls");
}

void pwd() {
    system("pwd");
}

void quit() {
    puts("Bye!");
    exit(0);
}

int main(int argc, char *argv[]) {
    char str[260];
    char *names[] = {"puts", "w", "ls", "pwd", "quit"};
    void (*reachable_functions[])() = {puts, w, ls, pwd, quit};
    void (*unreachable_functions[])() = {disable_security_check, enable_debug};
    char index = 0;
    int i;

    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    while (1) {
        puts("Allowed commands: w, ls, pwd, quit");
        printf("Please enter command: ");
        for (i = 0; i < 259; i++) {
            str[i] = getchar();
            if (str[i] == 10) break;
        }
        str[i] = 0;

        enable_security_check();

        index = strlen(str);

        if (index <= MAX) {
            printf("Calling ");
            (reachable_functions[0])(names[index]);
            (reachable_functions[0])("");
            (reachable_functions[index])();
        }
        
        if (index < 1 || index > MAX) {
            printf("Invalid command: ");
            print_function(str);
        }

        puts("");
    }
}
