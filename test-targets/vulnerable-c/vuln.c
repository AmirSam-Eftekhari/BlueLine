#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void copy_input(char *user_input) {
    char buffer[64];
    strcpy(buffer, user_input); /* VULN: strcpy */
    printf("%s\n", buffer);
}

void run_cmd(char *cmd) {
    system(cmd); /* VULN: system */
}

int main(int argc, char **argv) {
    char line[256];
    if (gets(line) != NULL) { /* VULN: gets */
        copy_input(line);
    }
    return 0;
}
