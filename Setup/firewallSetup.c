#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <unistd.h>
#include <fcntl.h>
#include "firewallSetup.h"

void freen(void* ptr) {
    free(ptr);
    ptr = NULL;
}

char* open_proc_fd(void) {
    proc_fd = open(PROC_FD, O_WRONLY);
        
    if(proc_fd == -1) {
        fprintf(stderr, "%s%s\n", "Failed opening ", PROC_FD);
        exit(EXIT_FAILURE);
    }
}

int main(int argc, char **argv)
{
    FILE *fp; // rules in a text file
    char *line = NULL;
    size_t len = 0;
    ssize_t read;

    char* rules;
    size_t rules_size = 1;

    rules = (char *) malloc(rules_size);
    if(!rules) {
        return -ENOMEM;
    }
    memset(rules, 0, rules_size);

    memcpy(rules, argv[1], 1);

    if (argc == 2 && strcmp(argv[1], "L") == 0)
    {
        open_proc_fd();    
    
        if(write(proc_fd, rules, rules_size) != rules_size) {
            fprintf(stderr, "%s%s\n", "Could not write to ", PROC_FD);
            freen(rules);
            exit(EXIT_FAILURE);
        }
        close(proc_fd);
        
        freen(rules);
        exit(EXIT_SUCCESS);
    } 
    else if ((argc == 3) && (strcmp(argv[1], "W") == 0))
    {
        fp = fopen(argv[2], "r");

        if (!fp)
        {
            fprintf(stderr, "%s\n", "Could not open file");
            freen(rules);
            exit(EXIT_FAILURE);
        }

        int port = 0;
        char* cursor;

        while ((read = getline(&line, &len, fp)) != -1)
        {
            cursor = line;

            port = *cursor - '0';
            cursor++;

            // Read port
            while(*cursor != ' ') {
                if(!isdigit(*cursor)) {
                    fprintf(stderr, "Illformed input file");
                    if (line) { freen(line); }
                    freen(rules);
                    fclose(fp);
                    exit(EXIT_FAILURE);
                }
                port = port * 10 + *cursor - '0';
                
                if(port > 65535) {
                    fprintf(stderr, "Invalid file format: Nothing will be written to the kernel\n");
                    if(line) { freen(line); }
                    freen(rules);
                    fclose(fp);
                    exit(EXIT_FAILURE); }
                
                cursor++;
            }
            char port_string[6] = {0};
            
            sprintf(port_string, "%d", port);

            // Skip spaces
            while(*cursor == ' ') {
                cursor++;
            }

            char *beg = cursor, *end;
            
            // Read executable path
            while(*cursor != '\n' && *cursor != '\0') {
                cursor++;
            }

            end = cursor;

            char* path = malloc(sizeof(char) * ((end - beg) + 1));
            if(!path) { 
                fprintf(stderr, "%s", "Error: No memory left");
                if (line) { freen(line); }
                freen(rules);
                fclose(fp);
                exit(EXIT_FAILURE); 
            }

            memset(path, 0, end - beg + 1);
            strncpy(path, beg, end - beg);

            if(access(path, F_OK|X_OK) == 0) {
                int old_rules_size = rules_size;
                rules_size = old_rules_size + 1 + strlen(port_string) + (5 - strlen(port_string)) + 1 + sizeof(char) * (end-beg) + 1; 
                /* rules_size = old rules size
                 * 1 = space between port number and path
                 * end-beg * sizeof(char) = path length
                 * strlen(port_string) = number of digits in port number
                 * 5 - strlen(port_string) = number of spaces in 6 characters available
                 * 1 = space between two different rules
                 * 1 = space between two different 
                 */
                
                rules = realloc(rules, rules_size);
                if(!rules) {
                    freen(rules);
                    freen(path);
                    return -ENOMEM;
                }

                memset(rules+old_rules_size, 0, rules_size - old_rules_size);

                strncat(rules, " ", 1);
                strncat(rules, port_string, strlen(port_string));

                for(int i = 0; i < 5 - strlen(port_string); i++) {
                    strncat(rules, " ", 1);
                }

                strncat(rules, " ", 1);
                strncat(rules, path, strlen(path));

            } else {
                fprintf(stderr, "Invalid paths in input file\n");
                if (line) { freen(line); }
                freen(path);
                freen(rules);
                exit(EXIT_FAILURE);
            }

            freen(path);
        }

        rules_size += 6;
        rules = realloc(rules, rules_size);
        if(!rules) {
            freen(rules);
            return -ENOMEM;
        }
        strncat(rules, " 0    ", 6);

        open_proc_fd();

        if(write(proc_fd, rules, rules_size) != rules_size) {
            fprintf(stderr, "%s%s\n", "Could not write to ", PROC_FD);
            if (line) { free(line); }
            freen(rules);
            exit(EXIT_FAILURE);
        }

        close(proc_fd);

        fclose(fp);
        if (line) { free(line); }
        
        freen(rules);
        exit(EXIT_SUCCESS);
    }
    else
    {   
        freen(rules);
        fprintf(stderr, "%s", "Invalid number of arguments. Use: `L` or `W filename`\n");
        exit(EXIT_FAILURE);
    }
}