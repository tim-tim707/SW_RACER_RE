#include "config.h"

#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

void setDefaultConfigValues(LoaderConfig* config)
{
    config->changeWindowFlags = false;
    config->assetBufferByteSize = 0x00800000;
}

void parseConfig(LoaderConfig* config_out)
{
    setDefaultConfigValues(config_out);

    FILE* config_file = fopen("Loader_config.txt", "r");
    if (config_file == NULL)
    {
        printf("Warning: 'Loader_config.txt' file not found. Defaults values will be used.\n");
        return;
    }

    size_t lineNumber = 0;
    char line_buffer[1024];
    char* res;
    do
    {
        res = fgets(line_buffer, sizeof(line_buffer), config_file);
        lineNumber += 1;
        if (res == NULL) // last line
            break;

        // Remove newlines and comments
        char* tmp = strchr(line_buffer, '\n');
        if (tmp != NULL)
            *tmp = '\0';
        tmp = strchr(line_buffer, '#');
        if (tmp != NULL)
            *tmp = '\0';
        tmp = strstr(line_buffer, "//");
        if (tmp != NULL)
            *tmp = '\0';
        if (line_buffer[0] == '\0')
            continue;

        tmp = strchr(line_buffer, '=');
        if (tmp == NULL)
        {
            printf("Warning: Ignoring line %d: \"%s\" as it doesnt contain an '=' sign\n", lineNumber, line_buffer);
            continue;
        }
        *tmp = '\0'; // split a = b by inserting a '\0' in place of the '='
        tmp += 1;

        char* token = line_buffer;
        char* value = tmp;

        // left trim
        while (isspace(*token))
            token += 1;
        while (isspace(*value))
            value += 1;
        // right trim
        tmp = strpbrk(line_buffer, " \t\r");
        if (tmp != NULL)
            *tmp = '\0';
        tmp = strpbrk(value, " \t\r");
        if (tmp != NULL)
            *tmp = '\0';

        if (*token == '\0')
        {
            printf("Warning: Ignoring line %d: \"%s\" as it doesnt contain a token\n", lineNumber, line_buffer);
            continue;
        }
        if (*value == '\0')
        {
            printf("Warning: Ignoring line %d: \"%s\" as it doesnt contain a value\n", lineNumber, line_buffer);
            continue;
        }

        // printf("Got token '%s' and value '%s'\n", token, value);

        if (strcasecmp("assetBufferByteSize", token) == 0)
        {
            int base = 10;
            if (value[0] == '0' && value[1] == 'x')
            {
                value += 2;
                base = 16;
            }

            unsigned long value_int = strtoul(value, NULL, base);
            if (value_int > 0xFFFFFFFF) // > 2^32 - 1
            {
                printf("Warning: Ignoring assetBufferByteSize value as it is greater than 2^32 - 1\n");
                continue;
            }
            config_out->assetBufferByteSize = value_int;
        }
        else if (strcasecmp("changeWindowFlags", token) == 0)
        {
            if (strcasecmp("true", value) == 0 || strcasecmp("yes", value) == 0 || strcmp("1", value))
                config_out->changeWindowFlags = true;
            continue;
        }

    } while (res != NULL);

    fclose(config_file);
}

void printConfig(LoaderConfig* config)
{
    printf("Asset Buffer Size: %08x bytes, Change Window Creation Flag ? %s\n", config->assetBufferByteSize, config->changeWindowFlags ? "Yes" : "No");
}
