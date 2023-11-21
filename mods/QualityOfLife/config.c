#include "config.h"

#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

LoaderConfig g_config;

void setDefaultConfigValues()
{
    g_config.assetBufferByteSize = 0x00800000;
    g_config.changeWindowFlags = false;
    g_config.cameraFOV = 1.0;
    g_config.skipRaceCutscene = false;
    g_config.skipIntroCamera = false;
    g_config.useHighestLOD = false;
    g_config.trimCountdown = false;
    g_config.skipCantinaScene = false;
    g_config.fasterLoad = false;
    g_config.developperMode = false;
}

int strcaseEq(const char* str1, char* str2)
{
    return (strcasecmp(str1, str2) == 0);
}

int strToBool(char* str)
{
    return (strcasecmp("true", str) == 0 || strcasecmp("yes", str) == 0 || strcmp("1", str) == 0);
}

int strToInteger(char* str)
{
    int base = 10;
    if (str[0] == '0' && str[1] == 'x')
    {
        str += 2;
        base = 16;
    }

    unsigned long value_int = strtoul(str, NULL, base);
    return value_int;
}

void parseConfig()
{
    setDefaultConfigValues();

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

        printf("Got token '%s' and value '%s'\n", token, value);

        if (strcaseEq("assetBufferByteSize", token))
        {
            unsigned long value_int = strToInteger(value);
            if (value_int > 0xFFFFFFFF) // > 2^32 - 1
            {
                printf("Warning: Ignoring assetBufferByteSize value as it is greater than 2^32 - 1\n");
                continue;
            }
            g_config.assetBufferByteSize = value_int;
        }
        else if (strcaseEq("changeWindowFlags", token))
        {
            g_config.changeWindowFlags = strToBool(value);
            continue;
        }
        else if (strcaseEq("cameraFOV", token))
        {
            g_config.cameraFOV = strtof(value, NULL);
            continue;
        }
        else if (strcaseEq("skipRaceCutscene", token))
        {
            g_config.skipRaceCutscene = strToBool(value);
            continue;
        }
        else if (strcaseEq("skipIntroCamera", token))
        {
            g_config.skipIntroCamera = strToBool(value);
            continue;
        }
        else if (strcaseEq("useHighestLOD", token))
        {
            g_config.useHighestLOD = strToBool(value);
            continue;
        }
        else if (strcaseEq("trimCountdown", token))
        {
            g_config.trimCountdown = strToBool(value);
            continue;
        }
        else if (strcaseEq("skipCantinaScene", token))
        {
            g_config.skipCantinaScene = strToBool(value);
            continue;
        }
        else if (strcaseEq("fasterLoad", token))
        {
            g_config.fasterLoad = strToBool(value);
            continue;
        }
        else if (strcaseEq("developperMode", token))
        {
            g_config.developperMode = strToBool(value);
            continue;
        }
    } while (res != NULL);

    fclose(config_file);
}

const char* boolToStr(int i)
{
    return i ? "True" : "False";
}

void printConfig()
{
    printf("Asset Buffer Size: %08x bytes\n", g_config.assetBufferByteSize);
    printf("Change Window Creation Flag ? %s\n", boolToStr(g_config.changeWindowFlags));
    printf("Camera FOV: %f\n", g_config.cameraFOV);
    printf("Skip Race Cutscene ? %s\n", boolToStr(g_config.skipRaceCutscene));
    printf("Skip Intro Camera ? %s\n", boolToStr(g_config.skipIntroCamera));
    printf("Use Highest Level Of Detail ? %s\n", boolToStr(g_config.useHighestLOD));
    printf("Trim countdown ? %s\n", boolToStr(g_config.trimCountdown));
    printf("Skip Cantina Scene ? %s\n", boolToStr(g_config.skipCantinaScene));
    printf("Fast Load ? %s\n", boolToStr(g_config.fasterLoad));
    printf("Developper Mode: %s\n", boolToStr(g_config.developperMode));
}
