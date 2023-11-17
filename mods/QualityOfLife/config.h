#ifndef CONFIG_H
#define CONFIG_H

#include <stdint.h>

typedef struct LoaderConfig
{
    int changeWindowFlags;
    uint32_t assetBufferByteSize;
} LoaderConfig;

void setDefaultConfigValues(LoaderConfig* config);
void parseConfig(LoaderConfig* config_out);
void printConfig(LoaderConfig* config);

#endif // CONFIG_H
