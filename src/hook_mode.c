#include "hook_mode.h"

#include "hook.h"

#include <string.h>
#include <windows.h>

#define HOOK_MODE_MAX_RULES 128
#define HOOK_MODE_MAX_PATTERN 96

typedef struct hook_mode_rule
{
    hook_mode mode;
    char pattern[HOOK_MODE_MAX_PATTERN];
} hook_mode_rule;

static hook_mode_rule hook_mode_rules[HOOK_MODE_MAX_RULES];
static int hook_mode_rule_count = 0;
static int hook_mode_verify = 0;
static int hook_mode_config_loaded = 0;

// Counts of what hook_install() actually did, for the summary line.
static int hook_mode_counts[3] = { 0, 0, 0 };

static uint8_t* hook_mode_image_base = NULL;

uint8_t* hook_retail_ptr(uint32_t retail_addr)
{
    // The retail EXE is not ASLR-aware, so in practice this resolves to 0x00400000
    // and the rebase is a no-op. Going through GetModuleHandle keeps that an
    // observation rather than an assumption, and keeps this translation unit
    // independent of src/hook.c (which the default build does not compile).
    if (hook_mode_image_base == NULL)
        hook_mode_image_base = (uint8_t*)GetModuleHandleA(NULL);

    return hook_mode_image_base + (retail_addr - SWR_BASE_ADDR_);
}

// Trailing '*' matches a prefix; a lone '*' matches everything; otherwise exact.
static int hook_mode_pattern_match(const char* pattern, const char* name)
{
    size_t len = strlen(pattern);

    if (len == 1 && pattern[0] == '*')
        return 1;
    if (len > 0 && pattern[len - 1] == '*')
        return strncmp(pattern, name, len - 1) == 0;

    return strcmp(pattern, name) == 0;
}

static int hook_mode_parse_mode(const char* token, hook_mode* out)
{
    if (strcmp(token, "original") == 0) {
        *out = HOOK_MODE_ORIGINAL;
        return 1;
    }
    if (strcmp(token, "reimpl") == 0) {
        *out = HOOK_MODE_REIMPL;
        return 1;
    }
    if (strcmp(token, "both") == 0) {
        *out = HOOK_MODE_BOTH;
        return 1;
    }
    return 0;
}

// Config grammar, one directive per line, '#' starts a comment:
//   <mode> <pattern>   mode = original | reimpl | both; pattern may end in '*'
//   verify             run the differential self-test once at startup
// Later rules win, so `reimpl *` followed by `original swrSound_*` reads naturally.
static void hook_mode_load_config(void)
{
    char line[256];
    FILE* config;

    hook_mode_config_loaded = 1;

    config = fopen(HOOK_MODE_CONFIG_FILE, "r");
    if (config == NULL)
        return;

    while (fgets(line, sizeof(line), config) != NULL) {
        char* comment;
        char* mode_token;
        char* pattern_token;
        hook_mode mode;

        comment = strchr(line, '#');
        if (comment != NULL)
            *comment = '\0';

        mode_token = strtok(line, " \t\r\n");
        if (mode_token == NULL)
            continue;

        if (strcmp(mode_token, "verify") == 0) {
            hook_mode_verify = 1;
            continue;
        }

        if (!hook_mode_parse_mode(mode_token, &mode))
            continue;

        pattern_token = strtok(NULL, " \t\r\n");
        if (pattern_token == NULL)
            continue;
        if (strlen(pattern_token) >= HOOK_MODE_MAX_PATTERN)
            continue;
        if (hook_mode_rule_count >= HOOK_MODE_MAX_RULES)
            continue;

        hook_mode_rules[hook_mode_rule_count].mode = mode;
        strcpy(hook_mode_rules[hook_mode_rule_count].pattern, pattern_token);
        hook_mode_rule_count++;
    }

    fclose(config);
}

hook_mode hook_mode_for(const char* function_name)
{
    hook_mode mode = HOOK_MODE_ORIGINAL;
    int i;

    if (!hook_mode_config_loaded)
        hook_mode_load_config();

    for (i = 0; i < hook_mode_rule_count; i++) {
        if (hook_mode_pattern_match(hook_mode_rules[i].pattern, function_name))
            mode = hook_mode_rules[i].mode;
    }

    return mode;
}

int hook_verify_requested(void)
{
    if (!hook_mode_config_loaded)
        hook_mode_load_config();

    return hook_mode_verify;
}

void hook_install(const char* function_name, uint32_t reimpl_addr, uint32_t retail_addr, int force_reimpl, FILE* hook_log)
{
    hook_mode mode = force_reimpl ? HOOK_MODE_REIMPL : hook_mode_for(function_name);

    hook_mode_counts[mode]++;

    switch (mode) {
    case HOOK_MODE_ORIGINAL:
        fprintf(hook_log, "\t[Original] %s <- 0x%08x\n", function_name, retail_addr);
        hook_function(function_name, reimpl_addr, (uint8_t*)retail_addr);
        break;
    case HOOK_MODE_REIMPL:
        fprintf(hook_log, "\t[Replace] %s -> 0x%08x\n", function_name, retail_addr);
        hook_function(function_name, retail_addr, (uint8_t*)reimpl_addr);
        break;
    case HOOK_MODE_BOTH:
        // Deliberately unredirected: both bodies stay intact so they can be compared.
        fprintf(hook_log, "\t[Both] %s <-> 0x%08x\n", function_name, retail_addr);
        break;
    }
}

void hook_mode_log_summary(FILE* hook_log)
{
    int live = hook_mode_counts[HOOK_MODE_REIMPL];
    int dormant = hook_mode_counts[HOOK_MODE_ORIGINAL];
    int compared = hook_mode_counts[HOOK_MODE_BOTH];
    int total = dormant + live + compared;
    double percent = total > 0 ? (double)live * 100.0 / (double)total : 0.0;

    fprintf(hook_log, "Hooked [%d/%d] functions (%.2f%%), %d left original, %d unredirected for comparison\n", live, total, percent, dormant, compared);
    fflush(hook_log);
}
