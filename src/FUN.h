#ifndef FUN_H
#define FUN_H

// Macros from Ben1138
#define DEF_TYPE(Addr, RetType, ...) typedef RetType(FUN_##Addr##_t)(__VA_ARGS__);

#define DEF_FUN(Addr, RetType, ...)                                                                \
    DEF_TYPE(Addr, RetType, __VA_ARGS__);                                                          \
    static FUN_##Addr##_t *FUN_##Addr = (FUN_##Addr##_t *) 0x##Addr

#define DEF_ALIAS(Addr, Alias, RetType, ...)                                                       \
    DEF_FUN(Addr, RetType, __VA_ARGS__);                                                           \
    static FUN_##Addr##_t *Alias = (FUN_##Addr##_t *) 0x##Addr

DEF_ALIAS(00421360, swrText_Translate, char *, char *text);

#endif// FUN_H
