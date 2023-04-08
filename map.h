#pragma once
#ifndef MAP_LIB_H
#define MAP_LIB_H

#include <string.h>
#include "mem.h"

struct map_t {
    struct map_t* nxt;
    char* name;
    wchar_t* value;
};

struct map_t* map_create();
void map_set(struct map_t* m, const char* name, const wchar_t* value);
wchar_t* map_get(struct map_t* m, char* name);
char* map_get_key_by_val(struct map_t* m, wchar_t* name);

#endif