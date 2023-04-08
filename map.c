#pragma warning(disable : 4996)
#include <stdio.h>
#include <stdlib.h>
#include "map.h"

struct map_t* map_create() {
    struct map_t* m;
    m = ALLOC(sizeof(struct map_t) * 1);
    m->name = NULL;
    m->value = NULL;
    m->nxt = NULL;
    return m;
}

void map_set(struct map_t* m, const char* name, const wchar_t* value) {
    struct map_t* map;

    if (m->name == NULL) {
        m->name = ALLOC(strlen(name) + 1);
        strcpy(m->name, name);
        m->value = ALLOC((sizeof(wchar_t) * (wcslen(value) + 1)));
        wcscpy(m->value, value);
        m->nxt = NULL;
        return;
    }
    for (map = m;; map = map->nxt) {
        if (!stricmp(name, map->name)) {
            if (map->value != NULL) {
                free(map->value);
                map->value = ALLOC((sizeof(wchar_t) * (wcslen(value) + 1)));
                wcscpy(map->value, value);
                return;
            }
        }
        if (map->nxt == NULL) {
            map->nxt = NEW(map->nxt);
            map = map->nxt;
            map->name = ALLOC(strlen(name) + 1);
            strcpy(map->name, name);
            map->value = ALLOC((sizeof(wchar_t) * (wcslen(value) + 1)));
            wcscpy(map->value, value);
            map->nxt = NULL;
            return;
        }
    }
}

wchar_t* map_get(struct map_t* m, char* name) {
    struct map_t* map;
    for (map = m; map != NULL; map = map->nxt) {
        if (!stricmp(name, map->name)) {
            return map->value;
        }
    }
    return L"";
}

char* map_get_key_by_val(struct map_t* m, wchar_t* name)
{
    struct map_t* map;
    for (map = m; map != NULL; map = map->nxt) {
        if (!wcscmp(name, map->value)) {
            return map->name;
        }
    }
    return NULL;
}
