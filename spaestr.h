#pragma once
#include <stdarg.h>
#include <string.h>
#include <limits.h>

#include "assert.h"
#include "mem.h"
#include "helper.h"

#define POOL "01"

extern char* Str_sub(const char* s, size_t i, size_t j);
extern char* Str_dup(const char* s, size_t i, size_t j, size_t n);
extern wchar_t* W_Str_dup(const wchar_t* s, size_t i, size_t j, size_t n);
extern char* Str_reverse(const char* s, size_t i, size_t j);
extern size_t Str_find(const char* s, size_t i, size_t j,
	const char* str);
extern size_t Str_rfind(const char* s, size_t i, size_t j,
	const char* str);
extern char* substr(char* string, size_t position, size_t length);
char* random_str(size_t count, const char* pool);
void insert_substring(wchar_t* res, wchar_t* a, wchar_t* b, size_t position);
void insert_single_pps_char(wchar_t* res, wchar_t* baseContent, wchar_t* c, size_t baseLen, size_t position);
void convert_spec_PPS_to_binary(char* result, const wchar_t* specPPS, char* progFileContent);

wchar_t* wsub_string(wchar_t* string, size_t position, size_t length);
size_t repl_wcs(wchar_t* line, const wchar_t* search, const wchar_t* replace);

char* spae_substr(const char* str, size_t start, size_t length);
void insert_substring_right_left(wchar_t* res, wchar_t* a, wchar_t* b, size_t position);
void w_insert_char_itself(wchar_t* str, wchar_t ch, size_t pos);