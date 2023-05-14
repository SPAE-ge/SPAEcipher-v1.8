#pragma once
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <ctype.h>
#include <dirent.h>
#include <direct.h>
#include <fcntl.h>
#include <io.h>

#include "mem.h"

#define MAX(x, y) (((x) > (y)) ? (x) : (y))
#define MIN(x, y) (((x) < (y)) ? (x) : (y))

#define ZERO_ANY(T, a, n) do{\
   T *a_ = (a);\
   size_t n_ = (n);\
   for (; n_ > 0; --n_, ++a_)\
     *a_ = (T) { 0 };\
} while (0)


#define FILE_OK 0
#define FILE_NOT_EXIST 1
#define FILE_TO_LARGE 2
#define FILE_READ_ERROR 3

#define READ_CHUNK_SIZE 1073741824 //1Gb
#define SD1_START_VALUE 2852127
#define SD1_END_VALUE   7046431

#define SD1_START_VALUE_LARGE 45634032
#define SD1_END_VALUE_LARGE   112742896

typedef enum {
    FILE_MODE_READ,
    FILE_MODE_WRITE,
    FILE_MODE_ABPLUS,
    FILE_MODE_APLUS
} FILE_MODE;

// Get the size of given file
size_t fsize(FILE* File);

// Open file using _wfopen_s
FILE* w_open_file(const wchar_t* filename, FILE_MODE mode, int* err);

// Open file using fopen_s
FILE* open_file(const char* filename, FILE_MODE mode, int* err);

// Read "unicode" file
wchar_t* wc_read_file(FILE* f, int* err, size_t* f_size);

// Read file
char* c_read_file(FILE* f, int* err, size_t* f_size);

// Scans a directory and retrieves all files of given extension
char** dirlist(char dirname[], char const* ext, size_t* elems);

// Get file exten
char* get_file_ext(const char* filename);

void set_str_null_terminator(char* s, size_t index);
void set_wstr_null_terminator(wchar_t* s, size_t index);
int  set_file_mode_to_utf(FILE** f);
int  is_file_empty(FILE* f);
int  is_file_exists(const char* fname);

size_t bindec(const char* bin);
void fmakeXOR(char* first, char* second);
void fmakeXNOR(char* first, char* second);
size_t arrayUniqueWithoutSorting(char* input[], size_t s);

size_t get_ones_count_in_file(char* s);
int is_number_in_1SD_range(size_t number);
size_t divisible_by_six(size_t num);
int natural_compare(const void* a, const void* b);
unsigned char* xor_short_strings(const char* str1, char* str2);
wchar_t* int2str(size_t in);
wchar_t* int2wstr(size_t in);
int value_in_array(size_t val, size_t* arr, size_t len);
wchar_t* wget_file_name_from_path(wchar_t* path);
int find_str_in_file(char const* fname, char* str);
void wcs_write_log(FILE* f, wchar_t* data);
void wcs_const_write_log(FILE* f, const wchar_t* data);
void write_log(FILE* f, const char* data);
void int_write_log(FILE* f, char* description, size_t val);
void int_wcs_write_log(FILE* f, wchar_t* description, size_t val);
void int_wcs_write_log_without_new_line(FILE* f, wchar_t* description, size_t val);
int is_array_set_to_zero(size_t* a, size_t size);
void decimalToBinary(char* binary, size_t num, int bits_count);
int is_number_in_1SD_range_large(size_t number);
char* get_current_datetime();
void int_write_log_without_newline(FILE* f, char* description, size_t val);
size_t number_of_digits(size_t n);
int is_even(size_t num);