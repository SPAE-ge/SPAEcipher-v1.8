#pragma once
#ifndef PPS_LIB_H
#define PPS_LIB_H

#include <string.h>
#include "mem.h"


#define PPS_CHARS_COUNT 7
#define PPS_STRUCT_RAW_LEN 2870 // ppp_ch_count x pps_insetion_pos_len + full lookup table for each char

typedef struct {
    char* charInsertionPos;
    char** lookupTbl;
} pps_t;

// pps_t prototypes.

pps_t* pps_new(void);

void pps_set(pps_t* p, const char* position, const char** tbl);

void pps_struct_into_array(char* ppsData, pps_t* pps);

void pps_get_nth_position(char* pos, size_t n, char* data);

void pps_get_nth_lookup_tbl(char* tbl, size_t n, char* data);

void pps_free(pps_t* p);

void get_PPS_positions_dynamic(char* positions, const char* buk, const char* mrs, size_t* seeker, size_t offset);

typedef struct {
    char* ctrlChar;
    char* position0;
    char* position1;
    char* position2;
    char* position3;
    char* position4;
    char* position5;
    char* position6;
    
} pps_dynamic_t;

// pps_dynamic_t prototypes.
pps_dynamic_t* dynamic_pps_new(void);

void dynamic_pps_free(pps_dynamic_t* p);

void dynamic_pps_set(pps_dynamic_t* p, const char* ctrlchar, char* positions);

void assign_values_to_dynamic_pps_struct(pps_dynamic_t* p, const char* positions);

void dynamic_pps_struct_into_array(char* ppsData, pps_dynamic_t* pps);

void dynamic_pps_get_positions_by_specchar(char* pos, const char* spec, char* data);

#endif