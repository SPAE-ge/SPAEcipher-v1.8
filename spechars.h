#pragma once
#include "map.h"
#include "helper.h"

#define SPEC_CHARS_COUNT 64
#define EXTENDED_SPEC_CHARS_COUNT 95
#define KEY_BITS_LEN     6
#define EXTENDED_KEY_BITS_LEN 7

static const char* simple_keys[64] =
{ "000000", "000001", "000010", "000011", "000100", "000101", "000110", "000111",
 "001000", "001001", "001010", "001011", "001100", "001101", "001110", "001111",
 "010000", "010001", "010010", "010011", "010100", "010101", "010110", "010111",
 "011000", "011001", "011010", "011011", "011100", "011101", "011110", "011111",
 "100000", "100001", "100010", "100011", "100100", "100101", "100110", "100111",
 "101000", "101001", "101010", "101011", "101100", "101101", "101110", "101111",
 "110000", "110001", "110010", "110011", "110100", "110101", "110110", "110111",
 "111000", "111001", "111010", "111011", "111100", "111101", "111110", "111111"
};

static const char* random_keys[64] =
{ "011110", "010100", "110100", "101000", "001110", "101110", "000101", "000100",
 "011011", "000111", "001011", "001101", "101101", "010011", "110000", "100010",
 "100111", "000001", "001001", "110010", "111110", "010101", "100101", "001010",
 "001100", "101001", "111111", "101011", "111100", "010000", "101100", "111011",
 "011100", "111000", "101010", "111001", "110110", "000110", "011101", "011010",
 "110011", "100100", "100001", "010010", "011000", "000011", "101111", "110101",
 "100011", "000000", "010001", "010111", "000010", "111101", "001111", "100110",
 "011111", "100000", "011001", "010110", "110001", "111010", "110111", "001000"
};

static const char* improved_keys[95] =
{ "0101011", "0001110", "0100010", "0110000", "0100100", "1000001", "1111001", "0000101",
  "0101000", "1010111", "1100111", "1001111", "0101100", "0101101", "0101110", "0101111",
  "0001101", "0010011", "0010110", "0110011", "0110100", "0110101", "0110110", "0110010",
  "0110001", "0111001", "1000010", "0111011", "1101011", "1101101", "0111110", "0101001",
  "0111101", "0011011", "0100101", "1000011", "0100110", "0111010", "1000110", "1000111",
  "0001011", "0010101", "1001010", "1001011", "1001100", "1001101", "1001110", "0000111",
  "1010001", "0100011", "1010010", "1010011", "1010100", "1010101", "1010110", "0111000",
  "1011000", "1011001", "1011010", "1011011", "1001000", "1011101", "1000100", "1011110",
  "1100000", "1100001", "1100010", "1100011", "1100100", "1100101", "1100110", "1000101",
  "1101000", "1101001", "1101010", "0111100", "1101100", "1011100", "1001001", "0100111",
  "1110000", "1110001", "1110010", "0011110", "1110100", "0011101", "0011100", "0011010",
  "1111000", "0011001", "0101010", "0000011", "1111010", "1111100", "0001010"
};

static const wchar_t* extended_spec_values[95] =
{ 
	L" ", L"!", L"\u0022",  L"\u0023",  L"$", L"%", L"&", L"\u0027",
	L"(", L")", L"*", L"+", L",", L"-", L".", L"/",
	L"0", L"1", L"2", L"3", L"4", L"5", L"6", L"7",
	L"8", L"9", L":", L";", L"<", L"=", L">", L"?",
	L"@", L"A", L"B", L"C", L"D", L"E", L"F", L"G", 
	L"H", L"I", L"J", L"K", L"L", L"M", L"N", L"O", 
	L"P", L"Q", L"R", L"S", L"T", L"U", L"V", L"W", 
	L"X", L"Y", L"Z", L"[", L"\u005C",  L"]", L"^", L"_", 
	L"`", L"a", L"b", L"c", L"d", L"e", L"f", L"g", 
	L"h", L"i", L"j", L"k", L"l", L"m", L"n", L"o", 
	L"p", L"q", L"r", L"s", L"t", L"u", L"v", L"w", 
	L"x", L"y", L"z", L"{", L"|", L"}", L"~"
};

static const wchar_t* spec_values[64] =
{ L"0", L"1", L"2", L"3", L"4", L"5", L"6", L"7",
 L"8", L"9", L"A", L"B", L"C", L"D", L"E", L"F",
 L"G", L"H", L"I", L"J", L"K", L"L", L"M", L"N",
 L"O", L"P", L"Q", L"R", L"S", L"T", L"U", L"V",
 L"W", L"X", L"Y", L"Z", L"a", L"b", L"c", L"d",
 L"e", L"f", L"g", L"h", L"i", L"j", L"k", L"l",
 L"m", L"n", L"o", L"p", L"q", L"r", L"s", L"t",
 L"u", L"v", L"w", L"x", L"y", L"z", L"\u2020", L"/"
};

char* xoredKeys[64];
wchar_t* wxoredKeys[64];

static struct map_t* _uk;
static struct map_t* _random;
static struct map_t* _simple;
static struct map_t* _dagger;
static struct map_t* _extended;

void init_spec_chars_table_random();
void init_spec_chars_table_simple();
void init_spec_chars_table_extended();
struct map_t* init_enc_spec_chars_table(char* keys);

void free_struct_map(struct map_t* m);

char* convert_spec_char_to_binary_for_uk(const wchar_t* content);
char* convert_spec_char_to_binary_for_uk_extended(const wchar_t* content);
void get_spec_char_by_index(wchar_t* r, char* index);
void get_spec_char_by_index_simple(wchar_t* r, char* index);
void convert_PPS_to_spec_chars(wchar_t* ppsSpec, char* pps);
char* convert_spec_chars_to_PPS(const wchar_t* pps);
void convert_plain_short_txt_to_spec_chars(wchar_t* pSpec, char* pTxt, char* xorBits);
void convert_spec_chars_to_binary_reverse(const wchar_t* content, char* xorBits, char* result);
void convert_enc_PPS_to_spec_char(wchar_t* ppsSpec, char* pps, char* lookupKeys);
void convert_enc_PPS_to_spec_chars_simple(wchar_t* ppsSpec, char* pps);
void convert_enc_plain_txt_to_spec_chars(wchar_t* plainSpec, char* binCont, char* xorBits, char* lookupKeys);
void convert_spec_chars_to_binary(const wchar_t* content, char* xorBits, char* result, char* lookupKeys);
size_t get_index_from_simple_keys(const char* target); // This one too
size_t w_get_index_from_simple_keys(const wchar_t* target); // This is from the Full version