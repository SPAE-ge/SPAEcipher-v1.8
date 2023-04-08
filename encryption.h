#pragma once
#include <stdlib.h>
#include "helper.h"
#include "spaestr.h"
#include "psp.h"

/// @brief Error codes for library "pads"
typedef enum enc_error_e
{
    /// No error
    ENC_ERROR_OK = 0,

    /// Invalid Id for member
    ENC_ERROR_INVALID_MEMBER_ID = 1,

	/// Error reading file
	ENC_ERROR_READFILE = 2,

	/// Error writing file
	ENC_ERROR_WRITEFILE = 3,

	/// Error few Pads
	ENC_ERROR_FEWPADS = 4,

	/// Error Member ID < 0
	ENC_ERROR_WRONGMEMID = 5,

	/// Error pads count < 0
	ENC_ERROR_WRONGPADSCOUNT = 6,

	/// Error commmon error
	ENC_ERROR_COMMON = 7,

	/// Error open file
	ENC_ERROR_OPENFILE = 8,

	/// Error open file
	ENC_ERROR_HUGEFILE = 9,

    /// Total # of errors in this list (NOT AN ACTUAL ERROR CODE);
    /// NOTE: that for this to work, it assumes your first error code is value 0 and you let it naturally 
    /// increment from there, as is done above, without explicitly altering any error values above
    ENC_ERROR_COUNT

} enc_error_t;

struct encryptionCfg {
	char pps[42];
	char specialCharIndex[6];
	char xorbits[6];
	size_t programNumber;
	size_t startPoint;
	size_t jumpPoint;
	size_t specialCharPosition;
	size_t totalBitsCount;
	size_t requestedBitsCount;
	size_t usedBitsCount;
	size_t availableBitsCount;
};


struct bitsInfo {
	size_t totalBitsCount;
	size_t requestedBitsCount;
	size_t usedBitsCount;
	size_t availableBitsCount;
};

typedef union { size_t int_value; char* s; } encCfgResponse;

#define READ_CHUNK_SZIE 1048576//16777216
#define PROG_FILES_COUNT 65
#define SPEC_PPS_LEN 7
#define SPEC_CHAR_LEN 1
#define PAD_FOR_PROG_FILE_DECR "1.txt"
#define PPS_PROG_FILE L"64.txt"
#define PROGRAMS_DIR L"C:/ProgramData/GGandJ/SPAE/programs/"

#define MB100 104857600
#define MB200 209715200
#define MB300 314572800
#define MB400 419430400
#define MB500 524288000
#define GB1   1073741824

struct encryptionCfg build_enc_cfg_file(char* f_name, char* fContent, size_t offset);
enc_error_t store_bits_info_into_cfg(const char* f_name, struct bitsInfo data);
enc_error_t store_enc_cfg(const char* f_name, struct encryptionCfg data, char* error_desc);
enc_error_t w_store_enc_cfg(const char* f_name, struct encryptionCfg data, wchar_t* error_desc);
wchar_t* encrypt_string(char* str, char* pad, char* error_desc);
struct encryptionCfg create_in_memeory_enc_cfg_file(char* fContent, size_t offset);
struct bitsInfo compute_bits_info(char* binContent, char* circle, char* enc_cfg_f_path, size_t member_id, unsigned int is_first_call, char* error_desc);
struct bitsInfo w_compute_bits_info(wchar_t* binContent, char* circle, char* enc_cfg_f_path, size_t member_id, unsigned int is_first_call, char* error_desc);
size_t* get_list_of_requested_pads_ID(char* circle, size_t mID, size_t requestedBitsCount, size_t* requestPadsCount, char* error_desc);
size_t* get_requested_pads_list(char* circle, size_t mID, size_t requestedBitsCount, size_t usedBitsCount, size_t avBitsCount, size_t* requestPadsCount, char* error_desc);
size_t* collect_list_of_requested_pads_ID(char* circle, size_t mID, size_t requestedBitsCount, size_t availableBitsCount, size_t usedBitsCount, size_t* requestPadsCount, size_t* enc_cfg_offset, char* error_desc);
size_t* get_member_pads_indexes(struct circle c_s, size_t m_ID, size_t membs_total_count, size_t* count);
struct encryptionCfg prepare_enc_cfg_file_data(const char* pad_path, size_t* pads_list, size_t mem_id, size_t offset, char* error_desc);
char* get_pps_and_prog_file_contents(char* circle, const char* pads_dir, size_t prog_num, char* error_desc);
char* decrypt_prog_file(FILE* f, char* pad, size_t ppsInsertionPoint, struct encryptionCfg s_encCfg, size_t added_bits_cnt, char* error_desc);
wchar_t* get_PPS_by_point(wchar_t* c, size_t p);
void get_PPS_by_points_array(wchar_t* pps, wchar_t* c, size_t* points);
void remove_PPS(wchar_t* c, size_t pp);
void remove_spec_char(wchar_t* c, size_t pp);
void get_spec_PPS(struct encryptionCfg e_s, char* content, wchar_t* spec_pps);
void get_spec_PPS_simple(struct encryptionCfg e_s, char* content, wchar_t* spec_pps);
void get_spec_text(struct encryptionCfg e_s, char* bin_content, char* prog_content, wchar_t* spec_text);
void insert_spec_char(struct encryptionCfg e_s, wchar_t* spec_content, wchar_t* result);
void insert_pps(struct encryptionCfg e_s, wchar_t* spec_content, wchar_t* s_pps, char* prog_content, wchar_t* result);
wchar_t* biuld_enc_file_name(wchar_t* content, size_t added_bits_count, const wchar_t* dir, char* enc_f_name);
enc_error_t write_cipher_to_file(const wchar_t* f_name, const wchar_t* cipher, char* error_desc);
encCfgResponse get_option_from_enc_cfg(char* path, char* optName, char* error_desc);
size_t* get_member_full_pad_IDs(size_t* all_list, size_t total_pads_count, size_t available_bits_count);
int get_member_partially_available_Pad_index(size_t* padList, size_t total_pads_count, size_t availableBits);
void insert_pps_with_log(struct encryptionCfg e_s, wchar_t* spec_content, wchar_t* s_pps, char* prog_content, wchar_t* result, size_t* positions, size_t* huge_pos);
void insert_spec_char_log(struct encryptionCfg e_s, wchar_t* spec_content, wchar_t* result, wchar_t* spc_chr);
char* get_dynamic_pps_and_prog_file_contents(char* circle, const char* pads_dir, char* error_desc);
void insert_dynamic_pps_left_to_right(struct encryptionCfg e_s, wchar_t* spec_content, wchar_t* s_pps, char* c9_char, char* prog_content, wchar_t* result);
void insert_dynamic_pps_right_to_left(struct encryptionCfg e_s, wchar_t* spec_content, wchar_t* s_pps, char* c9_char, char* prog_content, wchar_t* result);
void insert_dynamic_pps_with_log(struct encryptionCfg e_s,
	wchar_t* spec_content,
	wchar_t* s_pps,
	char* c9_char,
	char* prog_content,
	wchar_t* result,
	size_t* positions,
	size_t* huge_pos,
	int order);

void insert_dynamic_pps_with_order(struct encryptionCfg e_s,
	wchar_t* spec_content,
	wchar_t* s_pps,
	char* c9_char,
	char* prog_content,
	wchar_t* result,
	int order);