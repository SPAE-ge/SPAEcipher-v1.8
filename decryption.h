#pragma once
#include <stdlib.h>
#include "helper.h"
#include "spaestr.h"
#include "psp.h"
#include "encryption.h"
#include "spechars.h"
#include "pps.h"

/// @brief Error codes for library "pads"
typedef enum decr_error_e
{
	/// No error
	DECR_ERROR_OK = 0,

	/// Invalid Id for member
	DECR_ERROR_INVALID_MEMBER_ID = 1,

	/// Error reading file
	DECR_ERROR_READFILE = 2,

	/// Error writing file
	DECR_ERROR_WRITEFILE = 3,

	/// Error few Pads
	DECR_ERROR_FEWPADS = 4,

	/// Error Member ID < 0
	DECR_ERROR_WRONGMEMID = 5,

	/// Error pads count < 0
	DECR_ERROR_WRONGPADSCOUNT = 6,

	/// Error commmon error
	DECR_ERROR_COMMON = 7,

	/// Error open file
	DECR_ERROR_OPENFILE = 8,

	/// Error open file
	DECR_ERROR_HUGEFILE = 9,

	/// Empty file given
	DECR_ERROR_EMPTYFILE = 10,

	/// Empty file given
	DECR_ERROR_HISTORY = 11,
	/// Total # of errors in this list (NOT AN ACTUAL ERROR CODE);
	/// NOTE: that for this to work, it assumes your first error code is value 0 and you let it naturally 
	/// increment from there, as is done above, without explicitly altering any error values above
	DECR_ERROR_COUNT

} decr_error_t;

#define DECR_CONSTANTLY_UPD_FNAME "C:/ProgramData/GGandJ/SPAE/dechis.dat"

struct decryptionCfg 
{
	char circle_name[256];
	char dec_time[100];
	char pps[42];

	wchar_t spae_name[100];
	
	size_t member_number;
	size_t first_pad;
	size_t last_pad;
	size_t bits_used;
};

/*-------Opearations for decryptionCfg structure---------------*/
decr_error_t insert_data_into_dec_cfg(const char* cfg_path, struct decryptionCfg data, wchar_t* error_desc);
struct decryptionCfg* get_decr_data_by_SPAE_name(const wchar_t* spae_name, wchar_t* error_desc);

void get_binary_from_c_text(wchar_t* spec_text, struct encryptionCfg e_s, const char* prog_content, char* bin_data);
wchar_t** parse_file_name(wchar_t* s, const wchar_t* delim);
enc_error_t write_plain_txt_to_file(const char* f_name, const unsigned char* p_txt, size_t size, char* error_desc);
void get_dynamic_pps_positions_by_9th_char(size_t* positions, char* prog_content, const wchar_t c9, char* error_desc);
void remove_dynamic_PPS_by_single_char_RL(wchar_t* c, size_t pp);
void remove_dynamic_PPS_by_points_array(wchar_t* pps, wchar_t* c, size_t* points, wchar_t order_char);