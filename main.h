#pragma once
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <io.h>
#include <fcntl.h>
#include <time.h>

#include "spechars.h"
#include "helper.h"
#include "spaestr.h"
#include "mem.h"
#include "userkey.h"
#include "circle.h"
#include "pads.h"
#include "psp.h"
#include "sha256.h"
#include "encryption.h"
#include "decryption.h"
#include "mpir.h"
#include "pps.h"

#define SPAE_CALL __stdcall  
#define SPAE_DLL_EXPIMP __declspec(dllexport) 

//size_t* pads_disgussing_bits = ALLOC(_512_BUFFER * sizeof(size_t));
size_t pads_disgussing_bits[_512_BUFFER] = {0};

/* ------------------USER KEY FUNCTIONS----------------------------------------------------------------------- */

/*******************************************************************************

	Function :      char* convert_uk_to_bin(FILE* f, char* error_desc);

	Parameters :    Pointer to the user key file

	Returns :       The result is binary version of the file

	Description :   This function gets the pointer to the file and then converts
					it into binary version. It uses special chars lookup table
					in order to convert each char into its six-bits
					representation.

*******************************************************************************/
SPAE_DLL_EXPIMP char* SPAE_CALL    convert_uk_to_bin(wchar_t* data, char* error_desc);

/*******************************************************************************

	Function :      create_uk(char* key, char* error_desc);

	Parameters :    key -
						key string whcih we need to convert as an UK.

	Returns :       UK with the 2^26 lenght

	Description :   Takes a 01's string and make UK from it.

*******************************************************************************/
//SPAE_DLL_EXPIMP char* SPAE_CALL    create_uk(char* key, char* error_desc);
SPAE_DLL_EXPIMP int SPAE_CALL create_uk(char* userkey, char* buk, char* mrs, char* key, char* error_desc);

/*******************************************************************************

	Function :      sanitize_uk_file(wchar_t* user_file, int* wrong_chars_count, char* error_desc);

	Parameters :    key -
						key string whcih we need to convert as an UK.

	Returns :       UK with the 2^26 lenght

	Description :   Sanitizes input uk file.

*******************************************************************************/
SPAE_DLL_EXPIMP wchar_t* SPAE_CALL sanitize_uk_file(wchar_t* user_file, int* wrong_chars_count, char* error_desc);

/*******************************************************************************

	Function :      wchar_t* sanitize_uk_file_content(wchar_t* content, int* wrong_chars_count, char* error_desc);

	Parameters :    content -
						content which was given as a raw format not as a file.
					wrong_chars_count -
						keeps non-allowed chars count

	Returns :       The result is sanitized content

	Description :   This function gets the any content and then tries to sanitize
					it using whitelist.

*******************************************************************************/
SPAE_DLL_EXPIMP wchar_t* SPAE_CALL sanitize_uk_file_content(wchar_t* content, int* wrong_chars_count, char* error_desc);

/* ------------------CIRCLE MANAGEMENT FUNCTIONS---------------------------------------------------------------- */
/*******************************************************************************

	Function :      add_new_circle(struct circle c, struct member m, char* error_desc);

	Parameters :    c -
						filled Circle struct object
					m -
						filled Member struct object

	Returns :       The result is circle_error_t

	Description :   This function gets data about new Circle and Circle manager and
					and then adding it into the Circles config file.

*******************************************************************************/
SPAE_DLL_EXPIMP circle_error_t SPAE_CALL add_new_circle(struct circle c, struct member m, char* error_desc);
SPAE_DLL_EXPIMP circle_error_t SPAE_CALL get_circles_info(struct circle* data, int size, char* error_descr);
SPAE_DLL_EXPIMP circle_error_t SPAE_CALL get_circle_members_data(struct member* data, int size, const char* c_name, char* error_desc);
SPAE_DLL_EXPIMP circle_error_t SPAE_CALL add_new_member(const char* c_name, char* m_name, int pos, char* error_desc);
SPAE_DLL_EXPIMP circle_error_t SPAE_CALL delete_member(const char* c_name, int mem_pos, char* error_desc);
SPAE_DLL_EXPIMP circle_error_t SPAE_CALL lock_circle(const char* c_name, char* error_desc);
SPAE_DLL_EXPIMP int            SPAE_CALL get_circles_count(char* error_descr);
SPAE_DLL_EXPIMP int            SPAE_CALL get_circle_members_count(const char* c, char* error_desc);
SPAE_DLL_EXPIMP int            SPAE_CALL delete_circle(const char* c_name, char* error_desc);
SPAE_DLL_EXPIMP int            SPAE_CALL check_if_circle_locked(const char* c_name, char* error_desc);

SPAE_DLL_EXPIMP circle_error_t SPAE_CALL get_circle_data_by_name(struct circle* data, const char* c_name, char* error_desc);

/* ------------------PADS MANAGEMENT FUNCTIONS------------------------------------------------------------------ */
SPAE_DLL_EXPIMP pads_error_t  SPAE_CALL get_pad_cfg_head(struct pads* data, const char* cfg_path, char* error_desc);
SPAE_DLL_EXPIMP pads_error_t  SPAE_CALL set_pads_total_count_into_cfg_head(const char* cfg_path, int tc, char* error_desc);
SPAE_DLL_EXPIMP pads_error_t  SPAE_CALL set_valid_pads_count(const char* cfg_path, int vpc, char* error_desc);
SPAE_DLL_EXPIMP pads_error_t  SPAE_CALL set_invalid_pads_count(const char* cfg_path, int ipc, char* error_desc);
SPAE_DLL_EXPIMP pads_error_t  SPAE_CALL set_generated_pads_count_into_cfg_head(const char* cfg_path, int gc, char* error_desc);
SPAE_DLL_EXPIMP pads_error_t  SPAE_CALL set_new_request_data_into_cfg_head(const char* cfg_path, int total, int generated, char* error_desc);

SPAE_DLL_EXPIMP pads_error_t SPAE_CALL create_single_pad(char* pad, char* mrs, char* buk, char* prog_dir, char* error_desc);
SPAE_DLL_EXPIMP pads_error_t  SPAE_CALL reset_pad_cfg_file(char* path);



SPAE_DLL_EXPIMP char***       SPAE_CALL generate_special_chars_lookup_table(char* buk, char* mrs, size_t* seeker, char* error_desc);

SPAE_DLL_EXPIMP pads_error_t  SPAE_CALL rearrange_buk_file(char* bukr, char* buk, char* mrs, size_t* s, size_t o, char* error_desc);

SPAE_DLL_EXPIMP pads_error_t  SPAE_CALL generate_data_for_the_next_pad(char* buk, char* mrs, char* bukr, char* pmrs, size_t* sp, size_t* jp, size_t* rp, char* error_desc);

SPAE_DLL_EXPIMP pads_error_t  SPAE_CALL validate_pad(char* pad, char* error_desc);
SPAE_DLL_EXPIMP int           SPAE_CALL validate_pad_by_first_42bits(char* pad, char* cfg_path, char* error_desc);
SPAE_DLL_EXPIMP pads_error_t  SPAE_CALL write_pad_into_file(char* pad, char* path, int id, char* error_desc);
SPAE_DLL_EXPIMP pads_error_t  SPAE_CALL write_anysize_data_into_file(char* pad, char* path, char* name, size_t size, char* error_desc);
SPAE_DLL_EXPIMP pads_error_t  SPAE_CALL add_new_pad_block(char* pad, char* buk, char* mrs, char* cfg_path, int current_pad_id, int prev_pad_id, char* error_desc);
SPAE_DLL_EXPIMP pads_error_t  SPAE_CALL rearrange_next_pad_BUK_file(char* bukr, const char* buk, size_t* rearrange_points, char* error_desc);
SPAE_DLL_EXPIMP pads_error_t  SPAE_CALL permutate_next_pad_MRS_file(char* pmrs, char* mrs, size_t* start_points, size_t* jump_points, char* error_desc);

SPAE_DLL_EXPIMP char* SPAE_CALL permutate_MRS_sequence(char* mrs, size_t* start_points, size_t* jump_points, char* error_desc);

SPAE_DLL_EXPIMP pads_error_t  SPAE_CALL create_next_row_file(char* next_row, char* bukr, char* pmrs, char* error_desc);
SPAE_DLL_EXPIMP pads_error_t  SPAE_CALL generate_single_pad(char* pad, size_t pad_num, char* row, char* error_desc);

SPAE_DLL_EXPIMP pads_error_t  SPAE_CALL get_data_from_last_pad_block(const char* cfg_path, int* id, size_t* sp, size_t* jp, size_t* rp, char* error_desc);

SPAE_DLL_EXPIMP pads_error_t SPAE_CALL create_uk_from_sequences(char* uk, char* buk, char* mrs, char** list, size_t count, char* error_desc);

SPAE_DLL_EXPIMP int SPAE_CALL create_uk_by_single_file_content(char* userkey, char* buk, char* mrs, char* key, char* error_desc);


/* ------------------ENCRYPTION FUNCTIONS------------------------------------------------------------------ */
SPAE_DLL_EXPIMP char* SPAE_CALL file_to_binary_enc(char* file, size_t* req_bits_count, size_t* added_bits_count, wchar_t* error_desc);
SPAE_DLL_EXPIMP char* SPAE_CALL file_to_binary_simple(char* file, size_t* req_bits_count, wchar_t* error_desc);
SPAE_DLL_EXPIMP size_t  SPAE_CALL get_member_total_pads_count(size_t m_id, char* pad_path, size_t mem_count, char* error_desc);
SPAE_DLL_EXPIMP size_t SPAE_CALL get_circle_pads_count(char* pad_path, char* error_desc);
SPAE_DLL_EXPIMP int  SPAE_CALL get_member_fully_avail_pads_count(size_t m_id, char* pad_path, size_t mem_count, char* error_desc);
SPAE_DLL_EXPIMP enc_error_t SPAE_CALL create_enc_cfg_file(char* f_name, char* pad_path, size_t mem_id, char* error_desc);
SPAE_DLL_EXPIMP enc_error_t SPAE_CALL create_64_prog_files( char* padContent,
															char*** tbl,
															char* pps_insert_point,
															char* c9_position_26_bits,
															char* dynamic_pps_points,
															char* logic,
															const char* dir,
															char* error_desc);


SPAE_DLL_EXPIMP enc_error_t SPAE_CALL encrypt_file(char* f_name, char* circle, char* enc_cfg_f_path, size_t member_id, unsigned int is_first_usage, wchar_t* where_to_save, wchar_t* encrypted_f_name, wchar_t* error_msg);
SPAE_DLL_EXPIMP enc_error_t SPAE_CALL dev_encrypt_file(char* f_name, char* circle, char* enc_cfg_f_path, size_t member_id, unsigned int is_first_usage, wchar_t* where_to_save, wchar_t* encrypted_f_name, wchar_t* error_msg);
SPAE_DLL_EXPIMP enc_error_t SPAE_CALL merge_requested_pads(char* result, size_t* list, size_t count, char* pads_dir, size_t offset, wchar_t* error_desc);



/* ------------------DECRYPTION FUNCTIONS------------------------------------------------------------------ */

SPAE_DLL_EXPIMP decr_error_t SPAE_CALL decrypt_file_progressive(wchar_t* f_name, char* final_name, char* circle, char* decr_cfg_f_path, size_t member_id, unsigned int is_first_usage, wchar_t* error_desc);
size_t* get_list_of_requested_pads_ID_history(char* circle, size_t first_p, size_t last_p, size_t* req_pads_count, char* error_desc);
size_t* get_list_of_requested_pads_ID_progressive(char* circle, size_t first_p, size_t requestedBitsCount, size_t* req_pads_count, char* error_desc);
decr_error_t test_decrypt_file(wchar_t* f_name, char* final_name, wchar_t* error_desc);


SPAE_DLL_EXPIMP void  SPAE_CALL create_file(char*);
SPAE_DLL_EXPIMP void SPAE_CALL create_file_with_name(char* content, char* name);
SPAE_DLL_EXPIMP int  SPAE_CALL get_last_used_pad_id_encr(char* enc_cfg_f_path, char* error_desc);
int validate_large_sequences_by_first_42bits(char* sequence, char* error_desc);
SPAE_DLL_EXPIMP char* SPAE_CALL convert_uk_to_bin_file(wchar_t* data, char* error_desc);
SPAE_DLL_EXPIMP int is_limited_ver();
SPAE_DLL_EXPIMP enc_error_t SPAE_CALL encrypt_file_with_anal(char* f_name, char* circle, char* enc_cfg_f_path, size_t member_id, unsigned int is_first_usage, wchar_t* where_to_save, wchar_t* encrypted_f_name, wchar_t* log_path, wchar_t* error_msg);
SPAE_DLL_EXPIMP pads_error_t SPAE_CALL create_single_pad_with_log(char* pad, char* mrs, char* buk, char* prog_dir, char* circle_name, char* log_path, char* error_desc);

size_t get_dynamic_PPS_insertion_order(size_t sp);