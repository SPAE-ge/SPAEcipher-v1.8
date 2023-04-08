#pragma once

/// @brief Error codes for library "circle"
typedef enum uk_error_e
{
	/// No error
	UK_ERROR_OK = 0,

	/// Error opening/reading file
	UK_ERROR_FILE,

	/// Empty argument
	UK_ERROR_EMPTY_ARG,

	/// Out of range
	UK_ERROR_OUT_OF_RANGE,

	/// Not enough bits
	UK_ERROR_NOT_ENOUGH_BITS,

	/// Poor key
	UK_ERROR_POOR_KEY,

	/// Undefined error
	UK_ERROR_UNDEFINED

} uk_error_t;

#define UK_LENGHT 134217728 //User Key lenght 2^27
#define _2_POW_23 8388608              //pad file standart size 2^23
#define _2_POW_26 67108864              // 2^26
#define _512_BUFFER 512                //for pads disgussing
#define _8_BUFFER 8                //for pads disgussing
#define _511_MASKING_BITS 511                //for pads disgussing
#define _512_BITS_TUPLE_SIZE 9                //for pads disgussing

/* User Key Setup unique bits */
#define UK_DISGUSSING_UNIQUE_BITS_COUNT 168 //944 //1392 //5760 //7552

#define TUPLES_COUNT 7

#define SPEC_CHARS_LOOKUP_TBL_CNT 72

//char uniqueness_checker[_512_BUFFER] = { 0 };

/*******************************************************************************

	Function :      trim_uk(char* u_key, char* error_desc);

	Parameters :    key -
						key string whcih we need to cut.

	Returns :       Cut user key string to 2^26 lenght

	Description :   Takes a 01's string and cuts it to 2^26.

*******************************************************************************/
//char* trim_uk(char* u_key, char* error_desc);
int trim_uk(char* u_key, char* trimmed_key, char* error_desc);

/*******************************************************************************

	Function :      char* expand_uk(char* key, char* error_desc);

	Parameters :    key -
						key string whcih we need to extend.

	Returns :       Extended user key string up to 2^26

	Description :   Takes a 01's string and extends it up to 2^26 repetedaly
					concatenating given part.

*******************************************************************************/
char* expand_uk(char* key, char* error_desc);
void expand_uk_in(char* uk, char* key, char* error_desc);

void merge_sequences_by_content(char* result, char** list, size_t n);

void do_logical_operation(char* b, char* pb, char* bd, const char* m);

void do_logical_operation_for_the_next_pad(char* b, char* pb, char* bd, const char* m);

int generate_specialchars_lookup_table(char*** finalTable, const char* bukPart, const char* mrsPart, size_t* seeker, size_t pointer_shift, size_t* size);

void generate_rearrangement_points_for_program_files(char** bukRearrangementPointsArray, const char* bukPart, const char* mrsPart, size_t* seeker, size_t offset);

void get_PPS_insertion_point(char** PPSpointStr, const char* buk, const char* mrs, size_t* seeker, size_t offset);

void rearrange_files(char* bkr, const char* buffer, char** points);

void generate_data_for_next_pad(const char* bukPart, const char* mrsPart, size_t* startP, size_t* jumpP, size_t* rearrangingP);

int if_index_value_exists(char* u_array, size_t array_size, size_t index);
int collect_unique_bits_for_pads_permutation(size_t* final_array, const char* bukPart, const char* mrsPart, size_t* seeker, size_t offset, char* error_desc);
void permutate_pad(char* res, char* pad, size_t pad_num, size_t* points);
void permutate_pad_log(char* res, char* pad, size_t pad_num, size_t* points, FILE** log);

int collect_unique_bits_for_userkey_setup(char* final_array, const char* balanced_key, size_t* seeker, size_t* sets_count, char* error_desc);
void get_start_jump_points_26_bits(char* seq, size_t* start, size_t* jump);
void get_start_jump_points_17_bits(char* seq, size_t* start, size_t* jump);
size_t forced_balancing(char* key, char* error_desc);
void generate_transposition_values(char* sequence, size_t** points);
void permutate_small_sequence(char* res, char* seq, size_t set_cnt, size_t** points);
void get_C9_insertion_position(char* position, const char* buk, const char* mrs, size_t* seeker, size_t offset);
void last_26_bits(char* out, const char* in, size_t length); //we really need this?