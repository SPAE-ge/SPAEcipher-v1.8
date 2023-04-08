#pragma warning(disable : 4996)
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "userkey.h"
#include "mem.h"
#include "spaestr.h"
#include "helper.h"
#include "psp.h"

size_t bits_count[TUPLES_COUNT] = { 3, 3, 3, 3, 3, 3, 3 };
size_t total_tuples_count[TUPLES_COUNT] = { 8, 8, 8, 8, 8, 8, 8 };

int trim_uk(char* u_key, char* trimmed_key, char* error_desc)
{
	if (NULL == u_key) {
		strcpy_s(error_desc, 256, "\nError: empty argument given to expand_uk() function!\n");
		return UK_ERROR_EMPTY_ARG;
	}

	strncpy_s(trimmed_key, UK_LENGHT + 1, u_key, UK_LENGHT);
	trimmed_key[UK_LENGHT] = '\0';
	
	return UK_ERROR_OK;
}


/*Expand UserKey file*/
char* expand_uk(char* key, char* error_desc)
{
	if (NULL == key) {
		strcpy_s(error_desc, 256, "\nError: empty argument given to expand_uk() function!\n");
		return NULL;
	}

	size_t integer_part  = 0;
	size_t remained_part = 0;
	size_t key_len       = 0;

	char* uk = ALLOC(sizeof(char) * UK_LENGHT + 1);

	key_len = strlen(key);
	if (key_len == 0) {
		strcpy_s(error_desc, 256, "\nError: empty data submitted. Pls, check!\n");
		return NULL;
	}

	//get integer part of divided, eg. 2^26/18 = 3728270
	integer_part = UK_LENGHT / key_len;

	//get remained part, eg 4
	remained_part = UK_LENGHT % key_len;

	size_t index = 0;
	while (integer_part-- > 0)
	{
		strcpy_s(uk + index, key_len + 1, key);
		index += key_len;
	}

	strncpy_s(uk + index, remained_part + 1, key, remained_part);
	uk[UK_LENGHT] = '\0';

	return uk;
}

void expand_uk_in(char* uk, char* key, char* error_desc)
{
	if (NULL == key) {
		strcpy_s(error_desc, 256, "\nError: empty argument given to expand_uk() function!\n");
		return;
	}

	size_t integer_part = 0, remained_part = 0, key_len = 0;
	//char* uk = ALLOC(sizeof(char) * UK_LENGHT + 1);

	key_len = strlen(key);
	if (key_len == 0) {
		strcpy_s(error_desc, 256, "\nError: empty data submitted. Pls, check!\n");
		return;
	}

	//get integer part of divided, eg. 2^26/18 = 3728270
	integer_part = UK_LENGHT / key_len;

	//get remained part, eg 4
	remained_part = UK_LENGHT % key_len;

	size_t index = 0;
	while (integer_part-- > 0)
	{
		strcpy_s(uk + index, key_len + 1, key);
		index += key_len;
	}

	strncpy_s(uk + index, remained_part + 1, key, remained_part);
	uk[UK_LENGHT] = '\0';
}


void merge_sequences_by_content(char* result, char** list, size_t n)
{
	result[0] = '\0';

	for (size_t i = 0; i < n; i++)
	{
		strcat(result, list[i]);
	}
}



void do_logical_operation(char* b, char* pb, char* bd, const char* m)
{
	char* buk_i = ALLOC(_2_POW_23 + 1);
	char* bday_i = ALLOC(_2_POW_23 + 1);
	size_t offset = 0;

	for (size_t i = 0; i < 8; i++)
	{
		if (m[i] == '1')
		{
			memcpy(buk_i, pb + offset, _2_POW_23);
			buk_i[_2_POW_23] = '\0';
			memcpy(bday_i, bd + offset, _2_POW_23);
			bday_i[_2_POW_23] = '\0';
			fmakeXOR(buk_i, bday_i);
			strcat(b, buk_i);
			//b[(i + 1) * _2_POW_23] = '\0';
		}
		else
		{
			memcpy(buk_i, pb + offset, _2_POW_23);
			buk_i[_2_POW_23] = '\0';
			memcpy(bday_i, bd + offset, _2_POW_23);
			bday_i[_2_POW_23] = '\0';
			fmakeXNOR(buk_i, bday_i);
			strcat(b, buk_i);
			//b[(i + 1) * _2_POW_23] = '\0';
		}

		offset += _2_POW_23;
	}

	FREE(buk_i);
	FREE(bday_i);
}


void do_logical_operation_for_the_next_pad(char* b, char* pb, char* bd, const char* m)
{
	char* buk_i = ALLOC(_2_POW_23 + 1);
	size_t offset = 0;

	for (size_t i = 0; i < 8; i++)
	{
		if (m[i] == '1')
		{
			memcpy(buk_i, pb + offset, _2_POW_23);
			buk_i[_2_POW_23] = '\0';
			fmakeXOR(buk_i, bd);
			strcat(b, buk_i);
			b[(i + 1) * _2_POW_23] = '\0';
		}
		else
		{
			memcpy(buk_i, pb + offset, _2_POW_23);
			buk_i[_2_POW_23] = '\0';
			fmakeXNOR(buk_i, bd);
			strcat(b, buk_i);
			b[(i + 1) * _2_POW_23] = '\0';
		}

		offset += _2_POW_23;
	}

	FREE(buk_i);
}


void get_start_jump_points_26_bits(char* seq, size_t* start, size_t* jump)
{
	char* sp = ALLOC(26 + 1);
	char* jp = ALLOC(26 + 1);
	size_t offset = 26;

	memcpy(sp, seq, 26);
	sp[26] = '\0';
	memcpy(jp, seq + offset, 26);
	jp[26] = '\0';

	*start = bindec(sp);
	*jump = bindec(jp);

	FREE(sp);
	FREE(jp);
}

void get_start_jump_points_17_bits(char* seq, size_t* start, size_t* jump)
{
	char* sp = ALLOC(17 + 1);
	char* jp = ALLOC(17 + 1);
	size_t offset = 17;

	memcpy(sp, seq, 17);
	sp[17] = '\0';
	memcpy(jp, seq + offset, 17);
	jp[17] = '\0';

	*start = bindec(sp);
	*jump = bindec(jp);

	FREE(sp);
	FREE(jp);
}


int generate_specialchars_lookup_table(char*** finalTable, const char* bukPart, const char* mrsPart, size_t* seeker, size_t pointer_shift, size_t* size)
{
	// We will store unique tuples here
	char** uniqueTuple = ALLOC(128 * sizeof(char*));
	// This one is just for temporary use when we collecting the next tuple
	char tmpUniqueTuple[16][7] = { 0 };

	char* xuy = ALLOC(sizeof(char) * UK_LENGHT + 1);
	memcpy(xuy, bukPart, _2_POW_26);
	memcpy(xuy + _2_POW_26, mrsPart, _2_POW_26);
	xuy[UK_LENGHT] = '\0';
	size_t xlen = strlen(xuy);

	size_t offset = 0;
	size_t count = 0;
	size_t attempt = 1;

	size_t pointerPosition = pointer_shift;

	while (*size < SPEC_CHARS_LOOKUP_TBL_CNT && pointerPosition < UK_LENGHT) //was 65
	{
		

		// Value for first elem we getting from buk, second value from mrs.
		//for (size_t i = 0; i < 8; i++)
		//{
		//	memcpy(tmpUniqueTuple[i * 2], bukPart + pointerPosition + *seeker * 6, 6);
		//	tmpUniqueTuple[i * 2][6] = '\0';

		//	memcpy(tmpUniqueTuple[i * 2 + 1], mrsPart + pointerPosition + *seeker * 6, 6);
		//	tmpUniqueTuple[i * 2 + 1][6] = '\0';

		//	pointerPosition += _2_POW_23;
		//}
		for (size_t i = 0; i < 16; i++)
		{
			memcpy(tmpUniqueTuple[i], xuy + pointerPosition, 6);
			tmpUniqueTuple[i][6] = '\0';

			pointerPosition += 6;
		}

		offset += 6;
		/* We collected next portion of bits from BUK adn MRS strings.
		 * Now we should check if collected bits are unique.
		 */
		for (size_t i = 0; i < 16; i++)
		{
			uniqueTuple[count + i] = ALLOC(8 * sizeof(char));
			memcpy(uniqueTuple[count + i], tmpUniqueTuple[i], sizeof(*tmpUniqueTuple));
			uniqueTuple[count + i][6] = '\0';
		}

		// Check uniquness
		count = arrayUniqueWithoutSorting(uniqueTuple, count + 16);

		if (count >= 64)
		{
			finalTable[*size] = ALLOC(64 * sizeof(char*));

			for (size_t i = 0; i < 64; i++)
			{

				finalTable[*size][i] = ALLOC(6 * sizeof(char));

				memcpy(finalTable[*size][i], uniqueTuple[i], 6);
				finalTable[*size][i][6] = '\0';
				uniqueTuple[i] = NULL;
			}
			(*size)++;

			count = 0;
		}

		(*seeker) = pointerPosition;

		// If not found
		if (*size < SPEC_CHARS_LOOKUP_TBL_CNT && pointerPosition >= UK_LENGHT && attempt <= 3)
		{
			// Reset and start from the next bit
			pointerPosition = pointer_shift + attempt;
			attempt++;
		}
	}

	// Poor key
	if (*size < SPEC_CHARS_LOOKUP_TBL_CNT)
	{
		FREE(xuy);
		return UK_ERROR_POOR_KEY;
	}

	FREE(xuy);
	return UK_ERROR_OK;
}

/*
* REARRANGEMENT POINTS FOR BASE USER KEY SEQ's
*/
void generate_rearrangement_points_for_program_files(char** bukRearrangementPointsArray, const char* bukPart, const char* mrsPart, size_t* seeker, size_t offset)
{
	char* singlePointStr = ALLOC(sizeof(char) * 23 + 1);
	char* xuy = ALLOC(sizeof(char) * UK_LENGHT + 1);
	memcpy(xuy, bukPart, _2_POW_26);
	memcpy(xuy + _2_POW_26, mrsPart, _2_POW_26);
	xuy[UK_LENGHT] = '\0';
	size_t xlen = strlen(xuy);

	size_t size = 0;

	// check if there are enough bits (368)
	if (UK_LENGHT - offset < 368)
	{
		offset = 368 + 1;
	}

	for (size_t i = 0; i < 16; i++)
	{
		memcpy_s(singlePointStr, 24, xuy + offset, 23);
		singlePointStr[23] = '\0';

		bukRearrangementPointsArray[i] = ALLOC(24);
		memcpy(bukRearrangementPointsArray[i], singlePointStr, 23);
		bukRearrangementPointsArray[i][23] = '\0';

		offset += 23;
	}

	(*seeker) = offset;

	//for (size_t i = 0; i < 8; i++)
	//{
	//	memcpy_s(singlePointStr, 24, bukPart + offset + *seeker * 23, 23);
	//	singlePointStr[23] = '\0';

	//	bukRearrangementPointsArray[size] = ALLOC(24);
	//	memcpy(bukRearrangementPointsArray[size], singlePointStr, 23);
	//	bukRearrangementPointsArray[size][23] = '\0';
	//	size++;

	//	memcpy_s(singlePointStr, 24, mrsPart + offset + *seeker * 23, 23);
	//	singlePointStr[23] = '\0';

	//	bukRearrangementPointsArray[size] = ALLOC(24);
	//	memcpy(bukRearrangementPointsArray[size], singlePointStr, 23);
	//	bukRearrangementPointsArray[size][23] = '\0';
	//	size++;

	//	(*seeker)++;
	//}

	FREE(singlePointStr);
	FREE(xuy);
}


void get_PPS_insertion_point(char** PPSpointStr, const char* buk, const char* mrs, size_t* seeker, size_t offset)
{
	char* xuy = ALLOC(sizeof(char) * UK_LENGHT + 1);
	memcpy(xuy, buk, _2_POW_26);
	memcpy(xuy + _2_POW_26, mrs, _2_POW_26);
	xuy[UK_LENGHT] = '\0';

	// check if there are enough bits (368)
	if (UK_LENGHT - offset < 184)
	{
		offset = 368 + 1;
	}

	for (size_t i = 0; i < 7; i++)
	{
		PPSpointStr[i] = ALLOC(26 * sizeof(char));

		memcpy(PPSpointStr[i], xuy + offset, 26);
		PPSpointStr[i][26] = '\0';

		offset += 26;
	}

	(*seeker) = offset;
	FREE(xuy);
}

void get_C9_insertion_position(char* position, const char* buk, const char* mrs, size_t* seeker, size_t offset)
{
	char* xuy = ALLOC(sizeof(char) * UK_LENGHT + 1);
	memcpy(xuy, buk, _2_POW_26);
	memcpy(xuy + _2_POW_26, mrs, _2_POW_26);
	xuy[UK_LENGHT] = '\0';

	// check if there are enough bits (368)
	if (UK_LENGHT - offset < 26)
	{
		offset = 368 + 1;
	}

	memcpy(position, xuy + offset, 26);
	position[26] = '\0';

	offset += 26;

	(*seeker) = offset;
	FREE(xuy);
}

void rearrange_files(char* bkr, const char* buffer, char** points)
{
	char* temp = NEW(temp);
	size_t offset = 0;

	for (size_t i = 0; i < 8; i++)
	{
		size_t point = bindec(points[i]);
		if (_2_POW_23 < point) {
			point = point % _2_POW_23;
		}

		RESIZE(temp, (long)point + 1);

		memcpy(bkr + offset, buffer + offset + point, _2_POW_23 - point);
		bkr[_2_POW_23 - point] = '\0';
		memcpy(bkr + offset + _2_POW_23 - point, buffer + offset, point);
		bkr[_2_POW_23] = '\0';

		offset += _2_POW_23;
	}

	FREE(temp);
}

void generate_data_for_next_pad(const char* bukPart, const char* mrsPart, size_t* startP, size_t* jumpP, size_t* rearrangingP)
{
	size_t size = 0, pspStartPoint = 0, pspJumpPoint = 0, rP = 0, offset = 0;

	char* singlePSPdata = ALLOC(sizeof(char) * 46 + 1);
	char* singleReStr = ALLOC(sizeof(char) * 23 + 1);

	for (size_t i = 0; i < 8; i++)
	{
		/* Collect PSP points */
		memcpy(singlePSPdata, mrsPart + offset, 46);
		singlePSPdata[46] = '\0';

		pspStartPoint = bindec(spae_substr(singlePSPdata, 0, 23));
		pspJumpPoint = bindec(spae_substr(singlePSPdata, 23, 23));
		startP[size] = pspStartPoint;

		/*Be carefull with zero jump points*/
		if (pspJumpPoint != 0)
		{
			jumpP[size] = pspJumpPoint;
		}
		else
		{
			jumpP[size] = 128;
		}

		/* Collect rearranign points */
		memcpy(singleReStr, bukPart + offset, 23);
		singleReStr[23] = '\0';

		rP = bindec(singleReStr);
		rearrangingP[size] = rP;

		size++;
		offset += _2_POW_23;
	}

	FREE(singlePSPdata);
	FREE(singleReStr);
}

/// <summary>
/// 
/// </summary>
/// <param name="index"></param>
/// <returns>0 - YES and index value is not 0, 1 - otherwise</returns>
int if_index_value_exists(char* u_array, size_t array_size, size_t index)
{
	/* Check for array boundaries*/
	if (index < array_size)
	{
		if (u_array[index] != 0)
		{
			return 0; /* Item value is not 0, so we assume we already have this item */
		}
		return 1;
	}
	else
	{
		return UK_ERROR_OUT_OF_RANGE;
	}
}

int collect_unique_bits_for_pads_permutation(size_t* final_array, const char* bukPart, const char* mrsPart, size_t* seeker, size_t offset, char* error_desc)
{
	char uniqueness_checker[_512_BUFFER] = { 0 };
	char* tmp_nine_bits = ALLOC(sizeof(char) * _512_BITS_TUPLE_SIZE + 1);
	char* xuy = ALLOC(sizeof(char) * UK_LENGHT + 1);

	size_t pointerPosition = 0;
	size_t array_key       = 0;
	size_t i               = 0;
	size_t l = strlen(bukPart);

	memcpy(xuy, bukPart, _2_POW_26);
	memcpy(xuy + _2_POW_26, mrsPart, _2_POW_26);
	xuy[UK_LENGHT] = '\0';
	size_t xlen = strlen(xuy);

	while (*seeker + _512_BITS_TUPLE_SIZE < 100663296 && i < _512_BUFFER) // 3/4th of 2^27 (100663296)
	{
			memcpy(tmp_nine_bits, xuy + offset + *seeker, _512_BITS_TUPLE_SIZE);
			tmp_nine_bits[_512_BITS_TUPLE_SIZE] = '\0';

			array_key = bindec(tmp_nine_bits);
			if (array_key >= 0 && array_key < _512_BUFFER)
			{
				if (uniqueness_checker[array_key] == 0)
				{
					uniqueness_checker[array_key] = 1;
					final_array[i] = array_key;
					i++;
				}
			}

		////if (i < _512_buffer)
		////{
		////	memcpy(tmp_nine_bits, mrspart + offset + *seeker, _512_bits_tuple_size);
		////	tmp_nine_bits[_512_bits_tuple_size] = '\0';

		////	array_key = bindec(tmp_nine_bits);
		////	if (array_key >= 0 && array_key < _512_buffer)
		////	{
		////		if (uniqueness_checker[array_key] == 0)
		////		{
		////			uniqueness_checker[array_key] = 1;
		////			final_array[i] = array_key;
		////			i++;
		////		}
		////	}
		////}
		
		(*seeker) += _512_BITS_TUPLE_SIZE;
	}

	// Check if there are still values unfound
	if (i < _512_BUFFER)
	{
		// Find missed values and add them 
		for (size_t j = 0; j < 512; j++)
		{
			if (uniqueness_checker[j] == 0)
			{
				uniqueness_checker[j] = 1;
				final_array[i] = j;
				i++;
			}
		}
	}

	FREE(xuy);

	if (i < _512_BUFFER)
	{
		strcpy_s(error_desc, 256, "\nError: Not enough bits for transposition bits for Pads permutation.\n");
		return UK_ERROR_NOT_ENOUGH_BITS;
	}

	if (i > _512_BUFFER)
	{
		strcpy_s(error_desc, 256, "\nError: Why they are more than 512 values?.\n");
		return UK_ERROR_NOT_ENOUGH_BITS;
	}

	return UK_ERROR_OK;
}


int collect_unique_bits_for_userkey_setup(char* final_array, const char* balanced_key, size_t* seeker, size_t* sets_count, char* error_desc)
{
	char uniqueness_checker[8] = { 0 };
	char* tmp_nine_bits = ALLOC(sizeof(char) * _512_BITS_TUPLE_SIZE + 1);

	size_t pointer_position = 0;
	size_t array_key = 0;
	size_t i = 0;
	size_t attmpt = 1;
	size_t max_attempt = 3;
	size_t key_len = strlen(balanced_key);

	for (int j = 0; j < TUPLES_COUNT; j++)
	{
		while (*seeker + bits_count[j] < key_len && i < total_tuples_count[j] && attmpt <= max_attempt)
		{
			if (i < total_tuples_count[j])
			{
				memcpy(tmp_nine_bits, balanced_key + *seeker, bits_count[j]);
				tmp_nine_bits[bits_count[j]] = '\0';

				array_key = bindec(tmp_nine_bits);
				if (array_key >= 0)
				{
					if (uniqueness_checker[array_key] == 0)
					{
						uniqueness_checker[array_key] = 1;
						memcpy_s(final_array + pointer_position, UK_DISGUSSING_UNIQUE_BITS_COUNT, tmp_nine_bits, bits_count[j]);
						pointer_position += bits_count[j];
						i++;
					}
				}
			}

			if (i == total_tuples_count[j] - 1)
			{
				// find which value is not set to 1
				for (size_t k = 0; k < 8; k++)
				{
					if (uniqueness_checker[k] == 0)
					{
						// Convert index valu to binary
						char* add_binary = CALLOC(sizeof(char) * 3 + 1, 1);
						decimalToBinary(add_binary, k, 2);
						// add to final 
						memcpy_s(final_array + pointer_position, UK_DISGUSSING_UNIQUE_BITS_COUNT, add_binary, bits_count[j]);
						pointer_position += bits_count[j];
						i++;
						(*sets_count) += 1;
						break;
					}
				}
			}

			(*seeker) += bits_count[j];
		}

		if (attmpt <= max_attempt)
		{
 			if (i < total_tuples_count[j])
			{
				*seeker = attmpt;
				j--;
				attmpt++;
			}
			else
			{
				// Reset for the next cycle
				i = 0;
				memset(uniqueness_checker, 0, 8);
			}
		}
		else
		{
			// Max attempt has been done. No need to continue
			break;
		}
	}

	final_array[*sets_count * UK_DISGUSSING_UNIQUE_BITS_COUNT / TUPLES_COUNT] = '\0';
	//assert(strlen(final_array) == UK_DISGUSSING_UNIQUE_BITS_COUNT);

	if (strlen(final_array) < 24) // at least one complete set
	{
		strcpy_s(error_desc, 256, "\nError: Not enough bits for transposition bits for Pads permutation.\n");
		return UK_ERROR_NOT_ENOUGH_BITS;
	}

	return UK_ERROR_OK;
}

void generate_transposition_values(char* sequence, size_t** points)
{
	const size_t bits_count = 24;
	size_t seq_len = strlen(sequence);
	size_t offset = 0;
	size_t i = 0;

	char* buffer = ALLOC(sizeof(char) * bits_count + 1);

	while (*sequence != 0)
	{
		memcpy(buffer, sequence, bits_count);
		buffer[bits_count] = '\0';

			for (size_t j = 0; j < 8; j++)
			{
				//ints[j] = ALLOC(sizeof(size_t) * 8);
				char* tmp3bits = ALLOC(sizeof(char) * 3 + 1);
				memcpy(tmp3bits, buffer + offset, 3);
				tmp3bits[3] = '\0';

				points[i][j] = bindec(tmp3bits);

				offset += 3;
			}

		sequence += bits_count;
		i++;
		offset = 0;
	}
}

//
void permutate_small_sequence(char* res, char* seq, size_t set_cnt, size_t** points)
{
	size_t buffer_len = 8;
	char* buffer = ALLOC(sizeof(char) * buffer_len + 1);

	size_t offset = 0;
	int set_index = (int)set_cnt - 1;
	size_t len = strlen(seq);

	while (*seq != 0)
	{
		memcpy_s(buffer, buffer_len + 1, seq, buffer_len);
		buffer[buffer_len] = '\0';
		
		for (size_t j = 0; j < 8; j++)
		{
			if (points[set_index][j] >= strlen(buffer))
			{
				continue;
			}
			else
			{
				res[offset] = buffer[points[set_index][j]];
				offset++;
			}
		}
	

		seq += buffer_len;

		if (strlen(seq) < buffer_len)
		{
			buffer_len = strlen(seq);
		}

		set_index--;
		if (set_index < 0)
		{
			set_index = (int)(set_cnt - 1);
		}
	}

	res[len] = '\0';
}


void permutate_pad_log(char* res, char* pad, size_t pad_num, size_t* points, FILE** log_file)
{
	char* buffer = ALLOC(sizeof(char) * _512_BUFFER + 1);

	size_t offset = 0;
	size_t len = strlen(pad);
	size_t modified_permutation_values_array[512];

	for (size_t i = 0; i < _512_BUFFER; i++)
	{
		modified_permutation_values_array[i] = points[i] ^ (pad_num & _511_MASKING_BITS);
		assert(modified_permutation_values_array[i] < _512_BUFFER);
	}

	while (*pad != 0)
	{
		memcpy_s(buffer, _512_BUFFER + 1, pad, _512_BUFFER);
		buffer[_512_BUFFER] = '\0';

		for (size_t i = 0; i < _512_BUFFER; i++)
		{
			res[offset] = buffer[modified_permutation_values_array[i]];
			offset++;
		}
		pad += _512_BUFFER;
	}

	res[len] = '\0';

#if _DEBUG
	write_log(*log_file, "Nine bits tuples (ALREADY XOR-ed !!!!!!!!!!!!) :\n");
	for (size_t i = 0; i < _512_BUFFER; i++)
	{
		int_write_log(*log_file, "Element decimal value is: ", modified_permutation_values_array[i]);
	}
#endif

}

void permutate_pad(char* res, char* pad, size_t pad_num, size_t* points)
{
	char* buffer = ALLOC(sizeof(char) * _512_BUFFER + 1);

	size_t offset = 0;
	size_t len = strlen(pad);
	size_t modified_permutation_values_array[512];

	for (size_t i = 0; i < _512_BUFFER; i++)
	{
		modified_permutation_values_array[i] = points[i] ^ (pad_num & _511_MASKING_BITS);
		assert(modified_permutation_values_array[i] < _512_BUFFER);
	}

	while (*pad != 0)
	{
		memcpy_s(buffer, _512_BUFFER + 1, pad, _512_BUFFER);
		buffer[_512_BUFFER] = '\0';

		for (size_t i = 0; i < _512_BUFFER; i++)
		{
			res[offset] = buffer[modified_permutation_values_array[i]];
			offset++;
		}
		pad += _512_BUFFER;
	}

	res[len] = '\0';
}

size_t forced_balancing(char* key, char* error_desc)
{
	size_t balanced_ones_count = 0;
	size_t balanced_zeros_count = 0;
	char mask_to = '0';

	/* First of all get the key len */
	size_t key_len = strlen(key);

	if (key_len < 259)
	{
		strcpy_s(error_desc, 256, "\nError: Not enough bits for making a key.\n");
		return UK_ERROR_NOT_ENOUGH_BITS;
	}

	/* Get the 1's and 0's count in the key */
	const size_t ones_count = get_ones_count_in_file(key);
	const size_t zeros_count = key_len - ones_count;

	/* Check if all bits are the same */
	if (ones_count == key_len || zeros_count == key_len)
	{
		strcpy_s(error_desc, 256, "\nError: Pooooor key.\n");
		return UK_ERROR_POOR_KEY;
	}

	/* Check if it already balanced */
	if (MAX(ones_count, zeros_count) - MIN(ones_count, zeros_count) <= 1)
	{
		return UK_ERROR_OK;
	}

	/* Get the balancing middle */
	size_t balance_num = key_len / 2;

	/* Check which one we should fill */
	if (ones_count > zeros_count)
	{
		balanced_zeros_count = balance_num;
		balanced_ones_count = ones_count - (balance_num - zeros_count);
		mask_to = '1';
	}
	else
	{
		balanced_ones_count = balance_num;
		balanced_zeros_count = zeros_count - (balance_num - ones_count);
	}

	if (mask_to == '1')
	{
		lite_psp(key, mask_to, zeros_count, balanced_zeros_count);
	}
	else
	{
		lite_psp(key, mask_to, ones_count, balanced_ones_count);
	}

	return UK_ERROR_OK;
}

void last_26_bits(char* out, const char* in, size_t length) 
{
	if (length < 26) {
		return; // or handle error condition
	}

	const char* start = in + length - 26;
	memcpy(out, start, 26);
	out[26] = '\0'; // null terminate the output string
}
