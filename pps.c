#include "pps.h"
#include "assert.h"
#include "spechars.h"

/// <summary>
/// Allocate a new pps_t. NULL on failure.
/// </summary>
/// <param name=""></param>
/// <returns>An init-ed struct</returns>
pps_t* pps_new(void)
{
	pps_t* self;
	self = ALLOC(sizeof(pps_t) * 1);

	self->charInsertionPos = NULL;
	self->lookupTbl        = NULL;

	return self;
}

/// <summary>
/// Set appropriate values for newly created struct members.
/// </summary>
/// <param name="p"></param>
/// <param name="position"></param>
/// <param name="tbl"></param>
void pps_set(pps_t* p, const char* position, const char** tbl)
{
	/* Allocate enough memory */
	p->charInsertionPos = ALLOC(strlen(position)*sizeof(char) + 1);

	/* Assign value to PPS insertion position member */
	strcpy_s(p->charInsertionPos, strlen(position) + 1, position);

	/* Allocate memory for lookup table */
	p->lookupTbl = ALLOC(64 * sizeof(char*));

	/* Assign values using loop */
	for (size_t i = 0; i < 64; i++)
	{
		p->lookupTbl[i] = ALLOC(6 * sizeof(char));

		memcpy(p->lookupTbl[i], tbl[i], 6);
		p->lookupTbl[i][6] = '\0';
	}

	return;
}

/// <summary>
/// Marshaling PPS struct (7 element) into an "array".
/// </summary>
/// <param name="ppsData">Result array</param>
/// <param name="pps">Filled struct</param>
void pps_struct_into_array(char* ppsData, pps_t* pps)
{
	size_t pps_offset = 0;

	for (size_t i = 0; i < PPS_CHARS_COUNT; i++)
	{
		memcpy(ppsData + pps_offset, (pps + i)->charInsertionPos, strlen((pps + i)->charInsertionPos));

		pps_offset += strlen((pps + i)->charInsertionPos);
	}
	
	for (size_t i = 0; i < PPS_CHARS_COUNT; i++)
	{
		for (size_t j = 0; j < 64; j++) //SPEC_CHARS_COUNT
		{
			memcpy(ppsData + pps_offset, (pps + i)->lookupTbl[j], strlen((pps + i)->lookupTbl[j]));
			pps_offset += 6;
		}
	}

	ppsData[pps_offset] = '\0';
}

void pps_get_nth_position(char* pos, size_t n, char* data)
{
	assert(n < 7);
	size_t seek = 64 * 6 + n * 26;

	memcpy_s(pos, 27, data + seek, 26);
	pos[26] = '\0';
}

void pps_get_nth_lookup_tbl(char* tbl, size_t n, char* data)
{
	assert(n < 7);
	size_t seek = 64 * 6 + 7 * 26 + n*64*6;

	memcpy_s(tbl, 64 * 6 + 1, data + seek, 64 * 6);
	tbl[64 * 6] = '\0';
}

/// <summary>
/// Freed allocated struct obj
/// </summary>
/// <param name="p"></param>
void pps_free(pps_t* p)
{
	FREE(p->charInsertionPos);

	FREE(p->lookupTbl);

}


pps_dynamic_t* dynamic_pps_new(void)
{
	pps_dynamic_t* self;
	self = ALLOC(sizeof(pps_dynamic_t) * 1);

	self->ctrlChar  = NULL;
	self->position0 = NULL;
	self->position1 = NULL;
	self->position2 = NULL;
	self->position3 = NULL;
	self->position4 = NULL;
	self->position5 = NULL;
	self->position6 = NULL;

	return self;
}

void dynamic_pps_free(pps_dynamic_t* p)
{
	FREE(p->ctrlChar);

	FREE(p->position0);
	FREE(p->position1);
	FREE(p->position2);
	FREE(p->position3);
	FREE(p->position4);
	FREE(p->position4);
	FREE(p->position6);

}

//TODO pps_dynamic_t set function


/// <summary>
/// 
/// </summary>
/// <param name="positions"></param>
/// <param name="buk"></param>
/// <param name="mrs"></param>
/// <param name="seeker"></param>
/// <param name="offset"></param>

void get_PPS_positions_dynamic(char* positions, const char* buk, const char* mrs, size_t* seeker, size_t offset)
{
	char* xuy = ALLOC(sizeof(char) * 134217728 + 1);
	memcpy(xuy, buk, 67108864);
	memcpy(xuy + 67108864, mrs, 67108864);
	xuy[134217728] = '\0';

	size_t cnt = 64 * 7 * 26;

	// check if there are enough bits (368)
	if (134217728 - offset < cnt)
	{
		offset = 368 + 1;
	}

	memcpy(positions, xuy + offset, cnt);
	positions[cnt] = '\0';

	offset += cnt;
	(*seeker) = offset;

	FREE(xuy);
}

void dynamic_pps_set(pps_dynamic_t* p, const char* ctrlchar, char* positions) //positions is a 7x26 len seq
{
	size_t seek = 0;
	/* Allocate enough memory */
	p->ctrlChar = ALLOC(strlen(ctrlchar) * sizeof(char) + 1);

	/* Assign value to ctrl char */
	strcpy_s(p->ctrlChar, strlen(ctrlchar) + 1, ctrlchar);

	/* Allocate memory for positions */
	p->position0 = ALLOC(26 * sizeof(char) + 1);
	p->position1 = ALLOC(26 * sizeof(char) + 1);
	p->position2 = ALLOC(26 * sizeof(char) + 1);
	p->position3 = ALLOC(26 * sizeof(char) + 1);
	p->position4 = ALLOC(26 * sizeof(char) + 1);
	p->position5 = ALLOC(26 * sizeof(char) + 1);
	p->position6 = ALLOC(26 * sizeof(char) + 1);

	// Close string
	p->position0[26] = '\0';
	p->position1[26] = '\0';
	p->position2[26] = '\0';
	p->position3[26] = '\0';
	p->position4[26] = '\0';
	p->position5[26] = '\0';
	p->position6[26] = '\0';

	/* Assign values */
	memcpy_s(p->position0, 27, positions + seek, 26);
	seek += 26;
	memcpy_s(p->position1, 27, positions + seek, 26);
	seek += 26;
	memcpy_s(p->position2, 27, positions + seek, 26);
	seek += 26;
	memcpy_s(p->position3, 27, positions + seek, 26);
	seek += 26;
	memcpy_s(p->position4, 27, positions + seek, 26);
	seek += 26;
	memcpy_s(p->position5, 27, positions + seek, 26);
	seek += 26;
	memcpy_s(p->position6, 27, positions + seek, 26);

	return;
}

void assign_values_to_dynamic_pps_struct(pps_dynamic_t* p, const char* positions) // positions is a 64x7x26 len seq
{
	size_t poslen = 7 * 26;
	char* tmp_7_set_of_26 = ALLOC(poslen * sizeof(char) + 1);
	tmp_7_set_of_26[poslen] = '\0'; // set null terminator

	for (size_t i = 0; i < 64; i++)
	{
		memcpy_s(tmp_7_set_of_26, poslen + 1, positions + i*poslen, poslen);

		dynamic_pps_set(p + i, simple_keys[i], tmp_7_set_of_26);
	}

	FREE(tmp_7_set_of_26);
}

/// <summary>
/// Marshaling Dynamic PPS struct (64 element) into an "array".
/// </summary>
/// <param name="ppsData">Result array</param>
/// <param name="pps">Filled struct</param>
void dynamic_pps_struct_into_array(char* ppsData, pps_dynamic_t* pps)
{
	size_t pps_offset = 0;

	for (size_t i = 0; i < 64; i++)
	{
		memcpy(ppsData + pps_offset, (pps + i)->ctrlChar, strlen((pps + i)->ctrlChar));
		pps_offset += strlen((pps + i)->ctrlChar);

		memcpy(ppsData + pps_offset, (pps + i)->position0, strlen((pps + i)->position0));
		pps_offset += 26;
		memcpy(ppsData + pps_offset, (pps + i)->position1, strlen((pps + i)->position1));
		pps_offset += 26;
		memcpy(ppsData + pps_offset, (pps + i)->position2, strlen((pps + i)->position2));
		pps_offset += 26;
		memcpy(ppsData + pps_offset, (pps + i)->position3, strlen((pps + i)->position3));
		pps_offset += 26;
		memcpy(ppsData + pps_offset, (pps + i)->position4, strlen((pps + i)->position4));
		pps_offset += 26;
		memcpy(ppsData + pps_offset, (pps + i)->position5, strlen((pps + i)->position5));
		pps_offset += 26;
		memcpy(ppsData + pps_offset, (pps + i)->position6, strlen((pps + i)->position6));
		pps_offset += 26;
	}

	ppsData[pps_offset] = '\0';
}

void dynamic_pps_get_positions_by_specchar(char* pos, const char* spec, char* data)
{
	size_t seek = 64 * 6 + 7 * 26 + 7 * 64 * 6 + 1; // 64 * 6 - lookup table
												    // 7 * 26 - PPS pos (OLD)
												    // 7 * 64 * 6 - lookup tables for PPS chars
	                                                // 1 - log bit
	size_t dyn_strct_len_for_offset = 6 + 7 * 26;

	char* tmp_ctrl_char_bin = ALLOC(6 * sizeof(char) + 1);
	tmp_ctrl_char_bin[6] = '\0';

	// Get C9 index from simple_spec table
	size_t indexof_C9 = get_index_from_simple_keys(spec);
	
	// check if index is in range of 0-63
	assert(0 <= indexof_C9 <= 63);

	// get 9th char in bin
	memcpy_s(tmp_ctrl_char_bin, 6 + 1, data + seek + indexof_C9 * dyn_strct_len_for_offset, 6);

	// double check if we get right portion of data. Check 9th 6-bit
	if (strcmp(spec, tmp_ctrl_char_bin) == 0)
	{
		// get positions
		memcpy(pos, data + seek + indexof_C9 * dyn_strct_len_for_offset + 6, 7 * 26);
		pos[7 * 26] = '\0';
	}
	else
	{
		pos[0] = '\0';
	}
}