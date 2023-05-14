//#pragma warning(disable : 4996)
#include "spechars.h"
#include "mem.h"
#include "pps.h"

/// <summary>
///	Init spec chars table with the predefined random six-bits values.
/// </summary>
void init_spec_chars_table_random()
{
	_random = map_create();
	_dagger = map_create();

	for (size_t i = 0; i < SPEC_CHARS_COUNT; i++)
	{
		map_set(_random, random_keys[i], spec_values[i]);
		map_set(_dagger, random_keys[i], spec_values[i]);
	}
}

/// <summary>
/// Init spec chars table with the simple order six-bits values.
/// </summary>
void init_spec_chars_table_simple()
{
	_uk = map_create();
	_simple = map_create();

	for (size_t i = 0; i < SPEC_CHARS_COUNT; i++)
	{
		map_set(_uk, simple_keys[i], spec_values[i]);
		map_set(_simple, simple_keys[i], spec_values[i]);
	}
}
/// <summary>
/// Init spec chars table with the simple order seven-bits values.
/// </summary>
void init_spec_chars_table_extended()
{
	_extended = map_create();

	for (size_t i = 0; i < EXTENDED_SPEC_CHARS_COUNT; i++)
	{
		map_set(_extended, improved_keys[i], extended_spec_values[i]);
	}
}

/// <summary>
/// 
/// </summary>
struct map_t* init_enc_spec_chars_table(char* keys)
{
	struct map_t* m_s = { 0 };

	m_s = map_create();
	
	size_t offset = 0;
	char* key = ALLOC(sizeof(char) * 6 + 1);

	for (size_t i = 0; i < 64; i++)
	{
		memcpy_s(key, 7, keys + offset, 6);
		key[6] = '\0';

		map_set(m_s, key, spec_values[i]);
		offset += 6;
	}

	FREE(key);

	return m_s;
}

/// <summary>
/// Free allocated resource
/// </summary>
/// <param name="m"></param>
void free_struct_map(struct map_t* m)
{
	FREE(m->name);
	FREE(m->nxt);
	FREE(m->value);
	FREE(m);
}

char* convert_spec_char_to_binary_for_uk(const wchar_t* content)
{
	size_t tmp               = 0;
	const size_t length      = wcslen(content);
	const size_t buffer_size = length * KEY_BITS_LEN + 1 + 6;

	char* key    = ALLOC(sizeof(char) * KEY_BITS_LEN);
	char* result = ALLOC(sizeof(char) * buffer_size);

	init_spec_chars_table_simple();

	for (size_t i = 0; i < length; i++)
	{
		wchar_t vOut[2] = { content[i], 0 };

		key = map_get_key_by_val(_uk, vOut);
		
		memcpy_s(result + tmp, buffer_size, key, 6);

		tmp += 6;
	}

	result[tmp] = '\0';

	free_struct_map(_uk);

	return result;
}

char* convert_spec_char_to_binary_for_uk_extended(const wchar_t* content)
{
	size_t tmp = 0;
	const size_t length = wcslen(content);
	const size_t buffer_size = length * EXTENDED_KEY_BITS_LEN + 1 + 7;

	char* key = ALLOC(sizeof(char) * EXTENDED_KEY_BITS_LEN);
	char* result = ALLOC(sizeof(char) * buffer_size);

	init_spec_chars_table_extended();

	for (size_t i = 0; i < length; i++)
	{
		wchar_t vOut[2] = { content[i], 0 };

		key = map_get_key_by_val(_extended, vOut);

		memcpy_s(result + tmp, buffer_size, key, 7);

		tmp += 7;
	}

	result[tmp] = '\0';

	free_struct_map(_extended);

	return result;
}

void get_spec_char_by_index(wchar_t* r, char* index)
{
	init_spec_chars_table_random();

	wmemcpy(r, map_get(_random, index), 1);
	r[1] = '\0';

	free_struct_map(_random);
}

void get_spec_char_by_index_simple(wchar_t* r, char* index)
{
	init_spec_chars_table_simple();

	wmemcpy(r, map_get(_simple, index), 1);
	r[1] = '\0';

	free_struct_map(_simple);
}

void convert_PPS_to_spec_chars(wchar_t* ppsSpec, char* pps)
{
	init_spec_chars_table_simple();

	size_t offset = 0;
	size_t l = strlen(pps) / 6;

	char* splitted = ALLOC(7 * sizeof(char));

	for (size_t i = 0; i < l; i++)
	{
		memcpy(splitted, pps + offset, 6);
		splitted[6] = '\0';
		ppsSpec[i] = *map_get(_simple, splitted);
		offset += 6;
	}
	ppsSpec[l] = '\0';

	FREE(splitted);

	free_struct_map(_simple);
}

char* convert_spec_chars_to_PPS(const wchar_t* pps)
{
	init_spec_chars_table_simple();

	char* result = ALLOC(sizeof(char) * 42 + 1);

	size_t offset = 0;
	size_t length = wcslen(pps);
	for (size_t i = 0; i < length; i++)
	{
		wchar_t vOut[2] = { pps[i],0 };
		char* val = map_get_key_by_val(_simple, vOut);
		memcpy(result + offset, val, 6);
		offset += 6;
	}
	result[42] = '\0';

	free_struct_map(_simple);

	return result;
}


void convert_spec_PPS_to_binary(char* result, const wchar_t* specPPS, char* progFileContent)
{
	char* lookupKeys = ALLOC(sizeof(char) * 64 * 6 + 1);
	
	size_t shift = 0;

	for (size_t i = 0; i < 7; i++)
	{
		pps_get_nth_lookup_tbl(lookupKeys, i, progFileContent);

		struct map_t* decr_map_s = init_enc_spec_chars_table(lookupKeys);

		wchar_t vOut[2] = { specPPS[i], 0 };
		char* key = map_get_key_by_val(decr_map_s, vOut);
		strcpy_s(result + shift, strlen(key) + 1, key);
		shift += 6;

		free_struct_map(decr_map_s);
	}

	result[42] = '\0';

	FREE(lookupKeys);
}


void convert_plain_short_txt_to_spec_chars(wchar_t* pSpec, char* pTxt, char* xorBits)
{
	init_spec_chars_table_random();

	size_t offset = 0;
	size_t l = strlen(pTxt) / 6;
	
	char* splitted = ALLOC(7 * sizeof(char));
	unsigned char* xoredIndex = NULL;

	for (size_t i = 0; i < 64; i++)
	{
		xoredIndex = xor_short_strings(random_keys[i], xorBits);
		xoredKeys[i] = xoredIndex;
		map_set(_random, xoredKeys[i], spec_values[i]);
		FREE(xoredIndex);
	}


	for (size_t i = 0; i < l; i++)
	{
		memcpy(splitted, pTxt + offset, 6);
		splitted[6] = '\0';
		pSpec[i] = *map_get(_random, splitted);
		offset += 6;
	}
	pSpec[l] = '\0';

	FREE(splitted);
	FREE(xoredIndex);

	free_struct_map(_random);
}

void convert_spec_chars_to_binary_reverse(const wchar_t* content, char* xorBits, char* result)
{
	init_spec_chars_table_random();

	unsigned char* xoredIndex = NULL;
	//char* key;

	for (size_t i = 0; i < 64; i++)
	{
		xoredIndex = xor_short_strings(random_keys[i], xorBits);
		xoredKeys[i] = ALLOC(7 * sizeof(char));
		memcpy(xoredKeys[i], xoredIndex, 6);
		xoredKeys[i][6] = '\0';
		map_set(_dagger, xoredKeys[i], spec_values[i]);

		FREE(xoredIndex);
	}

	size_t tmp = 0;
	const size_t length = wcslen(content);

	for (size_t i = 0; i < length; i++)
	{
		wchar_t vOut[2] = { content[i], 0 };
		char* key = map_get_key_by_val(_dagger, vOut);
		memcpy_s(result + tmp, strlen(key) + 1, key, 6);
		tmp += 6;
	}
	result[length * 6] = '\0';

	free_struct_map(_dagger);
}



void convert_spec_chars_to_binary(const wchar_t* content, char* xorBits, char* result, char* lookupKeys)
{
	struct map_t* decr_map_s = init_enc_spec_chars_table(lookupKeys);

	unsigned char* xoredIndex = NULL;

	size_t shift = 0;
	char* key = ALLOC(sizeof(char) * 6 + 1);

	for (size_t i = 0; i < 64; i++)
	{
		memcpy_s(key, 7, lookupKeys + shift, 6);
		key[6] = '\0';

		xoredIndex = xor_short_strings(key, xorBits);
		
		xoredKeys[i] = ALLOC(7 * sizeof(char));
		memcpy(xoredKeys[i], xoredIndex, 6);
		xoredKeys[i][6] = '\0';

		map_set(decr_map_s, xoredKeys[i], spec_values[i]);
		shift += 6;

		FREE(xoredIndex);
	}

	size_t tmp = 0;
	const size_t length = wcslen(content);
	const size_t buffer_size = length * 6;

		for (size_t i = 0; i < length; i++)
		{
			wchar_t vOut[2] = { content[i], 0 };
			char* key = map_get_key_by_val(decr_map_s, vOut);
			memcpy_s(result + tmp, buffer_size + 1, key, 6);
			tmp += 6;
		}

	result[length * 6] = '\0';

	free_struct_map(decr_map_s);
}


void convert_enc_PPS_to_spec_char(wchar_t* ppsSpec, char* pps, char* lookupKeys)
{
	struct map_t* enc_map_s = init_enc_spec_chars_table(lookupKeys);

	wchar_t* single = ALLOC(sizeof(wchar_t) * 2);

	single = map_get(enc_map_s, pps);

	wmemcpy(ppsSpec, single, wcslen(single));

	ppsSpec[wcslen(single)] = '\0';

	free_struct_map(enc_map_s);
}

void convert_enc_PPS_to_spec_chars_simple(wchar_t* ppsSpec, char* pps)
{
	init_spec_chars_table_simple();

	size_t offset = 0;
	char* splitted = ALLOC(8 * sizeof(char));

	size_t l = strlen(pps) / 6;

	for (size_t i = 0; i < l; i++)
	{
		memcpy(splitted, pps + offset, 6);
		splitted[6] = '\0';
		ppsSpec[i] = *map_get(_simple, splitted);
		offset += 6;
	}
	ppsSpec[l] = '\0';

	FREE(splitted);

	free_struct_map(_simple);
}


void convert_enc_plain_txt_to_spec_chars(wchar_t* plainSpec, char* binCont, char* xorBits, char* lookupKeys)
{
	size_t offset = 0;
	char* splitted = ALLOC(8 * sizeof(char));
	size_t l = strlen(binCont) / 6;
	size_t bin_len = strlen(binCont) / 3 + 2;

	unsigned char* xoredIndex = ALLOC(7 * sizeof(unsigned char));
	struct map_t* encry_map_s = map_create();

	size_t shift = 0;
	char* key = ALLOC(sizeof(char) * 6 + 1);

	for (size_t i = 0; i < 64; i++)
	{
		memcpy_s(key, 7, lookupKeys + shift, 6);
		key[6] = '\0';

		xoredIndex = xor_short_strings(key, xorBits);
		xoredKeys[i] = ALLOC(7 * sizeof(char));
		memcpy(xoredKeys[i], xoredIndex, 6);
		xoredKeys[i][6] = '\0';

		map_set(encry_map_s, xoredKeys[i], spec_values[i]);
		//wxoredKeys[bindec(xoredIndex)] = spec_values[i];

		shift += 6;
	}

	for (size_t i = 0; i < l; i++)
	{
		memcpy(splitted, binCont + offset, 6);
		splitted[6] = '\0';
		//plainSpec[i] = *wxoredKeys[bindec(splitted)];
		wchar_t* val = map_get(encry_map_s, splitted);
		wmemcpy_s(plainSpec + i, bin_len, val, 1);
		offset += 6;
	}
	plainSpec[l] = '\0';

	FREE(splitted);
	FREE(xoredIndex);
	FREE(key);

	free_struct_map(encry_map_s);
}

size_t get_index_from_simple_keys(const char* target)
{
	size_t index = -1;
	for (size_t i = 0; i < 64; i++) {
		if (strcmp(simple_keys[i], target) == 0) {
			index = i;
			break;
		}
	}

	return index;
}

size_t w_get_index_from_simple_keys(const wchar_t* target)
{
	size_t index = -1;
	for (size_t i = 0; i < 64; i++) {
		if (wcscmp(spec_values[i], target) == 0) {
			index = i;
			break;
		}
	}

	return index;
}
