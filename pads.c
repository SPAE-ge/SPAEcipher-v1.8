#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pads.h"
#include "helper.h"
#include "userkey.h"
#include "spaestr.h"

void createPadCfgFile(FILE* f)
{
	struct pads p;
	memset(&p, 0, PADS_STRUCT_SIZE);
	const size_t count = fwrite(&p, PADS_STRUCT_SIZE, 1, f);

	if (count < PADS_STRUCT_SIZE)
	{

	}

	fclose(f);
}

pads_error_t create_pads_cfg_file(FILE* f)
{
	struct pads p;
	// Set values to 0
	memset(&p, 0, PADS_STRUCT_SIZE);
	const size_t count = fwrite(&p, PADS_STRUCT_SIZE, 1, f);

	if (count < 1)
	{
		return PADS_ERROR_WRITEFILE;
	}

	return PADS_ERROR_OK;
}

void make_single_pad(char* pad, char* row)
{
	char* temp = ALLOC(_2_POW_23 + 1);
	size_t offset = _2_POW_23, step = 1;

	for (size_t i = 0; i < 7; i++)
	{
		if (step == 1)
		{
			memcpy(pad, row, _2_POW_23);
			pad[_2_POW_23] = '\0';
			memcpy(temp, row + offset, _2_POW_23);
			temp[_2_POW_23] = '\0';
			fmakeXOR(pad, temp);

			step++;
			offset += _2_POW_23;
		}
		else
		{
			memcpy(temp, row + offset, _2_POW_23);
			fmakeXOR(pad, temp);

			step++;
			offset += _2_POW_23;
		}
	}

	FREE(temp);
}

struct pad collect_data_about_next_pad(char* pad_str, char* buk, char* mrs, int current_pad_id, int prev_pad_it, char* error_desc)
{
	size_t rP            = 0;
	size_t size          = 0;
	size_t offset        = 0;
	size_t pspJumpPoint  = 0;
	size_t pspStartPoint = 0;

	char* singlePSPdata = ALLOC(sizeof(char) * 46 + 1);
	char* singleReStr = ALLOC(sizeof(char) * 23 + 1);

	struct pad new_pad_block = { 0 };

	new_pad_block.id = current_pad_id;
	new_pad_block.prevPad = prev_pad_it;

	for (size_t i = 0; i < 8; i++)
	{
		/* Collect PSP points */
		memcpy(singlePSPdata, mrs + offset, 46);
		singlePSPdata[46] = '\0';

		pspStartPoint = bindec(spae_substr(singlePSPdata, 0, 23));
		pspJumpPoint = bindec(spae_substr(singlePSPdata, 23, 23));
		new_pad_block.nextPSPstartPoints[size] = pspStartPoint;
		new_pad_block.nextPSPjumpPoints[size] = pspJumpPoint;

		/* Collect rearranign points */
		memcpy(singleReStr, buk + offset, 23);
		singleReStr[23] = '\0';

		rP = bindec(singleReStr);
		new_pad_block.nextPSPrearrnagePoints[size] = rP;

		size++;
		offset += _2_POW_23;

		
	}

	memcpy(new_pad_block.pps, pad_str, 42);
	new_pad_block.pps[42] = '\0';
	
	FREE(singlePSPdata);
	FREE(singleReStr);

	return new_pad_block;
}

size_t get_first_used_pad_id(size_t* pads_list, size_t count, const char* pads_dir, char* pps, size_t* offset)
{
	size_t pad_id = 0;
	size_t pad_offset = 0;

	char* pad_path = ALLOC(sizeof(char) * _MAX_PATH);
	char* pad_name = ALLOC(sizeof(char) * 8 + 1);

	for (size_t i = 0; i < count; i++)
	{
		_ui64toa_s(pads_list[i], pad_name, 9, 10);
		strcat_s(pad_name, 9, ".txt");

		strcpy_s(pad_path, _MAX_PATH, pads_dir);
		pad_path[strlen(pads_dir)] = '\0';
		strcat_s(pad_path, _MAX_PATH, "\\");
		strcat_s(pad_path, _MAX_PATH, pad_name);

		pad_offset = find_str_in_file(pad_path, pps);
		if (-1 != pad_offset)
		{
			pad_id = pads_list[i];
			*offset = pad_offset;

			return pad_id;
		}
	}

	return 0;
}

int get_first_42_bits_of_any_pad(char* bits, size_t pad_num, char* pads_dir, wchar_t* error_desc)
{
	char* padPath = ALLOC(sizeof(char) * _MAX_PATH);
	char* padName = ALLOC(sizeof(char) * 8 + 1);

	/*Read whole file content into memory*/
	/*Allocate enough heap size for file content*/
	char* fContent;
	size_t contentSize = 0;

	int open_status;
	int readStatus;

	FILE* pd;

	_ui64toa_s(pad_num, padName, 9, 10);
	strcat_s(padName, 9, ".txt");

	strcpy_s(padPath, _MAX_PATH, pads_dir);
	padPath[strlen(pads_dir)] = '\0';
	strcat_s(padPath, _MAX_PATH, "/");
	strcat_s(padPath, _MAX_PATH, padName);

	/*Accept the file and try to open it*/
	pd = open_file(padPath, FILE_MODE_READ, &open_status);
	if (open_status != 0)
	{
		wcscpy_s(error_desc, 256, L"\nError: When trying to open a Pad for getting the first bits.\n");
		return PADS_ERROR_OPENFILE;
	}

	fContent = c_read_file(pd, &readStatus, &contentSize);
	if (readStatus)
	{
		wcscpy_s(error_desc, 256, L"\nError: When trying to open Pad file for merging.\n");
		return PADS_ERROR_OPENFILE;
	}

	memcpy(bits, fContent, 42);
	bits[42] = '\0';

	FREE(fContent);

	memset(padPath, 0, sizeof(padPath));
	memset(padName, 0, sizeof(padName));

	fclose(pd);

	return PADS_ERROR_OK;
}
