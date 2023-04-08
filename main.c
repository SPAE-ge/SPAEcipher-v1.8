#pragma warning(disable : 4996)
#include "main.h"
#include "encryption.h"

const size_t SEEK_NUMBER = 138;

int inline is_wstring_empty(wchar_t* s);

size_t inline howManyFullPadsIsIt(size_t bitsCount)
{
    return bitsCount / PAD_LEN;
}

size_t inline get_used_bits_count_of_part_pad(size_t ub)
{
    return ub % PAD_LEN;
}

size_t inline get_available_bits_count_of_part_pad(size_t ub)
{
    return PAD_LEN - get_used_bits_count_of_part_pad(ub);
}

inline char* get_current_time()
{
    time_t now = time(0); // Get the system time
    char* time_str = ctime(&now);
    time_str[strlen(time_str) - 1] = '\0';

    return time_str;
}



SPAE_DLL_EXPIMP char* SPAE_CALL convert_uk_to_bin(wchar_t* data, char* error_desc)
{
    const size_t length = wcslen(data);

    /* If empty string given */
    if (0 == length)
    {
        strcpy_s(error_desc, 256, "\nWhen trying to convert User Key to binary. Empty data given as an input value.\n");
        return NULL;
    }

    // Convert spec chars to six bits 
    char* bin_content = convert_spec_char_to_binary_for_uk_extended(data);

    // Len of binary string must be exactly equal to (6 * length)!!!
    // Otherwise it means there where some issue when converting spec to 6-bits
    const size_t bin_len = strlen(bin_content);

    // Check if converting op went ok
    if (bin_len != (EXTENDED_KEY_BITS_LEN * length))
    {
        strcpy_s(error_desc, 256, "\nWhen trying to convert User Key to binary. There is an issue when converting spec-chars to 6-bits.\n");
        return NULL;
    }

    return bin_content;
}

SPAE_DLL_EXPIMP char* SPAE_CALL convert_uk_to_bin_file(wchar_t* data, char* error_desc)
{
    const size_t length = wcslen(data);

    /* If empty string given */
    if (0 == length)
    {
        strcpy_s(error_desc, 256, "\nWhen trying to convert User Key to binary. Empty data given as an input value.\n");
        return NULL;
    }

    // Convert spec chars to six bits 
    char* bin_content = convert_spec_char_to_binary_for_uk(data);

    // Len of binary string must be exactly equal to (6 * length)!!!
    // Otherwise it means there where some issue when converting spec to 6-bits
    const size_t bin_len = strlen(bin_content);

    // Check if converting op went ok
    if (bin_len != (KEY_BITS_LEN * length))
    {
        strcpy_s(error_desc, 256, "\nWhen trying to convert User Key to binary. There is an issue when converting spec-chars to 6-bits.\n");
        return NULL;
    }

    return bin_content;
}

SPAE_DLL_EXPIMP int SPAE_CALL create_uk(char* userkey, char* buk, char* mrs, char* key, char* error_desc)
{
    size_t keyLen = strlen(key);
    char* tmp = ALLOC(sizeof(char) * UK_LENGHT + 1);

    // if data is NULL or empty
    if (keyLen <= 0)
    {
        strcpy_s(error_desc, 256, "\nEmpty data given as an input value when User Key should be created.\n");
        return UK_ERROR_NOT_ENOUGH_BITS;
    }

    // if potential key len is more than 2^27 we shall to truncate it
    if (keyLen > UK_LENGHT)
    {
        trim_uk(key, tmp, error_desc);
    }

    // if potential key len is less than 2^27 we shall to expand it
    if (keyLen <= UK_LENGHT)
    {
        // That was our PSP-like procedure that is used to jump 
        // around the sequence but reversing bits landed on if 
        // it help us toward balance.
        int ret_val = (int)forced_balancing(key, error_desc);
        
        // Check for errors
        if (ret_val != 0)
        {
            return ret_val;
        }

        /*                                                                   */
        /*    Collect Start&Jump points                                      */
        /*                                                                   */
        size_t start_point0 = 0;
        size_t jump_point0 = 0;

        get_start_jump_points_26_bits(key, &start_point0, &jump_point0);

        /*                                                                   */
        /*    Disguss collected bits                                         */
        /*                                                                   */
        char* smallpspeduk = PSP(key, start_point0 % keyLen, jump_point0 % keyLen);

        /*                                                                   */
        /*    Collect 7552 bits (9*512+8*256+7*128)                          */
        /*                                                                   */
        size_t seeker = 0;
        size_t set_count = 0;
        size_t offset = 0;
        size_t shift = 368;
        size_t s = 0;

        /* Transposition values. As an init size we assume there is full set */
        /* Allocate memory and init the whole 2D array immideatly.           */
        size_t** trans_values = ALLOC(sizeof(size_t*) * 8);
        for (size_t j = 0; j < 8; j++)
        {
            trans_values[j] = ALLOC(sizeof(size_t) * 8);
        }

        char* uk_disgussing_bits = ALLOC(UK_DISGUSSING_UNIQUE_BITS_COUNT * sizeof(char) + 1);
        char* permutated_key     = ALLOC(keyLen * sizeof(char) + 1);

        int ret_value = collect_unique_bits_for_userkey_setup(uk_disgussing_bits, smallpspeduk, &seeker, &set_count, error_desc);
        if (ret_value != 0)
        {
            return ret_value;
        }

        generate_transposition_values(uk_disgussing_bits, trans_values);
        
        permutate_small_sequence(permutated_key, smallpspeduk, set_count, trans_values);

        /*                                                                   */
/*    Collect Start&Jump points                                      */
/*                                                                   */
        size_t start_point2 = 0;
        size_t jump_point2 = 0;

        get_start_jump_points_26_bits(permutated_key, &start_point2, &jump_point2);

        /*                                                                   */
        /*    Disguss collected bits                                         */
        /*                                                                   */
        char* super_PSP_key = PSP(permutated_key, start_point2 % keyLen, jump_point2 % keyLen);

        expand_uk_in(tmp, super_PSP_key, error_desc);

        /*                                                                   */
        /*    Collect Start&Jump points                                      */
        /*                                                                   */
        size_t start_point1 = 0;
        size_t jump_point1 = 0;

        get_start_jump_points_26_bits(tmp, &start_point1, &jump_point1);

        /*                                                                   */
        /*    Disguss collected bits                                         */
        /*                                                                   */
        char* psp_res = PSP(tmp, start_point1 % UK_LENGHT, jump_point1 % UK_LENGHT);

        // Validate every 2x23 sequence by the first 42  bits to be unique
        int is_seqs_unique = validate_large_sequences_by_first_42bits(psp_res, error_desc);
        if (is_seqs_unique != 1)
        {
            strcpy_s(error_desc, 256, "\nNot unique problem with key detected. Please submit a different key.\n");
            return UK_ERROR_NOT_ENOUGH_BITS;
        }

        /* Make BUK */
        memcpy_s(buk, _2_POW_26, psp_res, _2_POW_26);
        //buk[_2_POW_26] = '\0';

        /* Reverse BUK bits */
        for (int i = 0; i < _2_POW_26; i++)
        {
            buk[i] = (char)((buk[i] - '0') ^ ('1' - '0') + '0');
        }

        /* Make MRS */
        memcpy_s(mrs, _2_POW_26, psp_res + _2_POW_26, _2_POW_26);
        //mrs[_2_POW_26] = '\0';
        memcpy_s(userkey, UK_LENGHT, psp_res, UK_LENGHT);
        //userkey[UK_LENGHT] = '\0';

        FREE(uk_disgussing_bits);
        FREE(permutated_key);
        FREE(tmp);
        FREE(psp_res);

        return UK_ERROR_OK;
    }

    return UK_ERROR_UNDEFINED;
}


SPAE_DLL_EXPIMP int SPAE_CALL create_uk_by_single_file_content(char* userkey, char* buk, char* mrs, char* key, char* error_desc)
{
    size_t keyLen = strlen(key);
    char* tmp = ALLOC(sizeof(char) * UK_LENGHT + 1);

    // if data is NULL or empty
    if (keyLen <= 0)
    {
        strcpy_s(error_desc, 256, "\nEmpty data given as an input value when User Key should be created.\n");
        return UK_ERROR_NOT_ENOUGH_BITS;
    }

    // if potential key len is more than 2^27 we shall to truncate it
    if (keyLen > UK_LENGHT)
    {
        trim_uk(key, tmp, error_desc);
    }

    // if potential key len is less than 2^27 we shall to expand it
    if (keyLen <= UK_LENGHT)
    {
        // Expand
        expand_uk_in(tmp, key, error_desc);

        // Validate to pass 1SD req
        const size_t ones_count = get_ones_count_in_file(tmp);
        if (is_number_in_1SD_range_large(ones_count) == 0)
        {
            strcpy_s(error_desc, 256, "\n1SD problem with key detected. Please submit a different key.\n");
            return UK_ERROR_NOT_ENOUGH_BITS;
        }

        /*                                                                   */
        /*    Collect Start&Jump points                                      */
        /*                                                                   */
        size_t start_point1 = 0;
        size_t jump_point1 = 0;

        get_start_jump_points_26_bits(tmp, &start_point1, &jump_point1);

        /*                                                                   */
        /*    Disguss collected bits                                         */
        /*                                                                   */
        char* psp_res = PSP(tmp, start_point1 % UK_LENGHT, jump_point1 % UK_LENGHT);

        // Validate every 2x23 sequence by the first 42  bits to be unique
        int is_seqs_unique = validate_large_sequences_by_first_42bits(psp_res, error_desc);
        if (is_seqs_unique != 1)
        {
            strcpy_s(error_desc, 256, "\nNot unique problem with key detected. Please submit a different key.\n");
            return UK_ERROR_NOT_ENOUGH_BITS;
        }

        memcpy(userkey, psp_res, UK_LENGHT);

        /* Make BUK */
        memcpy(buk, userkey, _2_POW_26);
        buk[_2_POW_26] = '\0';

        for (int i = 0; i < _2_POW_26; i++)
        {
            buk[i] = (char)((buk[i] - '0') ^ ('1' - '0') + '0');
        }

        memcpy(userkey, buk, _2_POW_26);

        /* Make MRS */
        memcpy(mrs, userkey + _2_POW_26, _2_POW_26);
        mrs[_2_POW_26] = '\0';
    }

    FREE(tmp);

    return UK_ERROR_OK;
}

SPAE_DLL_EXPIMP wchar_t* SPAE_CALL sanitize_uk_file(wchar_t* content, int* wrong_chars_count, char* error_desc)
{
    size_t offset = 0;
    size_t tmp = 0;

    // Our spec chars white list. u2020 is our DAGGER!
    static wchar_t whitelist_chars[] = L"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz†/";

    size_t   content_size = 0;

    // Check if there were some content but useful content was empty
    if (is_wstring_empty(content) == 1)
    {
        strcpy_s(error_desc, 256, "\nError: empty data submitted. Pls, check!\n");
        return NULL;
    }
    else
    {
        content_size = wcslen(content);
    }

    wchar_t* result = ALLOC(content_size + 2);

    wchar_t* cp = content; /* Cursor into string */
    const wchar_t* end = content + wcslen(content);

    size_t index = wcsspn(cp, whitelist_chars);
    if (index == wcslen(cp))
    {
        return cp;
    }

    for (cp += index; cp != end; cp += wcsspn(cp, whitelist_chars))
    {
        cp++; /* We are skipping bad char */

        wmemcpy(result + offset, content + tmp, index);
        offset += index;
        tmp += (index + 1);
        index = wcsspn(cp, whitelist_chars);
        wmemcpy(result + offset, content + tmp, index);
        *wrong_chars_count += 1;
    }

    result[offset + index] = '\0';
    return result;
}


SPAE_DLL_EXPIMP wchar_t* SPAE_CALL sanitize_uk_file_content(wchar_t* content, int* wrong_chars_count, char* error_desc)
{
    size_t offset = 0;
    size_t tmp = 0;

    //static wchar_t whitelist_chars[] = L"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz\u2020/";
    static wchar_t whitelist_chars[] = L" !$%&()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[]^_`abcdefghijklmnopqrstuvwxyz{|}~'\"#";

    size_t   content_size = 0;

    // Check if there were some content but useful content was empty
    if (is_wstring_empty(content) == 1)
    {
        strcpy_s(error_desc, 256, "\nError: empty data submitted. Pls, check!\n");
        return NULL;
    }
    else
    {
        content_size = wcslen(content);
    }

    wchar_t* result = ALLOC(content_size + 2);

    wchar_t* cp = content; /* Cursor into string */
    const wchar_t* end = content + wcslen(content);

    size_t index = wcsspn(cp, whitelist_chars);
    if (index == wcslen(cp))
    {
        return cp;
    }

    for (cp += index; cp != end; cp += wcsspn(cp, whitelist_chars))
    {
        cp++; /* We are skipping bad char */

        wmemcpy(result + offset, content + tmp, index);
        offset += index;
        tmp += (index + 1);
        index = wcsspn(cp, whitelist_chars);
        wmemcpy(result + offset, content + tmp, index);
        *wrong_chars_count += 1;
    }

    result[offset + index] = '\0';
    return result;
}


SPAE_DLL_EXPIMP circle_error_t SPAE_CALL add_new_circle(struct circle c, struct member m, char* error_desc)
{
#if _DEBUG
    FILE* log_file = NULL;
    int open_status;
    log_file = open_file("log_circles.txt", FILE_MODE_APLUS, &open_status);

    if (open_status != 0)
    {
        strcpy_s(error_desc, 256, "\nError: When trying to open a Log file.\n");
        return CIRCLE_ERROR_OPENF;
    }

    // Start log file
    write_log(log_file, "------Action: Add New Circle------ Time: ");
    write_log(log_file, get_current_time());
    write_log(log_file, "\n");
    write_log(log_file, "New circle name: ");
    write_log(log_file, c.circle_name);
    write_log(log_file, "\n");
    write_log(log_file, "New circle cfg path: ");
    write_log(log_file, c.config_path);
    write_log(log_file, "\n");
    write_log(log_file, "New circle pads path: ");
    write_log(log_file, c.pads_path);
    write_log(log_file, "\n");
    write_log(log_file, "New circle manager name: ");
    write_log(log_file, c.mbr.first_name);
    write_log(log_file, "\n");
    write_log(log_file, "Second member name: ");
    write_log(log_file, m.first_name);
    write_log(log_file, "\n");
#endif

    /* Open circles config file in binary + append mode */
    FILE* f_circle = NULL;
    fopen_s(&f_circle, CIRCLE_FILE_NAME, "ab+");
    if (f_circle == NULL)
    {
        strcpy_s(error_desc, 256, "Can't open circles config file. Pls, check if circles.txt exists and not currupted.");
        return CIRCLE_ERROR_OPENF;
    }

    /* Starting to read from the cfg file.
     * Since there is struct written so we shall to read in struct size.
     */
    struct circle buffer;
    /* This while checks is there is circle with the same name already created.*/
    while (fread(&buffer, CIRCLE_SIZE, 1, f_circle) == 1)
    {
        if (strcmp(c.circle_name, buffer.circle_name) == 0 && buffer.master == 1)
        {
            strcpy_s(error_desc, 256, "Duplicate Circle name.");
            fclose(f_circle);
            return CIRCLE_ERROR_DUPLICATE;
        }
    }

    // Writing info about new circle into the cfg file.
    // Since this is a new circle this wirte adds ONLY general info and a Circle's manager!
    if (fwrite(&c, sizeof(c), 1, f_circle) != 1)
    {
        strcpy_s(error_desc, 256, "Cannot write record into the circle file.");
        fclose(f_circle);
        return CIRCLE_ERROR_WRITEF;
    }
    else
    {
        // Flush and close Circle file, since it was successfully created
        fflush(f_circle);
        fclose(f_circle);

#if _DEBUG
        fflush(log_file);
        fclose(log_file);
#endif

        // Add second memeber which is mandatory
        add_new_member(c.circle_name, m.first_name, m.position_num, error_desc);

        // Immediately we are creating config file just/right for this circle which created.
        FILE* f_pads_cfg = NULL;
        fopen_s(&f_pads_cfg, c.config_path, "ab+");
        if (f_pads_cfg == NULL)
        {
            strcpy_s(error_desc, 256, "Error when creating Circle config file.");
            return PADS_ERROR_OPENFILE;
        }

        // Create empty cfg file for the circle which will store data about circle's pads
        int ret_val = create_pads_cfg_file(f_pads_cfg);

        // Check if file created
        if (0 != ret_val)
        {
            strcpy_s(error_desc, 256, "Error when creating circle's Pads config file.");
            return PADS_ERROR_OPENFILE;
        }

        fflush(f_pads_cfg);
        fclose(f_pads_cfg);
    }

    return CIRCLE_ERROR_OK;
}


SPAE_DLL_EXPIMP circle_error_t SPAE_CALL get_circles_info(struct circle* data, int size, char* error_descr)
{
    FILE* fp1 = NULL;

    fopen_s(&fp1, CIRCLE_FILE_NAME, "rb");
    if (fp1 == NULL)
    {
        strcpy_s(error_descr, 256, "\nError opening Circle config file.\n");
        return CIRCLE_ERROR_OPENF;
    }

    /* Check if file exists but contains no any data. */
    if (0 == is_file_empty(fp1))
    {
        strcpy_s(error_descr, 256, "\nThere is no any Circle to show.\n");
        fclose(fp1);

        return CIRCLE_ERROR_FILE_EMPTY;
    }

    if (data != NULL)
    {
        struct circle buffer;
        fseek(fp1, 0, SEEK_SET);   // move file position indicator to beginning of file

        int i = 0; // Will store circles count
        while (fread(&buffer, CIRCLE_SIZE, 1, fp1) == 1)
        {
            if (buffer.master) // We must see only records which master = 1, since this value indicates circle "head".
            {
                memcpy(data + i, &buffer, CIRCLE_SIZE * 1);
                i++;
            }
        }

        // If nothing found in the cfg file
        if (0 == i)
        {
            strcpy_s(error_descr, 256, "There is something wrong or corrupted in Circle config file.");
            fclose(fp1);

            return CIRCLE_ERROR_FILE_CURRUPT;
        }
    }
    else
    {
        fclose(fp1);
        return CIRCLE_ERROR_NOMEM;
    }

    fclose(fp1);
    return CIRCLE_ERROR_OK;
}

SPAE_DLL_EXPIMP circle_error_t SPAE_CALL get_circle_members_data(struct member* data, int size, const char* c_name, char* error_desc)
{
    int open_status;

    /*Accept the file and try to open it*/
    FILE* fp1 = NULL;
    /*Trying to open the file*/
    fp1 = open_file(CIRCLE_FILE_NAME, FILE_MODE_READ, &open_status);

    if (open_status != 0)
    {
        strcpy_s(error_desc, 256, "\nError: When trying to open Circle cfg file.\n");
        return CIRCLE_ERROR_OPENF;
    }

    if (data != NULL)
    {
        struct circle buffer;

        fseek(fp1, 0, SEEK_SET);   // move file position indicator to beginning of file

        int i = 0;
        while (fread(&buffer, CIRCLE_SIZE, 1, fp1) == 1)
        {
            if (strcmp(c_name, buffer.circle_name) == 0)
            {
                memcpy(data + i, &buffer.mbr, sizeof(struct member) * 1);
                i++;
            }
        }
        // If nothing found in the cfg file
        if (0 == i)
        {
            strcpy_s(error_desc, 256, "Circle has not any member or Circle config file is corrupted.");
            fclose(fp1);
            return CIRCLE_ERROR_FILE_CURRUPT;
        }
    }
    else
    {
        fclose(fp1);
        return CIRCLE_ERROR_NOMEM;
    }

    fclose(fp1);
    return CIRCLE_ERROR_OK;
}


SPAE_DLL_EXPIMP int SPAE_CALL get_circles_count(char* error_descr)
{
    int circles_c = 0;

    FILE* fp1 = NULL;
    fopen_s(&fp1, CIRCLE_FILE_NAME, "rb");
    if (fp1 == NULL)
    {
        strcpy_s(error_descr, 256, "Cannot open Circles config file.");
        return CIRCLE_ERROR_OPENF;
    }

    /* Check if file exists but contains no any data. */
    if (0 == is_file_empty(fp1))
    {
        strcpy_s(error_descr, 256, "Circle config file exists but it is empty.");
        //return CIRCLE_ERROR_FILE_EMPTY;
        fclose(fp1);
        return circles_c;
    }

    struct circle buffer;
    fseek(fp1, 0, SEEK_SET);   // move file position indicator to beginning of file
    while (fread(&buffer, sizeof(buffer), 1, fp1) == 1)
    {
        if (buffer.master)
        {
            ++circles_c;
        }
    }

    fclose(fp1);
    return circles_c;
}

SPAE_DLL_EXPIMP int SPAE_CALL get_circle_members_count(const char* c, char* error_desc)
{
    int members_c = 0;
    int open_status;

    // Accept the file and try to open it
    FILE* fCircleCfg = NULL;
    fCircleCfg = open_file(CIRCLE_FILE_NAME, FILE_MODE_READ, &open_status);

    // Check open file status
    if (open_status != 0)
    {
        strcpy_s(error_desc, 256, "\nError: When trying to open a Circle cfg file.\n");
        return 0;
    }

    // Start to read
    struct circle buffer;
    fseek(fCircleCfg, 0, SEEK_SET);   // move file position indicator to beginning of file
    while (fread(&buffer, sizeof(buffer), 1, fCircleCfg) == 1)
    {
        if (strcmp(c, buffer.circle_name) == 0)
        {
            members_c++;
        }
    }

    fflush(fCircleCfg);
    fclose(fCircleCfg);

    return members_c;
}

SPAE_DLL_EXPIMP int SPAE_CALL delete_circle(const char* c_name, char* error_desc)
{
    int error = 0;
    int found = 0;
    int open_status;

    // Accept the file and try to open it
    FILE* fp1 = NULL;
    fp1 = open_file(CIRCLE_FILE_NAME, FILE_MODE_READ, &open_status);

    if (open_status != 0)
    {
        strcpy_s(error_desc, 256, "\nError: When trying to open a file for deleting Circle.\n");
        error = 1;
        return error;
    }

    // Open temp file
    FILE* ftmp = NULL;
    ftmp = open_file(CIRCLE_TMP_FILE_NAME, FILE_MODE_WRITE, &open_status);

    if (open_status != 0)
    {
        strcpy_s(error_desc, 256, "\nError: When trying to open a temp file for deleting Circle.\n");
        error = 1;
        return error;
    }

    struct circle buffer;
    fseek(fp1, 0, SEEK_SET);   // move file position indicator to beginning of file
    while (fread(&buffer, sizeof(struct circle), 1, fp1) == 1)
    {
        if (strcmp(c_name, buffer.circle_name) == 0)
        {
            // A record with requested name found and skipped.
            found = 1;
        }
        else
        {
            // Otherwise write data about other circles into tmp file
            fwrite(&buffer, sizeof(struct circle), 1, ftmp);
        }
    }
    if (!found) {

        strcpy_s(error_desc, 256, "\nNo record(s) found with the requested name.\n\n");
        error = 1;
    }

    if (fclose(fp1) != 0)
    {
        strcpy_s(error_desc, 256, "Error closing file circles cfg file.");
        error = 1;
    }

    if (fclose(ftmp) != 0)
    {
        strcpy_s(error_desc, 256, "Error closing file tmp circles cfg file.");
        error = 1;
    }

    if (remove(CIRCLE_FILE_NAME) == -1)
    {
        strcpy_s(error_desc, 256, "\nCould't delete cfg file. Updated file saved as tmp_circles.txt.\n");
        error = 1;
    }

    int result = rename(CIRCLE_TMP_FILE_NAME, CIRCLE_FILE_NAME);
    if (result != 0)
    {
        strcpy_s(error_desc, 256, "\nCould't rename tmp file. You can manualy rename it to circles.txt\n");
        error = 1;
    }
    // YES! We should delete config file too BUT now we do this in C# using Gutmann
    /*else
    {
        // Besides all we must delete Circle's config file too!!!
        if (remove(buffer.config_path) == -1)
        {
            strcpy_s(error_desc, 256, "\nCould't delete cfg file.\n");
            error = 1;
        }
    }*/
    if (fflush(fp1) != 0)
    {
        strcpy_s(error_desc, 256, "Error flushing circles cfg file.");
        error = 1;
    }

    //if (fclose(fp1) != 0)
    //{
    //    strcpy_s(error_desc, 256, "Error closing file circles cfg file.");
    //    error = 1;
    //}

    return error;
}

SPAE_DLL_EXPIMP int SPAE_CALL check_if_circle_locked(const char* c_name, char* error_desc)
{
    int is_locked = 0; //not locked

    // Check if Circle locked
    is_locked = is_circle_locked(c_name, error_desc);

    return is_locked;
}

SPAE_DLL_EXPIMP circle_error_t SPAE_CALL get_circle_data_by_name(struct circle* data, const char* c_name, char* error_desc)
{
    int open_status;

    // Accept the file and try to open it
    FILE* fp1 = NULL;
    // Trying to open the file
    fp1 = open_file(CIRCLE_FILE_NAME, FILE_MODE_READ, &open_status);
    // Chek open file status
    if (open_status != 0)
    {
        strcpy_s(error_desc, 256, "\nError: When trying to open a Circle cfg file.\n");
        return CIRCLE_ERROR_OPENF;
    }

    if (data != NULL)
    {
        struct circle buffer;

        fseek(fp1, 0, SEEK_SET);   // move file position indicator to beginning of file

        while (fread(&buffer, CIRCLE_SIZE, 1, fp1) == 1)
        {
            if (strcmp(c_name, buffer.circle_name) == 0 && buffer.master == 1)
            {
                memcpy(data, &buffer, CIRCLE_SIZE * 1);

                fclose(fp1);
                return CIRCLE_ERROR_OK;
            }
        }
    }
    else
    {
        fclose(fp1);
        return CIRCLE_ERROR_NOMEM;
    }

    fclose(fp1);
    return CIRCLE_ERROR_OK;
}


SPAE_DLL_EXPIMP pads_error_t SPAE_CALL get_pad_cfg_head(struct pads* data, const char* cfg_path, char* error_desc)
{
    int open_status;

    /*Accept the file and try to open it*/
    FILE* fp1 = NULL;
    /*Trying to open the file*/
    fp1 = open_file(cfg_path, FILE_MODE_READ, &open_status);

    if (open_status != 0)
    {
        strcpy_s(error_desc, 256, "\nError: When trying to open a file Circle's pad cfg.\n");
        return PADS_ERROR_OPENFILE;
    }
    size_t ret_code = fread(data, PADS_STRUCT_SIZE, 1, fp1);

    /*If error*/
    if (ret_code != PADS_STRUCT_SIZE) {
        if (feof(fp1))
        {
            fclose(fp1);
            strcpy_s(error_desc, 256, "\nError reading pad config file: unexpected end of file.\n");
            exit(EXIT_FAILURE);
        }
        else if (ferror(fp1))
        {
            fclose(fp1);
            strcpy_s(error_desc, 256, "\nError reading pad config\n");
            exit(EXIT_FAILURE);
        }
    }

    fclose(fp1);
    return PADS_ERROR_OK;
}

// We are not using this func yet
SPAE_DLL_EXPIMP pads_error_t SPAE_CALL set_pads_total_count_into_cfg_head(const char* cfg_path, int tc, char* error_desc)
{
    int open_status;

    // Accept the file and try to open it
    FILE* f = NULL;
    // Trying to open the file
    f = open_file(cfg_path, FILE_MODE_READ, &open_status);

    if (open_status != 0)
    {
        strcpy_s(error_desc, 256, "\nError: When trying to open a file Circle's pad cfg.\n");
        return PADS_ERROR_OPENFILE;
    }

    // Read and set total count
    struct pads pads_head_data;
    get_pad_cfg_head(&pads_head_data, cfg_path, error_desc);
    pads_head_data.total_count = tc;

    /*Accept the file and try to open it*/
    FILE* ftmp = NULL;
    /*Trying to open the temp file*/
    ftmp = open_file(USER_PADS_CFG_TMP_FILE_NAME, FILE_MODE_WRITE, &open_status);

    if (open_status != 0)
    {
        strcpy_s(error_desc, 256, "\nError: When trying to open a tmp file Circle's pad cfg.\n");
        return PADS_ERROR_OPENFILE;
    }

    // Write head part
    fwrite(&pads_head_data, sizeof(struct pads), 1, ftmp);
    // Close the config file
    fclose(f);

    /*Accept the file and try to open it*/
    FILE* nf = NULL;
    /*Trying to open the file*/
    nf = open_file(cfg_path, FILE_MODE_READ, &open_status);

    if (open_status != 0)
    {
        strcpy_s(error_desc, 256, "\nError: When trying to open a file Circle's pad cfg.\n");
        return PADS_ERROR_OPENFILE;
    }

    // move file position indicator to forward equals pads size
    fseek(nf, PADS_STRUCT_SIZE, SEEK_SET);

    struct pad pad_data;
    // Read from cfg and then write into tmp
    while (fread(&pad_data, PAD_STRUCT_SIZE, 1, nf) == 1)
    {
        fwrite(&pad_data, PAD_STRUCT_SIZE, 1, ftmp);
    }

    fclose(nf);
    fclose(ftmp);

    // Trying to remove cfg file
    if (remove(cfg_path) == -1)
    {
        return CIRCLE_ERROR_DELETEF;
    }

    // Rename tmp to cfg
    int result = rename(USER_PADS_CFG_TMP_FILE_NAME, cfg_path);
    if (result != 0)
    {
        strcpy_s(error_desc, 256, "\nCould't rename tmp file. You can manualy rename it to [circlename.txt]\n");
        return CIRCLE_ERROR_RENAMEF;
    }

    fflush(nf);
    return PADS_ERROR_OK;
}

SPAE_DLL_EXPIMP pads_error_t SPAE_CALL set_valid_pads_count(const char* cfg_path, int vpc, char* error_desc)
{
    int open_status;

    /*Accept the file and try to open it*/
    FILE* f = NULL;
    /*Trying to open the file*/
    f = open_file(cfg_path, FILE_MODE_READ, &open_status);

    if (open_status != 0)
    {
        strcpy_s(error_desc, 256, "\nError: When trying to open a file Circle's pad cfg.\n");
        return PADS_ERROR_OPENFILE;
    }

    // Read and set total count
    struct pads pads_head_data;
    get_pad_cfg_head(&pads_head_data, cfg_path, error_desc);
    pads_head_data.valid_pads = vpc;

    /*Accept the file and try to open it*/
    FILE* ftmp = NULL;
    /*Trying to open the temp file*/
    ftmp = open_file(USER_PADS_CFG_TMP_FILE_NAME, FILE_MODE_WRITE, &open_status);

    if (open_status != 0)
    {
        strcpy_s(error_desc, 256, "\nError: When trying to open a tmp file Circle's pad cfg.\n");
        return PADS_ERROR_OPENFILE;
    }

    // Write head part
    fwrite(&pads_head_data, sizeof(struct pads), 1, ftmp);
    // Close the config file
    fclose(f);

    /*Accept the file and try to open it*/
    FILE* nf = NULL;
    /*Trying to open the file*/
    nf = open_file(cfg_path, FILE_MODE_READ, &open_status);

    if (open_status != 0)
    {
        strcpy_s(error_desc, 256, "\nError: When trying to open a file Circle's pad cfg.\n");
        return PADS_ERROR_OPENFILE;
    }

    // move file position indicator to forward equals pads size
    fseek(nf, PADS_STRUCT_SIZE, SEEK_SET);

    struct pad pad_data;
    // Read from cfg and then write into tmp
    while (fread(&pad_data, PAD_STRUCT_SIZE, 1, nf) == 1)
    {
        fwrite(&pad_data, PAD_STRUCT_SIZE, 1, ftmp);
    }

    fflush(nf);
    fclose(nf);
    fclose(ftmp);

    // Trying to remove cfg file
    if (remove(cfg_path) == -1)
    {
        return CIRCLE_ERROR_DELETEF;
    }

    // Rename tmp to cfg
    int result = rename(USER_PADS_CFG_TMP_FILE_NAME, cfg_path);
    if (result != 0)
    {
        strcpy_s(error_desc, 256, "\nCould't rename tmp file. You can manualy rename it to [circlename.txt]\n");
        return CIRCLE_ERROR_RENAMEF;
    }

    return PADS_ERROR_OK;
}

SPAE_DLL_EXPIMP pads_error_t SPAE_CALL set_invalid_pads_count(const char* cfg_path, int ipc, char* error_desc)
{
    int open_status;

    /*Accept the file and try to open it*/
    FILE* f = NULL;
    /*Trying to open the file*/
    f = open_file(cfg_path, FILE_MODE_READ, &open_status);

    if (open_status != 0)
    {
        strcpy_s(error_desc, 256, "\nError: When trying to open a file Circle's pad cfg.\n");
        return PADS_ERROR_OPENFILE;
    }

    // Read and set total count
    struct pads pads_head_data;
    get_pad_cfg_head(&pads_head_data, cfg_path, error_desc);
    pads_head_data.invalid_pads = ipc;

    /*Accept the file and try to open it*/
    FILE* ftmp = NULL;
    /*Trying to open the temp file*/
    ftmp = open_file(USER_PADS_CFG_TMP_FILE_NAME, FILE_MODE_WRITE, &open_status);

    if (open_status != 0)
    {
        strcpy_s(error_desc, 256, "\nError: When trying to open a tmp file Circle's pad cfg.\n");
        return PADS_ERROR_OPENFILE;
    }

    // Write head part
    fwrite(&pads_head_data, sizeof(struct pads), 1, ftmp);
    // Close the config file
    fclose(f);

    /*Accept the file and try to open it*/
    FILE* nf = NULL;
    /*Trying to open the file*/
    nf = open_file(cfg_path, FILE_MODE_READ, &open_status);

    if (open_status != 0)
    {
        strcpy_s(error_desc, 256, "\nError: When trying to open a file Circle's pad cfg.\n");
        return PADS_ERROR_OPENFILE;
    }

    // move file position indicator to forward equals pads size
    fseek(nf, PADS_STRUCT_SIZE, SEEK_SET);

    struct pad pad_data;
    // Read from cfg and then write into tmp
    while (fread(&pad_data, PAD_STRUCT_SIZE, 1, nf) == 1)
    {
        fwrite(&pad_data, PAD_STRUCT_SIZE, 1, ftmp);
    }

    fclose(nf);
    fclose(ftmp);

    // Trying to remove cfg file
    if (remove(cfg_path) == -1)
    {
        return CIRCLE_ERROR_DELETEF;
    }

    // Rename tmp to cfg
    int result = rename(USER_PADS_CFG_TMP_FILE_NAME, cfg_path);
    if (result != 0)
    {
        strcpy_s(error_desc, 256, "\nCould't rename tmp file. You can manualy rename it to [circlename.txt]\n");
        return CIRCLE_ERROR_RENAMEF;
    }

    fflush(nf);
    return PADS_ERROR_OK;
}

SPAE_DLL_EXPIMP pads_error_t SPAE_CALL set_generated_pads_count_into_cfg_head(const char* cfg_path, int gc, char* error_desc)
{
    int open_status;

    /*Accept the file and try to open it*/
    FILE* f = NULL;
    /*Trying to open the file*/
    f = open_file(cfg_path, FILE_MODE_READ, &open_status);

    if (open_status != 0)
    {
        strcpy_s(error_desc, 256, "\nError: When trying to open a file Circle's pad cfg.\n");
        return PADS_ERROR_OPENFILE;
    }

    // Read and set total count
    struct pads pads_head_data;
    get_pad_cfg_head(&pads_head_data, cfg_path, error_desc);
    pads_head_data.generated_pads = gc;

    /*Accept the file and try to open it*/
    FILE* ftmp = NULL;
    /*Trying to open the temp file*/
    ftmp = open_file(USER_PADS_CFG_TMP_FILE_NAME, FILE_MODE_WRITE, &open_status);

    if (open_status != 0)
    {
        strcpy_s(error_desc, 256, "\nError: When trying to open a tmp file Circle's pad cfg.\n");
        return PADS_ERROR_OPENFILE;
    }

    // Write head part
    fwrite(&pads_head_data, sizeof(struct pads), 1, ftmp);
    // Close the config file
    fclose(f);

    /*Accept the file and try to open it*/
    FILE* nf = NULL;
    /*Trying to open the file*/
    nf = open_file(cfg_path, FILE_MODE_READ, &open_status);

    if (open_status != 0)
    {
        strcpy_s(error_desc, 256, "\nError: When trying to open a file Circle's pad cfg.\n");
        return PADS_ERROR_OPENFILE;
    }

    // move file position indicator to forward equals pads size
    fseek(nf, PADS_STRUCT_SIZE, SEEK_SET);

    struct pad pad_data;
    // Read from cfg and then write into tmp
    while (fread(&pad_data, PAD_STRUCT_SIZE, 1, nf) == 1)
    {
        fwrite(&pad_data, PAD_STRUCT_SIZE, 1, ftmp);
    }

    fflush(nf);
    fclose(nf);
    fclose(ftmp);

    // Trying to remove cfg file
    if (remove(cfg_path) == -1)
    {
        return CIRCLE_ERROR_DELETEF;
    }

    // Rename tmp to cfg
    int result = rename(USER_PADS_CFG_TMP_FILE_NAME, cfg_path);
    if (result != 0)
    {
        strcpy_s(error_desc, 256, "\nCould't rename tmp file. You can manualy rename it to [circlename.txt]\n");
        return CIRCLE_ERROR_RENAMEF;
    }

    return PADS_ERROR_OK;
}

SPAE_DLL_EXPIMP pads_error_t SPAE_CALL set_new_request_data_into_cfg_head(const char* cfg_path, int total, int generated, char* error_desc)
{
    int open_status;

    /*Accept the file and try to open it*/
    FILE* f = NULL;
    /*Trying to open the file*/
    f = open_file(cfg_path, FILE_MODE_READ, &open_status);

    if (open_status != 0)
    {
        strcpy_s(error_desc, 256, "\nError: When trying to open a file Circle's pad cfg.\n");
        return PADS_ERROR_OPENFILE;
    }

    // Read and set total count
    struct pads pads_head_data;
    get_pad_cfg_head(&pads_head_data, cfg_path, error_desc);
    pads_head_data.total_count = total;
    pads_head_data.generated_pads = generated;

    /*Accept the file and try to open it*/
    FILE* ftmp = NULL;
    /*Trying to open the temp file*/
    ftmp = open_file(USER_PADS_CFG_TMP_FILE_NAME, FILE_MODE_WRITE, &open_status);

    if (open_status != 0)
    {
        strcpy_s(error_desc, 256, "\nError: When trying to open a tmp file Circle's pad cfg.\n");
        return PADS_ERROR_OPENFILE;
    }

    // Write head part
    fwrite(&pads_head_data, sizeof(struct pads), 1, ftmp);
    // Close the config file
    fclose(f);

    /*Accept the file and try to open it*/
    FILE* nf = NULL;
    /*Trying to open the file*/
    nf = open_file(cfg_path, FILE_MODE_READ, &open_status);

    if (open_status != 0)
    {
        strcpy_s(error_desc, 256, "\nError: When trying to open a file Circle's pad cfg.\n");
        return PADS_ERROR_OPENFILE;
    }

    // move file position indicator to forward equals pads size
    fseek(nf, PADS_STRUCT_SIZE, SEEK_SET);

    struct pad pad_data;
    // Read from cfg and then write into tmp
    while (fread(&pad_data, PAD_STRUCT_SIZE, 1, nf) == 1)
    {
        fwrite(&pad_data, PAD_STRUCT_SIZE, 1, ftmp);
    }

    fflush(nf);
    fclose(nf);
    fclose(ftmp);

    // Trying to remove cfg file
    if (remove(cfg_path) == -1)
    {
        return CIRCLE_ERROR_DELETEF;
    }

    // Rename tmp to cfg
    int result = rename(USER_PADS_CFG_TMP_FILE_NAME, cfg_path);
    if (result != 0)
    {
        strcpy_s(error_desc, 256, "\nCould't rename tmp file. You can manualy rename it to [circlename.txt]\n");
        return CIRCLE_ERROR_RENAMEF;
    }

    return PADS_ERROR_OK;
}


SPAE_DLL_EXPIMP pads_error_t SPAE_CALL create_single_pad(char* pad, char* mrs, char* buk, char* prog_dir, char* error_desc)
{
#if _DEBUG
    FILE* log_file = NULL;
    int log_open_status;
    log_file = open_file("log_pads.txt", FILE_MODE_APLUS, &log_open_status);

    if (log_open_status != 0)
    {
        strcpy_s(error_desc, 256, "\nError: When trying to open a Log file.\n");
        return CIRCLE_ERROR_OPENF;
    }

    // Start log file
    write_log(log_file, "------Action: Create single (mostly the first) pad------ Time: ");
    write_log(log_file, get_current_time());
    write_log(log_file, "\n");

    write_log(log_file, "First 64 bits of BUK: ");
    write_log(log_file, substr(buk, 0, 64));
    write_log(log_file, "\n");
    write_log(log_file, "First 64 bits of MRS: ");
    write_log(log_file, substr(mrs, 0, 64));
    write_log(log_file, "\n");

#endif

    /*                                                                   */
    /*    Generate Spec Chars Lookup tbl                                 */
    /*                                                                   */
    size_t seeker = 0;
    size_t offset = 0;
    size_t shift = 368;
    size_t s     = 0;

#if _DEBUG
    write_log(log_file, "Collecting a 9-bits for 512 preposition values!\n");
#endif

    size_t* first_pads_disgussing_bits = ALLOC(_512_BUFFER * sizeof(size_t));
    int ret = collect_unique_bits_for_pads_permutation(first_pads_disgussing_bits, buk, mrs, &seeker, offset + shift, error_desc);
    if (ret != 0)
    {
        return PADS_ERROR_STRANDS;
    }

#if _DEBUG
    write_log(log_file, "Nine bits tuples (NEEDED TO BE XORed WITH PAD NUM!!!!!!!!!!!!) :\n");
    for (size_t i = 0; i < _512_BUFFER; i++)
    {
        int_write_log(log_file, "Element decimal value is: ", first_pads_disgussing_bits[i]);
    }
    int_write_log(log_file, "Seeker value (after): ", seeker);
#endif

    offset = seeker;
    seeker = 0;

#if _DEBUG
    write_log(log_file, "Generating lookup table for special chars\n");
#endif

    char*** lookupTbl = ALLOC(SPEC_CHARS_LOOKUP_TBL_CNT * sizeof(char**)); //was 64(must be 65 at least)
    if (generate_specialchars_lookup_table(lookupTbl, buk, mrs, &seeker, offset, &s) != 0)
    {
        strcpy_s(error_desc, 256, "\nError: Poor key.\n");
        return UK_ERROR_POOR_KEY;
    }

#if _DEBUG
    int_write_log(log_file, "Seeker value (after): ", seeker);
#endif

#if _DEBUG
    write_log(log_file, "Lookup table data:\n");
    for (size_t i = 0; i < 72; i++)
    {
        for (size_t j = 0; j < 64; j++)
        {
            write_log(log_file, lookupTbl[i][j]);
            write_log(log_file, "\t");
        }
    }
#endif

    //multiply by 6 since for chars we were used six bits
    //offset += seeker * 6;
    offset = seeker;
    seeker = 0;

#if _DEBUG
    int_write_log(log_file, "Offset value after lookup table: ", offset);
#endif

    /*                                                                   */
    /*    Collect logical operation methods for 64 prog files            */
    /*                                                                   */
    char* logicalMethodsForProgFiles = ALLOC(64 * sizeof(char));
    for (size_t i = 0; i < 64; i++)
    {
        logicalMethodsForProgFiles[i] = (char)(1 + '0');
    }
    logicalMethodsForProgFiles[64] = '\0';
    //generate_logical_op_data_for_program_files(logicalMethodsForProgFiles, buk, mrs, &seeker, offset);
#if _DEBUG
    write_log(log_file, "\nLogical op methods for program files: ");
    write_log(log_file, logicalMethodsForProgFiles);
#endif
    /*                                                                   */
    /*    REARRANGEMENT POINTS FOR BASE USER KEY SEQ's                   */
    /*    Since during above step we used $seeker * 6 bits from every seq*/
    /*    getting new offset so, the next offset point will be           */
    /*                                                                   */
    //offset = seeker;
    //seeker = 0;

#if _DEBUG
    int_write_log(log_file, "Offset value after getting logical bits: ", offset);
#endif

    char** rearrangementPointsArray = ALLOC(16 * sizeof(char*));
    generate_rearrangement_points_for_program_files(rearrangementPointsArray, buk, mrs, &seeker, offset);

#if _DEBUG
    write_log(log_file, "Rearragement points :\n");
    for (size_t i = 0; i < 16; i++)
    {
        write_log(log_file, rearrangementPointsArray[i]);
        write_log(log_file, "\n");
    }
#endif

    /*                                                                   */
    /*    PSP START/JUMP POINTS FOR MRS SEQ's                            */
    /*                                                                   */
    //offset += seeker * 23;
    offset = seeker;
    seeker = 0;

#if _DEBUG
    write_log(log_file, "\n");
    int_write_log(log_file, "Offset value after getting rearragements points: ", offset);
#endif

    char** pointPPS = ALLOC(7 * sizeof(char*));
    get_PPS_insertion_point(pointPPS, buk, mrs, &seeker, offset);

#if _DEBUG
    for (size_t i = 0; i < 7; i++)
    {
        write_log(log_file, "PPS insertion points for 64 program files: ");
        write_log(log_file, pointPPS[i]);
        write_log(log_file, "\n");
    }
#endif

    offset = seeker;
    seeker = 0;
#if _DEBUG
    write_log(log_file, "\n");
    int_write_log(log_file, "Offset value after getting PPS insertion points for 64 program files: ", offset);
#endif

    /* Getting fliud positions for PPS */

    char* PPS_insert_pos = ALLOC(64 * 7 * 26 * sizeof(char) + 1);
    get_PPS_positions_dynamic(PPS_insert_pos, buk, mrs, &seeker, offset);

    offset = seeker;
    seeker = 0;
    /* Getting C9 position. 26 bits */
    char* c9_position_26_bits = ALLOC(sizeof(char) * 26 + 1);
    get_C9_insertion_position(c9_position_26_bits, buk, mrs, &seeker, offset);

    /*                                                                   */
    /*    Rearrange BUK files                                            */
    /*                                                                   */
#if _DEBUG
    write_log(log_file, "Rearranging a BUK file: \n");
#endif

    char* bukr = ALLOC(UK_LENGHT + 1);
    rearrange_files(bukr, buk, rearrangementPointsArray);

#if _DEBUG
    write_log(log_file, "First 64 bits of BUKR: ");
    write_log(log_file, substr(bukr, 0, 64));
    write_log(log_file, "\n");
#endif

    /*-------------------------------------------FIRST PAD--------------------------------------------------------*/
                /*                                                                   */
                /*    Collect Start&Jump points for the next pad                     */
                /*                                                                   */
#if _DEBUG
    write_log(log_file, "Creating FIRST pad!\n");
#endif

    /*                                                                   */
    /*    XOR/XNOR -ing base MRS files with base User Key files and      */
    /*    make ROW files.                                                */
    /*    Collect Logicical Op Methods for BUK generating                */
    /*                                                                   */
    
    char* rowLogicMethods = ALLOC(8 * sizeof(char));
    for (size_t i = 0; i < 8; i++)
    {
        rowLogicMethods[i] = (char)(1 + '0');
    }
    rowLogicMethods[8] = '\0';
    //collect_logic_op_methods(rowLogicMethods, mrs);

#if _DEBUG
    write_log(log_file, "Creating ROW doing a XOR/XNOR!\n");
#endif
    char* row = CALLOC(UK_LENGHT + 1, 1);
    do_logical_operation(row, mrs, bukr, rowLogicMethods);

#if _DEBUG
    write_log(log_file, "Making a single pad!\n");
#endif
    char* tmp_pad = ALLOC(_2_POW_23 + 1);
    make_single_pad(tmp_pad, row);

#if _DEBUG
    write_log(log_file, "Permutating a pad.\n");
    //permutate_pad_log(pad, tmp_pad, 1, first_pads_disgussing_bits, &log_file);
#endif

    permutate_pad(pad, tmp_pad, 1, first_pads_disgussing_bits);

    /* Reset transposition array */
    ZERO_ANY(size_t, pads_disgussing_bits, _512_BUFFER);

    FREE(tmp_pad);

#if _DEBUG
    write_log(log_file, "\nGenerating PPS structs and converting them into a raw array of chars...\n");
#endif

    /*---------NEW WAY-----DYNAMIC POSITIONS-------------*/
    pps_dynamic_t* _dynamic_pps_ptr = dynamic_pps_new();

    // allocating memory for n numbers of struct person
    _dynamic_pps_ptr = (pps_dynamic_t*)ALLOC(64 * sizeof(pps_dynamic_t));
    
    assign_values_to_dynamic_pps_struct(_dynamic_pps_ptr, PPS_insert_pos);

    /* Marshaling struct into array */
    char* dynamicPPSdata = (char*)ALLOC(sizeof(char) * (64 * (6 + PPS_CHARS_COUNT * 26)) + 1);
    dynamic_pps_struct_into_array(dynamicPPSdata, _dynamic_pps_ptr);
    /*---------END OF NEW WAY----------------------------*/

    pps_t* _pps_ptr;

    // allocating memory for n numbers of struct person
    _pps_ptr = (pps_t*)ALLOC(7 * sizeof(pps_t));
    for (size_t i = 0; i < 7; i++)
    {
        pps_set(_pps_ptr + i, pointPPS[i], lookupTbl[PROG_FILES_COUNT + i]);
    }
    
    /* Marshaling struct into array */
    /* Allocated memory size is: ppp_ch_count x pps_insetion_pos_len + full lookup table for each char */
    char* ppsData = (char*)ALLOC(sizeof(char)*(PPS_CHARS_COUNT * 26 + PPS_CHARS_COUNT * 64 * 6) + 1);
    pps_struct_into_array(ppsData, _pps_ptr);

#if _DEBUG
    write_log(log_file, ppsData);
#endif

    pps_free(_pps_ptr); //Be careful here!!!

#if _DEBUG
    write_log(log_file, "\nCreating 64 program files!\n");
#endif
    create_64_prog_files(pad, 
                         lookupTbl, 
                         ppsData, 
                         c9_position_26_bits, 
                         dynamicPPSdata, 
                         logicalMethodsForProgFiles, 
                         prog_dir, 
                         error_desc);

#if _DEBUG
    fflush(log_file);
    fclose(log_file);
#endif

    return PADS_ERROR_OK;
}

SPAE_DLL_EXPIMP pads_error_t SPAE_CALL reset_pad_cfg_file(char* path)
{
    FILE* f;

    fopen_s(&f, path, "wb");
    if (f == NULL) {
        printf("error in opening file : \n");
        exit(EXIT_FAILURE);
    }

    struct pads p = { 0 };
    fwrite(&p, sizeof(struct pads), 1, f);

    struct pad pd;
    memset(&pd, 0, sizeof(struct pad));

    fflush(f);
    fclose(f);

    return PADS_ERROR_OK;
}


SPAE_DLL_EXPIMP char*** SPAE_CALL generate_special_chars_lookup_table(char* buk, char* mrs, size_t* seeker, char* error_desc)
{
    char*** tbl = ALLOC(64 * sizeof(char**));
    char** uniqueTuple = ALLOC(128 * sizeof(char*));
    char tmpUniqueTuple[16][7] = { 0 };

    size_t offset = 0;
    size_t count = 0;
    size_t size = 0;

    while (size < 65)
    {
        size_t pointerPosition = 0;

        for (size_t i = 0; i < 8; i++)
        {
            memcpy(tmpUniqueTuple[i * 2], buk + pointerPosition + *seeker * 6, 6);
            tmpUniqueTuple[i * 2][6] = '\0';

            memcpy(tmpUniqueTuple[i * 2 + 1], mrs + pointerPosition + *seeker * 6, 6);
            tmpUniqueTuple[i * 2 + 1][6] = '\0';


            pointerPosition += _2_POW_23;
        }
        offset += 6;
        for (size_t i = 0; i < 16; i++)
        {
            uniqueTuple[count + i] = ALLOC(8 * sizeof(char));
            memcpy(uniqueTuple[count + i], tmpUniqueTuple[i], sizeof(*tmpUniqueTuple));
            uniqueTuple[count + i][6] = '\0';
        }

        count = arrayUniqueWithoutSorting(uniqueTuple, count + 16);

        if (count >= 64)
        {
            tbl[size] = ALLOC(64 * sizeof(char*));

            for (size_t i = 0; i < 64; i++)
            {

                tbl[size][i] = ALLOC(6 * sizeof(char));

                memcpy(tbl[size][i], uniqueTuple[i], 6);
                tbl[size][i][6] = '\0';
                uniqueTuple[i] = NULL;
            }
            size++;
            count = 0;
        }

        (*seeker)++;
    }
    return tbl;
}


SPAE_DLL_EXPIMP pads_error_t SPAE_CALL rearrange_buk_file(char* bukr, char* buk, char* mrs, size_t* s, size_t o, char* error_desc)
{
    char** rearrangementPointsArray = ALLOC(16 * sizeof(char*));
    generate_rearrangement_points_for_program_files(rearrangementPointsArray, buk, mrs, s, o);

    /*                                                                   */
    /*    Rearrange BUK files                                            */
    /*                                                                   */
    //char* bukr = ALLOC(UK_LENGHT + 1);
    rearrange_files(bukr, buk, rearrangementPointsArray);

    return PADS_ERROR_OK;
}


SPAE_DLL_EXPIMP pads_error_t SPAE_CALL generate_data_for_the_next_pad(char* buk, char* mrs, char* bukr, char* pmrs, size_t* sp, size_t* jp, size_t* rp, char* error_desc)
{
    size_t size = 0, pspStartPoint = 0, pspJumpPoint = 0, rP = 0, offset = 0;

    char* singlePSPdata = ALLOC(sizeof(char) * 46 + 1);
    char* singleReStr = ALLOC(sizeof(char) * 23 + 1);

    for (size_t i = 0; i < 8; i++)
    {
        /* Collect PSP points */
        memcpy(singlePSPdata, pmrs + offset, 46);
        singlePSPdata[46] = '\0';

        pspStartPoint = bindec(spae_substr(singlePSPdata, 0, 23));
        pspJumpPoint = bindec(spae_substr(singlePSPdata, 23, 23));
        sp[size] = pspStartPoint;
        jp[size] = pspJumpPoint;

        /* Collect rearranging points */
        
        memcpy(singleReStr, bukr + offset, 23);
        singleReStr[23] = '\0';

        rP = bindec(spae_substr(singleReStr, 0, 23));
        rp[size] = rP;

        size++;
        offset += _2_POW_23;
    }

    int is_empty_array = is_array_set_to_zero(pads_disgussing_bits, _512_BUFFER);

    if (is_empty_array == 0)
    {
        size_t shift = 368;
        size_t seeker = 0;

        collect_unique_bits_for_pads_permutation(pads_disgussing_bits, buk, mrs, &seeker, shift, error_desc);
    }

    FREE(singlePSPdata);
    FREE(singleReStr);

    return PADS_ERROR_OK;
}

SPAE_DLL_EXPIMP pads_error_t SPAE_CALL validate_pad(char* pad, char* error_desc)
{
    if (strlen(pad) != _2_POW_23)
    {
        strcpy_s(error_desc, 256, "\nError: Pad len is not equal to 8388608.\n");
        return 0;
    }
    else
    {
        const size_t ones_count = get_ones_count_in_file(pad);
        if (is_number_in_1SD_range(ones_count))
        {
            return 1;
        }
        else
        {
            return 0;
        }
    }
}

SPAE_DLL_EXPIMP int SPAE_CALL validate_pad_by_first_42bits(char* pad, char* cfg_path, char* error_desc)
{
    struct pad p;

    char* pps = ALLOC(sizeof(char) * 43);

    /*Accept the file and try to open it*/
    FILE* nf = NULL;
    int open_status;
    /*Trying to open the file*/
    nf = open_file(cfg_path, FILE_MODE_READ, &open_status);

    if (open_status != 0)
    {
        strcpy_s(error_desc, 256, "\nError: When trying to open a file Circle's pad cfg.\n");
        return PADS_ERROR_OPENFILE;
    }

    memcpy_s(pps, 43, pad, 42);
    pps[42] = '\0';

    fseek(nf, sizeof(struct pads), SEEK_SET);   // move file position indicator to beginning of file
    while (fread(&p, sizeof(struct pad), 1, nf) == 1)
    {
        if (strcmp(pps, p.pps) == 0)
        {
            fflush(nf);
            fclose(nf);

            return 1; // Pad is invalid - there is an PPS in prev Pads with the same bits
        }
    }

    fflush(nf);
    fclose(nf);

    FREE(pps);
    return 0;
}


int validate_large_sequences_by_first_42bits(char* sequence, char* error_desc)
{
    size_t offset = 0;
    const size_t count = 8;
    char** start_42_bits = ALLOC(sizeof(char*) * 8);
    char* pps = ALLOC(sizeof(char) * 42 + 1);

    for (size_t i = 0; i < 8; i++)
    {
        start_42_bits[i] = ALLOC(sizeof(char) * 42 + 1);
        memcpy_s(start_42_bits[i], 43, sequence + offset, 42);
        start_42_bits[i][42] = '\0';

        offset += _2_POW_23;
    }

    for (int i = 0; i < count - 1; i++) { 
        for (int j = i + 1; j < count; j++) {
            if (strcmp(start_42_bits[i], start_42_bits[j]) == 0) {
                // duplicate
                return -1;
            }
        }
    }

    return 1;
}


SPAE_DLL_EXPIMP pads_error_t SPAE_CALL write_pad_into_file(char* pad, char* path, int id, char* error_desc)
{
    char* padFullPath = CALLOC(sizeof(char) * _MAX_PATH, 1);
    char* padName = ALLOC(sizeof(char) * 7);

    // Building the pad path
    _ui64toa_s(id, padName, 7, 10);                // converting pad's # from inti to char
    strcat_s(padFullPath, _MAX_PATH + 1, path);    // Pads dir
    strcat_s(padFullPath, _MAX_PATH + 1, "/");     // Add backslash
    strcat_s(padFullPath, _MAX_PATH + 1, padName); // Concatenate pad # num
    strcat_s(padFullPath, _MAX_PATH + 1, ".txt");  // Add extenssion

    int open_status;

    /*Accept the file and try to open it*/
    FILE* f_pad = NULL;
    /*Trying to open the file*/
    f_pad = open_file(padFullPath, FILE_MODE_WRITE, &open_status);

    if (open_status != 0)
    {
        strcpy_s(error_desc, 256, "\nError: When trying to open a Pad file for writing.\n");
        return PADS_ERROR_OPENFILE;
    }
    else
    {
        fwrite(pad, sizeof(char), _2_POW_23, f_pad);

        fflush(f_pad);
        fclose(f_pad);

        return PADS_ERROR_OK;
    }
}

SPAE_DLL_EXPIMP pads_error_t SPAE_CALL write_anysize_data_into_file(char* pad, char* path, char* name, size_t size, char* error_desc)
{
    char* padFullPath = CALLOC(sizeof(char) * _MAX_PATH, 1);
    char* padName = ALLOC(sizeof(char) * 7);

    // Building the pad path
    strcat_s(padFullPath, _MAX_PATH + 1, path);    // Pads dir
    strcat_s(padFullPath, _MAX_PATH + 1, "/");     // Add backslash
    strcat_s(padFullPath, _MAX_PATH + 1, name); // Concatenate pad # num
    strcat_s(padFullPath, _MAX_PATH + 1, ".txt");  // Add extenssion

    int open_status;

    /*Accept the file and try to open it*/
    FILE* f_pad = NULL;
    /*Trying to open the file*/
    f_pad = open_file(padFullPath, FILE_MODE_WRITE, &open_status);

    if (open_status != 0)
    {
        strcpy_s(error_desc, 256, "\nError: When trying to open a Pad file for writing.\n");
        return PADS_ERROR_OPENFILE;
    }
    else
    {
        fwrite(pad, sizeof(char), size, f_pad);

        fflush(f_pad);
        fclose(f_pad);

        return PADS_ERROR_OK;
    }
}

SPAE_DLL_EXPIMP pads_error_t SPAE_CALL add_new_pad_block(char* pad, char* buk, char* mrs, char* cfg_path, int current_pad_id, int prev_pad_id, char* error_desc)
{
#if _DEBUG
    FILE* log_file = NULL;
    int open_status;
    log_file = open_file("log_pads.txt", FILE_MODE_APLUS, &open_status);

    if (open_status != 0)
    {
        strcpy_s(error_desc, 256, "\nError: When trying to open a Log file.\n");
        return CIRCLE_ERROR_OPENF;
    }

    // Start log file
    write_log(log_file, "------Action: Add new pad block into config file------ Time: ");
    write_log(log_file, get_current_time());
    write_log(log_file, "\n");
    write_log(log_file, "Config file path: ");
    write_log(log_file, cfg_path);
    write_log(log_file, "\n");
    int_write_log(log_file, "Previous pad #: ", prev_pad_id);
    int_write_log(log_file, "Current pad #: ", current_pad_id);
    write_log(log_file, "\n");
    write_log(log_file, "First 64 bits of the pad: ");
    write_log(log_file, substr(pad, 0, 64));
    write_log(log_file, "\n");
    write_log(log_file, "First 64 bits of BUK/BUKR: ");
    write_log(log_file, substr(buk, 0, 64));
    write_log(log_file, "\n");
    write_log(log_file, "First 64 bits of MRS/PMRS: ");
    write_log(log_file, substr(mrs, 0, 64));
    write_log(log_file, "\n");

#endif

    struct pad n_p = { 0 };
#if _DEBUG
    write_log(log_file, "Collecting data for the next pad\n");
#endif
    n_p = collect_data_about_next_pad(pad, buk, mrs, current_pad_id, prev_pad_id, error_desc);

#if _DEBUG
    write_log(log_file, "Jump points for next pad:\n");
    for (size_t i = 0; i < 8; i++)
    {
        int_write_log(log_file, "Jump point: ", n_p.nextPSPjumpPoints[i]);
    }
#endif
#if _DEBUG
    write_log(log_file, "Start points for next pad:\n");
    for (size_t i = 0; i < 8; i++)
    {
        int_write_log(log_file, "Start point: ", n_p.nextPSPstartPoints[i]);
    }
#endif
#if _DEBUG
    write_log(log_file, "Rearrange points for next pad:\n");
    for (size_t i = 0; i < 8; i++)
    {
        int_write_log(log_file, "Rearrange point: ", n_p.nextPSPrearrnagePoints[i]);
    }
#endif
#if _DEBUG
    write_log(log_file, "Current pad PPS:");
    write_log(log_file, n_p.pps);
    write_log(log_file, "\n");
#endif


    FILE* f;

    fopen_s(&f, cfg_path, "ab+");
    if (f == NULL)
    {
        strcpy_s(error_desc, 256, "\nError: error in opening file for adding new Pad blcok!\n");
        return PADS_ERROR_OPENFILE;
    }

    /* Write/append the next generated pad block */
    fwrite(&n_p, PAD_STRUCT_SIZE, 1, f);

    fflush(f);
    fclose(f);

#if _DEBUG
    fflush(log_file);
    fclose(log_file);
#endif

    return PADS_ERROR_OK;
}

SPAE_DLL_EXPIMP pads_error_t SPAE_CALL rearrange_next_pad_BUK_file(char* bukr, const char* buk, size_t* rearrange_points, char* error_desc)
{
    size_t offset = 0;

    for (size_t i = 0; i < 8; i++)
    {
        size_t point = rearrange_points[i];
        if (_2_POW_23 < point) {
            point = point % _2_POW_23;
        }

        memcpy_s(bukr + offset, _2_POW_26, buk + offset + point, _2_POW_23 - point);
        memcpy_s(bukr + offset + _2_POW_23 - point, _2_POW_26, buk + offset, point);

        offset += _2_POW_23;
    }

    bukr[offset] = '\0';

    return PADS_ERROR_OK;
}

SPAE_DLL_EXPIMP pads_error_t SPAE_CALL permutate_next_pad_MRS_file(char* pmrs, char* mrs, size_t* start_points, size_t* jump_points, char* error_desc)
{
    size_t offset = 0;
    char* tmp = ALLOC(sizeof(char) * _2_POW_23 + 1);

    for (size_t i = 0; i < 8; i++)
    {
        memcpy(tmp, mrs + offset, _2_POW_23);
        tmp[_2_POW_23] = '\0';
        char* psp = PSP(tmp, start_points[i], jump_points[i]);
        memcpy(pmrs + offset, psp, _2_POW_23);

        offset += _2_POW_23;

        FREE(psp);
    }
    pmrs[offset] = '\0';

    FREE(tmp);

    return PADS_ERROR_OK;
}

SPAE_DLL_EXPIMP char* SPAE_CALL permutate_MRS_sequence(char* mrs, size_t* start_points, size_t* jump_points, char* error_desc)
{
    size_t offset = 0;
    char* tmp = ALLOC(sizeof(char) * _2_POW_23 + 1);
    char* pmrs = ALLOC(sizeof(char) * _2_POW_26 + 1);

    for (size_t i = 0; i < 8; i++)
    {
        memcpy(tmp, mrs + offset, _2_POW_23);
        tmp[_2_POW_23] = '\0';
        char* psp = PSP(tmp, start_points[i], jump_points[i]);
        memcpy(pmrs + offset, psp, _2_POW_23);

        offset += _2_POW_23;

        FREE(psp);
    }
    pmrs[offset] = '\0';

    FREE(tmp);

    return pmrs;
}

SPAE_DLL_EXPIMP pads_error_t SPAE_CALL create_next_row_file(char* next_row, char* bukr, char* pmrs, char* error_desc)
{
#if _DEBUG
    FILE* log_file = NULL;
    int log_open_status;
    log_file = open_file("log_pads.txt", FILE_MODE_APLUS, &log_open_status);

    if (log_open_status != 0)
    {
        strcpy_s(error_desc, 256, "\nError: When trying to open a create_next_row_file Log file.\n");
        return CIRCLE_ERROR_OPENF;
    }

    // Start log file
    write_log(log_file, "------Action: Create next ROW for the next pad------ Time: ");
    write_log(log_file, get_current_time());
    write_log(log_file, "\n");

    write_log(log_file, "First 64 bits of BUKR: ");
    write_log(log_file, substr(bukr, 0, 64));
    write_log(log_file, "\n");
    write_log(log_file, "First 64 bits of PMRS: ");
    write_log(log_file, substr(pmrs, 0, 64));
    write_log(log_file, "\n");

#endif

    /*                                                                   */
    /*    Collect Logicical Op Methods                                   */
    /*                                                                   */
    char* preROWLogicMethods = ALLOC(8 * sizeof(char) + 1);
    for (size_t i = 0; i < 8; i++)
    {
        preROWLogicMethods[i] = (char)(1 + '0');
    }
    preROWLogicMethods[8] = '\0';

    /*                                                                   */
    /*    Make XOR Logical operation with PRE_ROW files and Prev. pad    */
    /*                                                                   */
    //char* preROW = CALLOC(_2_POW_26 + 1, 1);

    //do_logical_operation(preROW, bukr, pmrs, preROWLogicMethods);
    do_logical_operation_for_the_next_pad(next_row, bukr, pmrs, preROWLogicMethods);

    //memcpy_s(next_row, _2_POW_26+1, preROW, _2_POW_26);
    //next_row[_2_POW_26] = '\0';
    // 
    // 
    //do_logical_operation_for_the_next_pad(next_row, preROW, fContent, preROWLogicMethods);

#if _DEBUG
    fflush(log_file);
    fclose(log_file);
#endif

    //FREE(preROW);

    return PADS_ERROR_OK;
}

SPAE_DLL_EXPIMP pads_error_t SPAE_CALL generate_single_pad(char* pad, size_t pad_num, char* row, char* error_desc)
{
#if _DEBUG
    FILE* log_file = NULL;
    int log_open_status;
    log_file = open_file("log_pads.txt", FILE_MODE_APLUS, &log_open_status);

    if (log_open_status != 0)
    {
        strcpy_s(error_desc, 256, "\nError: When trying to open a Pads Log file.\n");
        return CIRCLE_ERROR_OPENF;
    }
#endif

    char* temp = ALLOC(_2_POW_23 + 1);
    size_t offset = _2_POW_23, step = 1;

    char* tmp_pad = ALLOC(_2_POW_23 + 1);

    for (size_t i = 0; i < 7; i++)
    {
        if (step == 1)
        {
            memcpy(tmp_pad, row, _2_POW_23);
            tmp_pad[_2_POW_23] = '\0';
            memcpy(temp, row + offset, _2_POW_23);
            temp[_2_POW_23] = '\0';
            fmakeXOR(tmp_pad, temp);

            step++;
            offset += _2_POW_23;
        }
        else
        {
            memcpy(temp, row + offset, _2_POW_23);
            temp[_2_POW_23] = '\0';
            fmakeXOR(tmp_pad, temp);

            step++;
            offset += _2_POW_23;
        }
    }

    int is_empty_array = is_array_set_to_zero(pads_disgussing_bits, _512_BUFFER);

    if (is_empty_array == 0)
    {
        memcpy_s(pad, _2_POW_23 + 1, tmp_pad, _2_POW_23);
        pad[_2_POW_23] = '\0';
    }
    else
    {
#if _DEBUG
        write_log(log_file, "\nNine bits tuples (next pad) (NEEDED TO BE XOR!!!!) :\n");
        for (size_t i = 0; i < _512_BUFFER; i++)
        {
            int_write_log(log_file, "Element decimal value is: ", pads_disgussing_bits[i]);
        }

        permutate_pad_log(pad, tmp_pad, pad_num, pads_disgussing_bits, &log_file);
#else
        permutate_pad(pad, tmp_pad, pad_num, pads_disgussing_bits);
#endif
    }

    FREE(tmp_pad);
    FREE(temp);

#if _DEBUG
    fflush(log_file);
    fclose(log_file);
#endif

    return PADS_ERROR_OK;
}


SPAE_DLL_EXPIMP pads_error_t SPAE_CALL get_data_from_last_pad_block(const char* cfg_path, int* id, size_t* sp, size_t* jp, size_t* rp, char* error_desc)
{
    int open_status;

    /*Accept the file and try to open it*/
    FILE* cfg_f = NULL;
    /*Trying to open the file*/
    cfg_f = open_file(cfg_path, FILE_MODE_READ, &open_status);

    if (open_status != 0)
    {
        strcpy_s(error_desc, 256, "\nError: When trying to open Circle cfg file for reading last Pad block.\n");
        return PADS_ERROR_OPENFILE;
    }

    // Pass the cfg head part
    fseek(cfg_f, sizeof(struct pads), SEEK_SET);

    struct pad p;
    // May be not effective but anyway
    while (fread(&p, sizeof(struct pad), 1, cfg_f) == 1)
        ;

    /*sp = p.nextPSPstartPoints;
    jp = p.nextPSPjumpPoints;
    rp = p.nextPSPrearrnagePoints;*/

    for (size_t i = 0; i < 8; i++)
    {
        sp[i] = p.nextPSPstartPoints[i];
        jp[i] = p.nextPSPjumpPoints[i];
        rp[i] = p.nextPSPrearrnagePoints[i];
    }

    *id = p.id;

    fclose(cfg_f);

    return PADS_ERROR_OK;
}


SPAE_DLL_EXPIMP pads_error_t SPAE_CALL create_uk_from_sequences(char* uk, char* buk, char* mrs, char** list, size_t count, char* error_desc)
{
    char* tmp = ALLOC(sizeof(char) * UK_LENGHT + 1);

    /*                                                                   */
    /*    Combine sequences into one large string.						 */
    /*                                                                   */
    char* tempMergedSeqs = ALLOC(sizeof(char) * (int)count * _2_POW_23 + 1);
    merge_sequences_by_content(tempMergedSeqs, list, count);

    expand_uk_in(tmp, tempMergedSeqs, error_desc);

    // Validate to pass 1SD req
    const size_t ones_count = get_ones_count_in_file(tmp);
    if (is_number_in_1SD_range_large(ones_count) == 0)
    {
        strcpy_s(error_desc, 256, "\n1SD problem with key detected. Please submit a different key.\n");
        return UK_ERROR_NOT_ENOUGH_BITS;
    }

    /*                                                                   */
    /*    Collect Start&Jump points                                      */
    /*                                                                   */
    size_t start_point = 0;
    size_t jump_point = 0;

    get_start_jump_points_26_bits(tmp, &start_point, &jump_point);

    /*                                                                   */
    /*    Disguss collected bits                                         */
    /*                                                                   */
    char* psped_sequence = PSP(tmp, start_point % UK_LENGHT, jump_point % UK_LENGHT);

    // Validate every 2x23 sequence by the first 42  bits to be unique
    int is_seqs_unique = validate_large_sequences_by_first_42bits(psped_sequence, error_desc);
    if (is_seqs_unique != 1)
    {
        strcpy_s(error_desc, 256, "\nNot unique problem with key detected. Please submit a different key.\n");
        return UK_ERROR_NOT_ENOUGH_BITS;
    }

    /* Reverse bits for BUK */
    for (int i = 0; i < _2_POW_26; i++)
    {
        psped_sequence[i] = (char)((psped_sequence[i] - '0') ^ ('1' - '0') + '0');
    }

    // Validate to pass 1SD req
    const size_t ones_count_0 = get_ones_count_in_file(psped_sequence);
    if (is_number_in_1SD_range_large(ones_count_0) == 0)
    {
        strcpy_s(error_desc, 256, "\n1SD problem with key detected. Please submit a different key.\n");
        return UK_ERROR_NOT_ENOUGH_BITS;
    }

    // Validate every 2x23 sequence by the first 42  bits to be unique
    int is_seqs_unique_0 = validate_large_sequences_by_first_42bits(psped_sequence, error_desc);
    if (is_seqs_unique_0 != 1)
    {
        strcpy_s(error_desc, 256, "\nNot unique problem with key detected. Please submit a different key.\n");
        return UK_ERROR_NOT_ENOUGH_BITS;
    }

    memcpy(uk, psped_sequence, UK_LENGHT);

    /* Make BUK */
    memcpy(buk, uk, _2_POW_26);
    buk[_2_POW_26] = '\0';

    /* Make MRS */
    memcpy(mrs, uk + _2_POW_26, _2_POW_26);
    mrs[_2_POW_26] = '\0';

    FREE(tempMergedSeqs);
    FREE(tmp);
    FREE(psped_sequence);

    return PADS_ERROR_OK;
}


SPAE_DLL_EXPIMP char* SPAE_CALL file_to_binary_enc(char* file, size_t* req_bits_count, size_t* added_bits_count, wchar_t* error_desc)
{
    /*Crucial varibales whcih will be used when we call MPZ funictions in order to convert file to binary*/
    mpz_t c;
    mpz_init(c);

    int open_status;

    /*Accept the file and try to open it*/
    FILE* f = NULL;
    /*Trying to open the file*/
    f = open_file(file, FILE_MODE_READ, &open_status);

    if (open_status != 0)
    {
        wcscpy_s(error_desc, 256, L"\nError: When trying to open a file for encryption.\n");
        return NULL;
    }

    // Get the encrypted file size
    size_t enc_file_size = fsize(f);

    if (enc_file_size == 0)
    {
        wcscpy_s(error_desc, 256, L"\nError: File is empty.\n");

        fclose(f);
        return NULL;
    }

    // File size in bin
    size_t bin_file_size = enc_file_size * 8;

    // We are accepting files less than 500Mb currently
    if (enc_file_size > MB300)
    {
        wcscpy_s(error_desc, 256, L"\nError: We are accepting files less than 100Mb currently.\n");

        fclose(f);
        return NULL;
    }

    // Check if bin size is divisible by six and needed for additional bits
    size_t addedBitsCount = divisible_by_six(bin_file_size);

    /* Allocate enough memory */
    char* bin_content = ALLOC(sizeof(char) * (bin_file_size + 1 + addedBitsCount));

    size_t bytesRead = 0;
    size_t offset = 0;

    char* buffer = ALLOC(sizeof(char) * READ_CHUNK_SZIE + 1); // allocate memory

    char* tmp_buffer = ALLOC(sizeof(char) * READ_CHUNK_SZIE * 8 + 1); // allocate memory

    while ((bytesRead = fread(buffer, 1, READ_CHUNK_SZIE, f)) > 0)
    {

        buffer[bytesRead * 1] = '\0';
        mpz_import(c, bytesRead, 1, sizeof(buffer[0]), 0, 0, buffer);
        mpz_get_str(tmp_buffer, 2, c);

        const size_t len = strlen(tmp_buffer);

        if (len >= bytesRead * 8)
        {
            memcpy(bin_content + addedBitsCount + offset, tmp_buffer, len);
            offset = offset + len;
        }
        else
        {
            char* tmp_bin_result = ALLOC(sizeof(char) * ((bytesRead * 8) + (bytesRead * 8 - len) + 1));

            sprintf_s(tmp_bin_result, (bytesRead * 8) + (int)(bytesRead * 8 - len), "%0*d%s", (int)(bytesRead * 8 - len), 0, tmp_buffer);

            memcpy(bin_content + addedBitsCount + offset, tmp_bin_result, bytesRead * 8);
            offset = offset + bytesRead * 8;

            FREE(tmp_bin_result);
        }

        memset(buffer, 0, sizeof(buffer));
    }
    bin_content[addedBitsCount + offset] = '\0';

    fclose(f);
    FREE(tmp_buffer);

    /* Check if we need to add some bits from the start of bin_content */
    if (addedBitsCount > 0)
    {
        /*Generate some random bits*/
        char* addedBits = ALLOC(sizeof(char) * 6);
        addedBits = random_str(addedBitsCount, POOL);
        addedBits[addedBitsCount] = '\0';

        memcpy(bin_content, addedBits, addedBitsCount);

        // return requested bits count too
        *req_bits_count = bin_file_size + addedBitsCount;
        *added_bits_count = addedBitsCount;

        return bin_content;
        FREE(addedBits);
    }

    // return requested bits count too
    *req_bits_count = bin_file_size + addedBitsCount;
    *added_bits_count = addedBitsCount;

    return bin_content;
}

SPAE_DLL_EXPIMP size_t SPAE_CALL get_member_total_pads_count(size_t m_id, char* pad_path, size_t mem_count, char* error_desc)
{
    size_t padCount = 0;
    size_t total_pads_count = 0;

    //TODO check for 0
    dirlist(pad_path, "txt", &padCount);
    /* Since dirlist returned not ordered list - 1.txt, 10.txt, 9.txt, .... */
    /* so we need to do natural sort algorithm on it!!!                     */
    /* BUTTTTTTTTTTT !!!                                                    */
    /* Because we just counting it does not matter order                    */

    if (padCount <= 0)
    {
        strcpy_s(error_desc, 256, "\nThere is no any pads found for the circle.\n");
        return total_pads_count;
    }

    size_t i = m_id;
    for (; i <= padCount; )
    {
        total_pads_count++;
        i += mem_count;
    }

    return total_pads_count;
}

SPAE_DLL_EXPIMP size_t SPAE_CALL get_circle_pads_count(char* pad_path, char* error_desc)
{
    size_t padCount = 0;
    size_t total_pads_count = 0;

    //TODO check for 0
    dirlist(pad_path, "txt", &padCount);
    /* Since dirlist returned not ordered list - 1.txt, 10.txt, 9.txt, .... */
    /* so we need to do natural sort algorithm on it!!!                     */
    /* BUTTTTTTTTTTT !!!                                                    */
    /* Because we just counting it does not matter order                    */

    if (padCount <= 0)
    {
        strcpy_s(error_desc, 256, "\nThere is no any pads found for the circle.\n");
        return total_pads_count;
    }

    total_pads_count = padCount;

    return total_pads_count;
}

SPAE_DLL_EXPIMP int SPAE_CALL get_member_fully_avail_pads_count(size_t m_id, char* enc_cfg_f_path, size_t mem_count, char* error_desc)
{
    int count = 0;
    // Check if cfg file exists
    if (0 != is_file_exists(enc_cfg_f_path))
    {
        return -1;
    }

    size_t avail_bits_count = get_option_from_enc_cfg(enc_cfg_f_path, "usedBitsCount", error_desc).int_value;
    count = (int)avail_bits_count / PAD_LEN; // How many full pad is it

    return count;
}

SPAE_DLL_EXPIMP enc_error_t SPAE_CALL create_enc_cfg_file(char* f_name, char* pad_path, size_t mem_id, char* error_desc)
{
    char* firstPadPath = CALLOC(sizeof(char) * _MAX_PATH, 1);

    size_t padsCount = 0;

    char** padList = dirlist(pad_path, "txt", &padsCount);

    /* There is no encryption file created before we need to create it from the fresh */
    /* Since dirlist returned not ordered list - 1.txt, 10.txt, 9.txt, ....           */
    /* so we need to do natural sort algorithm on it!!!                               */
    qsort(padList, padsCount, sizeof(char*), natural_compare);

    /* Get the first pad of particular member.                                        */
    /* Due to array indexing starts from 0, so member ID should be (-1)               */
    /* For creating encryption fresh config file we ALWAYS using member's first pad!  */

    /* Build the first pad full path!                                                 */
    strcat_s(firstPadPath, _MAX_PATH, pad_path);

    if (mem_id <= 0)
    {
        strcpy_s(error_desc, 256, "\nError: Member ID could not be less or equal to zero.\n");
        return ENC_ERROR_INVALID_MEMBER_ID;
    }
    else
    {
        strcat_s(firstPadPath, _MAX_PATH, padList[mem_id - 1]);
    }

    int open_status;

    /*Accept the file and try to open it*/
    FILE* f_member_1_pad = NULL;
    /*Trying to open the file*/
    f_member_1_pad = open_file(firstPadPath, FILE_MODE_READ, &open_status);

    /* Read whole file content into memory                                             */
    char* padContent;
    size_t contentSize = 0;
    int readStatus;

    padContent = c_read_file(f_member_1_pad, &readStatus, &contentSize);
    if (readStatus)
    {
        strcpy_s(error_desc, 256, "\nError: There was an error when reading first pad for config file.\n");
        fclose(f_member_1_pad);
        return ENC_ERROR_READFILE;
    }

    struct encryptionCfg encData = { 0 };
    encData = build_enc_cfg_file(f_name, padContent, 0);

    fclose(f_member_1_pad);
    FREE(padContent);
    return ENC_ERROR_OK;
}

SPAE_DLL_EXPIMP enc_error_t SPAE_CALL create_64_prog_files(char* padContent, 
                                                           char*** tbl, 
                                                           char* pps_insert_point, 
                                                           char* c9_position_26_bits, 
                                                           char* dynamic_pps_points, 
                                                           char* logic, 
                                                           const char* dir, 
                                                           char* error_desc)
{
    const size_t contentLen    = 64 * 6 + PPS_STRUCT_RAW_LEN + 3 + 1 + 1; /* 64 spec chars six-bits representation + PPS data + added_bits + XOR bit + null end */
    char* content              = ALLOC((long)(sizeof(char) * contentLen + strlen(dynamic_pps_points) + 26));
    char* addedBits            = ALLOC(3 * sizeof(char)); // Why exactly 3?? Because 3255/6 = 5. 3255 is const and it is len of prog string
    wchar_t* circle_prog_dir_w = ALLOC(sizeof(wchar_t) * (long)(_MAX_DIR + 1));
    wchar_t* prog_f_name       = ALLOC(sizeof(wchar_t) * 7);
    wchar_t* prog_files_dir    = ALLOC(sizeof(wchar_t) * _MAX_PATH);

    int open_status;

    for (size_t i = 0; i < PROG_FILES_COUNT; i++)
    {
        // Start to build the contetn of every Prog file
        for (size_t j = 0; j < 64; j++)
        {
            memcpy(content + j * 6, tbl[i][j], 6);
        }
        content[64 * 6] = '\0';

        memcpy(content + 64 * 6, pps_insert_point, PPS_STRUCT_RAW_LEN); // pps_i_p must be a dec value but here we need its bin form
        content[64 * 6 + PPS_STRUCT_RAW_LEN] = '\0';

        // For the last (PPS) file we always use first bit val as a log op method
        if (i == 64)
        {
            char vIn = logic[0];
            char vOut[2] = { vIn,0 };
            memcpy(content + 64 * 6 + PPS_STRUCT_RAW_LEN, vOut, 1);
            memcpy(content + 64 * 6 + PPS_STRUCT_RAW_LEN + 1, dynamic_pps_points, strlen(dynamic_pps_points));
            memcpy(content + 64 * 6 + PPS_STRUCT_RAW_LEN + 1 + strlen(dynamic_pps_points), c9_position_26_bits, 26); // 
            content[64 * 6 + PPS_STRUCT_RAW_LEN + 1 + strlen(dynamic_pps_points) + 26] = '\0';

            //Generate some random bits
            //addedBits = random_str(3, POOL); //3255/6 = 3
            //addedBits[3] = '\0';

            //memcpy(content + 64 * 6 + PPS_STRUCT_RAW_LEN + 1 + strlen(dynamic_pps_points), addedBits, 3);
            //content[64 * 6 + PPS_STRUCT_RAW_LEN + 1 + 3 + strlen(dynamic_pps_points)] = '\0';
        }
        else
        {
            char vIn = logic[i];
            char vOut[2] = { vIn,0 };
            memcpy(content + 64 * 6 + PPS_STRUCT_RAW_LEN, vOut, 1);
            content[64 * 6 + PPS_STRUCT_RAW_LEN + 1] = '\0';

            //Generate some random bits
            addedBits = random_str(3, POOL); //3255/6 = 3
            addedBits[3] = '\0';

            memcpy(content + 64 * 6 + PPS_STRUCT_RAW_LEN + 1, addedBits, 3);
            content[64 * 6 + PPS_STRUCT_RAW_LEN + 1 + 3] = '\0';
        }

        // Encrypt content
        wchar_t* cipher_txt = encrypt_string(content, padContent, error_desc);

        /* Convert to wide string and pass as an argument */

        mbstowcs_s(NULL, circle_prog_dir_w, _MAX_DIR + 1, dir, _MAX_DIR);

        _ui64tow_s(i, prog_f_name, 7, 10);
        wcscat_s(prog_f_name, 7, L".txt");
        wcscpy_s(prog_files_dir, _MAX_PATH, circle_prog_dir_w);
        wcscat_s(prog_files_dir, _MAX_PATH, prog_f_name);

        // Write to file
        FILE* f = NULL;
        /*Trying to open the file*/
        f = w_open_file(prog_files_dir, FILE_MODE_WRITE, &open_status);

        if (open_status != 0)
        {
            strcpy_s(error_desc, 256, "\nError: When trying to open a file for Prog File.\n");
            //return NULL;
        }

        /* Fail to set mode to UTF */
        if (-1 == set_file_mode_to_utf(&f))
        {
            strcpy_s(error_desc, 256, "\nError: When trying to set file mode to UTF.\n");
            //return NULL;
        }

        fwrite(cipher_txt, 2, wcslen(cipher_txt), f);
        fclose(f);

        FREE(cipher_txt);
    }

    FREE(content);
    FREE(circle_prog_dir_w);
    FREE(prog_f_name);
    FREE(prog_files_dir);

    return ENC_ERROR_OK;
}

SPAE_DLL_EXPIMP enc_error_t SPAE_CALL encrypt_file(char* f_name, char* circle, char* enc_cfg_f_path, size_t member_id, unsigned int is_first_usage, wchar_t* where_to_save, wchar_t* encrypted_f_name, wchar_t* error_msg)
{
    size_t requested_bits_count = 0;
    size_t added_bits_count     = 0;
    size_t* requested_pads_list = NULL;

    struct circle circle_s         = { 0 };
    struct bitsInfo bitsInfo_s     = { 0 };
    struct encryptionCfg enc_cfg_s = { 0 };

    char* used_pads_content = NULL;

    char* error_desc = ALLOC(sizeof(char) * 256);

    // Get some info about the circle
    get_circle_data_by_name(&circle_s, circle, error_desc);

    // Convert to binary
    char* binary_content = file_to_binary_enc(f_name, &requested_bits_count, &added_bits_count, error_msg);

    if (binary_content == NULL)
    {
        wcscpy_s(error_msg, 256, L"\nFile too large. 500mb file size limit for encryption.\n");
        return ENC_ERROR_HUGEFILE;
    }

    /* Get members bits info */
    bitsInfo_s = compute_bits_info(binary_content, circle, enc_cfg_f_path, member_id, is_first_usage, error_desc);

    // Check if there are enough bits for enc
    if (bitsInfo_s.availableBitsCount == 0 && bitsInfo_s.totalBitsCount == 0 && bitsInfo_s.usedBitsCount == 0 &&
        bitsInfo_s.requestedBitsCount > 0)
    {
        size_t _addit_P_count = bitsInfo_s.requestedBitsCount;
        wchar_t* how_many = int2wstr(_addit_P_count);
        wcscpy_s(error_msg, 256, how_many);
        return ENC_ERROR_FEWPADS;
    }

    // Check if there are enough bits for enc
    if (bitsInfo_s.availableBitsCount == 0 && bitsInfo_s.totalBitsCount == 0 && bitsInfo_s.usedBitsCount == 0 &&
        bitsInfo_s.requestedBitsCount == 0)
    {
        wcscpy_s(error_msg, 256, L"No Pads found for the circle.");
        return PADS_ERROR_NOPADS;
    }

    size_t r_p_c = 0; // requested pads count
    size_t enc_cfg_offset = 0; // requested pads count

    if (is_first_usage > 0)
    {
        requested_pads_list = get_list_of_requested_pads_ID(circle, member_id, requested_bits_count, &r_p_c, error_desc);

        // Prepare some data
        enc_cfg_s = prepare_enc_cfg_file_data(circle_s.pads_path, requested_pads_list, member_id, 0, error_desc);
    }
    else
    {
        requested_pads_list = collect_list_of_requested_pads_ID(circle, member_id, requested_bits_count, bitsInfo_s.availableBitsCount, bitsInfo_s.usedBitsCount, &r_p_c, &enc_cfg_offset, error_desc);

        // Prepare some data
        enc_cfg_s = prepare_enc_cfg_file_data(circle_s.pads_path, requested_pads_list, member_id, enc_cfg_offset, error_desc);
    }

    /* Now we should open each requested pad and merge thier content into one.        */
    if (r_p_c >= 1)
    {
        used_pads_content = CALLOC(sizeof(char) * r_p_c * PAD_LEN + 1, 1);
        int res = merge_requested_pads(used_pads_content, requested_pads_list, r_p_c, circle_s.pads_path, enc_cfg_offset, error_msg);
        if (res != 0)
        {
            //strcpy_s(error_desc, 256, "\nError: When merging Pads.\n");
            return ENC_ERROR_COMMON;
        }
    }
    else
    {
        wcscpy_s(error_msg, 256, L"\nWarning: There is no Pads to merge.\n");
        return ENC_ERROR_WRONGPADSCOUNT;
    }

    /* Adding additional bits using xor 6 bits  */
    memcpy(binary_content, enc_cfg_s.xorbits, added_bits_count);

    // Get Prog&PPS files raw content
    char* prog_pps_content = get_pps_and_prog_file_contents(circle, circle_s.pads_path, enc_cfg_s.programNumber, error_desc);
    char* dynamic_pps_prog_content = get_dynamic_pps_and_prog_file_contents(circle, circle_s.pads_path, error_desc);

    /* Do logical operation                                                           */
    /* Get logical op method from program file content.It is a value of 3255-th bit.   */
    if ((*(prog_pps_content + 3254)) - '0' == 1) //3254=6*64+2870
    {
        // Do XOR
        fmakeXOR(binary_content, used_pads_content);
    }
    else
    {
        // Do XNOR
        fmakeXNOR(binary_content, used_pads_content);
    }

    /* Get PPS from config file content and convert it to spec chars.                 */
    wchar_t* spec_PPS = ALLOC(sizeof(wchar_t) * (2 * SPEC_PPS_LEN + 2));
    get_spec_PPS(enc_cfg_s, prog_pps_content, spec_PPS);
    //get_spec_PPS_simple(enc_cfg_s, prog_pps_content, spec_PPS);

    /* Convert plain text to their six-bits spec chars representation.                */
    wchar_t* plainSpec = ALLOC(sizeof(wchar_t) * (strlen(binary_content) / 3 + 2));
    get_spec_text(enc_cfg_s, binary_content, prog_pps_content, plainSpec);

    // Do PSP action.
    W_PSP(plainSpec, enc_cfg_s.startPoint, enc_cfg_s.jumpPoint);

    /* Insert special char into its position.	                 	                  */
    wchar_t* plain_spec_with_char = ALLOC(sizeof(wchar_t) * (wcslen(plainSpec) + 2));
    insert_spec_char(enc_cfg_s, plainSpec, plain_spec_with_char);

    /* Insert PPS into its position.	                 	                          */
    /* But first of all we need to get PPS insertion point from program content       */
    /* it starts from 385th bit with the len 26 bit                                   */
    wchar_t* plain_spec_with_char_and_PPS = ALLOC(sizeof(wchar_t) * (wcslen(plainSpec) + wcslen(spec_PPS) + 2 + 3));
    //insert_pps(enc_cfg_s, plain_spec_with_char, spec_PPS, prog_pps_content, plain_spec_with_char_and_PPS);

    // Now it is the time to know in which order need we insert PPS L->R or R->L
    // If 0, 2,4... then we place char's with the wrapaaround number left to right
    
    char* sp_in_bin = CALLOC(sizeof(char) * 28 + 1, 1);
    decimalToBinary(sp_in_bin, enc_cfg_s.startPoint, 25);

    // Now get the first 6 bits which will point insertion order in decimal
    char* c9_char_six_bits = ALLOC(sizeof(char) * 6 + 1);
    memcpy_s(c9_char_six_bits, 7, sp_in_bin, 6);
    c9_char_six_bits[6] = '\0';

    size_t insert_order = bindec(c9_char_six_bits);
    int insert_order_val = 0;
    if (is_even(insert_order)) 
    {
        // even L->R
        insert_order_val = 0;
        //insert_dynamic_pps_left_to_right(enc_cfg_s, plain_spec_with_char, spec_PPS, c9_char_six_bits, dynamic_pps_prog_content, plain_spec_with_char_and_PPS);
    }
    else 
    {
        // odd R->L
        insert_order_val = 1;
        //insert_dynamic_pps_right_to_left(enc_cfg_s, plain_spec_with_char, spec_PPS, c9_char_six_bits, dynamic_pps_prog_content, plain_spec_with_char_and_PPS);
    }

    insert_dynamic_pps_with_order(enc_cfg_s, plain_spec_with_char, spec_PPS, c9_char_six_bits, dynamic_pps_prog_content, plain_spec_with_char_and_PPS, insert_order_val);


    /* Insert 9th ctrl char */
    // Get the char position
    char last_bits[27]; // allocate buffer for 26 bits plus null terminator
    last_26_bits(last_bits, dynamic_pps_prog_content, strlen(dynamic_pps_prog_content));
    size_t c9_insrt_pos = bindec(last_bits);
    // wraparound it
    if (c9_insrt_pos > wcslen(plain_spec_with_char_and_PPS))
    {
        c9_insrt_pos = c9_insrt_pos % wcslen(plain_spec_with_char_and_PPS);
    }

    // Get 9th ctrl spec char
    wchar_t* last_ctrl_spec_char = ALLOC(sizeof(wchar_t) * 2);
    get_spec_char_by_index_simple(last_ctrl_spec_char, c9_char_six_bits);

    w_insert_char_itself(plain_spec_with_char_and_PPS, *last_ctrl_spec_char, c9_insrt_pos);

    /* Build encrypted file name:  	                 	                              */
    /* First 7 chars of the file + added bits count + original ext + spae             */
    wchar_t* final_f_name = biuld_enc_file_name(plain_spec_with_char_and_PPS, added_bits_count, where_to_save, f_name);

    wmemcpy_s(encrypted_f_name, _MAX_FNAME, final_f_name, wcslen(final_f_name));
    encrypted_f_name[wcslen(final_f_name)] = '\0';
    //strcpy_s(encrypted_f_name, 256, "\nFile name si fuck\n");

    /* Write into file            	                 	                              */
    write_cipher_to_file(final_f_name, plain_spec_with_char_and_PPS, error_desc);

    enc_cfg_s.totalBitsCount = bitsInfo_s.totalBitsCount;
    enc_cfg_s.requestedBitsCount = bitsInfo_s.requestedBitsCount;
    enc_cfg_s.usedBitsCount = bitsInfo_s.usedBitsCount + bitsInfo_s.requestedBitsCount + SEEK_NUMBER;
    enc_cfg_s.availableBitsCount = bitsInfo_s.availableBitsCount - bitsInfo_s.requestedBitsCount;

    /*enc_cfg_s.usedBitsCount = bitsInfo_s.usedBitsCount;
    enc_cfg_s.availableBitsCount = bitsInfo_s.availableBitsCount;*/

    //store_enc_cfg(enc_cfg_f_path, enc_cfg_s, error_desc);
    w_store_enc_cfg(enc_cfg_f_path, enc_cfg_s, error_msg);

    FREE(binary_content);
    FREE(used_pads_content);
    FREE(plain_spec_with_char_and_PPS);
    //FREE(final_f_name);

    //wcscpy_s(error_msg, 256, spec_PPS);
    return ENC_ERROR_OK;
}




SPAE_DLL_EXPIMP enc_error_t SPAE_CALL merge_requested_pads(char* result, size_t* list, size_t count, char* pads_dir, size_t offset, wchar_t* error_desc)
{
    char* padPath = ALLOC(sizeof(char) * _MAX_PATH);
    char* padName = ALLOC(sizeof(char) * 8 + 1);

    /*Read whole file content into memory*/
    /*Allocate enough heap size for file content*/
    char* fContent;
    size_t contentSize = 0;
    size_t shift = 0;

    int open_status;
    int readStatus;

    FILE* pd;
    for (size_t i = 0; i < count; i++)
    {
        _ui64toa_s(list[i], padName, 9, 10);
        strcat_s(padName, 9, ".txt");

        strcpy_s(padPath, _MAX_PATH, pads_dir);
        padPath[strlen(pads_dir)] = '\0';
        strcat_s(padPath, _MAX_PATH, "/");
        strcat_s(padPath, _MAX_PATH, padName);

        /*Accept the file and try to open it*/
        pd = open_file(padPath, FILE_MODE_READ, &open_status);
        if (open_status != 0)
        {
            wcscpy_s(error_desc, 256, L"\nError: When trying to open a Pad for merging.\n");
            return ENC_ERROR_OPENFILE;
        }

        if (i == 0)
        {
            /* if this is a first step of loop, so we need to seek from first pad used bits */
            fseek(pd, (long)(offset + SEEK_NUMBER), SEEK_SET);
        }

        fContent = c_read_file(pd, &readStatus, &contentSize);
        if (readStatus)
        {
            wcscpy_s(error_desc, 256, L"\nError: When trying to open Pad file for merging.\n");
            return ENC_ERROR_READFILE;
        }

        memcpy(result + shift, fContent, contentSize);
        shift += contentSize;

        FREE(fContent);

        memset(padPath, 0, sizeof(padPath));
        memset(padName, 0, sizeof(padName));

        fclose(pd);
    }
    result[shift] = '\0';

    return ENC_ERROR_OK;
}


SPAE_DLL_EXPIMP decr_error_t SPAE_CALL decrypt_file_progressive(wchar_t* f_name, char* final_name, char* circle, char* decr_cfg_f_path, size_t member_id, unsigned int is_first_usage, wchar_t* error_desc)
{
#if _DEBUG
    FILE* log_file = NULL;
    int log_open_status;
    log_file = open_file("log_decrypt.txt", FILE_MODE_APLUS, &log_open_status);

    if (log_open_status != 0)
    {
        wcscpy_s(error_desc, 256, L"\nError: When trying to open a Log file.\n");
        return DECR_ERROR_OPENFILE;
    }

    // Start log file
    write_log(log_file, "------Action: Decrypt a File------ Time: ");
    write_log(log_file, get_current_time());
    write_log(log_file, "\n");

#endif

    mpz_t res;
    mpz_init(res);

    size_t requested_bits_count = 0;
    size_t added_bits_count     = 0;
    size_t bits_removed         = 0;
    size_t isZero               = 0;
    size_t result               = 0;
    size_t* requested_pads_list = NULL;

    wchar_t* f_content    = NULL;
    size_t   content_size = 0;
    int      read_status;
    int      open_status;

    struct circle circle_s          = { 0 };
    struct bitsInfo bitsInfo_s      = { 0 };
    struct encryptionCfg decr_cfg_s = { 0 };

    char* used_pads_content = NULL;
    char* error_str         = ALLOC(sizeof(char) * 256);
    wchar_t* orig_extension = ALLOC(sizeof(wchar_t) * _MAX_EXT);

    //Get SPAE filename from the path
    wchar_t* spae_f_name = wget_file_name_from_path(f_name);
    if (spae_f_name == NULL || is_wstring_empty(spae_f_name) == 1)
    {
        wcscpy_s(error_desc, 256, L"Wrong or empty Spae file name given. Pls check.");
        return DECR_ERROR_COMMON;
    }

#if _DEBUG
    write_log(log_file, "SPAE file name: ");
    wcs_write_log(log_file, spae_f_name);
    write_log(log_file, "\n");
#endif

    // Check history file
    struct decryptionCfg* dec_history_data;
    dec_history_data = get_decr_data_by_SPAE_name(spae_f_name, error_desc);
    if (NULL != dec_history_data)
    {
        if (strcmp(circle, dec_history_data->circle_name) == 0)
        {
            circle = dec_history_data->circle_name;
        }
        else
        {
            wcscpy_s(error_desc, 256, L"There is SPAE in history but it seems you have selected wrong Circle. Pls check and try again.");
            return DECR_ERROR_HISTORY;
        }

        if (member_id == dec_history_data->member_number)
        {
            member_id = dec_history_data->member_number;
        }
        else
        {
            wcscpy_s(error_desc, 256, L"There is SPAE in history but it seems you have selected wrong member. Pls check and try again.");
            return DECR_ERROR_HISTORY;
        }

#if _DEBUG
        write_log(log_file, "There is an history decr history file and it contains data about this file.\n");
        write_log(log_file, "Decrypted file name: ");
        wcs_write_log(log_file, f_name);
        write_log(log_file, "\n");

        write_log(log_file, "Temporary file name: ");
        write_log(log_file, final_name);
        write_log(log_file, "\n");

        write_log(log_file, "Circle name: ");
        write_log(log_file, dec_history_data->circle_name);
        write_log(log_file, "\n");
#endif

        test_decrypt_file(f_name, final_name, error_desc);

#if _DEBUG
        fflush(log_file);
        fclose(log_file);
#endif

        return DECR_ERROR_OK;
    }

    // Get some info about the circle
    get_circle_data_by_name(&circle_s, circle, error_str);

#if _DEBUG
    write_log(log_file, "Circle name: ");
    write_log(log_file, circle_s.circle_name);
    write_log(log_file, "\n");

    write_log(log_file, "Circle config path: ");
    write_log(log_file, circle_s.config_path);
    write_log(log_file, "\n");

    write_log(log_file, "Circle pads path: ");
    write_log(log_file, circle_s.pads_path);
    write_log(log_file, "\n");

    write_log(log_file, "Member name: ");
    write_log(log_file, circle_s.mbr.first_name);
    write_log(log_file, "\n");
#endif

    /*Accept the file and try to open it*/
    FILE* c_file = NULL;
    /*Trying to open the file*/
    c_file = w_open_file(f_name, FILE_MODE_READ, &open_status);

    if (open_status != 0)
    {
        wcscpy_s(error_desc, 256, L"\nError: When trying to open c-file.\n");
        return DECR_ERROR_OPENFILE;
    }

    /* Fail to set mode to UTF */
    if (-1 == set_file_mode_to_utf(&c_file))
    {
        wcscpy_s(error_desc, 256, L"\nError: When trying to set file mode to UTF.\n");
        return DECR_ERROR_READFILE;
    }

    /* Read whole file content into memory */
    f_content = wc_read_file(c_file, &read_status, &content_size);

    if (read_status)
    {
        wcscpy_s(error_desc, 100, L"Error opening or reading a file.");
        return DECR_ERROR_READFILE;
    }

    // Check if there were some content but useful content was empty
    if (is_wstring_empty(f_content) == 1)
    {
        wcscpy_s(error_desc, 256, L"\nError: empty c-file submitted. Pls, check!\n");
        return DECR_ERROR_EMPTYFILE;
    }
    /*-------------------------------------------------------------------------------------------------------*/
    /*-------------------------------------------------------------------------------------------------------*/
    /*-------------------------------------------------------------------------------------------------------*/

    /* First of all we need to remove 9th control bit */

    // Get PPS from any Prog file since PPS is the same for all
    char* prog_file_content = get_dynamic_pps_and_prog_file_contents(circle, circle_s.pads_path, error_str);

    // Get 9th insertion pos
    char last_bits[27]; // allocate buffer for 26 bits plus null terminator
    last_26_bits(last_bits, prog_file_content, strlen(prog_file_content));
    size_t c9_insrt_pos = bindec(last_bits);
    // wraparound it
    if (c9_insrt_pos > (wcslen(f_content) - 1))
    {
        c9_insrt_pos = c9_insrt_pos % (wcslen(f_content) - 1);
    }

    const wchar_t C9_wchar = f_content[c9_insrt_pos];

    // Remove C9 char
    remove_spec_char(f_content, c9_insrt_pos);

    


    // Get PPS decimal values from prog
    //size_t* pps_positions = ALLOC(sizeof(size_t) * 7);
    size_t* huge_dynamic_pps_positions = ALLOC(sizeof(size_t) * 7);
    get_dynamic_pps_positions_by_9th_char(huge_dynamic_pps_positions, prog_file_content, C9_wchar, error_str);

    /* But first of all we need to get PPS insertion point from program content       */
    /* it starts from 385th bit with the len 26 bit                                   */
    //char* pps_insertion_point_str = ALLOC(sizeof(char) * 26 + 1);
    //size_t pps_insertion_points_decimal[7] = { 0 };

    //for (size_t i = 0; i < 7; i++)
    //{
    //    pps_get_nth_position(pps_insertion_point_str, i, prog_file_content);
    //    pps_insertion_points_decimal[i] = bindec(pps_insertion_point_str);
    //}

    wchar_t* p_p_s = ALLOC(sizeof(wchar_t) * 7 + 2);

    // We are getting real PPS 7 spec chars from c-text
    //wchar_t* p_p_s = get_PPS_by_point(f_content, pps_insertion_point_dec);
    //TODO Memory consuming point
    //get_PPS_by_points_array(p_p_s, f_content, pps_insertion_points_decimal);
    remove_dynamic_PPS_by_points_array(p_p_s, f_content, huge_dynamic_pps_positions, C9_wchar);

#if _DEBUG
    write_log(log_file, "PPS is: ");
    wcs_write_log(log_file, p_p_s);
    write_log(log_file, "\n");
#endif // _DEBUG

    //char* raw_PPS = convert_spec_chars_to_PPS(p_p_s);
    char* raw_PPS = ALLOC(sizeof(char) * 42 + 1);
    convert_spec_PPS_to_binary(raw_PPS, p_p_s, prog_file_content);

#if _DEBUG
    write_log(log_file, "PPS converted into six-bits: ");
    write_log(log_file, raw_PPS);
    write_log(log_file, "\n");
#endif // _DEBUG

    // Do search in Member Pads list in order to get Pad ID and an offsset
    // Get members total count in the Circle
    int members_count = get_circle_members_count(circle, error_str);

#if _DEBUG
    int_write_log(log_file, "Members count in the circle: ", members_count);
#endif // _DEBUG

    size_t member_pads_count = 0;
    size_t* _mem_pads_list_id = get_member_pads_indexes(circle_s, member_id, members_count, &member_pads_count);

    if (member_pads_count <= 0)
    {
        wcscpy_s(error_desc, 256, L"\nMember has no any Pad available. Pls, check.\n");
        return PADS_ERROR_INVALID;
    }

#if _DEBUG
    int_write_log(log_file, "Member's Pads count: ", member_pads_count);
#endif // _DEBUG

    // Get first used Pad and offset
    //TODO Weakest point is here!!!!!!!!!!!!!!!!!!!!
    size_t used_pad_offset = 0;
    size_t first_used_pad_id = get_first_used_pad_id(_mem_pads_list_id, member_pads_count, circle_s.pads_path, raw_PPS, &used_pad_offset);

    if (0 == first_used_pad_id)
    {
        //mbstowcs(error_desc, raw_PPS, 42);
        wcscpy_s(error_desc, 256, L"Can't find first Pad which was used for Encryption for this file.");
        return PADS_ERROR_INVALID;
    }

#if _DEBUG
    int_write_log(log_file, "Pad index which was used as a first: ", first_used_pad_id);
    int_write_log(log_file, "Used Pad offset: ", used_pad_offset);
#endif // _DEBUG












    /*-------------------------------------------------------------------------------------------------------*/
    /*-------------------------------------------------------------------------------------------------------*/
    /*-------------------------------------------------------------------------------------------------------*/
    /* Get members bits info */
    bitsInfo_s = w_compute_bits_info(f_content, circle, decr_cfg_f_path, member_id, is_first_usage, error_str);

    // Check if no error
    // Check if there are enough bits for enc
    if (bitsInfo_s.availableBitsCount == 0 && bitsInfo_s.totalBitsCount == 0 && bitsInfo_s.usedBitsCount == 0 &&
        bitsInfo_s.requestedBitsCount == 0)
    {
        wcscpy_s(error_desc, 256, L"\nError: Can't open circles config file or there are no members in the circle.\n");
        return DECR_ERROR_OPENFILE;
    }

    requested_bits_count = bitsInfo_s.requestedBitsCount;

#if _DEBUG
    int_write_log(log_file, "Total Bits Count: ", bitsInfo_s.totalBitsCount);
    int_write_log(log_file, "Available Bits Count: ", bitsInfo_s.availableBitsCount);
    int_write_log(log_file, "Used Bits Count: ", bitsInfo_s.usedBitsCount);
    int_write_log(log_file, "Requested Bits Count: ", bitsInfo_s.requestedBitsCount);
#endif // _DEBUG


    // Check if there are enough bits for dec
    if (bitsInfo_s.availableBitsCount == 0 && bitsInfo_s.totalBitsCount == 0 && bitsInfo_s.usedBitsCount == 0 &&
        bitsInfo_s.requestedBitsCount > 0)
    {
        size_t _addit_P_count = bitsInfo_s.requestedBitsCount;
        wchar_t* how_many = int2wstr(_addit_P_count);
        wcscpy_s(error_desc, 256, how_many);
        return ENC_ERROR_FEWPADS;
    }

    size_t r_p_c = 0; // requested pads count
    size_t decr_cfg_offset = used_pad_offset;

    requested_pads_list = get_list_of_requested_pads_ID_progressive(circle, first_used_pad_id, requested_bits_count, &r_p_c, error_str);
    // Prepare some data
    decr_cfg_s = prepare_enc_cfg_file_data(circle_s.pads_path, requested_pads_list, member_id, decr_cfg_offset, error_str);

#if _DEBUG
    int_write_log(log_file, "Requested pads count: ", r_p_c);
    write_log(log_file, "Requested pads IDs: ");
    for (size_t i = 0; i < r_p_c; i++)
    {
        int_write_log(log_file, "Requested pad ID: ", requested_pads_list[i]);
    }

#endif // _DEBUG


    /* Now we should open each requested pad and merge thier content into one.        */
    if (r_p_c >= 1)
    {
        used_pads_content = CALLOC(sizeof(char) * r_p_c * PAD_LEN + 1, 1);
        int res = merge_requested_pads(used_pads_content, requested_pads_list, r_p_c, circle_s.pads_path, decr_cfg_offset, error_desc);
        if (res != 0)
        {
            //strcpy_s(error_desc, 256, "\nError: When merging Pads.\n");
            return DECR_ERROR_COMMON;
        }
    }
    else
    {
        wcscpy_s(error_desc, 256, L"\nWarning: There is no Pads to merge.\n");
        return DECR_ERROR_WRONGPADSCOUNT;
    }

    // Get Prog&PPS files raw content
    char* prog_pps_content = get_pps_and_prog_file_contents(circle, circle_s.pads_path, decr_cfg_s.programNumber, error_str);

    /*Find & Remove PPS*/
    /* Remove PPS into its position.	                 	                          */
    /* But first of all we need to get PPS insertion point from program content       */
    /* it starts from 385th bit with the len 26 bit                                   */
//    char* ppsInsertionPointStr = ALLOC(sizeof(char) * 26 + 1);
//    memcpy_s(ppsInsertionPointStr, 26 + 1, prog_pps_content + 64 * 6, 26);
//    ppsInsertionPointStr[26] = '\0';
//
//    size_t psLen = wcslen(f_content) - 7;
//    size_t ppsInsertionPoint = bindec(ppsInsertionPointStr);
//
//    if (psLen < ppsInsertionPoint)
//    {
//        ppsInsertionPoint = ppsInsertionPoint % psLen;
//    }
//
//#if _DEBUG
//    int_write_log(log_file, "PPS insertion point: ", ppsInsertionPoint);
//#endif // _DEBUG
//
//    remove_PPS(f_content, ppsInsertionPoint);
//
//#if _DEBUG
//    write_log(log_file, "PPS removed\n");
//#endif // _DEBUG

    // Find and remove PPS chars but first of all let us get PPS insertion order
    //size_t insert_order_for_PPS = get_dynamic_PPS_insertion_order(decr_cfg_s.startPoint);

    /* Delete special char */
    remove_spec_char(f_content, decr_cfg_s.specialCharPosition);

#if _DEBUG
    int_write_log(log_file, "Ghost char removed from the position: ", decr_cfg_s.specialCharPosition);
#endif // _DEBUG

#if _DEBUG
    write_log(log_file, "Doing PSP revers using data below:\n");
#endif // _DEBUG

    // Doing reverse PSP
    wchar_t* reversedContent = reverse_PSP_decr(f_content, decr_cfg_s.startPoint, decr_cfg_s.jumpPoint);

#if _DEBUG
    int_write_log(log_file, "Reverse PPS start point", decr_cfg_s.startPoint);
    int_write_log(log_file, "Reverse PPS jump point", decr_cfg_s.jumpPoint);
#endif // _DEBUG

    // Convert spec char to their six-bits represent
    char* binary_content = ALLOC(sizeof(char) * (wcslen(reversedContent) * 6 + 1));
    get_binary_from_c_text(reversedContent, decr_cfg_s, prog_pps_content, binary_content);

#if _DEBUG
    write_log(log_file, "Got binary from c-text.\n");
#endif // _DEBUG

    /* Get logical op method from program file content.It is a value of 411-th bit.   */
    if ((*(prog_pps_content + 3254)) - '0' == 1)
    {
        // Do XOR
        fmakeXOR(binary_content, used_pads_content);

#if _DEBUG
        write_log(log_file, "Did XOR\n");
#endif // _DEBUG
    }
    else
    {
        // Do XNOR
        fmakeXNOR(binary_content, used_pads_content);

#if _DEBUG
        write_log(log_file, "Did XNOR\n");
#endif // _DEBUG
    }

    // Parsing file name in order to get info about added bits, orig ext and etc...
    wchar_t** file_name_parsed = parse_file_name(f_name, L".");

    /* Bits to be removed */
    bits_removed = wcstoul(file_name_parsed[1], NULL, 10);

#if _DEBUG
    int_write_log(log_file, "Bits to be removed", bits_removed);
#endif // _DEBUG

    /* File's original extension */
    size_t extLen = wcslen(file_name_parsed[2]);
    wmemcpy(orig_extension, file_name_parsed[2], extLen);
    orig_extension[extLen] = '\0';

#if _DEBUG
    write_log(log_file, "Original file extenssion: ");
    wcs_write_log(log_file, orig_extension);
#endif // _DEBUG

    /* Remove added bits from final binary file */
    size_t bcLen = 0;
    bcLen = strlen(binary_content);

#if _DEBUG
    int_write_log(log_file, "Binary content len", bcLen);
#endif // _DEBUG

    /*char* withoutAddedBitsContent = ALLOC(sizeof(char) * (bcLen - bits_removed + 1));

    memcpy(withoutAddedBitsContent, binary_content + bits_removed, bcLen);
    withoutAddedBitsContent[bcLen] = '\0';*/

    FREE(f_content);
    FREE(reversedContent);
    //FREE(binary_content);

    // Convert Binary to File
    if (binary_content[bits_removed] == '0')
    {
        binary_content[bits_removed] = '1';
        isZero = 1;
    }

    mpz_init_set_str(res, binary_content + bits_removed, 2);
    FREE(binary_content);
    unsigned char* rawContent = (unsigned char*)mpz_export(NULL, &result, 1, 1, 0, 0, res);

    if (isZero == 1)
    {
        unsigned char newCh = (char)((int)rawContent[0] - 128);
        rawContent[0] = newCh;
        isZero = 0;
    }

    // Build decrypted file name
    char* final_file_name = CALLOC(sizeof(char) * _MAX_FNAME, 1);
    //strcat_s(final_file_name, _MAX_FNAME, "/");
    strcat_s(final_file_name, _MAX_FNAME, final_name);
    strcat_s(final_file_name, _MAX_FNAME, ".");

    char* origExt = ALLOC(sizeof(char) * wcslen(orig_extension) + 1);
    wcstombs_s(NULL, origExt, wcslen(orig_extension) + 1, orig_extension, wcslen(orig_extension) + 1);

    strcat_s(final_file_name, _MAX_FNAME, origExt);

    // Write to file
    write_plain_txt_to_file(final_file_name, rawContent, result, error_str);

    decr_cfg_s.totalBitsCount = bitsInfo_s.totalBitsCount;
    decr_cfg_s.availableBitsCount = bitsInfo_s.availableBitsCount;
    decr_cfg_s.requestedBitsCount = bitsInfo_s.requestedBitsCount;
    decr_cfg_s.usedBitsCount = bitsInfo_s.usedBitsCount;

    store_enc_cfg(decr_cfg_f_path, decr_cfg_s, error_str);

    struct decryptionCfg info_s = { 0 };

    //info_s.circle_name = ALLOC(sizeof(char) * strlen(circle) + 1);
    strcpy_s(info_s.circle_name, 256, circle);
    info_s.circle_name[strlen(circle)] = '\0';

    memcpy_s(info_s.pps, 42, decr_cfg_s.pps, 42);

    //info_s.dec_time = ALLOC(sizeof(char) * 100);
    time_t now = time(0);
    strftime(info_s.dec_time, 100, "%Y-%m-%d %H:%M:%S.000", localtime(&now));

    //info_s.spae_name = ALLOC(sizeof(wchar_t) * wcslen(f_name) + 1);
    wcscpy_s(info_s.spae_name, 100, spae_f_name);
    info_s.spae_name[wcslen(spae_f_name)] = '\0';
    /*wmemcpy_s(info_s.spae_name, 100, file_name_parsed[0] + (wcslen(file_name_parsed[0]) - 7), 7);
    info_s.spae_name[7] = '\0';
    wcscat_s(info_s.spae_name, 100, L".");
    wcscat_s(info_s.spae_name, 100, file_name_parsed[1]);
    wcscat_s(info_s.spae_name, 100, L".");
    wcscat_s(info_s.spae_name, 100, file_name_parsed[2]);
    wcscat_s(info_s.spae_name, 100, L".");
    wcscat_s(info_s.spae_name, 100, L"spae");*/

    info_s.bits_used = requested_bits_count;
    info_s.first_pad = requested_pads_list[0];
    info_s.last_pad = requested_pads_list[r_p_c - 1];
    info_s.member_number = member_id;

    insert_data_into_dec_cfg(DECR_CONSTANTLY_UPD_FNAME, info_s, error_desc);

#if _DEBUG
    fflush(log_file);
    fclose(log_file);
#endif

    return DECR_ERROR_OK;
}


decr_error_t test_decrypt_file(wchar_t* f_name, char* final_name, wchar_t* error_desc)
{
    mpz_t res;
    mpz_init(res);

    size_t requested_bits_count = 0;
    size_t added_bits_count = 0;
    size_t bits_removed = 0;
    size_t isZero = 0;
    size_t result = 0;
    size_t* requested_pads_list = NULL;

    wchar_t* f_content = NULL;
    size_t   content_size = 0;
    int      read_status;
    int      open_status;

    struct circle circle_s = { 0 };
    struct bitsInfo bitsInfo_s = { 0 };
    struct encryptionCfg decr_cfg_s = { 0 };

    char* used_pads_content = NULL;
    char* error_str = ALLOC(sizeof(char) * 256);
    wchar_t* orig_extension = ALLOC(sizeof(wchar_t) * _MAX_EXT);

    //Get SPAE filename from the path
    wchar_t* spae_f_name = wget_file_name_from_path(f_name);

    // Check history file
    struct decryptionCfg* dec_history_data;
    dec_history_data = get_decr_data_by_SPAE_name(spae_f_name, error_desc);

    // Get some info about the circle
    get_circle_data_by_name(&circle_s, dec_history_data->circle_name, error_str);

    /*Accept the file and try to open it*/
    FILE* c_file = NULL;
    /*Trying to open the file*/
    c_file = w_open_file(f_name, FILE_MODE_READ, &open_status);

    if (open_status != 0)
    {
        wcscpy_s(error_desc, 256, L"\nError: When trying to open c-file.\n");
        return DECR_ERROR_OPENFILE;
    }

    /* Fail to set mode to UTF */
    if (-1 == set_file_mode_to_utf(&c_file))
    {
        wcscpy_s(error_desc, 256, L"\nError: When trying to set file mode to UTF.\n");
        return DECR_ERROR_READFILE;
    }

    /* Read whole file content into memory */
    f_content = wc_read_file(c_file, &read_status, &content_size);

    if (read_status)
    {
        wcscpy_s(error_desc, 100, L"Error opening or reading a file.");
        return DECR_ERROR_READFILE;
    }

    // Check if there were some content but useful content was empty
    if (is_wstring_empty(f_content) == 1)
    {
        wcscpy_s(error_desc, 256, L"\nError: empty c-file submitted. Pls, check!\n");
        return DECR_ERROR_EMPTYFILE;
    }

    /* Get members bits info */
    //bitsInfo_s = w_compute_bits_info(f_content, dec_history_data->circle_name, decr_cfg_f_path, member_id, is_first_usage, error_str);

    requested_bits_count = dec_history_data->bits_used;

    size_t r_p_c = 0; // requested pads count

    requested_pads_list = get_list_of_requested_pads_ID_history(dec_history_data->circle_name, dec_history_data->first_pad, dec_history_data->last_pad, &r_p_c, error_str);

    // Prepare some data
    size_t cfg_offset = 0;
    char* firstPadPath = CALLOC(sizeof(char) * _MAX_PATH, 1);

    /* Get the first pad of particular member.                                        */
    /* Due to array indexing starts from 0, so member ID should be (-1)               */
    /* For creating encryption fresh config file we ALWAYS using member's first pad!  */

    /* Build the first pad full path!                                                 */
    strcat_s(firstPadPath, _MAX_PATH, circle_s.pads_path);
    strcat_s(firstPadPath, _MAX_PATH, "\\");

    char padIndex[11];
    _ui64toa_s(dec_history_data->first_pad, padIndex, sizeof(padIndex), 10);
    strcat_s(firstPadPath, _MAX_PATH, padIndex);
    strcat_s(firstPadPath, _MAX_PATH, ".txt");

    char* historical_pps = ALLOC(sizeof(char) * 42 + 1);
    memcpy_s(historical_pps, 43, dec_history_data->pps, 42);
    historical_pps[42] = '\0';
    cfg_offset = find_str_in_file(firstPadPath, historical_pps);
    decr_cfg_s = prepare_enc_cfg_file_data(circle_s.pads_path, requested_pads_list, dec_history_data->member_number, cfg_offset, error_str);

    /* Now we should open each requested pad and merge thier content into one.        */
    if (r_p_c >= 1)
    {
        used_pads_content = CALLOC(sizeof(char) * r_p_c * PAD_LEN + 1, 1);
        int res = merge_requested_pads(used_pads_content, requested_pads_list, r_p_c, circle_s.pads_path, cfg_offset, error_desc);
        if (res != 0)
        {
            //strcpy_s(error_desc, 256, "\nError: When merging Pads.\n");
            return DECR_ERROR_COMMON;
        }
    }
    else
    {
        wcscpy_s(error_desc, 256, L"\nWarning: There is no Pads to merge.\n");
        return DECR_ERROR_WRONGPADSCOUNT;
    }

    // Get Prog&PPS files raw content
    char* prog_pps_content = get_pps_and_prog_file_contents(dec_history_data->circle_name, circle_s.pads_path, decr_cfg_s.programNumber, error_str);

    /* First of all we need to remove 9th control bit */

    // Get PPS from any Prog file since PPS is the same for all
    char* prog_file_content = get_dynamic_pps_and_prog_file_contents(dec_history_data->circle_name, circle_s.pads_path, error_str);

    // Get 9th insertion pos
    char last_bits[27]; // allocate buffer for 26 bits plus null terminator
    last_26_bits(last_bits, prog_file_content, strlen(prog_file_content));
    size_t c9_insrt_pos = bindec(last_bits);
    // wraparound it
    if (c9_insrt_pos > (wcslen(f_content) - 1))
    {
        c9_insrt_pos = c9_insrt_pos % (wcslen(f_content) - 1);
    }

    const wchar_t C9_wchar = f_content[c9_insrt_pos];

    // Remove C9 char
    remove_spec_char(f_content, c9_insrt_pos);

    size_t* huge_dynamic_pps_positions = ALLOC(sizeof(size_t) * 7);
    get_dynamic_pps_positions_by_9th_char(huge_dynamic_pps_positions, prog_file_content, C9_wchar, error_str);

    /*Find & Remove PPS*/
    /* Remove PPS into its position.	                 	                          */
    //char* pps_insertion_point_str = ALLOC(sizeof(char) * 26 + 1);
    //size_t pps_insertion_points_decimal[7] = { 0 };

    //for (size_t i = 0; i < 7; i++)
    //{
    //    pps_get_nth_position(pps_insertion_point_str, i, prog_pps_content);
    //    pps_insertion_points_decimal[i] = bindec(pps_insertion_point_str);
    //}

    wchar_t* p_p_s = ALLOC(sizeof(wchar_t) * 7 + 2);

    // We are getting real PPS 7 spec chars from c-text
    //wchar_t* p_p_s = get_PPS_by_point(f_content, pps_insertion_point_dec);
    //get_PPS_by_points_array(p_p_s, f_content, pps_insertion_points_decimal);
    remove_dynamic_PPS_by_points_array(p_p_s, f_content, huge_dynamic_pps_positions, C9_wchar);

    /* Delete special char */
    remove_spec_char(f_content, decr_cfg_s.specialCharPosition);

    // Doing reverse PSP
    wchar_t* reversedContent = reverse_PSP_decr(f_content, decr_cfg_s.startPoint, decr_cfg_s.jumpPoint);

    // Convert spec char to their six-bits represent
    char* binary_content = ALLOC(sizeof(char) * (wcslen(reversedContent) * 6 + 1));
    get_binary_from_c_text(reversedContent, decr_cfg_s, prog_pps_content, binary_content);

    /* Get logical op method from program file content.It is a value of 411-th bit.   */
    if (*(prog_pps_content + 3254) - '0' == 1)
    {
        // Do XOR
        fmakeXOR(binary_content, used_pads_content);
    }
    else
    {
        // Do XNOR
        fmakeXNOR(binary_content, used_pads_content);
    }

    // Parsing file name in order to get info about added bits, orig ext and etc...
    wchar_t** file_name_parsed = parse_file_name(f_name, L".");

    /* Bits to be removed */
    bits_removed = wcstoul(file_name_parsed[1], NULL, 10);

    /* File's original extension */
    size_t extLen = wcslen(file_name_parsed[2]);
    wmemcpy(orig_extension, file_name_parsed[2], extLen);
    orig_extension[extLen] = '\0';

    /* Remove added bits from final binary file */
    size_t bcLen = 0;
    bcLen = strlen(binary_content);

    //char* withoutAddedBitsContent = ALLOC(sizeof(char) * (bcLen - bits_removed + 1));

    //memcpy(withoutAddedBitsContent, binary_content + bits_removed, bcLen);
    //withoutAddedBitsContent[bcLen] = '\0';

    FREE(f_content);
    FREE(reversedContent);

    // Convert Binary to File
    if (binary_content[bits_removed] == '0')
    {
        binary_content[bits_removed] = '1';
        isZero = 1;
    }

    mpz_init_set_str(res, binary_content + bits_removed, 2);
    FREE(binary_content);

    unsigned char* rawContent = (unsigned char*)mpz_export(NULL, &result, 1, 1, 0, 0, res);

    if (isZero == 1)
    {
        unsigned char newCh = (char)((int)rawContent[0] - 128);
        rawContent[0] = newCh;
        isZero = 0;
    }

    // Build decrypted file name
    char* final_file_name = CALLOC(sizeof(char) * _MAX_FNAME, 1);
    //strcat_s(final_file_name, _MAX_FNAME, "/");
    strcat_s(final_file_name, _MAX_FNAME, final_name);
    strcat_s(final_file_name, _MAX_FNAME, ".");

    char* origExt = ALLOC(sizeof(char) * wcslen(orig_extension) + 1);
    wcstombs_s(NULL, origExt, wcslen(orig_extension) + 1, orig_extension, wcslen(orig_extension) + 1);

    strcat_s(final_file_name, _MAX_FNAME, origExt);

    // Write to file
    write_plain_txt_to_file(final_file_name, rawContent, result, error_str);

    return DECR_ERROR_OK;
}


SPAE_DLL_EXPIMP void SPAE_CALL create_file(char* content)
{
    int open_status;

    /*Accept the file and try to open it*/
    FILE* fp1 = NULL;
    /*Trying to open the file*/
    fp1 = open_file("binary.txt", FILE_MODE_WRITE, &open_status);

    fwrite(content, 1, strlen(content), fp1);

    fclose(fp1);
    /*if (open_status != 0)
    {
        strcpy_s(error_desc, 256, "\nError: When trying to open a Circle cfg file.\n");
        return CIRCLE_ERROR_OPENF;
    }*/
}

SPAE_DLL_EXPIMP void SPAE_CALL create_file_with_name(char* content, char* name)
{
    int open_status;

    /*Accept the file and try to open it*/
    FILE* fp1 = NULL;
    /*Trying to open the file*/
    fp1 = open_file(name, FILE_MODE_WRITE, &open_status);

    fwrite(content, 1, strlen(content), fp1);
    /*if (open_status != 0)
    {
        strcpy_s(error_desc, 256, "\nError: When trying to open a Circle cfg file.\n");
        return CIRCLE_ERROR_OPENF;
    }*/
}


SPAE_DLL_EXPIMP int SPAE_CALL get_last_used_pad_id_encr(char* enc_cfg_f_path, char* error_desc)
{
    int count = 0;
    // Check if cfg file exists
    if (0 != is_file_exists(enc_cfg_f_path))
    {
        return -1;
    }

    size_t used_bits_count = get_option_from_enc_cfg(enc_cfg_f_path, "usedBitsCount", error_desc).int_value;
    count = (int)used_bits_count / PAD_LEN + 1; // How many full pad is it + 1

    return count;
}

SPAE_DLL_EXPIMP circle_error_t SPAE_CALL add_new_member(const char* c_name, char* m_name, int pos, char* error_desc)
{
#if _DEBUG
    FILE* log_file = NULL;
    int open_status;
    log_file = open_file("log_circles.txt", FILE_MODE_APLUS, &open_status);

    if (open_status != 0)
    {
        strcpy_s(error_desc, 256, "\nError: When trying to open a Log file.\n");
        return CIRCLE_ERROR_OPENF;
    }

    // Start log file
    write_log(log_file, "------Action: Add New Member into circle------ Time: ");
    write_log(log_file, get_current_time());
    write_log(log_file, "\n");
    write_log(log_file, "In which circle to add: ");
    write_log(log_file, c_name);
    write_log(log_file, "\n");
    write_log(log_file, "Member name: ");
    write_log(log_file, m_name);
    write_log(log_file, "\n");
    int_write_log(log_file, "Member position in circle: ", pos);
    write_log(log_file, "\n");

#endif

    // Check if Circle locked
    if (0 == is_circle_locked(c_name, error_desc))
    {
        strcpy_s(error_desc, 256, "\nError: Circle is locked!\n");
        return CIRCLE_ERROR_CIRCLE_LOCKED;
    }

#if _DEBUG
    write_log(log_file, "Circle is not locked so we can add new members!");
    write_log(log_file, "\n");
#endif

#if _DEBUG
    fflush(log_file);
    fclose(log_file);
#endif

    int found = 0;

    FILE* fp1 = NULL;
    fopen_s(&fp1, CIRCLE_FILE_NAME, "ab+");
    if (fp1 == NULL)
    {
        strcpy_s(error_desc, 256, "\nError: When trying to open a Circle cfg file.\n");
        return CIRCLE_ERROR_OPENF;
    }

    struct circle buffer;
    fseek(fp1, 0, SEEK_SET);   // move file position indicator to beginning of file
    while (fread(&buffer, sizeof(struct circle), 1, fp1) == 1)
    {
        if (strcmp(c_name, buffer.circle_name) == 0)
        {
            struct circle circleData = { 0 };
            strcpy_s(circleData.circle_name, sizeof(circleData.circle_name), buffer.circle_name);
            strcpy_s(circleData.config_path, sizeof(circleData.config_path), buffer.config_path);
            strcpy_s(circleData.pads_path, sizeof(circleData.pads_path), buffer.pads_path);

            circleData.mbr.position_num = pos;
            strcpy_s(circleData.mbr.first_name, sizeof(circleData.mbr.first_name), m_name);

            if (fseek(fp1, 0L, SEEK_CUR) != 0) {

            }

            if (fwrite(&circleData, sizeof(struct circle), 1, fp1) != 1)
            {
                strcpy_s(error_desc, 256, "\nCannot write new Member data into cfg.\n");

                fflush(fp1);
                fclose(fp1);
                return CIRCLE_ERROR_WRITEF;
            }

            found = 1;
            fflush(fp1);
            fclose(fp1);

            return CIRCLE_ERROR_OK;
        }
    }

    if (!found)
    {
        fflush(fp1);
        fclose(fp1);
        strcpy_s(error_desc, 256, "No record(s) found with the requested Circle name.");
        return CIRCLE_ERROR_NOCIRCLE;
    }

    return CIRCLE_ERROR_OK;
}


SPAE_DLL_EXPIMP circle_error_t SPAE_CALL delete_member(const char* c_name, int mem_pos, char* error_desc)
{
    int error = 0;
    int found = 0;

    FILE* fp1 = NULL;
    fopen_s(&fp1, CIRCLE_FILE_NAME, "rb");
    if (fp1 == NULL)
    {
        return CIRCLE_ERROR_OPENF;
    }

    FILE* ftmp = NULL;
    fopen_s(&ftmp, CIRCLE_TMP_FILE_NAME, "wb");
    if (ftmp == NULL)
    {
        return CIRCLE_ERROR_OPENF;
    }

    struct circle buffer;
    fseek(fp1, 0, SEEK_SET);   // move file position indicator to beginning of file
    while (fread(&buffer, sizeof(struct circle), 1, fp1) == 1)
    {
        if (strcmp(c_name, buffer.circle_name) == 0)
        {
            if (buffer.mbr.position_num == mem_pos)
            {
                //printf("A record with requested name found and deleted.\n\n");
                found = 1;
            }
            else
            {
                fwrite(&buffer, sizeof(struct circle), 1, ftmp);
            }
        }
        else
        {
            fwrite(&buffer, sizeof(struct circle), 1, ftmp);
        }
    }
    if (!found)
    {
        strcpy_s(error_desc, 256, "No record(s) found with the requested Member name.");
        error = 1;
    }

    fflush(fp1);
    fclose(fp1);
    fclose(ftmp);

    if (remove(CIRCLE_FILE_NAME) == -1)
    {
        return CIRCLE_ERROR_DELETEF;
    }

    int result = rename(CIRCLE_TMP_FILE_NAME, CIRCLE_FILE_NAME);
    if (result != 0)
    {
        return CIRCLE_ERROR_RENAMEF;
    }

    if (error)
    {
        return CIRCLE_ERROR_NOMEMBER;
    }

    return CIRCLE_ERROR_OK;
}

SPAE_DLL_EXPIMP circle_error_t SPAE_CALL lock_circle(const char* c_name, char* error_desc)
{
    int error = 0;
    int found = 0;

    FILE* fp1 = NULL;
    fopen_s(&fp1, CIRCLE_FILE_NAME, "rb");
    if (fp1 == NULL)
    {
        return CIRCLE_ERROR_OPENF;
    }

    FILE* ftmp = NULL;
    fopen_s(&ftmp, CIRCLE_TMP_FILE_NAME, "wb");
    if (ftmp == NULL)
    {
        return CIRCLE_ERROR_OPENF;
    }

    struct circle buffer;
    fseek(fp1, 0, SEEK_SET);   // move file position indicator to beginning of file
    while (fread(&buffer, sizeof(struct circle), 1, fp1) == 1)
    {
        if (strcmp(c_name, buffer.circle_name) == 0 && buffer.master == 1)
        {
            if (buffer.locked == 1)
            {
                fclose(fp1);
                fclose(ftmp);
                strcpy_s(error_desc, 256, "\nCircle already locked.\n");

                if (remove(CIRCLE_TMP_FILE_NAME) == -1)
                {
                    return CIRCLE_ERROR_DELETEF;
                }

                return CIRCLE_ERROR_CIRCLE_LOCKED;
            }

            struct circle circleData = { 0 };
            strcpy_s(circleData.circle_name, sizeof(circleData.circle_name), buffer.circle_name);
            strcpy_s(circleData.config_path, sizeof(circleData.config_path), buffer.config_path);
            strcpy_s(circleData.pads_path, sizeof(circleData.pads_path), buffer.pads_path);
            circleData.master = 1;
            circleData.locked = 1; //Lock the Circle

            circleData.mbr.position_num = buffer.mbr.position_num;
            strcpy_s(circleData.mbr.first_name, sizeof(circleData.mbr.first_name), buffer.mbr.first_name);

            fwrite(&circleData, sizeof(struct circle), 1, ftmp);

            found = 1;
        }
        else
        {
            fwrite(&buffer, sizeof(struct circle), 1, ftmp);
        }
    }
    if (!found)
    {
        strcpy_s(error_desc, 256, "\nNo Circle found with the requested name.\n");
        error = 1;
    }

    fflush(fp1);
    fclose(fp1);
    fclose(ftmp);

    if (remove(CIRCLE_FILE_NAME) == -1)
    {
        return CIRCLE_ERROR_DELETEF;
    }

    int result = rename(CIRCLE_TMP_FILE_NAME, CIRCLE_FILE_NAME);
    if (result != 0)
    {
        return CIRCLE_ERROR_RENAMEF;
    }

    if (error)
    {
        return CIRCLE_ERROR_NOMEMBER;
    }

    return CIRCLE_ERROR_OK;
}

int inline is_wstring_empty(wchar_t* s)
{
    if (wcscmp(s, L"") == 0)
    {
        return 1;
    }
    else
    {
        return 0;
    }
}


struct bitsInfo compute_bits_info(char* binContent, char* circle, char* enc_cfg_f_path, size_t member_id, unsigned int is_first_call, char* error_desc)
{
    struct bitsInfo bits_i = { 0 };
    struct circle circle_s = { 0 };

    const size_t c_len = strlen(binContent);

    // Set requested bits count. It does not matter is this first call for enc or not
    bits_i.requestedBitsCount = c_len;

    // Get members total count in the Circle
    int members_count = get_circle_members_count(circle, error_desc);

    // Get overall data about the Circle
    get_circle_data_by_name(&circle_s, circle, error_desc);

    // Get the member total Pads count
    size_t _member_pads_count = get_member_total_pads_count(member_id, circle_s.pads_path, members_count, error_desc);

    if (_member_pads_count == 0)
    {
        // Return error with all fileds set to 0 except requested filed set to needed pads count
        bits_i.availableBitsCount = 0;
        bits_i.requestedBitsCount = 0;
        bits_i.totalBitsCount = 0;
        bits_i.usedBitsCount = 0;

        return bits_i;
    }

    // Total bits for member
    size_t _member_total_bits_count = _member_pads_count * PAD_LEN;

    if (is_first_call > 0)
    {
        // It is a first call of enc

        // Set total bits count
        bits_i.totalBitsCount = _member_total_bits_count;

        // Check if there are enough bits for enc
        if ((_member_total_bits_count - SEEK_NUMBER) <= c_len)
        {
            size_t _addit_P_count = (c_len - _member_total_bits_count + SEEK_NUMBER) / PAD_LEN + 1;

            // Return error with all fileds set to 0 except requested filed set to needed pads count
            bits_i.availableBitsCount = 0;
            bits_i.requestedBitsCount = _addit_P_count * members_count;
            bits_i.totalBitsCount = 0;
            bits_i.usedBitsCount = 0;

            return bits_i;
        }

        // Set available bits count
        bits_i.availableBitsCount = _member_total_bits_count; // total - requestedbits
        //bits_i.availableBitsCount = _member_total_bits_count - c_len; // total - requestedbits

        // Set used bits
        bits_i.usedBitsCount = 0; // the same as requestedBitsCount
        //bits_i.usedBitsCount = c_len; // the same as requestedBitsCount
    }

    else
    {
        /* Since there is enc.cfg it means it is a not first enc process, so we need to   */
        /* get used bits count from the enc.cfg file.                                     */
        size_t used_Bits_Count = get_option_from_enc_cfg(enc_cfg_f_path, "usedBitsCount", error_desc).int_value;

        /* Get available bits from the config file                                        */
        //size_t available_Bits = get_option_from_enc_cfg(enc_cfg_f_path, "availableBitsCount", error_desc).int_value;
        size_t available_Bits = _member_total_bits_count - used_Bits_Count;

        // Check if there are enough bits for enc
        if ((available_Bits - SEEK_NUMBER) <= c_len)
        {
            size_t _addit_P_count = (c_len - available_Bits + SEEK_NUMBER) / PAD_LEN + 1;

            // Return error with all fileds set to 0 except requested filed set to needed pads count
            bits_i.availableBitsCount = 0;
            bits_i.requestedBitsCount = _addit_P_count * members_count;
            bits_i.totalBitsCount = 0;
            bits_i.usedBitsCount = 0;

            return bits_i;
        }

        //size_t available_Bits = _member_total_bits_count - used_Bits_Count;

         // Set total bits count
        bits_i.totalBitsCount = _member_total_bits_count;

        // Set available bits count
        //bits_i.availableBitsCount = _member_total_bits_count - (used_Bits_Count + c_len); // total - requestedbits
        bits_i.availableBitsCount = available_Bits; // total - requestedbits

        // Set used bits
        bits_i.usedBitsCount = used_Bits_Count;

    }

    return bits_i;
}

struct bitsInfo w_compute_bits_info(wchar_t* binContent, char* circle, char* enc_cfg_f_path, size_t member_id, unsigned int is_first_call, char* error_desc)
{
    struct bitsInfo bits_i = { 0 };
    struct circle circle_s = { 0 };

    size_t c_len = wcslen(binContent) + 7;

    // Set requested bits count. It does not matter is this first call for enc or not
    bits_i.requestedBitsCount = (c_len - SPEC_PPS_LEN - SPEC_CHAR_LEN) * 6;

    // Get members total count in the Circle
    int members_count = get_circle_members_count(circle, error_desc);

    if (members_count <= 0)
    {
        bits_i.requestedBitsCount = 0;
        return bits_i;
    }

    // Get overall data about the Circle
    get_circle_data_by_name(&circle_s, circle, error_desc);

    // Get the member total Pads count
    size_t _member_pads_count = get_member_total_pads_count(member_id, circle_s.pads_path, members_count, error_desc);

    // Total bits for member
    size_t _member_total_bits_count = _member_pads_count * PAD_LEN;

    if (is_first_call > 0)
    {
        // It is a first call of enc

        // Set total bits count
        bits_i.totalBitsCount = _member_total_bits_count;

        // Check if there are enough bits for enc
        if (_member_total_bits_count <= c_len)
        {
            size_t _addit_P_count = (c_len - _member_total_bits_count) / PAD_LEN + 1;

            // Return error with all fileds set to 0 except requested filed set to needed pads count
            bits_i.availableBitsCount = 0;
            bits_i.requestedBitsCount = _addit_P_count;
            bits_i.totalBitsCount = 0;
            bits_i.usedBitsCount = 0;

            return bits_i;
        }

        // Set available bits count
        bits_i.availableBitsCount = _member_total_bits_count;
        //bits_i.availableBitsCount = _member_total_bits_count - bits_i.requestedBitsCount; // total - requestedbits

        // Set used bits
        bits_i.usedBitsCount = 0;
        //bits_i.usedBitsCount = bits_i.requestedBitsCount; // the same as requestedBitsCount
    }

    else
    {
        /* Since there is enc.cfg it means it is a not first enc process, so we need to   */
        /* get used bits count from the enc.cfg file.                                     */
        size_t used_Bits_Count = get_option_from_enc_cfg(enc_cfg_f_path, "usedBitsCount", error_desc).int_value;

        /* Get available bits from the config file                                        */
        size_t available_Bits = get_option_from_enc_cfg(enc_cfg_f_path, "availableBitsCount", error_desc).int_value;

        // Check if there are enough bits for dec
        if (available_Bits <= c_len)
        {
            size_t _addit_P_count = (c_len - available_Bits) / PAD_LEN + 1;

            // Return error with all fileds set to 0 except requested filed set to needed pads count
            bits_i.availableBitsCount = 0;
            bits_i.requestedBitsCount = _addit_P_count;
            bits_i.totalBitsCount = 0;
            bits_i.usedBitsCount = 0;

            return bits_i;
        }

        // Set total bits count
        bits_i.totalBitsCount = _member_total_bits_count;

        // Set available bits count
        bits_i.availableBitsCount = available_Bits;
        //bits_i.availableBitsCount = _member_total_bits_count - (used_Bits_Count + bits_i.requestedBitsCount); // total - requestedbits

        // Set used bits
        bits_i.usedBitsCount = used_Bits_Count;
        //bits_i.usedBitsCount = used_Bits_Count + bits_i.requestedBitsCount;

    }

    return bits_i;
}

size_t* get_list_of_requested_pads_ID(char* circle, size_t mID, size_t requestedBitsCount, size_t* requestPadsCount, char* error_desc)
{
    if (mID < 0)
    {
        strcpy_s(error_desc, 256, "\nWhy member ID is less than 0??? Pls, check!\n");
        return NULL;
    }

    // Get members total count in the Circle
    int members_count = get_circle_members_count(circle, error_desc);

    // Get overall data about the Circle
    struct circle circle_s = { 0 };
    get_circle_data_by_name(&circle_s, circle, error_desc);

    size_t member_pads_count = 0;
    size_t* _mem_p_list_id = get_member_pads_indexes(circle_s, mID, members_count, &member_pads_count);

    if (member_pads_count <= 0)
    {
        strcpy_s(error_desc, 256, "\nMember has no any Pad available. Pls, check.\n");
        return NULL;
    }

    /* How many full pad requested */
    size_t requestdFullPadsCount = howManyFullPadsIsIt(requestedBitsCount);
    *requestPadsCount = requestdFullPadsCount + 1; // When first usage always add +1 Pad

    // First usage, so we can just return diff of pads full list & available pads full list
    size_t* reqList = ALLOC(sizeof(size_t) * (*requestPadsCount));
    memcpy_s(reqList, *requestPadsCount * sizeof(*_mem_p_list_id), &_mem_p_list_id[0], *requestPadsCount * sizeof(*_mem_p_list_id));

    return reqList;
}


size_t* get_list_of_requested_pads_ID_history(char* circle, size_t first_p, size_t last_p, size_t* req_pads_count, char* error_desc)
{
    // Get members total count in the Circle
    int members_count = get_circle_members_count(circle, error_desc);

    /* How many full pad requested */
    size_t requestdFullPadsCount = (last_p - first_p) / members_count + 1;
    *req_pads_count = requestdFullPadsCount;
    // First usage, so we can just return diff of pads full list & available pads full list
    size_t* reqList = ALLOC(sizeof(size_t) * (requestdFullPadsCount));

    size_t start_index = first_p;
    for (size_t i = 0; i < requestdFullPadsCount; i++)
    {
        reqList[i] = start_index;
        start_index += members_count;
    }

    return reqList;
}


size_t* get_list_of_requested_pads_ID_progressive(char* circle, size_t first_p, size_t requestedBitsCount, size_t* req_pads_count, char* error_desc)
{
    // Get members total count in the Circle
    int members_count = get_circle_members_count(circle, error_desc);

    /* How many full pad requested */
    size_t requestdFullPadsCount = howManyFullPadsIsIt(requestedBitsCount) + 1;
    *req_pads_count = requestdFullPadsCount;
    // First usage, so we can just return diff of pads full list & available pads full list
    size_t* reqList = ALLOC(sizeof(size_t) * (requestdFullPadsCount));

    size_t start_index = first_p;
    for (size_t i = 0; i < requestdFullPadsCount; i++)
    {
        reqList[i] = start_index;
        start_index += members_count;
    }

    return reqList;
}

size_t* get_requested_pads_list(char* circle, size_t mID, size_t requestedBitsCount, size_t usedBitsCount, size_t avBitsCount, size_t* requestPadsCount, char* error_desc)
{
    if (mID < 0)
    {
        strcpy_s(error_desc, 256, "\nWhy member ID is less than 0??? Pls, check!\n");
        return NULL;
    }

    // Get members total count in the Circle
    int members_count = get_circle_members_count(circle, error_desc);

    // Get overall data about the Circle
    struct circle circle_s = { 0 };
    get_circle_data_by_name(&circle_s, circle, error_desc);

    size_t member_pads_count = 0;
    size_t* _mem_p_list_id = get_member_pads_indexes(circle_s, mID, members_count, &member_pads_count);

    if (member_pads_count <= 0)
    {
        strcpy_s(error_desc, 256, "\nMember has no any Pad available. Pls, check.\n");
        return NULL;
    }

    /* How many full pad requested */
    size_t requestdFullPadsCount = howManyFullPadsIsIt(requestedBitsCount);
    int availablePartlyPadIndex = get_member_partially_available_Pad_index(_mem_p_list_id, member_pads_count, avBitsCount);
    size_t* availableFullPadsList = get_member_full_pad_IDs(_mem_p_list_id, member_pads_count, avBitsCount);

    if (requestdFullPadsCount == 0 && availablePartlyPadIndex > -1)
    {
        // So, requested bits count less than PAD_SIZE
        // Let's try to use partly available pad's bits if their count is enough for that
        size_t avBits = get_available_bits_count_of_part_pad(usedBitsCount);

        if (avBits > requestedBitsCount)
        {
            // There is enough bits in pivot pad. 
            // So we can use ONLY that partly pad.
            *requestPadsCount = 1;
            size_t* reqList = ALLOC(sizeof(size_t) * 1);
            memcpy_s(reqList, *requestPadsCount * sizeof(*_mem_p_list_id), &_mem_p_list_id[availablePartlyPadIndex], *requestPadsCount * sizeof(*_mem_p_list_id));
            return reqList;
        }
        else
        {
            // There is not enough bits ONLY in partly pad.
            // So, we should return 2 pads list starting from that
            *requestPadsCount = 2;
            size_t* reqList = ALLOC(sizeof(size_t) * 2);
            memcpy_s(reqList, *requestPadsCount * sizeof(*_mem_p_list_id), &_mem_p_list_id[availablePartlyPadIndex], *requestPadsCount * sizeof(*_mem_p_list_id));
            return reqList;
        }
    }

    if (requestdFullPadsCount == 0 && availablePartlyPadIndex == -1)
    {
        // There is no partly pad available but requested less than PAD_SIZE
        // So we can return next full pad
        *requestPadsCount = 1;
        size_t* reqList = ALLOC((long)(*requestPadsCount) * sizeof(size_t));
        memcpy_s(reqList, *requestPadsCount * sizeof(*availableFullPadsList), &availableFullPadsList[0], *requestPadsCount * sizeof(*availableFullPadsList));
        return reqList;

    }

    if (requestdFullPadsCount > 0 && availablePartlyPadIndex > -1)
    {
        // There is at least one full pad requested and we have partly pad available
        size_t avBits = get_available_bits_count_of_part_pad(usedBitsCount);
        // Trying to understand is there enough bits in partly pad so we can return
        // that pad and the next full pads requested Or we should return 
        // partly pad + requested full pads + 1 additional pad.
        if (avBits < (requestedBitsCount % PAD_LEN))
        {
            // There is not enough bits in part pad
            *requestPadsCount = requestdFullPadsCount + 1 + 1;
            size_t* reqList = ALLOC((long)(*requestPadsCount) * sizeof(size_t));
            memcpy_s(reqList, *requestPadsCount * sizeof(*_mem_p_list_id), &_mem_p_list_id[availablePartlyPadIndex], *requestPadsCount * sizeof(*_mem_p_list_id));
            return reqList;
        }
        else
        {
            *requestPadsCount = requestdFullPadsCount + 1;
            size_t* reqList = ALLOC((long)(*requestPadsCount) * sizeof(size_t));
            memcpy_s(reqList, *requestPadsCount * sizeof(*_mem_p_list_id), &_mem_p_list_id[availablePartlyPadIndex], *requestPadsCount * sizeof(*_mem_p_list_id));
            return reqList;
        }
    }

    if (requestdFullPadsCount > 0 && availablePartlyPadIndex == -1)
    {
        // There is at least one full pad requested and we have not partly pad available
        *requestPadsCount = requestdFullPadsCount;
        size_t* reqList = ALLOC((long)(*requestPadsCount) * sizeof(size_t));
        memcpy_s(reqList, *requestPadsCount * sizeof(*availableFullPadsList), &availableFullPadsList[0], *requestPadsCount * sizeof(*availableFullPadsList));
        return reqList;
    }

    return NULL;
}

size_t* collect_list_of_requested_pads_ID(char* circle, size_t mID, size_t requestedBitsCount, size_t availableBitsCount, size_t usedBitsCount, size_t* requestPadsCount, size_t* enc_cfg_offset, char* error_desc)
{
    /* Get completely available pad list.This is when we are excluding pads were used */
    if (mID < 0)
    {
        strcpy_s(error_desc, 256, "\nWhy member ID is less than 0??? Pls, check!\n");
        return NULL;
    }

    // Get members total count in the Circle
    int members_count = get_circle_members_count(circle, error_desc);

    // Get overall data about the Circle
    struct circle circle_s = { 0 };
    get_circle_data_by_name(&circle_s, circle, error_desc);

    size_t member_pads_count = 0;
    size_t* _mem_p_list_id = get_member_pads_indexes(circle_s, mID, members_count, &member_pads_count);

    if (member_pads_count <= 0)
    {
        strcpy_s(error_desc, 256, "\nMember has no any Pad available. Pls, check.\n");
        return NULL;
    }

    /* Get partially available pad list if there is.                                  */
    int partlyPadIndex = get_member_partially_available_Pad_index(_mem_p_list_id, member_pads_count, availableBitsCount);

    /* If there is partly pad so we need to get used bits count and use as an offset */
    if (_mem_p_list_id != NULL && partlyPadIndex > -1)
    {
        size_t availableBitsInPartlyPad = get_available_bits_count_of_part_pad(usedBitsCount);
        *enc_cfg_offset = get_used_bits_count_of_part_pad(usedBitsCount);

        if (availableBitsInPartlyPad <= 100)
        {
            // There are no enough count of bits for generating PPS and etc...
            // so we mark this pad as used and return next one.
            usedBitsCount += availableBitsInPartlyPad;
            *enc_cfg_offset = 0;

        }
    }

    size_t* list = get_requested_pads_list(circle, mID, requestedBitsCount, usedBitsCount, availableBitsCount, requestPadsCount, error_desc);

    return list;
}



size_t* get_member_pads_indexes(struct circle c_s, size_t m_ID, size_t membs_total_count, size_t* count)
{
    size_t pads_count = 0;

    dirlist(c_s.pads_path, "txt", &pads_count);

    size_t* member_pads_ID_list = ALLOC(sizeof(size_t) * pads_count);

    /* Due to array indexing starts from 0, so member ID should be (-1) */
    size_t memberID = m_ID - 1;

    for (size_t i = m_ID; i <= pads_count; i += membs_total_count)
    {
        member_pads_ID_list[*count] = i;
        (*count)++;
    }

    return member_pads_ID_list;
}

SPAE_DLL_EXPIMP enc_error_t SPAE_CALL dev_encrypt_file(char* f_name, char* circle, char* enc_cfg_f_path, size_t member_id, unsigned int is_first_usage, wchar_t* where_to_save, wchar_t* encrypted_f_name, wchar_t* error_msg)
{
    size_t requested_bits_count = 0;
    size_t added_bits_count     = 0;
    size_t* requested_pads_list = NULL;

    struct circle circle_s         = { 0 };
    struct bitsInfo bitsInfo_s     = { 0 };
    struct encryptionCfg enc_cfg_s = { 0 };

    char* used_pads_content = NULL;

    char* error_desc = ALLOC(sizeof(char) * 256);
    char* log_str    = ALLOC(sizeof(char) * 1024);

    int open_status;

    /*Accept the file and try to open it*/
    FILE* log_file = NULL;
    /*Trying to open the file*/
    log_file = open_file("log_encr.txt", FILE_MODE_APLUS, &open_status);

    if (open_status != 0)
    {
        strcpy_s(error_desc, 256, "\nError: When trying to open a Log file.\n");
        return CIRCLE_ERROR_OPENF;
    }

    // Start log file
    write_log(log_file, "------Starting ENCRYPTION for below data------\n");
    strcpy_s(log_str, 1024, "Encrypted file name is: ");
    write_log(log_file, log_str);
    write_log(log_file, f_name);
    write_log(log_file, "\n");

    strcpy_s(log_str, 1024, "Encryption for Circle: ");
    write_log(log_file, log_str);
    write_log(log_file, circle);
    write_log(log_file, "\n");

    // Get some info about the circle
    get_circle_data_by_name(&circle_s, circle, error_desc);

    // Log
    strcpy_s(log_str, 1024, "Circle config path: ");
    write_log(log_file, log_str);
    write_log(log_file, circle_s.config_path);
    write_log(log_file, "\n");

    strcpy_s(log_str, 1024, "Circle pads path: ");
    write_log(log_file, log_str);
    write_log(log_file, circle_s.pads_path);
    write_log(log_file, "\n");

    write_log(log_file, "\n------Starting File To Binary function------\n");
    // Convert to binary
    char* binary_content = file_to_binary_enc(f_name, &requested_bits_count, &added_bits_count, error_msg);

    if (binary_content == NULL)
    {
        return ENC_ERROR_HUGEFILE;
    }

    int_write_log(log_file, "Requested Bits Count: ", requested_bits_count);
    int_write_log(log_file, "Added Bits Count: ", added_bits_count);

    /* Get members bits info */
    write_log(log_file, "\n------Starting collect bits info ------\n");
    bitsInfo_s = compute_bits_info(binary_content, circle, enc_cfg_f_path, member_id, is_first_usage, error_desc);

    int_write_log(log_file, "Member ID: ", member_id);
    write_log(log_file, "Encryption config file path: ");
    write_log(log_file, enc_cfg_f_path);
    write_log(log_file, "\n");

    int_write_log(log_file, "Total Bits Count: ", bitsInfo_s.totalBitsCount);
    int_write_log(log_file, "Available Bits Count: ", bitsInfo_s.availableBitsCount);
    int_write_log(log_file, "Used Bits Count: ", bitsInfo_s.usedBitsCount);
    int_write_log(log_file, "Requested Bits Count: ", bitsInfo_s.requestedBitsCount);

    // Check if there are enough bits for enc
    if (bitsInfo_s.availableBitsCount == 0 && bitsInfo_s.totalBitsCount == 0 && bitsInfo_s.usedBitsCount == 0 &&
        bitsInfo_s.requestedBitsCount > 0)
    {
        size_t _addit_P_count = bitsInfo_s.requestedBitsCount;
        wchar_t* how_many = int2wstr(_addit_P_count);
        wcscpy_s(error_msg, 256, how_many);
        return ENC_ERROR_FEWPADS;
    }

    size_t r_p_c = 0; // requested pads count
    size_t enc_cfg_offset = 0; // requested pads count

    if (is_first_usage > 0)
    {
        write_log(log_file, "\n------It is First usage ------\n");
        requested_pads_list = get_list_of_requested_pads_ID(circle, member_id, requested_bits_count, &r_p_c, error_desc);

        // Prepare some data
        enc_cfg_s = prepare_enc_cfg_file_data(circle_s.pads_path, requested_pads_list, member_id, 0, error_desc);
    }
    else
    {
        write_log(log_file, "\n------Starting collect list of requested pads ID ------\n");
        requested_pads_list = collect_list_of_requested_pads_ID(circle, member_id, requested_bits_count, bitsInfo_s.availableBitsCount, bitsInfo_s.usedBitsCount, &r_p_c, &enc_cfg_offset, error_desc);

        if (r_p_c >= 1)
        {
            int_write_log(log_file, "Requested Pads ID count: ", r_p_c);
            int_write_log(log_file, "Offset for Encryption config file: ", enc_cfg_offset);
            for (size_t i = 0; i < r_p_c; i++)
            {
                int_write_log(log_file, "Pad index (in full list): ", requested_pads_list[i]);
            }
        }

        // Prepare some data
        write_log(log_file, "\n------ Preparing encryption config data ------\n");
        enc_cfg_s = prepare_enc_cfg_file_data(circle_s.pads_path, requested_pads_list, member_id, enc_cfg_offset, error_desc);

        int_write_log(log_file, "Available Bits Count: ", enc_cfg_s.availableBitsCount);
        int_write_log(log_file, "Jump Point: ", enc_cfg_s.jumpPoint);
        write_log(log_file, "PPS: ");
        write_log(log_file, enc_cfg_s.pps);
        write_log(log_file, "\n");
        int_write_log(log_file, "Program Number: ", enc_cfg_s.programNumber);
        int_write_log(log_file, "Requested Bits Count: ", enc_cfg_s.requestedBitsCount);
        write_log(log_file, "Special Char index: ");
        write_log(log_file, enc_cfg_s.specialCharIndex);
        write_log(log_file, "\n");
        int_write_log(log_file, "Special Char Position: ", enc_cfg_s.specialCharPosition);
        int_write_log(log_file, "Start Point for PSP: ", enc_cfg_s.startPoint);
        int_write_log(log_file, "Total Bits Count: ", enc_cfg_s.totalBitsCount);
        int_write_log(log_file, "Used Bits Count: ", enc_cfg_s.usedBitsCount);
        write_log(log_file, "XOR Bits: ");
        write_log(log_file, enc_cfg_s.xorbits);
        write_log(log_file, "\n");

    }

    /* Now we should open each requested pad and merge thier content into one.        */
    if (r_p_c >= 1)
    {
        write_log(log_file, "\n------ Starting To Merge Requested Pads by Thier ID ------\n");
        used_pads_content = CALLOC(sizeof(char) * r_p_c * PAD_LEN + 1, 1);
        int res = merge_requested_pads(used_pads_content, requested_pads_list, r_p_c, circle_s.pads_path, enc_cfg_offset, error_msg);
        if (res != 0)
        {
            //strcpy_s(error_desc, 256, "\nError: When merging Pads.\n");
            return ENC_ERROR_COMMON;
        }
        write_log(log_file, "\n------ Finished Process of Merge Requested Pads by Thier ID ------\n");
        char* used_bits_5952 = ALLOC(sizeof(char) * 5952 + 1);
        memcpy(used_bits_5952, used_pads_content, 5952);
        used_bits_5952[5952] = '\0';
        write_log(log_file, used_bits_5952);

    }
    else
    {
        wcscpy_s(error_msg, 256, L"\nWarning: There is no Pads to merge.\n");
        return ENC_ERROR_WRONGPADSCOUNT;
    }

    /* Adding additional bits using xor 6 bits  */
    memcpy(binary_content, enc_cfg_s.xorbits, added_bits_count);

    write_log(log_file, "\nProgram File Content: \n");
    // Get Prog&PPS files raw content
    char* prog_pps_content = get_pps_and_prog_file_contents(circle, circle_s.pads_path, enc_cfg_s.programNumber, error_desc);
    write_log(log_file, prog_pps_content);
    write_log(log_file, "\n");
    /* Do logical operation                                                           */
    /* Get logical op method from program file content.It is a value of 411-th bit.   */
    if ((*(prog_pps_content + 3254)) - '0' == 1) //3254=6*64+2870
    {
        // Do XOR
        write_log(log_file, "\n------ Starting to do XOR ------\n");
        fmakeXOR(binary_content, used_pads_content);
        write_log(log_file, "------ Finished to do XOR ------\n");
    }
    else
    {
        // Do XNOR
        write_log(log_file, "\n------ Starting to do XNOR ------\n");
        fmakeXNOR(binary_content, used_pads_content);
        write_log(log_file, "------ Finished to do XNOR ------\n");
    }

    /* Get PPS from config file content and convert it to spec chars.                 */
    wchar_t* spec_PPS = ALLOC(sizeof(wchar_t) * (2 * SPEC_PPS_LEN + 2));
    //get_spec_PPS_simple(enc_cfg_s, prog_pps_content, spec_PPS);
    get_spec_PPS(enc_cfg_s, prog_pps_content, spec_PPS);
    write_log(log_file, "Specal PPS: ");
    wcs_write_log(log_file, spec_PPS);
    write_log(log_file, "\n");

    /* Convert plain text to their six-bits spec chars representation.                */
    write_log(log_file, "\n------ Converting plain text to their six-bits spec chars representation ------\n");
    wchar_t* plainSpec = ALLOC(sizeof(wchar_t) * (strlen(binary_content) / 3 + 2));
    get_spec_text(enc_cfg_s, binary_content, prog_pps_content, plainSpec);
    write_log(log_file, "------ Completed converting plain text to their six-bits spec chars representation ------\n");

    // Do PSP action.
    write_log(log_file, "\n------ Starting PSP action ------\n");
    W_PSP(plainSpec, enc_cfg_s.startPoint, enc_cfg_s.jumpPoint);
    write_log(log_file, "------ PSP action was completed ------\n");

    /* Insert special char into its position.	                 	                  */
    write_log(log_file, "\n------ Inserting Spech Char ------\n");
    wchar_t* plain_spec_with_char = ALLOC(sizeof(wchar_t) * (wcslen(plainSpec) + 2));
    insert_spec_char(enc_cfg_s, plainSpec, plain_spec_with_char);
    write_log(log_file, "------ Spec Char inserted ------\n");

    /* Insert PPS into its position.	                 	                          */
    /* But first of all we need to get PPS insertion point from program content       */
    /* it starts from 385th bit with the len 26 bit                                   */
    write_log(log_file, "\n------ Inserting PPS into its position ------\n");
    wchar_t* plain_spec_with_char_and_PPS = ALLOC(sizeof(wchar_t) * (wcslen(plainSpec) + wcslen(spec_PPS) + 2));
    insert_pps(enc_cfg_s, plain_spec_with_char, spec_PPS, prog_pps_content, plain_spec_with_char_and_PPS);
    write_log(log_file, "------ PPS inserted ------\n");

    /* Build encrypted file name:  	                 	                              */
    /* First 7 chars of the file + added bits count + original ext + spae             */
    wchar_t* final_f_name = biuld_enc_file_name(plain_spec_with_char_and_PPS, added_bits_count, where_to_save, f_name);

    wmemcpy_s(encrypted_f_name, _MAX_FNAME, final_f_name, wcslen(final_f_name));
    encrypted_f_name[wcslen(final_f_name)] = '\0';

    write_log(log_file, "Final file name: ");
    wcs_write_log(log_file, encrypted_f_name);
    write_log(log_file, "\n");

    /* Write into file            	                 	                              */
    write_log(log_file, "\n------ Writing c-text into file ------\n");
    write_cipher_to_file(final_f_name, plain_spec_with_char_and_PPS, error_desc);
    write_log(log_file, "\n------ Encrypted file was created ------\n");

    enc_cfg_s.totalBitsCount = bitsInfo_s.totalBitsCount;
    enc_cfg_s.requestedBitsCount = bitsInfo_s.requestedBitsCount;
    enc_cfg_s.usedBitsCount = bitsInfo_s.usedBitsCount + bitsInfo_s.requestedBitsCount + SEEK_NUMBER;
    enc_cfg_s.availableBitsCount = bitsInfo_s.availableBitsCount - bitsInfo_s.requestedBitsCount;

    int_write_log(log_file, "Available Bits Count: ", enc_cfg_s.availableBitsCount);
    int_write_log(log_file, "Requested Bits Count: ", enc_cfg_s.requestedBitsCount);
    int_write_log(log_file, "Total Bits Count: ", enc_cfg_s.totalBitsCount);
    int_write_log(log_file, "Used Bits Count: ", enc_cfg_s.usedBitsCount);

    write_log(log_file, "\n------ Updating Enc config file ------\n");
    store_enc_cfg(enc_cfg_f_path, enc_cfg_s, error_desc);

    write_log(log_file, "\n------ FREE binary_content ------\n");
    FREE(binary_content);
    write_log(log_file, "\n------ FREE used_pads_content ------\n");
    FREE(used_pads_content);
    write_log(log_file, "\n------ FREE plain_spec_with_char_and_PPS ------\n");
    FREE(plain_spec_with_char_and_PPS);

#if _DEBUG
    fflush(log_file);
    fclose(log_file);
#endif

    return ENC_ERROR_OK;
}


SPAE_DLL_EXPIMP char* SPAE_CALL file_to_binary_simple(char* file, size_t* req_bits_count, wchar_t* error_desc)
{
    /*Crucial varibales whcih will be used when we call MPZ funictions in order to convert file to binary*/
    mpz_t c;
    mpz_init(c);

    int open_status;

    /*Accept the file and try to open it*/
    FILE* f = NULL;
    /*Trying to open the file*/
    f = open_file(file, FILE_MODE_READ, &open_status);

    if (open_status != 0)
    {
        wcscpy_s(error_desc, 256, L"\nError: When trying to open a file for encryption.\n");
        return NULL;
    }

    // Get the encrypted file size
    size_t encFileSize = fsize(f);

    // File size in bin
    size_t bin_file_size = encFileSize * 8;

    // We are accepting files less than 500Mb currently
    if (encFileSize > MB500)
    {
        wcscpy_s(error_desc, 256, L"\nError: We are accepting files less than 500Mb currently.\n");

        fclose(f);
        return NULL;
    }

    // Check if bin size is divisible by six and needed for additional bits
    size_t addedBitsCount = divisible_by_six(bin_file_size);

    /* Allocate enough memory */
    char* bin_content = ALLOC(sizeof(char) * (bin_file_size + 1));

    size_t bytesRead = 0;
    size_t offset = 0;

    char* buffer;
    buffer = ALLOC(sizeof(char) * READ_CHUNK_SZIE + 1); // allocate memory

    char* tmpBuffer;
    tmpBuffer = ALLOC(sizeof(char) * READ_CHUNK_SZIE * 8 + 1); // allocate memory

    while ((bytesRead = fread(buffer, 1, READ_CHUNK_SZIE, f)) > 0)
    {

        buffer[bytesRead * 1] = '\0';
        mpz_import(c, bytesRead, 1, sizeof(buffer[0]), 0, 0, buffer);
        mpz_get_str(tmpBuffer, 2, c);

        size_t len = strlen(tmpBuffer);

        if (len >= bytesRead * 8)
        {
            memcpy(bin_content + offset, tmpBuffer, len);
            offset = offset + len;
        }
        else
        {
            char* tmpBinResult = ALLOC(sizeof(char) * ((bytesRead * 8) + (bytesRead * 8 - len) + 1));

            sprintf_s(tmpBinResult, (bytesRead * 8) + (int)(bytesRead * 8 - len), "%0*d%s", (int)(bytesRead * 8 - len), 0, tmpBuffer);

            memcpy(bin_content + offset, tmpBinResult, bytesRead * 8);
            offset = offset + bytesRead * 8;

            FREE(tmpBinResult);
        }

        memset(buffer, 0, sizeof(buffer));
    }
    bin_content[offset] = '\0';

    fclose(f);
    FREE(tmpBuffer);

    // return requested bits count too
    *req_bits_count = bin_file_size;

    return bin_content;
}

// return 0 - Full Version
// return 1 - Limited
SPAE_DLL_EXPIMP int is_limited_ver()
{
    return 0;
}

SPAE_DLL_EXPIMP enc_error_t SPAE_CALL encrypt_file_with_anal(char* f_name, char* circle, char* enc_cfg_f_path, size_t member_id, unsigned int is_first_usage, wchar_t* where_to_save, wchar_t* encrypted_f_name, wchar_t* log_path, wchar_t* error_msg)
{
    size_t requested_bits_count = 0;
    size_t added_bits_count     = 0;
    size_t* requested_pads_list = NULL;
    char* used_pads_content     = NULL;

    struct circle circle_s         = { 0 };
    struct bitsInfo bitsInfo_s     = { 0 };
    struct encryptionCfg enc_cfg_s = { 0 };

    char* error_desc = ALLOC(sizeof(char) * 256);
    char* log_str    = ALLOC(sizeof(char) * 1024);

    int open_status;

    /*Accept the file and try to open it*/
    FILE* log_file = NULL;
    wchar_t* logFileName = ALLOC(sizeof(wchar_t) * _MAX_FNAME);

    // Build the file name connecting with the path
    wmemcpy(logFileName, log_path, wcslen(log_path));
    logFileName[wcslen(log_path)] = '\0';
    
    wcscat(logFileName, L"\\");
    wcscat(logFileName, L"spaenclog.txt");

    /*Trying to open the file*/
    log_file = w_open_file(logFileName, FILE_MODE_WRITE, &open_status);

    if (open_status != 0)
    {
        strcpy_s(error_desc, 256, "\nError: When trying to open a Log file.\n");
        return CIRCLE_ERROR_OPENF;
    }

    /* Fail to set mode to UTF */
    if (-1 == set_file_mode_to_utf(&log_file))
    {
        strcpy_s(error_desc, 256, "\nError: When trying to set file mode to UTF.\n");
        return CIRCLE_ERROR_OPENF;
    }
/*-------------------------------------------LOG--------------------------------------------------------------*/
    // Start log file
    wcs_write_log(log_file, L"#############################################################################\n");
    wcs_write_log(log_file, L"Encryption Analysis with SPAE Rev. 1.8 used to encrypt\n");
    wcs_write_log(log_file, L"Logging started at ");
    
    // Log Get & set logging time
    char* dtm = get_current_datetime();
    wchar_t* w_dtm = ALLOC(sizeof(wchar_t) * strlen(dtm) + 1);
    mbstowcs_s(NULL, w_dtm, strlen(dtm) + 1, dtm, strlen(dtm));

    wcs_write_log(log_file, w_dtm);

    // Log the encrypted file name with path
    wcs_write_log(log_file, L"\n\tFile encrypted is:               ");
    wchar_t* w_enc_fn = ALLOC(sizeof(wchar_t) * strlen(f_name) + 1);
    mbstowcs_s(NULL, w_enc_fn, strlen(f_name) + 1, f_name, strlen(f_name));

    wcs_write_log(log_file, w_enc_fn);
/*---------------------------------------------------------------------------------------------------*/

    // Get some info about the circle
    get_circle_data_by_name(&circle_s, circle, error_desc);

    // Convert to binary
    char* binary_content = file_to_binary_enc(f_name, &requested_bits_count, &added_bits_count, error_msg);

    if (binary_content == NULL)
    {
        fflush(log_file);
        fclose(log_file);

        return ENC_ERROR_HUGEFILE;
    }

    /*-------------------------------------------LOG--------------------------------------------------------------*/
    // Log file's binary size
    int_wcs_write_log(log_file, L"\n\tFile size in bits is:            ", requested_bits_count);
    /*---------------------------------------------------------------------------------------------------------*/

    bitsInfo_s = compute_bits_info(binary_content, circle, enc_cfg_f_path, member_id, is_first_usage, error_desc);

    // Check if there are enough bits for enc
    if (bitsInfo_s.availableBitsCount == 0 && bitsInfo_s.totalBitsCount == 0 && bitsInfo_s.usedBitsCount == 0 &&
        bitsInfo_s.requestedBitsCount > 0)
    {
        size_t _addit_P_count = bitsInfo_s.requestedBitsCount;
        wchar_t* how_many = int2wstr(_addit_P_count);
        wcscpy_s(error_msg, 256, how_many);

        fflush(log_file);
        fclose(log_file);

        return ENC_ERROR_FEWPADS;
    }

    size_t r_p_c          = 0; // requested pads count
    size_t enc_cfg_offset = 0; // requested pads count

    if (is_first_usage > 0)
    {
        requested_pads_list = get_list_of_requested_pads_ID(circle, member_id, requested_bits_count, &r_p_c, error_desc);

        // Prepare some data
        enc_cfg_s = prepare_enc_cfg_file_data(circle_s.pads_path, requested_pads_list, member_id, 0, error_desc);

        /*-------------------------------------------LOG--------------------------------------------------------------*/
        wcs_write_log(log_file, L"\tPPS 42 bit sequence is:          ");
        wchar_t* w_pps = ALLOC(sizeof(wchar_t) * strlen(enc_cfg_s.pps) + 1);
        mbstowcs_s(NULL, w_pps, strlen(enc_cfg_s.pps) + 1, enc_cfg_s.pps, 42);

        wcs_write_log(log_file, w_pps);
        /*---------------------------------------------------------------------------------------------------------*/
    }
    else
    {
        requested_pads_list = collect_list_of_requested_pads_ID(circle, member_id, requested_bits_count, bitsInfo_s.availableBitsCount, bitsInfo_s.usedBitsCount, &r_p_c, &enc_cfg_offset, error_desc);

        // Prepare some data
        enc_cfg_s = prepare_enc_cfg_file_data(circle_s.pads_path, requested_pads_list, member_id, enc_cfg_offset, error_desc);

        /*-------------------------------------------LOG--------------------------------------------------------------*/
        wcs_write_log(log_file, L"\tPPS 42-bit sequence is:          ");
        wchar_t* w_pps = ALLOC(sizeof(wchar_t) * strlen(enc_cfg_s.pps) + 1);
        mbstowcs_s(NULL, w_pps, strlen(enc_cfg_s.pps) + 1, enc_cfg_s.pps, 42);

        wcs_write_log(log_file, w_pps);
        /*---------------------------------------------------------------------------------------------------------*/

    }

    /* Now we should open each requested pad and merge thier content into one.        */
    if (r_p_c >= 1)
    {
        /*-------------------------------------------LOG--------------------------------------------------------------*/
        // Log the prog num where PPS is
        int_wcs_write_log(log_file, L"\n\tPPS begins at pad#:              ", requested_pads_list[0]);

        //char* pad_first_42_bits = ALLOC(sizeof(char) * 42 + 1);
        //get_first_42_bits_of_any_pad(pad_first_42_bits, requested_pads_list[0], circle_s.pads_path, error_msg);
        //
        //wchar_t* w_pad_first_42_bits = ALLOC(sizeof(wchar_t) * strlen(pad_first_42_bits) + 1);
        //mbstowcs_s(NULL, w_pad_first_42_bits, strlen(pad_first_42_bits) + 1, pad_first_42_bits, 42);
        //
        //wcs_write_log(log_file, L"\tLeading pad bits used to encrypt:");
        //wcs_write_log(log_file, w_pad_first_42_bits);
        /*---------------------------------------------------------------------------------------------------------*/

        used_pads_content = CALLOC(sizeof(char) * r_p_c * PAD_LEN + 1, 1);
        int res = merge_requested_pads(used_pads_content, requested_pads_list, r_p_c, circle_s.pads_path, enc_cfg_offset, error_msg);
        if (res != 0)
        {
            fflush(log_file);
            fclose(log_file);

            return ENC_ERROR_COMMON;
        }

        size_t leading_bts_count = 42;
        if (requested_bits_count < 42)
        {
            leading_bts_count = requested_bits_count;
        }

        char* pad_first_42_bits = ALLOC(sizeof(char) * leading_bts_count + 1);

        memcpy_s(pad_first_42_bits, leading_bts_count + 1, used_pads_content, leading_bts_count);
        pad_first_42_bits[leading_bts_count] = '\0';

        wchar_t* w_pad_first_42_bits = ALLOC(sizeof(wchar_t) * strlen(pad_first_42_bits) + 1);
        mbstowcs_s(NULL, w_pad_first_42_bits, strlen(pad_first_42_bits) + 1, pad_first_42_bits, leading_bts_count);

        wcs_write_log(log_file, L"\tLeading pad bits used to encrypt:");
        wcs_write_log(log_file, w_pad_first_42_bits);
    }
    else
    {
        wcscpy_s(error_msg, 256, L"\nWarning: There is no Pads to merge.\n");

        fflush(log_file);
        fclose(log_file);

        return ENC_ERROR_WRONGPADSCOUNT;
    }

    /* Adding additional bits using xor 6 bits  */
    memcpy(binary_content, enc_cfg_s.xorbits, added_bits_count);

    // Get added bits
    char* added_bits_set = ALLOC(sizeof(char) * 6 + 1);
    memcpy_s(added_bits_set, 7, binary_content, added_bits_count);
    added_bits_set[added_bits_count] = '\0';

    /*-------------------------------------------LOG--------------------------------------------------------------*/
    // Log
    wcs_write_log(log_file, L"\n\n\tNumber of bits added for perfect 6 divisibility are in the c-text file name");
    /*---------------------------------------------------------------------------------------------------------*/

    // Get Prog&PPS files raw content
    char* prog_pps_content = get_pps_and_prog_file_contents(circle, circle_s.pads_path, enc_cfg_s.programNumber, error_desc);
    char* dynamic_pps_prog_content = get_dynamic_pps_and_prog_file_contents(circle, circle_s.pads_path, error_desc);

    /* Do logical operation                                                           */
    /* Get logical op method from program file content.It is a value of 411-th bit.   */
    if ((*(prog_pps_content + 3254)) - '0' == 1) //3254=6*64+2870
    {
        // Do XOR
        fmakeXOR(binary_content, used_pads_content);
    }
    else
    {
        // Do XNOR
        fmakeXNOR(binary_content, used_pads_content);
    }

    /* Get PPS from config file content and convert it to spec chars.                 */
    wchar_t* spec_PPS = ALLOC(sizeof(wchar_t) * (2 * SPEC_PPS_LEN + 2));
    //get_spec_PPS_simple(enc_cfg_s, prog_pps_content, spec_PPS);
    get_spec_PPS(enc_cfg_s, prog_pps_content, spec_PPS);

    /* Convert plain text to their six-bits spec chars representation.                */
    wchar_t* plainSpec = ALLOC(sizeof(wchar_t) * (strlen(binary_content) / 3 + 2));
    get_spec_text(enc_cfg_s, binary_content, prog_pps_content, plainSpec);

    /*-------------------------------------------LOG--------------------------------------------------------------*/
    // Log converted size 
    int_wcs_write_log_without_new_line(log_file, L"\n\tC-text characters count is: ", wcslen(plainSpec));
    int_wcs_write_log_without_new_line(log_file, L" + 9 control char's = ", wcslen(plainSpec) + 9);
    wcs_write_log(log_file, L" total char's for file encrypted\n");
    /*---------------------------------------------------------------------------------------------------------*/

    // Do PSP action.
    //W_PSP(plainSpec, enc_cfg_s.startPoint, enc_cfg_s.jumpPoint);
    size_t next_prime_num = 0;
    W_PSP_for_log(plainSpec, enc_cfg_s.startPoint, enc_cfg_s.jumpPoint, &next_prime_num);

    /*-------------------------------------------LOG--------------------------------------------------------------*/
    int_wcs_write_log(log_file, L"\n\tPrime number used for PSP:       ", next_prime_num);

    wcs_write_log(log_file, L"\n\tThe following eight control characters in order of insertion into the c-text character sequence during encryption:");
    
    wcs_write_log(log_file, L"\n-----------------------------------------------------------------------------\n");
    
    /* Insert special char into its position.	                 	                  */
    wchar_t* plain_spec_with_char = ALLOC(sizeof(wchar_t) * (wcslen(plainSpec) + 2));
    wchar_t* lock_char = ALLOC(sizeof(wchar_t) * 2);
    insert_spec_char_log(enc_cfg_s, plainSpec, plain_spec_with_char, lock_char);
    
    wcs_write_log(log_file, L"\tPSP-lock char:  ");
    wcs_write_log(log_file, L"\n\t\t");
    wcs_write_log(log_file, lock_char);

    wcs_write_log(log_file, L"\t\t\t");

    char* spc_char_index_seq = ALLOC(sizeof(char) * 6 + 1);
    memcpy_s(spc_char_index_seq, 7, enc_cfg_s.specialCharIndex, 6);
    spc_char_index_seq[6] = '\0';
    wchar_t* w_spec_c_seq = ALLOC(sizeof(wchar_t) * strlen(spc_char_index_seq) + 1);
    mbstowcs_s(NULL, w_spec_c_seq, strlen(spc_char_index_seq) + 1, spc_char_index_seq, strlen(spc_char_index_seq));
    wcs_write_log(log_file, w_spec_c_seq);

    // Convert index value to binary
    char* lock_char_pos_binary = CALLOC(sizeof(char) * 28 + 1, 1);
    decimalToBinary(lock_char_pos_binary, enc_cfg_s.specialCharPosition, 25);
    wchar_t* w_lock_char_pos_binary = ALLOC(sizeof(wchar_t) * strlen(lock_char_pos_binary) + 1);
    mbstowcs_s(NULL, w_lock_char_pos_binary, strlen(lock_char_pos_binary) + 1, lock_char_pos_binary, strlen(lock_char_pos_binary));

    wcs_write_log(log_file, L"\t\t\t");
    wcs_write_log(log_file, w_lock_char_pos_binary);
    int_wcs_write_log_without_new_line(log_file, L"=>", enc_cfg_s.specialCharPosition);
    int_wcs_write_log(log_file, L"=>", enc_cfg_s.specialCharPosition% wcslen(plainSpec));
    wcs_write_log(log_file, L"-----------------------------------------------------------------------------");

    
    wcs_write_log(log_file, L"\n\tPPS bits in special character format, used for control: ");
    wcs_write_log(log_file, spec_PPS);
    /*---------------------------------------------------------------------------------------------------------*/

    /* Insert PPS into its position.	                 	                          */
    /* But first of all we need to get PPS insertion point from program content       */
    /* it starts from 385th bit with the len 26 bit                                   */
    wchar_t* plain_spec_with_char_and_PPS = ALLOC(sizeof(wchar_t) * (wcslen(plainSpec) + wcslen(spec_PPS) + 2 + 3));
    //insert_pps(enc_cfg_s, plain_spec_with_char, spec_PPS, prog_pps_content, plain_spec_with_char_and_PPS);
    // Log pps positions
    
    // Now it is the time to know in which order need we insert PPS L->R or R->L
    // If 0, 2,4... then we place char's with the wrapaaround number left to right

    char* sp_in_bin = CALLOC(sizeof(char) * 28 + 1, 1);
    decimalToBinary(sp_in_bin, enc_cfg_s.startPoint, 25);

    // Now get the first 6 bits which will point insertion order in decimal
    char* c9_char_six_bits = ALLOC(sizeof(char) * 6 + 1);
    memcpy_s(c9_char_six_bits, 7, sp_in_bin, 6);
    c9_char_six_bits[6] = '\0';

    size_t insert_order = bindec(c9_char_six_bits);
    int insert_order_val = 0;
    if (is_even(insert_order))
    {
        // L->R
        insert_order_val = 0;
    }
    else
    {
        // R->L
        insert_order_val = 1;
    }

    size_t* pps_positions = ALLOC(sizeof(size_t) * 7);
    size_t* huge_pps_positions = ALLOC(sizeof(size_t) * 7);
    //insert_pps_with_log(enc_cfg_s, plain_spec_with_char, spec_PPS, prog_pps_content, plain_spec_with_char_and_PPS, pps_positions, huge_pps_positions);
    insert_dynamic_pps_with_log(enc_cfg_s, plain_spec_with_char, spec_PPS, c9_char_six_bits, dynamic_pps_prog_content, plain_spec_with_char_and_PPS, pps_positions, huge_pps_positions, insert_order_val);

    /*-------------------------------------------LOG--------------------------------------------------------------*/
    wcs_write_log(log_file, L"\n\tPPS chars insertion order: ");
    if (is_even(insert_order))
    {
        // L->R
        wcs_write_log(log_file, L"\tL->R");
    }
    else
    {
        // R->L
        wcs_write_log(log_file, L"\tR->L");
    }

    wchar_t* w_pps_42 = ALLOC(sizeof(wchar_t) * 42 + 1);
    mbstowcs_s(NULL, w_pps_42, 42 + 1, enc_cfg_s.pps, 42);

    wchar_t* w_pps_6 = ALLOC(sizeof(wchar_t) * 6 + 1);
    wchar_t* w_pps_1 = ALLOC(sizeof(wchar_t) * 1 + 1);

    wcs_write_log(log_file, L"\n\tCharacter");
    wcs_write_log(log_file, L"\t\tbit seq.");
    wcs_write_log(log_file, L"\t\tPPS char inserted position, after wraparound");

    for (size_t i = 0; i < 7; i++)
    {
        wmemcpy_s(w_pps_6, 7, w_pps_42 + i*6, 6);
        w_pps_6[6] = '\0';

        wmemcpy_s(w_pps_1, 1, spec_PPS + i, 1);
        w_pps_1[1] = '\0';
        
        if (0 == i)
        {
            wcs_write_log(log_file, L"\n\t\t");
            wcs_write_log(log_file, w_pps_1);      // Character

            wcs_write_log(log_file, L"\t\t\t");
            wcs_write_log(log_file, w_pps_6);          // bit. seq

            // Convert index value to binary
            char* huge_pps_pos_binary = CALLOC(sizeof(char) * 28 + 1, 1);
            decimalToBinary(huge_pps_pos_binary, huge_pps_positions[i], 25);
            wchar_t* w_huge_pps_pos_binary = ALLOC(sizeof(wchar_t) * strlen(huge_pps_pos_binary) + 1);
            mbstowcs_s(NULL, w_huge_pps_pos_binary, strlen(huge_pps_pos_binary) + 1, huge_pps_pos_binary, strlen(huge_pps_pos_binary));

            wcs_write_log(log_file, L"\t\t\t");
            wcs_write_log(log_file, w_huge_pps_pos_binary);
            int_wcs_write_log_without_new_line(log_file, L"=>", huge_pps_positions[i]);
            int_wcs_write_log(log_file, L"=>", pps_positions[i]); // PPS position
            
            //FREE(w_huge_pps_pos_binary);
        }
        else
        {
            wcs_write_log(log_file, L"\t\t");
            wcs_write_log(log_file, w_pps_1);      // Character

            wcs_write_log(log_file, L"\t\t\t");
            wcs_write_log(log_file, w_pps_6);          // bit. seq

            // Convert index value to binary
            char* huge_pps_pos_binary = CALLOC(sizeof(char) * 28 + 1, 1);
            decimalToBinary(huge_pps_pos_binary, huge_pps_positions[i], 25);
            wchar_t* w_huge_pps_pos_binary = ALLOC(sizeof(wchar_t) * strlen(huge_pps_pos_binary) + 1);
            mbstowcs_s(NULL, w_huge_pps_pos_binary, strlen(huge_pps_pos_binary) + 1, huge_pps_pos_binary, strlen(huge_pps_pos_binary));

            wcs_write_log(log_file, L"\t\t\t");
            wcs_write_log(log_file, w_huge_pps_pos_binary);
            int_wcs_write_log_without_new_line(log_file, L"=>", huge_pps_positions[i]);
            int_wcs_write_log(log_file, L"=>", pps_positions[i]); // PPS position
            
            //FREE(w_huge_pps_pos_binary);
        }
    }


    /*---------------------------------------------------------------------------------------------------------*/

    wcs_write_log(log_file, L"-----------------------------------------------------------------------------");
    /* Insert 9th ctrl char */
    // Get the char position
    char last_bits[27]; // allocate buffer for 26 bits plus null terminator
    last_26_bits(last_bits, dynamic_pps_prog_content, strlen(dynamic_pps_prog_content));
    size_t c9_insrt_pos = bindec(last_bits);
    // wraparound it
    if (c9_insrt_pos > wcslen(plain_spec_with_char_and_PPS))
    {
        c9_insrt_pos = c9_insrt_pos % wcslen(plain_spec_with_char_and_PPS);
    }

    // Get 9th ctrl spec char
    wchar_t* last_ctrl_spec_char = ALLOC(sizeof(wchar_t) * 2);
    get_spec_char_by_index_simple(last_ctrl_spec_char, c9_char_six_bits);

    w_insert_char_itself(plain_spec_with_char_and_PPS, *last_ctrl_spec_char, c9_insrt_pos);

    wcs_write_log(log_file, L"\n\tC9 control char:  ");
    wcs_write_log(log_file, L"\n\t\t");
    wcs_write_log(log_file, last_ctrl_spec_char);

    wcs_write_log(log_file, L"\t\t\t");

    char* c9_spc_char_index_seq = ALLOC(sizeof(char) * 6 + 1);
    memcpy_s(c9_spc_char_index_seq, 7, c9_char_six_bits, 6);
    c9_spc_char_index_seq[6] = '\0';
    wchar_t* w_spec_c9_seq = ALLOC(sizeof(wchar_t) * strlen(c9_spc_char_index_seq) + 1);
    mbstowcs_s(NULL, w_spec_c9_seq, strlen(c9_spc_char_index_seq) + 1, c9_spc_char_index_seq, strlen(c9_spc_char_index_seq));
    wcs_write_log(log_file, w_spec_c9_seq);

    // Convert index value to binary
    wchar_t* w_c9_lock_char_pos_binary = ALLOC(sizeof(wchar_t) * strlen(last_bits) + 1);
    mbstowcs_s(NULL, w_c9_lock_char_pos_binary, strlen(last_bits) + 1, last_bits, strlen(last_bits));

    wcs_write_log(log_file, L"\t\t\t");
    wcs_write_log(log_file, w_c9_lock_char_pos_binary);
    int_wcs_write_log_without_new_line(log_file, L"=>", bindec(last_bits));
    int_wcs_write_log(log_file, L"=>", c9_insrt_pos);

    wcs_write_log(log_file, L"-----------------------------------------------------------------------------");

    /* Build encrypted file name:  	                 	                              */
    /* First 7 chars of the file + added bits count + original ext + spae             */
    wchar_t* final_f_name = biuld_enc_file_name(plain_spec_with_char_and_PPS, added_bits_count, where_to_save, f_name);

    wmemcpy_s(encrypted_f_name, _MAX_FNAME, final_f_name, wcslen(final_f_name));
    encrypted_f_name[wcslen(final_f_name)] = '\0';

    /*-------------------------------------------LOG--------------------------------------------------------------*/
    wcs_write_log(log_file, L"\n\tFinal Encrypted File Name:       ");
    wcs_write_log(log_file, encrypted_f_name);

    wcs_write_log(log_file, L"\n\nImmediately following the 42 PPS bits is the 96 bit control sequence detailed below.");
    wcs_write_log(log_file, L"\n-----------------------------------------------------------------------------");
    wcs_write_log(log_file, L"\n\tBits 1-6 Program #(0-63):                   ");
    //int_wcs_write_log(log_file, L"\n\tBits 1-6 Program #(0-63):                   ", enc_cfg_s.programNumber);
    // Convert index value to binary
    char* prog_num_binary = CALLOC(sizeof(char) * 10, 1);
    decimalToBinary(prog_num_binary, enc_cfg_s.programNumber, 5);
    wchar_t* w_prog_num_binary = ALLOC(sizeof(wchar_t) * strlen(prog_num_binary) + 1);
    mbstowcs_s(NULL, w_prog_num_binary, strlen(prog_num_binary) + 1, prog_num_binary, strlen(prog_num_binary));

    wcs_write_log(log_file, w_prog_num_binary);
    int_wcs_write_log(log_file, L"=>", enc_cfg_s.programNumber);


    wcs_write_log(log_file, L"\tBits 7-12 to convert table 2 into table 3,\n");
    wcs_write_log(log_file, L"\tand leading bits also used for perfect 6 divisibility: ");
    char* xor_bits_6 = ALLOC(sizeof(char) * 6 + 1);
    memcpy_s(xor_bits_6, 6, enc_cfg_s.xorbits, 6);
    xor_bits_6[6] = '\0';
    wchar_t* w_xor_bits = ALLOC(sizeof(wchar_t) * strlen(xor_bits_6) + 1);
    mbstowcs_s(NULL, w_xor_bits, strlen(xor_bits_6) + 1, xor_bits_6, strlen(xor_bits_6));
    wcs_write_log(log_file, w_xor_bits);

    
    //int_wcs_write_log(log_file, L"\n\tBits 13-38 PSP start:             ", enc_cfg_s.startPoint% wcslen(plainSpec));
    wcs_write_log(log_file, L"\n\tBits 13-38 PSP start:             \t\t\t");
    // Convert index value to binary
    char* psp_start_binary = CALLOC(sizeof(char) * 28, 1);
    decimalToBinary(psp_start_binary, enc_cfg_s.startPoint, 25);
    wchar_t* w_psp_start_binary = ALLOC(sizeof(wchar_t) * strlen(psp_start_binary) + 1);
    mbstowcs_s(NULL, w_psp_start_binary, strlen(psp_start_binary) + 1, psp_start_binary, strlen(psp_start_binary));

    wcs_write_log(log_file, w_psp_start_binary);
    int_wcs_write_log_without_new_line(log_file, L"=>", enc_cfg_s.startPoint);
    int_wcs_write_log_without_new_line(log_file, L"=>", enc_cfg_s.startPoint% wcslen(plainSpec));
    wcs_write_log(log_file, L" by wraparound\n");


    //int_wcs_write_log(log_file, L"\tBits 39-64 PSP jump:             ", enc_cfg_s.jumpPoint% wcslen(plainSpec));
    wcs_write_log(log_file, L"\tBits 39-64 PSP jump:             \t\t\t");
    // Convert index value to binary
    char* psp_jump_binary = CALLOC(sizeof(char) * 28, 1);
    decimalToBinary(psp_jump_binary, enc_cfg_s.jumpPoint, 25);
    wchar_t* w_psp_jump_binary = ALLOC(sizeof(wchar_t) * strlen(psp_jump_binary) + 1);
    mbstowcs_s(NULL, w_psp_jump_binary, strlen(psp_jump_binary) + 1, psp_jump_binary, strlen(psp_jump_binary));

    wcs_write_log(log_file, w_psp_jump_binary);
    int_wcs_write_log_without_new_line(log_file, L"=>", enc_cfg_s.jumpPoint);
    int_wcs_write_log_without_new_line(log_file, L"=>", enc_cfg_s.jumpPoint% wcslen(plainSpec));
    wcs_write_log(log_file, L" by wraparound\n");


    //int_wcs_write_log(log_file, L"\tBits 65-90 PSP-lock char position:          ", enc_cfg_s.specialCharPosition % wcslen(plainSpec));
    wcs_write_log(log_file, L"\tBits 65-90 PSP-lock char position:          ");
    // Convert index value to binary
    char* s_lock_char_pos_binary = CALLOC(sizeof(char) * 28, 1);
    decimalToBinary(s_lock_char_pos_binary, enc_cfg_s.specialCharPosition, 25);
    wchar_t* wn_lock_char_pos_binary = ALLOC(sizeof(wchar_t) * strlen(s_lock_char_pos_binary) + 1);
    mbstowcs_s(NULL, wn_lock_char_pos_binary, strlen(s_lock_char_pos_binary) + 1, s_lock_char_pos_binary, strlen(s_lock_char_pos_binary));

    wcs_write_log(log_file, wn_lock_char_pos_binary);
    int_wcs_write_log_without_new_line(log_file, L"=>", enc_cfg_s.specialCharPosition);
    int_wcs_write_log_without_new_line(log_file, L"=>", enc_cfg_s.specialCharPosition% wcslen(plainSpec));
    wcs_write_log(log_file, L" by wraparound\n");


    wcs_write_log(log_file, L"\tBits 91-96 PSP-lock char bit sequence:      ");
    char* spc_char_index = ALLOC(sizeof(char) * 6 + 1);
    memcpy_s(spc_char_index, 7, enc_cfg_s.specialCharIndex, 6);
    spc_char_index[6] = '\0';
    wchar_t* w_spec_c = ALLOC(sizeof(wchar_t) * strlen(spc_char_index) + 1);
    mbstowcs_s(NULL, w_spec_c, strlen(spc_char_index) + 1, spc_char_index, strlen(spc_char_index));
    wcs_write_log(log_file, w_spec_c);
    wcs_write_log(log_file, L"=> becomes char by Table 4");

    wcs_write_log(log_file, L"\n=============================================================================\n");
    
    wcs_write_log(log_file, L"\n\nTable 1");
    wcs_write_log(log_file, L"\n\n64 c-text char’s in order used with other tables used below used for substitution:");
    wcs_write_log(log_file, L"\n\n0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz†/\n");

    wcs_write_log(log_file, L"\n-----------------------------------------------------------------------------\n");

    wcs_write_log(log_file, L"\nTable 2");
    wcs_write_log(log_file, L"\n\nBit table used by program # for conversion of bits to c-text characters\n");
    char* lookup_tbl_keys = ALLOC(sizeof(char) * 64 * 6 + 1);
    memcpy_s(lookup_tbl_keys, 64 * 6 + 1, prog_pps_content, 64 * 6);
    lookup_tbl_keys[64 * 6] = '\0';
    char* tbl_key = ALLOC(sizeof(char) * 6 + 1);
    char* tbl_xored_key = ALLOC(7 * sizeof(char));
    wchar_t* w_tbl_key = ALLOC(sizeof(wchar_t) * strlen(tbl_key) + 1);
    for (size_t i = 0; i < 64; i++)
    {
        memcpy_s(tbl_key, 7, lookup_tbl_keys + i*6, 6);
        tbl_key[6] = '\0';
        
        mbstowcs_s(NULL, w_tbl_key, strlen(tbl_key) + 1, tbl_key, strlen(tbl_key));
        wcs_write_log(log_file, w_tbl_key);
        wcs_write_log(log_file, L"\t");
    }

    wcs_write_log(log_file, L"\n-----------------------------------------------------------------------------\n");

    wcs_write_log(log_file, L"\nTable 3");
    wcs_write_log(log_file, L"\n\nBit table above used after modification by bits 7-12 of control bits for final c-text char actually used\n");

    for (size_t i = 0; i < 64; i++)
    {
        memcpy_s(tbl_key, 7, lookup_tbl_keys + i * 6, 6);
        tbl_key[6] = '\0';

        tbl_xored_key = xor_short_strings(tbl_key, enc_cfg_s.xorbits);
        tbl_xored_key[6] = '\0';

        mbstowcs_s(NULL, w_tbl_key, strlen(tbl_xored_key) + 1, tbl_xored_key, strlen(tbl_xored_key));
        wcs_write_log(log_file, w_tbl_key);
        wcs_write_log(log_file, L"\t");
    }

    wcs_write_log(log_file, L"\n-----------------------------------------------------------------------------\n");

    wcs_write_log(log_file, L"\nTable 4");

    wcs_write_log(log_file, L"\n\nPSP-lock char lookup table\n");

    for (size_t i = 0; i < 64; i++)
    {
        mbstowcs_s(NULL, w_tbl_key, strlen(simple_keys[i]) + 1, simple_keys[i], strlen(simple_keys[i]));
        wcs_write_log(log_file, w_tbl_key);
        wcs_write_log(log_file, L"\t");
    }

    wcs_write_log(log_file, L"\n-----------------------------------------------------------------------------\n");

    char* PPSlookupTbl = ALLOC(sizeof(char) * 64 * 6 + 1);
    
    for (size_t j = 0; j < 7; j++)
    {
        int_wcs_write_log(log_file, L"\n\nTable ", j + 5);
        int_wcs_write_log(log_file, L"\nPPS lookup table for char ", j + 1);

        pps_get_nth_lookup_tbl(PPSlookupTbl, j, prog_pps_content);

        for (size_t i = 0; i < 64; i++)
        {
            memcpy_s(tbl_key, 7, PPSlookupTbl + i * 6, 6);
            tbl_key[6] = '\0';

            mbstowcs_s(NULL, w_tbl_key, strlen(tbl_key) + 1, tbl_key, strlen(tbl_key));
            wcs_write_log(log_file, w_tbl_key);
            wcs_write_log(log_file, L"\t");
        }

        wcs_write_log(log_file, L"\n-----------------------------------------------------------------------------\n");
    }

    wcs_write_log(log_file, L"\n\nEND OF LOG");
    /*---------------------------------------------------------------------------------------------------------*/

    /* Write into file            	                 	                              */
    write_cipher_to_file(final_f_name, plain_spec_with_char_and_PPS, error_desc);
    
    enc_cfg_s.totalBitsCount = bitsInfo_s.totalBitsCount;
    enc_cfg_s.requestedBitsCount = bitsInfo_s.requestedBitsCount;
    enc_cfg_s.usedBitsCount = bitsInfo_s.usedBitsCount + bitsInfo_s.requestedBitsCount + SEEK_NUMBER;
    enc_cfg_s.availableBitsCount = bitsInfo_s.availableBitsCount - bitsInfo_s.requestedBitsCount;

    w_store_enc_cfg(enc_cfg_f_path, enc_cfg_s, error_msg);

    FREE(binary_content);
    FREE(used_pads_content);
    FREE(plain_spec_with_char_and_PPS);

    fflush(log_file);
    fclose(log_file);

    return ENC_ERROR_OK;
}

// Create single pad with log
SPAE_DLL_EXPIMP pads_error_t SPAE_CALL create_single_pad_with_log(char* pad, char* mrs, char* buk, char* prog_dir, char* circle_name, char* log_path, char* error_desc)
{

    char* logFileName = ALLOC(sizeof(char) * _MAX_FNAME);

    // Build the file name connecting with the path
    memcpy(logFileName, log_path, strlen(log_path));
    logFileName[strlen(log_path)] = '\0';

    strcat(logFileName, "\\");
    strcat(logFileName, circle_name);
    strcat(logFileName, ".txt");

    FILE* log_file = NULL;
    int log_open_status;
    log_file = open_file(logFileName, FILE_MODE_WRITE, &log_open_status);

    if (log_open_status != 0)
    {
        strcpy_s(error_desc, 256, "\nError: When trying to open a Log file.\n");
        return CIRCLE_ERROR_OPENF;
    }

    /*                                                                   */
    /*    Generate Spec Chars Lookup tbl                                 */
    /*                                                                   */
    size_t seeker = 0;
    size_t offset = 0;
    size_t shift = 368;
    size_t s = 0;

    size_t* first_pads_disgussing_bits = ALLOC(_512_BUFFER * sizeof(size_t));
    int ret = collect_unique_bits_for_pads_permutation(first_pads_disgussing_bits, buk, mrs, &seeker, offset + shift, error_desc);
    if (ret != 0)
    {
        return PADS_ERROR_STRANDS;
    }

    write_log(log_file, "+------------------------------------------------------------------+\n");
    write_log(log_file, "|\t\tNine bit seq's in decimal (THAT NEED TO BE XORed with PAD NUM!)\t\t|\n");
    write_log(log_file, "+------------------------------------------------------------------+\n");
    size_t indx = 0;
    for (size_t i = 0; i < 64; i++)
    {
        write_log(log_file, "+-------+-------+-------+-------+-------+-------+-------+-------+\n");
        write_log(log_file, "|");
        for (size_t j = 0; j < 8; j++)
        {
            int_write_log_without_newline(log_file, "  ", first_pads_disgussing_bits[indx]);
            // Get dig num in num
            size_t dgnm = number_of_digits(first_pads_disgussing_bits[indx]);
            if (dgnm == 1)
            {
                write_log(log_file, "    |");
            }
            if (dgnm == 2)
            {
                write_log(log_file, "   |");
            }
            if (dgnm == 3)
            {
                write_log(log_file, "  |");
            }

            indx++;
        }
        write_log(log_file, "\n");
        //write_log(log_file, "+-------+--------+--------+-------+--------+--------+-------+--------+--------+-------+--------+--------+-------+--------+--------+--------+\n");
    }

    
    //for (size_t i = 0; i < _512_BUFFER; i++)
    //{
    //    int_write_log(log_file, "Element decimal value is: ", first_pads_disgussing_bits[i]);
    //}

    offset = seeker;
    seeker = 0;

    char*** lookupTbl = ALLOC(SPEC_CHARS_LOOKUP_TBL_CNT * sizeof(char**)); //was 64(must be 65 at least)
    if (generate_specialchars_lookup_table(lookupTbl, buk, mrs, &seeker, offset, &s) != 0)
    {
        strcpy_s(error_desc, 256, "\nError: Poor key.\n");
        return UK_ERROR_POOR_KEY;
    }

    //multiply by 6 since for chars we were used six bits
    //offset += seeker * 6;
    offset = seeker;
    seeker = 0;

    /*                                                                   */
    /*    Collect logical operation methods for 64 prog files            */
    /*                                                                   */
    char* logicalMethodsForProgFiles = ALLOC(64 * sizeof(char));
    for (size_t i = 0; i < 64; i++)
    {
        logicalMethodsForProgFiles[i] = (char)(1 + '0');
    }
    logicalMethodsForProgFiles[64] = '\0';
    //generate_logical_op_data_for_program_files(logicalMethodsForProgFiles, buk, mrs, &seeker, offset);
    /*                                                                   */
    /*    REARRANGEMENT POINTS FOR BASE USER KEY SEQ's                   */
    /*    Since during above step we used $seeker * 6 bits from every seq*/
    /*    getting new offset so, the next offset point will be           */
    /*                                                                   */
    //offset = seeker;
    //seeker = 0;

    char** rearrangementPointsArray = ALLOC(16 * sizeof(char*));
    generate_rearrangement_points_for_program_files(rearrangementPointsArray, buk, mrs, &seeker, offset);

    /*                                                                   */
    /*    PSP START/JUMP POINTS FOR MRS SEQ's                            */
    /*                                                                   */
    //offset += seeker * 23;
    offset = seeker;
    seeker = 0;

    char** pointPPS = ALLOC(7 * sizeof(char*));
    get_PPS_insertion_point(pointPPS, buk, mrs, &seeker, offset);

    /* Getting fliud positions for PPS */
    offset = seeker;
    seeker = 0;

    char* PPS_insert_pos = ALLOC(64 * 7 * 26 * sizeof(char) + 1);
    get_PPS_positions_dynamic(PPS_insert_pos, buk, mrs, &seeker, offset);

    offset = seeker;
    seeker = 0;
    /* Getting C9 position. 26 bits */
    char* c9_position_26_bits = ALLOC(sizeof(char) * 26 + 1);
    get_C9_insertion_position(c9_position_26_bits, buk, mrs, &seeker, offset);

    /*                                                                   */
    /*    Rearrange BUK files                                            */
    /*                                                                   */

    char* bukr = ALLOC(UK_LENGHT + 1);
    rearrange_files(bukr, buk, rearrangementPointsArray);

    /*-------------------------------------------FIRST PAD--------------------------------------------------------*/
                /*                                                                   */
                /*    Collect Start&Jump points for the next pad                     */
                /*                                                                   */

    /*                                                                   */
    /*    XOR/XNOR -ing base MRS files with base User Key files and      */
    /*    make ROW files.                                                */
    /*    Collect Logicical Op Methods for BUK generating                */
    /*                                                                   */

    char* rowLogicMethods = ALLOC(8 * sizeof(char));
    for (size_t i = 0; i < 8; i++)
    {
        rowLogicMethods[i] = (char)(1 + '0');
    }
    rowLogicMethods[8] = '\0';
    //collect_logic_op_methods(rowLogicMethods, mrs);

    char* row = CALLOC(UK_LENGHT + 1, 1);
    do_logical_operation(row, mrs, bukr, rowLogicMethods);

    char* tmp_pad = ALLOC(_2_POW_23 + 1);
    make_single_pad(tmp_pad, row);

//#if _DEBUG
//    write_log(log_file, "Permutating a pad.\n");
//    //permutate_pad_log(pad, tmp_pad, 1, first_pads_disgussing_bits, &log_file);
//#endif

    permutate_pad(pad, tmp_pad, 1, first_pads_disgussing_bits);

    /* Reset transposition array */
    ZERO_ANY(size_t, pads_disgussing_bits, _512_BUFFER);

    FREE(tmp_pad);

    /*---------NEW WAY-----DYNAMIC POSITIONS-------------*/
    pps_dynamic_t* _dynamic_pps_ptr = dynamic_pps_new();

    // allocating memory for n numbers of struct person
    _dynamic_pps_ptr = (pps_dynamic_t*)ALLOC(64 * sizeof(pps_dynamic_t));

    assign_values_to_dynamic_pps_struct(_dynamic_pps_ptr, PPS_insert_pos);

    /* Marshaling struct into array */
    char* dynamicPPSdata = (char*)ALLOC(sizeof(char) * (64 * (6 + PPS_CHARS_COUNT * 26)) + 1);
    dynamic_pps_struct_into_array(dynamicPPSdata, _dynamic_pps_ptr);
    /*---------END OF NEW WAY----------------------------*/

    pps_t* _pps_ptr;

    // allocating memory for n numbers of struct person
    _pps_ptr = (pps_t*)ALLOC(7 * sizeof(pps_t));
    for (size_t i = 0; i < 7; i++)
    {
        pps_set(_pps_ptr + i, pointPPS[i], lookupTbl[PROG_FILES_COUNT + i]);
    }

    /* Marshaling struct into array */
    /* Allocated memory size is: ppp_ch_count x pps_insetion_pos_len + full lookup table for each char */
    char* ppsData = (char*)ALLOC(sizeof(char) * (PPS_CHARS_COUNT * 26 + PPS_CHARS_COUNT * 64 * 6) + 1);
    pps_struct_into_array(ppsData, _pps_ptr);

    pps_free(_pps_ptr); //Be careful here!!!

    //create_64_prog_files(pad, lookupTbl, ppsData, ppsData, logicalMethodsForProgFiles, prog_dir, error_desc);
    //create_64_prog_files(pad, lookupTbl, ppsData, c9_position_26_bits, dynamicPPSdata, logicalMethodsForProgFiles, prog_dir, error_desc);
    create_64_prog_files(pad,
        lookupTbl,
        ppsData,
        c9_position_26_bits,
        dynamicPPSdata,
        logicalMethodsForProgFiles,
        prog_dir,
        error_desc);

    fflush(log_file);
    fclose(log_file);

    return PADS_ERROR_OK;
}

size_t get_dynamic_PPS_insertion_order(size_t sp)
{
    char* sp_in_bin = CALLOC(sizeof(char) * 28 + 1, 1);
    decimalToBinary(sp_in_bin, sp, 25);

    // Now get the first 6 bits which will point insertion order in decimal
    char* c9_char_six_bits = ALLOC(sizeof(char) * 6 + 1);
    memcpy_s(c9_char_six_bits, 7, sp_in_bin, 6);
    c9_char_six_bits[6] = '\0';

    size_t insert_order = bindec(c9_char_six_bits);
    int insert_order_val = 0;
    if (is_even(insert_order))
    {
        // L->R
        return 0;
    }
    else
    {
        // R->L
        return 1;
    }
}
