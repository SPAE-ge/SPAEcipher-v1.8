#include <assert.h>
#include <time.h>
#include "helper.h"
#include <mpir.h>

FILE* w_open_file(const wchar_t* filename, FILE_MODE mode, int* err)
{
    FILE* file = NULL;

    /*Trying to open the file*/
    switch (mode)
    {
    case FILE_MODE_READ:
        _wfopen_s(&file, filename, L"rb");
        if (!file) 
        {   //If the file does not exist
            *err = FILE_NOT_EXIST;
        }
        else 
        {   //Or if the file does exist
            *err = FILE_OK;
            return file; //Returns the pointer to the file
        }
        break;
    case FILE_MODE_WRITE:
        _wfopen_s(&file, filename, L"wb");
        if (!file)
        {   //If the file does not exist
        *err = FILE_NOT_EXIST;
        }
        else
        {   //Or if the file does exist
        *err = FILE_OK;
        return file; //Returns the pointer to the file
        }
        break;
    default:
        return NULL;
        break;
    }

    return NULL;
}

FILE* open_file(const char* filename, FILE_MODE mode, int* err)
{
    FILE* file = NULL;

    errno_t c_err;

    /*Trying to open the file*/
    switch (mode)
    {
    case FILE_MODE_READ:
        c_err = fopen_s(&file, filename, "rb");
        if (!file)
        {   //If the file does not exist
            *err = FILE_NOT_EXIST;
        }
        else
        {   //Or if the file does exist
            *err = FILE_OK;
            return file; //Returns the pointer to the file
        }
        break;
    case FILE_MODE_WRITE:
        fopen_s(&file, filename, "wb");
        if (!file)
        {   //If the file does not exist
            *err = FILE_NOT_EXIST;
        }
        else
        {   //Or if the file does exist
            *err = FILE_OK;
            return file; //Returns the pointer to the file
        }
        break;
    case FILE_MODE_ABPLUS:
        fopen_s(&file, filename, "ab+");
        if (!file)
        {   //If the file does not exist
            *err = FILE_NOT_EXIST;
        }
        else
        {   //Or if the file does exist
            *err = FILE_OK;
            return file; //Returns the pointer to the file
        }
        break;
    case FILE_MODE_APLUS:
        fopen_s(&file, filename, "a");
        if (!file)
        {   //If the file does not exist
            *err = FILE_NOT_EXIST;
        }
        else
        {   //Or if the file does exist
            *err = FILE_OK;
            return file; //Returns the pointer to the file
        }
        break;
    default:
        return NULL;
        break;
    }

    return NULL;
}

wchar_t* wc_read_file(FILE* f, int* err, size_t* f_size)
{
    wchar_t* buffer = NULL;

    size_t length = 0;
    size_t read_length = 0;

    if (f)
    {
        fseek(f, 0, SEEK_END);
        length = ftell(f);
        fseek(f, 0, SEEK_SET);

        // 1 GiB; best not to load a whole large file in one string
        if (length > READ_CHUNK_SIZE)
        {
            *err = FILE_TO_LARGE; return NULL;
        }

        buffer = ALLOC(sizeof(wchar_t) * (length + 1));

        if (length)
        {
            read_length = fread(buffer, 2, length, f);
            //set_wstr_null_terminator(buffer, read_length);
            buffer[read_length] = '\0';
        }

        fclose(f);
        *err = FILE_OK;
        //Return read len as a size.
        *f_size = read_length;
    }
    else
    {
        *err = FILE_NOT_EXIST; return buffer;
    }

    return buffer;
}

char** dirlist(char dirname[], char const* ext, size_t* elems)
// Scans a directory and retrieves all files of given extension
{
    DIR* d = NULL;
    struct dirent* dir = NULL;
    char** list = NEW(list); //will be free-ed in strands combining function

    d = opendir(dirname);
    if (d)
    {
        while ((dir = readdir(d)) != NULL)
        {
            if (strcmp(get_file_ext(dir->d_name), ext) == 0)
            {
                list = RESIZE(list, (long)(sizeof(*list) * (*elems + 1)));
                list[(*elems)++] = _strdup(dir->d_name);
            }
        }
        closedir(d);
    }
    return list;
}

void set_str_null_terminator(char* s, size_t index)
{
    s[index] = '\0';
}

void set_wstr_null_terminator(wchar_t* s, size_t index)
{
    s[index] = L'\0';
}

int set_file_mode_to_utf(FILE** f)
{
    int modeResult;

    modeResult = _setmode(_fileno(*f), _O_U8TEXT);
    return modeResult;
}

int is_file_empty(FILE* f)
{
    long saved_offset = ftell(f);
    fseek(f, 0, SEEK_END);

    if (ftell(f) == 0) {
        return 0;
    }

    fseek(f, saved_offset, SEEK_SET);
    return -1;
}

int is_file_exists(const char* fname)
{
    // Check for existence.
    if ((_access(fname, 0)) != -1)
    {
        return 0;
    }
    else
    {
        return 1;
    }
}

char* get_file_ext(const char* filename)
{
    char* dot = strrchr(filename, '.');
    if (!dot || dot == filename) return "";
    return dot + 1;
}


/*Convert bin to dec*/
size_t bindec(const char* bin)
{
    int i = 0, j;
    j = sizeof(size_t) * 8;
    while ((j--) && ((*bin == '0') || (*bin == '1'))) {
        i <<= 1;
        if (*bin == '1') i++;
        bin++;
    }
    return i;
}

/* Convert decimal to binary */

// this method will print all the given bits of a number
void decimalToBinary(char* binary, size_t num, int bits_count)
{
    for (int i = bits_count; i >= 0; i--) {

        // calculate bitmask to check whether
        // ith bit of num is set or not
        int mask = (1 << i);

        // ith bit of num is set 
        if (num & mask)
            strcat_s(binary, bits_count + 2, "1");
        // ith bit of num is not set   
        else
            strcat_s(binary, bits_count + 2, "0");
    }
}


void fmakeXOR(char* first, char* second)
{
	const size_t l1 = strlen(first);
	const size_t l2 = strlen(second);
    int i;
    //	int thread_id;

#pragma omp parallel
    {
        //thread_id = omp_get_thread_num();
#pragma omp for
        for (i = 0; i < MIN(l1, l2); i++)
        {
            first[i] = (char)((first[i] - '0') ^ (second[i] - '0') + '0');
        }
    }
}

void fmakeXNOR(char* first, char* second)
{
	const size_t l1 = strlen(first);
	const size_t l2 = strlen(second);

    for (size_t i = 0; i < MIN(l1, l2); i++)
    {
        if (first[i] == second[i])
        {
            first[i] = (char)(1 + '0');
        }
        else
        {
            first[i] = '0';
        }
    }
}

char* c_read_file(FILE* f, int* err, size_t* f_size) 
{
    char* buffer;
    size_t length;
    size_t read_length;

    if (f) {

        long int pos = ftell(f);

        fseek(f, 0, SEEK_END);
        length = ftell(f) - pos;
        fseek(f, pos, SEEK_SET);

        // 1 GiB; best not to load a whole large file in one string
        if (length > 1073741824) {
            *err = FILE_TO_LARGE;

            return NULL;
        }

        buffer = ALLOC(sizeof(char) * length + 1);

        if (length) {
            read_length = fread(buffer, 1, length, f);

            if (length != read_length) {
                *err = FILE_READ_ERROR;

                return NULL;
            }
        }

        fclose(f);

        *err = FILE_OK;
        buffer[length] = '\0';
        *f_size = length;
    }
    else {
        *err = FILE_NOT_EXIST;

        return NULL;
    }

    return buffer;
}

size_t arrayUniqueWithoutSorting(char* input[], size_t s)
{
    size_t prev = 0;
    size_t curr = 1;
    size_t last = s - 1;

    while (curr <= last) {
        for (prev = 0; prev < curr && strcmp(input[curr], input[prev]) != 0; ++prev);
        if (prev == curr) {
            ++curr;
        }
        else {
            input[curr] = input[last];
            --last;
        }
    }
    return curr;
}


size_t get_ones_count_in_file(char* s)
{
    /*                                                                  */
    /*  mpz_t is the C data type for multiple precision integer         */
    /*                                                                  */
    mpz_t op;
    size_t n;
    /*                                                                   */
    /* Initialization of all  multiple precision variables ( op )        */
    /*         and assignment of data to entrance variables ( op )       */
    /*                                                                   */
    mpz_init(op);
    /*                                                                   */
    /*    Call mpz_set_str to set n = 17654372174325565422222224         */
    /*                                                                   */
    mpz_set_str(op, s, 2);
    /*                                                                   */
    /*     Call mpz_popcount to set                                      */
    /* n = the number of 1 bits in the binary representation if op >= 0  */
    /* n = the largest possible unsigned long if op < 0                  */
    /*                                                                   */
    n = mpz_popcount(op);
    /*                                                                   */
    /*             Free the space occupied by op                         */
    /*                                                                   */
    mpz_clear(op);

    return n;
}

int is_number_in_1SD_range(size_t number)
{
    if (number >= SD1_START_VALUE 
     && number <= SD1_END_VALUE)
    {
        return 1;
    }
    else 
    {
        return 0;
    }
}

int is_number_in_1SD_range_large(size_t number)
{
    if (number >= SD1_START_VALUE_LARGE
        && number <= SD1_END_VALUE_LARGE)
    {
        return 1;
    }
    else
    {
        return 0;
    }
}

char* get_current_datetime()
{
    time_t t = time(NULL);
    struct tm buf;
    localtime_s(&buf, &t);
    char* formatted_datetime = ALLOC(sizeof(char) * 64);
    size_t ret = strftime(formatted_datetime, 64, "%c", &buf);
    assert(ret);
    
    return formatted_datetime;
}


size_t divisible_by_six(size_t num)
{
    size_t addedBitsCount = 0;

    size_t fractionalPart = num % 6;

    if (fractionalPart > 0)
    {
        addedBitsCount = 6 - fractionalPart;
    }

    assert(addedBitsCount >= 0);
    return addedBitsCount;
}

/*Get the size of any file*/
size_t fsize(FILE* File)
{
    size_t FSZ;
    fseek(File, 0, SEEK_END);
    FSZ = ftell(File);
    rewind(File);
    return FSZ;
}


int natural_compare(const void* a, const void* b)
{
    const char* aa, * bb;
    int num1, num2;

    for (aa = *(const char**)a, bb = *(const char**)b; *aa && *bb; ++aa, ++bb) {
        if (isdigit(*aa) && isdigit(*bb)) {
            sscanf_s(aa, "%d", &num1);
            sscanf_s(bb, "%d", &num2);
            if (num1 != num2) {
                return num1 - num2;
            }
            while (*(++aa) && isdigit(*aa));
            while (*(++bb) && isdigit(*bb));
            --aa; --bb;
        }
        else if (*aa != *bb) {
            return *aa - *bb;
        }
    }

    return *aa - *bb;
}


/*Do XOR on short strings*/
unsigned char* xor_short_strings(const char* str1, char* str2)
{
    unsigned char* xored;
    xored = ALLOC(sizeof(unsigned char) * 7);

    if (strlen(str1) != strlen(str2))
        return 0;

    for (size_t i = 0; i < strlen(str1); i++)
    {
        xored[i] = (unsigned char)((str1[i] - '0') ^ (str2[i] - '0') + '0');
    }
    xored[6] = '\0';
    return xored;
}

wchar_t* int2str(size_t in)
{
    wchar_t* vOut = ALLOC(sizeof(wchar_t) * 20);
    _ui64tow_s(in, vOut, sizeof(vOut), 10);

    return vOut;
}

wchar_t* int2wstr(size_t in)
{
    wchar_t* vOut = ALLOC(sizeof(wchar_t) * 20);
    _ui64tow_s(in, vOut, 20, 10);

    return vOut;
}

int value_in_array(size_t val, size_t* arr, size_t len)
{
    int i;
    for (i = 0; i < len; i++)
    {
        if (arr[i] == val)
            return 1;
    }
    return 0;
}

wchar_t* wget_file_name_from_path(wchar_t* path)
{
    if (path == NULL)
        return NULL;

    size_t len = 0;
    
    wchar_t* pFileName = ALLOC(sizeof(wchar_t) * _MAX_PATH);
    for (wchar_t* pCur = path; *pCur != '\0'; pCur++)
    {
        if (*pCur == '/' || *pCur == '\\')
        {
            wcscpy_s(pFileName, _MAX_PATH, pCur + 1);
            //pFileName = pCur + 1;
            len = wcslen(pCur);
        }
    }

    pFileName[len] = '\0';

    return pFileName;
}

int find_str_in_file(char const* fname, char* str)
{
    FILE* f = NULL;
    errno_t err;
    int ret_pos;

    err = fopen_s(&f, fname, "rb");
    if (f == NULL)
    {
        return -1;
    }

    char* buffer = ALLOC(sizeof(char) * 8388608);
    fread(buffer, 1, 8388608, f);

    char* pos = strstr(buffer, str);
    if (pos) 
    {
        fclose(f);
        ret_pos = (int)(pos - buffer);
        FREE(buffer);
        return ret_pos;
    }
    else
    {
        FREE(buffer);
        fclose(f);
        return -1;
    }
}


void write_log(FILE* f, const char* data)
{
    fprintf(f, "%s", data);
    fflush(f);
    //fwrite(&data, 1, strlen(data), f);
}

void wcs_write_log(FILE* f, wchar_t* data)
{
    fwprintf(f, L"%lS", data);
    fflush(f);
}

void int_write_log(FILE* f, char* description, size_t val)
{
    char* log = CALLOC(sizeof(char) * 256, 1);
    char tempbuf[13];

    strcat_s(log, 256, description);

    int bytes = sprintf_s(tempbuf, 13, "%zu\n", val);
    if (bytes > 0)
    {
        strcat_s(log, 256, tempbuf);

        fprintf(f, "%s", log);
        fflush(f);
    }

    FREE(log);
}

void int_write_log_without_newline(FILE* f, char* description, size_t val)
{
    char* log = CALLOC(sizeof(char) * 256, 1);
    char tempbuf[13];

    strcat_s(log, 256, description);

    int bytes = sprintf_s(tempbuf, 13, "%zu", val);
    if (bytes > 0)
    {
        strcat_s(log, 256, tempbuf);

        fprintf(f, "%s", log);
        fflush(f);
    }

    FREE(log);
}


void int_wcs_write_log(FILE* f, wchar_t* description, size_t val)
{
    wchar_t* log = CALLOC(sizeof(wchar_t) * 256, 1);
    wchar_t tempbuf[13];

    wcscat_s(log, 256, description);

    int bytes = swprintf_s(tempbuf, 13, L"%zu\n", val);
    if (bytes > 0)
    {
        wcscat_s(log, 256, tempbuf);

        fwprintf(f, L"%lS", log);
        fflush(f);
    }

    FREE(log);
}

void int_wcs_write_log_without_new_line (FILE* f, wchar_t* description, size_t val)
{
    wchar_t* log = CALLOC(sizeof(wchar_t) * 256, 1);
    wchar_t tempbuf[13];

    wcscat_s(log, 256, description);

    int bytes = swprintf_s(tempbuf, 13, L"%zu", val);
    if (bytes > 0)
    {
        wcscat_s(log, 256, tempbuf);

        fwprintf(f, L"%lS", log);
        fflush(f);
    }

    FREE(log);
}

int is_array_set_to_zero(size_t* a, size_t size)
{
    int sum = 0;
    for (size_t i = 0; i < size; ++i) 
    {
        sum |= a[i];
    }

    if (sum != 0)
    {
        return 1;
    }
    else
    {
        return 0;
    }
}

size_t number_of_digits(size_t n)
{
    size_t count = 0;

    do {
        n /= 10;
        ++count;
    } while (n != 0);

    return count;
}

/// <summary>
/// This function takes an integer as input and returns 1 if the number is even and 0 if the number is odd. 
/// The % operator returns the remainder of dividing num by 2, so if the remainder is 0, then num is even.
/// </summary>
/// <param name="num"></param>
/// <returns></returns>
int is_even(size_t num) 
{
    return (num % 2 == 0);
}
