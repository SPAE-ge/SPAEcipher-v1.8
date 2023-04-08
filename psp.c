#pragma warning(disable : 4996)
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <wchar.h>
#include "prime.h"
#include "mem.h"
#include "spaestr.h"
#include "psp.h"
#include "userkey.h"

#define MRS_LEN 8388608

char* PSP(char* buffer, size_t startP, size_t jumpP)
{
    size_t index, contentLen, next_Prime = 0;

    /*Get the len of result content*/
    contentLen = strlen(buffer);

    char* resultBuffer = ALLOC(sizeof(char) * contentLen + 1184);
    size_t* ghost = ALLOC(1184 * sizeof(size_t)); // The PRIME GAP 1,184 	43,841,547,845,541,059
    char* ghosted;

    if (jumpP == 0 && contentLen < 100)
    {
        //jumpP = get_effective_jump_point(jumpPoint, contentLen);
        jumpP = 1;
    }
    else
    {
        validate_jump_point(&jumpP);
    }

    if (contentLen >= 100)
    {
        validate_start_point(&startP);
    }

    /*Assign StartPint's char to result buffer as a first symbol*/
    index = startP;
    memcpy(&resultBuffer[0], &buffer[index], 1); /*May change to 	//resultBuf[0] = result[index];	//resultBuf[1] = L'\0'; ?????*/
    //resultBuffer[1] = '\0';

    //check if file size number is Prime number
    if (isPrime(contentLen) == 0)
    {
        //not a prime?
        next_Prime = nextPrime(contentLen);
        //adding some Ghost bits
        char* gBits = Str_dup("+", 1, 0, next_Prime - contentLen);

        ghosted = ALLOC(sizeof(char) * next_Prime + 1);
        memcpy(ghosted, buffer, contentLen);
        ghosted[contentLen] = '\0';
        strncat_s(ghosted, next_Prime + 1, gBits, next_Prime - contentLen);

        //strcat(ghosted, gBits);
        contentLen = next_Prime - 1;
    }
    else
    {
        ghosted = ALLOC(contentLen + 1);
        memcpy(ghosted, buffer, contentLen);
        ghosted[contentLen] = '\0';

        next_Prime = contentLen;
        contentLen--;
    }

    size_t j = 0;
    for (size_t i = 1; i <= contentLen; i++)
    {
        index = (index + jumpP) % next_Prime;
        if (ghosted[index] == '+')
        {
            ghost[j] = i;
            j++;
        }
        memcpy(&resultBuffer[i], &ghosted[index], 1);
        //resultBuf[i] = result[index];
        resultBuffer[i + 1] = '\0';
    }

    //Find and Replace all ghost symbols with empty string
    for (size_t i = 0; i < j; i++)
    {
        memcpy(&resultBuffer[ghost[i] - i], &resultBuffer[ghost[i] + 1 - i], strlen(resultBuffer) + i - ghost[i]);
    }

    FREE(ghost);
    FREE(ghosted);

    return resultBuffer;
}

void W_PSP(wchar_t* buffer, size_t startP, size_t jumpPoint)
{
    size_t index, next_Prime = 0, contentLen, contentBaseLen;

    /*Get the len of result content*/
    contentBaseLen = contentLen = wcslen(buffer);

    startP = startP % contentLen;
    size_t jumpP = jumpPoint % contentLen;

    if (jumpP == 0 && contentLen < 100)
    {
        //jumpP = get_effective_jump_point(jumpPoint, contentLen);
        jumpP = 1;
    }
    else
    {
        validate_jump_point(&jumpP);
    }

    if (startP >= 0 && contentLen < 100)
    {
        /* Do nothing */
        ;
    }
    else
    {
        validate_start_point(&startP);
    }

    wchar_t* resultBuffer = ALLOC((sizeof(wchar_t) * (contentLen + 1184)));
    size_t* ghost = ALLOC(1184 * sizeof(size_t)); // The PRIME GAP 1,184 	43,841,547,845,541,059
    wchar_t* ghosted = NULL;


    /*Assign StartPint's char to result buffer as a first symbol*/
    index = startP;
    wmemcpy(&resultBuffer[0], &buffer[index], 1); /*May change to 	//resultBuf[0] = result[index];	//resultBuf[1] = L'\0'; ?????*/
    resultBuffer[1] = L'\0';

    //check if file size number is Prime number
    if (isPrime(contentLen) == 0)
    {
        //not a prime?
        next_Prime = nextPrime(contentLen);
        //adding some Ghost bits
        wchar_t* gBits = W_Str_dup(L"+", 1, 0, next_Prime - contentLen);

        ghosted = ALLOC(sizeof(wchar_t) * (next_Prime + 1));
        wmemcpy_s(ghosted, next_Prime + 1, buffer, contentLen);
        ghosted[contentLen] = L'\0';

        wcsncat_s(ghosted, next_Prime + 1, gBits, next_Prime - contentLen);
        contentLen = next_Prime - 1;

        FREE(gBits);
    }

    else
    {
        ghosted = ALLOC((sizeof(wchar_t) * (contentLen + 1)));
        wmemcpy(ghosted, buffer, contentLen);
        ghosted[contentLen] = '\0';

        next_Prime = contentLen;
        contentLen--;
    }

    size_t j = 0;
    for (size_t i = 1; i <= contentLen; i++)
    {
        index = (index + jumpP) % next_Prime;
        if (ghosted[index] == '+')
        {
            ghost[j] = i;
            j++;
        }
        wmemcpy(&resultBuffer[i], &ghosted[index], 1);

        //resultBuf[i] = result[index];
        //resultBuffer[i + 1] = L'\0';
    }
    resultBuffer[contentLen + 1] = L'\0';

    //Find and Replace all ghost symbols with empty string
    for (size_t i = 0; i < j; i++)
    {
        wmemcpy(&resultBuffer[ghost[i] - i], &resultBuffer[ghost[i] + 1 - i], wcslen(resultBuffer) + i - ghost[i]);
    }

    //resultBuffer[contentLen] = L'\0';
    wmemcpy(buffer, resultBuffer, contentBaseLen);
    buffer[contentBaseLen] = L'\0';

    FREE(ghost);
    FREE(ghosted);
    FREE(resultBuffer);
}

/*Repeate a given string n times. This is for generating pseudo-random bits for prepending to file*/
wchar_t* string_repeat(size_t n, const wchar_t* s) {
    if (n == 0) return NULL;
    size_t slen = wcslen(s);
    wchar_t* dest = (wchar_t*)malloc(sizeof(wchar_t) * n * slen + 1);
    if (dest == NULL) return NULL;

    size_t i; wchar_t* p;
    for (i = 0, p = dest; i < n; ++i, p += slen) {
        wmemcpy(p, s, slen);
    }
    *p = L'\0';
    return dest;
}

void permutateMRS(char* res, char* mrs, size_t* sp, size_t* jp)
{
    size_t offset = 0;
    char* tmp = ALLOC(sizeof(char) * MRS_LEN + 1);

    for (size_t i = 0; i < 8; i++)
    {
        memcpy(tmp, mrs + offset, MRS_LEN);
        tmp[MRS_LEN] = '\0';
        char* psp = PSP(tmp, sp[i], jp[i]);
        memcpy(res + offset, psp, MRS_LEN);

        offset += MRS_LEN;

        FREE(psp);
    }
    res[offset] = '\0';
    FREE(tmp);
}

wchar_t* reverse_PSP(wchar_t* buffer, size_t startP, size_t jumpP)
{
    size_t gc = 0, contentLen, next_Prime, index = 0, ghostCharsCount = 0;
    wchar_t* reversedArray;

    contentLen = wcslen(buffer);
    gc = get_ghost_bits_count(buffer);

    wchar_t* result = ALLOC(sizeof(wchar_t) * (contentLen + gc + 1));

    recover_PSP(result, buffer, startP % contentLen, jumpP % contentLen);

    contentLen = wcslen(result);
    startP = startP % (contentLen - gc);
    jumpP = jumpP % (contentLen - gc);

    if (jumpP == 0 && (contentLen - gc) < 100)
    {
        //jumpP = get_effective_jump_point(jumpPoint, contentLen);
        jumpP = 1;
    }
    else
    {
        validate_jump_point(&jumpP);
    }

    //validate_jump_point(&jumpP);
    validate_start_point(&startP);

    reversedArray = ALLOC(sizeof(wchar_t) * (contentLen + 1));
    for (size_t i = 0; i < contentLen; i++)
    {
        index = (startP + (jumpP * i)) % contentLen;
        reversedArray[index] = result[i];

    }
    reversedArray[contentLen] = L'\0';

    /* Check if file size number is Prime number */
    if (isPrime(contentLen - gc) == 0)
    {
        //not a prime?
        //trim ghost chars from the end
        next_Prime = nextPrime(contentLen - gc);
        ghostCharsCount = next_Prime - (contentLen - gc);
        delete_ghost_bits(reversedArray, gc);
    }

    FREE(result);
    return reversedArray;
}


wchar_t* reverse_PSP_decr(wchar_t* buffer, size_t startP, size_t jumpPoint)
{
    size_t gc = 0, contentLen, contentBaseLen, next_Prime, index = 0, ghostCharsCount = 0;
    wchar_t* reversedArray;

    /*Get the len of result content*/
    contentBaseLen = contentLen = wcslen(buffer);

    startP = startP % contentBaseLen;
    size_t jumpP = jumpPoint % contentBaseLen;

    if (jumpP == 0 && contentBaseLen < 100)
    {
        //jumpP = get_effective_jump_point(jumpPoint, contentBaseLen);
        jumpP = 1;
    }
    else
    {
        validate_jump_point(&jumpP);
    }

    if (startP >= 0 && contentBaseLen < 100)
    {
        /* Do nothing */
        ;
    }
    else
    {
        validate_start_point(&startP);
    }
    gc = get_ghost_bits_count(buffer);

    wchar_t* result = ALLOC(sizeof(wchar_t) * (contentBaseLen + gc + 2));

    recover_PSP(result, buffer, startP, jumpP);

    contentLen = wcslen(result);

    reversedArray = ALLOC(sizeof(wchar_t) * (contentLen + 2));
    for (size_t i = 0; i < contentLen; i++)
    {
        index = (startP + (jumpP * i)) % contentLen;
        reversedArray[index] = result[i];

    }
    reversedArray[contentLen] = L'\0';

    /* Check if file size number is Prime number */
    if (isPrime(contentLen - gc) == 0)
    {
        //not a prime?
        //trim ghost chars from the end
        next_Prime = nextPrime(contentLen - gc);
        delete_ghost_bits(reversedArray, gc);
    }

    FREE(result);
    return reversedArray;
}


size_t get_ghost_bits_count(wchar_t* buffer)
{
    size_t next_Prime, contentLen, ghostCharsCount = 0;

    /* Get the len of result content */
    contentLen = wcslen(buffer);

    /* check if file size number is Prime number */
    if (isPrime(contentLen) == 0)
    {
        /* not a prime? */
        next_Prime = nextPrime(contentLen);
        /* we need to get how many chars were added as a ghost char */
        ghostCharsCount = next_Prime - contentLen;

        if (ghostCharsCount <= 0)
        {
            return EXIT_FAILURE;
        }
    }

    return ghostCharsCount;
}

void delete_ghost_bits(wchar_t* c, size_t p)
{
    wchar_t* f;
    size_t length;

    length = wcslen(c);

    f = wsub_string(c, 1, length - p);

    wcscpy_s(c, length, L"");
    wcscat_s(c, length, f);
}

void validate_jump_point(size_t* jp)
{
    if (*jp <= 0)
    {
        *jp += 100;
    }
}

void validate_start_point(size_t* sp)
{
    if (*sp <= 0)
    {
        *sp += 100;
    }
}

void recover_PSP(wchar_t* result, wchar_t* buffer, size_t startP, size_t jumpP)
{
    size_t next_Prime, contentLen, ghostCharsCount = 0, index = 0;
    size_t* ghostCharsIndexesInNewFile;

    /* Get the len of result content */
    contentLen = wcslen(buffer);

    if (jumpP == 0 && contentLen < 100)
    {
        //jumpP = get_effective_jump_point(jumpPoint, contentBaseLen);
        jumpP = 1;
    }
    else
    {
        validate_jump_point(&jumpP);
    }

    /*startP = startP % contentLen;
    jumpP = jumpP % contentLen;*/

    /* check if file size number is Prime number */
    if (isPrime(contentLen) == 0)
    {
        /* not a prime? */
        next_Prime = nextPrime(contentLen);
        /* we need to get how many chars were added as a ghost char */
        ghostCharsCount = next_Prime - contentLen;

        if (ghostCharsCount <= 0)
        {
            exit(1);
        }

        size_t* ghostIndexes = ALLOC(sizeof(size_t) * (long)ghostCharsCount);

        /* Then we need to get ghost chars indexes in PSP-ed file */
        /* For that, firstly we are getting ghost chars indexes as an added last chars into sequence */
        ghostCharsIndexesInNewFile = ALLOC((sizeof(size_t) * (long)ghostCharsCount));

        for (size_t i = 0; i < ghostCharsCount; i++)
        {
            ghostCharsIndexesInNewFile[i] = contentLen + i;
        }

        /* Get chars offsets during PSP operation */
        /* The formula is (start + (i * jump)%nextPrime) */
        size_t ghostCount = 0;

        for (size_t i = 0; i < next_Prime; i++)
        {
            /* We have found all the necessary offsets */
            if (ghostCount == ghostCharsCount)
            {
                break;
            }

            size_t pspOffset = (startP + (jumpP * i)) % next_Prime;
            if (value_in_array(pspOffset, ghostCharsIndexesInNewFile, ghostCharsCount))
            {
                /* Store index */
                ghostIndexes[ghostCount] = i;

                ghostCount++;
                index++;
            }
        }

        /* Trying recover */
        size_t prev = 0, offset = 0, placed = 0;
        for (size_t i = 0; i < index; i++)
        {
            wmemcpy(result + offset, buffer + placed, ghostIndexes[i] - offset);
            wmemcpy(result + ghostIndexes[i], L"+", sizeof(wchar_t) * 1);
            prev = ghostIndexes[i];
            placed += (ghostIndexes[i] - offset);
            offset = prev + 1;
        }
        //wmemcpy(result + prev + index - 1, buffer + placed, contentLen - prev + (index - 1));
        wcscat(result, buffer + placed);
        result[contentLen + index] = '\0';
        /*size_t prev = 0, offset = 0;
        for (size_t i = 0; i < index; i++)
        {
            wmemcpy(result + offset, buffer + prev, ghostIndexes[i] - prev);
            wmemcpy(result + ghostIndexes[i], L"+", sizeof(wchar_t));
            prev = ghostIndexes[i];
            //offset += (prev + 1);
            offset = prev + 1;
        }
        wmemcpy(result + prev + 1, buffer + prev - 1, contentLen - prev + 1);
        result[contentLen + index] = '\0';*/

        FREE(ghostIndexes);
        FREE(ghostCharsIndexesInNewFile);
    }
    else
    {
        wmemcpy(result, buffer, contentLen);
        result[contentLen] = '\0';
    }
}

size_t get_effective_jump_point(size_t jp, size_t len)
{
    size_t effectivePoint = jp % len;
    if (effectivePoint != 0)
    {
        return effectivePoint;
    }
    else
    {
        return get_effective_jump_point(jp >> 1, len);
    }
}

void lite_psp(char* seq, char mask, size_t prev_count, size_t count)
{
    size_t index = 0;
    size_t next_prime = 0;
    size_t content_len = strlen(seq);
    size_t base_content_len = strlen(seq);

    char* result_buffer = ALLOC(sizeof(char) * content_len + 1184);
    /*                                                                   */
    /*    Collect Start&Jump points                                      */
    /*                                                                   */
    size_t start_point = 0;
    size_t jump_point = 0;

    get_start_jump_points_26_bits(seq, &start_point, &jump_point);

    start_point = start_point % content_len;
    jump_point  = jump_point % content_len;

    if (jump_point == 0 && content_len < 100)
    {
        jump_point = 1;
    }
    else
    {
        validate_jump_point(&jump_point);
    }

    if (content_len >= 100)
    {
        validate_start_point(&start_point);
    }

    /*Assign StartPint's char to result buffer as a first symbol*/
    index = start_point;
    if (seq[index] == mask)
    {
        seq[index] = (char)((seq[index] - '0') ^ 1 + '0');
        prev_count++;
    }

    //check if file size number is Prime number
    if (isPrime(content_len) == 0)
    {
        //not a prime?
        next_prime = nextPrime(content_len);
        //adding some Ghost bits
        char* gBits = Str_dup("+", 1, 0, next_prime - content_len);

        memcpy(result_buffer, seq, content_len);
        result_buffer[content_len] = '\0';
        strncat_s(result_buffer, next_prime + 1, gBits, next_prime - content_len);

        content_len = next_prime - 1;
    }
    else
    {
        memcpy(result_buffer, seq, content_len);
        result_buffer[content_len] = '\0';

        next_prime = content_len;
        content_len--;
    }

    while (prev_count < count)
    {
        index = (index + jump_point) % next_prime;
        
        if (result_buffer[index] == mask)
        {
            result_buffer[index] = (char)((result_buffer[index] - '0') ^ 1 + '0');
            prev_count++;
        }
    }

    memcpy(seq, result_buffer, base_content_len);

    FREE(result_buffer);
}

void W_PSP_for_log(wchar_t* buffer, size_t startP, size_t jumpPoint, size_t* next_prime)
{
    size_t index, next_Prime = 0, contentLen, contentBaseLen;

    /*Get the len of result content*/
    contentBaseLen = contentLen = wcslen(buffer);

    startP = startP % contentLen;
    size_t jumpP = jumpPoint % contentLen;

    if (jumpP == 0 && contentLen < 100)
    {
        //jumpP = get_effective_jump_point(jumpPoint, contentLen);
        jumpP = 1;
    }
    else
    {
        validate_jump_point(&jumpP);
    }

    if (startP >= 0 && contentLen < 100)
    {
        /* Do nothing */
        ;
    }
    else
    {
        validate_start_point(&startP);
    }

    wchar_t* resultBuffer = ALLOC((sizeof(wchar_t) * (contentLen + 1184)));
    size_t* ghost = ALLOC(1184 * sizeof(size_t)); // The PRIME GAP 1,184 	43,841,547,845,541,059
    wchar_t* ghosted = NULL;


    /*Assign StartPint's char to result buffer as a first symbol*/
    index = startP;
    wmemcpy(&resultBuffer[0], &buffer[index], 1); /*May change to 	//resultBuf[0] = result[index];	//resultBuf[1] = L'\0'; ?????*/
    resultBuffer[1] = L'\0';

    //check if file size number is Prime number
    if (isPrime(contentLen) == 0)
    {
        //not a prime?
        next_Prime = nextPrime(contentLen);
        //adding some Ghost bits
        wchar_t* gBits = W_Str_dup(L"+", 1, 0, next_Prime - contentLen);

        ghosted = ALLOC(sizeof(wchar_t) * (next_Prime + 1));
        wmemcpy_s(ghosted, next_Prime + 1, buffer, contentLen);
        ghosted[contentLen] = L'\0';

        wcsncat_s(ghosted, next_Prime + 1, gBits, next_Prime - contentLen);
        contentLen = next_Prime - 1;

        FREE(gBits);
    }

    else
    {
        ghosted = ALLOC((sizeof(wchar_t) * (contentLen + 1)));
        wmemcpy(ghosted, buffer, contentLen);
        ghosted[contentLen] = '\0';

        next_Prime = contentLen;
        contentLen--;
    }

    size_t j = 0;
    for (size_t i = 1; i <= contentLen; i++)
    {
        index = (index + jumpP) % next_Prime;
        if (ghosted[index] == '+')
        {
            ghost[j] = i;
            j++;
        }
        wmemcpy(&resultBuffer[i], &ghosted[index], 1);

        //resultBuf[i] = result[index];
        //resultBuffer[i + 1] = L'\0';
    }
    resultBuffer[contentLen + 1] = L'\0';

    //Find and Replace all ghost symbols with empty string
    for (size_t i = 0; i < j; i++)
    {
        wmemcpy(&resultBuffer[ghost[i] - i], &resultBuffer[ghost[i] + 1 - i], wcslen(resultBuffer) + i - ghost[i]);
    }

    //resultBuffer[contentLen] = L'\0';
    wmemcpy(buffer, resultBuffer, contentBaseLen);
    buffer[contentBaseLen] = L'\0';
    *next_prime = next_Prime;

    FREE(ghost);
    FREE(ghosted);
    FREE(resultBuffer);
}