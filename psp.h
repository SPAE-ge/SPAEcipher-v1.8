#pragma once
char* PSP(char* buffer, size_t startP, size_t jumpP);
void W_PSP(wchar_t* buffer, size_t startP, size_t jumpP);
wchar_t* string_repeat(size_t n, const wchar_t* s);
void permutateMRS(char* res, char* mrs, size_t* sp, size_t* jp);
size_t get_ghost_bits_count(wchar_t* buffer);
void delete_ghost_bits(wchar_t* c, size_t p);
void validate_jump_point(size_t* jp);
void validate_start_point(size_t* sp);
wchar_t* reverse_PSP(wchar_t* buffer, size_t startP, size_t jumpP);
void recover_PSP(wchar_t* result, wchar_t* buffer, size_t startP, size_t jumpP);
size_t get_effective_jump_point(size_t jp, size_t len);
wchar_t* reverse_PSP_decr(wchar_t* buffer, size_t startP, size_t jumpPoint);
void lite_psp(char* seq, char mask, size_t prev_count, size_t count);
void W_PSP_for_log(wchar_t* buffer, size_t startP, size_t jumpPoint, size_t* next_prime);