#pragma once

/// @brief Error codes for library "pads"
typedef enum pads_error_e
{
    /// No error
    PADS_ERROR_OK = 0,

    /// Error when opening pads config file
    PADS_ERROR_OPENFILE,

    /// Error when writing pads config file
    PADS_ERROR_WRITEFILE,

    /// Error when writing pads config file
    PADS_ERROR_READFILE,

    /// Error Strands count
    PADS_ERROR_STRANDS,

    /// Error Pad is Invalid
    PADS_ERROR_INVALID,

    /// Note Pad is Valid
    PADS_ERROR_VALID,

    /// Note Pad is Valid
    PADS_ERROR_NOPADS,

    /// Undefined error
    PADS_ERROR_UNDEFINED,

    /// Total # of errors in this list (NOT AN ACTUAL ERROR CODE);
    /// NOTE: that for this to work, it assumes your first error code is value 0 and you let it naturally 
    /// increment from there, as is done above, without explicitly altering any error values above
    Pads_ERROR_COUNT

} pads_error_t;

struct pad
{
    int id;
    int prevPad;
    size_t nextPSPstartPoints[8];
    size_t nextPSPjumpPoints[8];
    size_t nextPSPrearrnagePoints[8];
    char pps[42 + 1];
};

/*******************************************************************************

    Structure :     pads

    Parameters :    totalCount -
                        Count of Pads which we nedd to generate for the specific Circle.

                    generatedPads -
                        Actual generated pads count.

                    validPads -
                        Valid pads count.

                    invalidPads -
                        Invalid pads count.

    Description :   This structure stores config data about generated pads for
                    specific Circle.

*******************************************************************************/
struct pads {
    int total_count;
    int generated_pads;
    int valid_pads;
    int invalid_pads;
};

static int PADS_STRUCT_SIZE = sizeof(struct pads);
static int PAD_STRUCT_SIZE  = sizeof(struct pad);
static int PAD_LEN          = 8388608;

pads_error_t create_pads_cfg_file(FILE* f);
void make_single_pad(char* pad, char* row);

/*                                                                   */
/*    Collect Start&Jump points for the next pad                     */
/*                                                                   */
struct pad collect_data_about_next_pad(char* pad_str, char* buk, char* mrs, int current_pad_id, int prev_pad_it, char* error_desc);
size_t get_first_used_pad_id(size_t* pads_list, size_t count, const char* pads_dir, char* pps, size_t* offset);
int get_first_42_bits_of_any_pad(char* bits, size_t pad_num, char* pads_dir, wchar_t* error_desc);