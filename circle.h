#pragma once
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

#define CIRCLE_FILE_NAME "C:\\ProgramData\\GGandJ\\SPAE\\circles.txt"
#define CIRCLE_TMP_FILE_NAME "C:\\ProgramData\\GGandJ\\SPAE\\tmp_circles.txt"
#define USER_PADS_CFG_TMP_FILE_NAME "C:\\ProgramData\\GGandJ\\SPAE\\tmp_pads_cfg.txt"

/// @brief Error codes for library "circle"
typedef enum circle_error_e
{
    /// No error
    CIRCLE_ERROR_OK = 0,

    /// Invalid arguments (ex: NULL pointer where a valid pointer is required)
    CIRCLE_ERROR_INVARG,

    /// Out of memory (RAM)
    CIRCLE_ERROR_NOMEM,

    /// Error opening a file
    CIRCLE_ERROR_OPENF,

    /// Error writing a file
    CIRCLE_ERROR_WRITEF,

    /// No Circle with the name
    CIRCLE_ERROR_NOCIRCLE,

    /// No Member with the name
    CIRCLE_ERROR_NOMEMBER,

    /// Could not delete file
    CIRCLE_ERROR_DELETEF,

    /// Could not rename file
    CIRCLE_ERROR_RENAMEF,

    /// Duplicate name
    CIRCLE_ERROR_DUPLICATE,

    /// Cfg file is empty
    CIRCLE_ERROR_FILE_EMPTY,

    /// Cfg file is curropted
    CIRCLE_ERROR_FILE_CURRUPT,

    /// Circle is locked
    CIRCLE_ERROR_CIRCLE_LOCKED,

    /// Total # of errors in this list (NOT AN ACTUAL ERROR CODE);
    /// NOTE: that for this to work, it assumes your first error code is value 0 and you let it naturally 
    /// increment from there, as is done above, without explicitly altering any error values above
    CIRCLE_ERROR_COUNT

} circle_error_t;

/*******************************************************************************

    Structure :     member

    Parameters :    f_name -
                        Store memeber first name in specific Circle.

                    position_num -
                        Member's number in Circle.

    Description :   This structure stores data about members in Circles.

*******************************************************************************/
struct member {
    char first_name[100];

    int position_num;
    //char last_name[100];
    //char e_mail[128];
};

/*******************************************************************************

    Structure :     circle

    Parameters :    circleName -
                        Store Circle name.

                    configPath -
                        Every circle has its own config file, so we need to
                        know where exactly this file is stored.

                    padsPath -
                        Every circle has its own Pad's folder, so we need to
                        know where exactly this folder is stored.

                    userKey -
                        Every circle has its own userkey file, so we need to
                        know where exactly this file is stored.
                        ATTENTION!!!
                        May be it worth removing this in furthere releases!

                    struct member -
                        Stores info about a member.

    Description :   This structure stores data about Circles and members belongs
                    to that Circle.

*******************************************************************************/
struct circle {
    char circle_name[100];
    char config_path[100];
    char pads_path[100];
    //char userkey_path[100];

    struct member mbr;

    int locked; //0-NO, 1-YES
    int master;
};

static int MEMBER_SIZE = sizeof(struct member);
static int CIRCLE_SIZE = sizeof(struct circle);

int is_circle_locked(const char* c_name, char* error_desc);