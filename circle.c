#include "circle.h"
#include "helper.h"

int is_circle_locked(const char* c_name, char* error_desc)
{
    int locked = -1; // Not Locked
    int open_status;

    /*Accept the file and try to open it*/
    FILE* fp1 = NULL;
    /*Trying to open the file*/
    fp1 = open_file(CIRCLE_FILE_NAME, FILE_MODE_READ, &open_status);

    if (open_status != 0)
    {
        strcpy_s(error_desc, 256, "\nError: When trying to open a Circle cfg file.\n");
        return CIRCLE_ERROR_OPENF;
    }

    struct circle buffer;
    fseek(fp1, 0, SEEK_SET);   // move file position indicator to beginning of file
    while (fread(&buffer, sizeof(struct circle), 1, fp1) == 1)
    {
        if (strcmp(c_name, buffer.circle_name) == 0 && buffer.master == 1 && buffer.locked == 1)
        {
            locked = 0; // We found a circle is locked!

            fflush(fp1);
            fclose(fp1);
            return locked;
        }
    }

    fflush(fp1);
    fclose(fp1);
    return locked;
}
