#ifndef PAYLOAD_H
#define PAYLOAD_H

#include <stdio.h>

extern int _payload(
    FILE *(*_fopen) (const char *, const char *),
    int (*_fprintf) (FILE *, const char *, ...),
    int (*_fclose) (FILE *),
    int x
) {
    char filename[] = "result.txt";
    char mode[] = "w";
    char format[] = "%d";

    FILE *file = _fopen(filename, mode);
    if (file == NULL) {
        return 1;
    }

    _fprintf(file, format, x * 20);
    _fclose(file);
    return 0;
}
extern void _end(void);

#endif