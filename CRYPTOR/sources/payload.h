int _payload(
	FILE* (*_fopen) (const char *, const char *),
	size_t (*_fwrite) (const void *, size_t, size_t, FILE *),
	int (*_fclose) (FILE *),
	char *data,
	int size
) {
	char fnm[] = "filename.txt";
	char mde[] = "wb";
	FILE *file = _fopen(fnm, mde);
	if (file == NULL) {
		return 1;
	}
	_fwrite(data, sizeof(char), size, file);
	_fclose(file);
	return 0;
}
void _end(void){}
