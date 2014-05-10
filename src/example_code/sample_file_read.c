#include <stdio.h>
#include <stdlib.h>

int main(int argc, char* argv[]) {
    if (argc < 2) {
	printf("Usage: %s <file>\n", argv[0]);
	return 1;
    }

    size_t len;
    size_t bytesRead;
    char* contents;
    FILE* f;

    f = fopen(argv[1], "rb");
    if (f == NULL) {
	fprintf(stderr, "Error opening file: %s", argv[1]);
	return 1;
    }

    // what's the size?
    fseek(f, 0, SEEK_END);
    len = ftell(f);
    rewind(f);

    // read contents
    contents = (char*) malloc(sizeof(char) * len + 1);
    contents[len] = '\0'; // this is needed only for printing to stdout with printf!
    if (contents == NULL) {
	fprintf(stderr, "Failed to allocate memory");
	return 2;
    }

    bytesRead = fread(contents, sizeof(char), len, f);

    // close the file
    fclose(f);

    printf("File length: %d, bytes read: %d\n", len, bytesRead);
    printf("Contents:\n%s", contents);

    free(contents);
    return 0;
}