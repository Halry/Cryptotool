#include <stdafx.h>
#include <inc\rng.h>
#include <libsodium/include/sodium.h>
bool generate_random_file()
{
	printf_s("Enter random output file name:");
	char filename[20];
	scanf_s(" %s", &filename, 20);
	FILE *random_output_file;
	fopen_s(&random_output_file, filename, "wb+");
	if (random_output_file == NULL)
	{
		printf_s("Unable access file");
		return false;
	}
	int random_length;
	printf_s("Enter output length:");
	scanf_s("%d", &random_length);
	uint8_t *random_output;
	random_output = (uint8_t*)sodium_malloc(random_length);
	randombytes_buf(random_output, random_length);
	printf_s("Display the output?(y or n):");
	char display_selection = 0;
	scanf_s(" %c", &display_selection, 1);
	if (display_selection == 'y')
	{
		char *random_display = (char*)sodium_malloc(random_length * 2 + 1);
		sodium_bin2hex(random_display, random_length * 2 + 1, random_output, random_length);
		printf_s("Output:");
		printf_s(random_display);
		printf_s("\n");
	}
	fwrite(random_output, sizeof(char), random_length, random_output_file);
	fclose(random_output_file);
	printf_s("Random Number File Generated\n");
	sodium_free(random_output);
	system("pause");
	return true;
}
