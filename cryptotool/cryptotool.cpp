// cryptotool.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "stdio.h"
#define SODIUM_STATIC
#include "libsodium\include\sodium.h"
bool generate_random();
bool main()
{
	if (sodium_init() < 0)
	{
		printf_s("Libsodium not good,press any key to exit");
		system("pause");
		system("exit");
	}
	generate_random();
	system("pause");
}
bool generate_random()
{
	printf_s("Enter output file name:");
	char filename[20];
	gets_s(filename, 20);
	FILE *random_output_file = fopen(filename, "wb+");
	if (random_output_file == NULL)
	{
		return false;
	}
	int random_length;
	printf_s("Enter output length:");
	scanf_s("%d", &random_length);
	uint8_t *random_output;
	random_output =(uint8_t*) sodium_malloc(random_length + 1);
	randombytes_buf(random_output, random_length);
	fwrite(random_output, sizeof(char), random_length, random_output_file);
	fclose(random_output_file);
	
	
	printf_s("Random Number Generated\n");
	system("pause");
	sodium_free(random_output);
}
