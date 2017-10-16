#include <stdafx.h>
#include <inc/ed25519.h>
#include <libsodium/include/sodium.h>
bool generate_ed25519_keypair(void)
{
	uint8_t public_key[crypto_sign_PUBLICKEYBYTES];
	uint8_t private_key[crypto_sign_SECRETKEYBYTES];
	crypto_sign_keypair(public_key, private_key);
	printf_s("Enter Private Key File name:");
	char sk_filename[20];
	scanf_s(" %s", &sk_filename, 20);
	FILE *sk_output_file;
	fopen_s(&sk_output_file, sk_filename, "wb+");
	if (sk_output_file == NULL)
	{
		printf_s("Unable access file");
		return false;
	}
	fwrite(private_key, sizeof(char), crypto_sign_SECRETKEYBYTES, sk_output_file);
	fclose(sk_output_file);
	printf_s("Private Key Outputed,length:%d", crypto_sign_SECRETKEYBYTES);
	printf_s("\nEnter Public Key File name:");
	char pk_filename[20];
	scanf_s(" %s", &pk_filename, 20);
	FILE *pk_output_file;
	fopen_s(&pk_output_file, pk_filename, "wb+");
	if (pk_output_file == NULL)
	{
		printf_s("Unable access file");
		return false;
	}
	fwrite(public_key, sizeof(char), crypto_sign_PUBLICKEYBYTES, pk_output_file);
	fclose(pk_output_file);
	printf_s("Public Key Outputed,length:%d\n", crypto_sign_PUBLICKEYBYTES);
	printf_s("Display the output?(y or n):");
	char display_selection = 0;
	scanf_s(" %c", &display_selection, 1);
	if (display_selection == 'y')
	{
		char *sk_display = (char*)sodium_malloc(crypto_sign_SECRETKEYBYTES * 2 + 1);
		char *pk_display = (char*)sodium_malloc(crypto_sign_PUBLICKEYBYTES * 2 + 1);
		sodium_bin2hex(sk_display, crypto_sign_SECRETKEYBYTES * 2 + 1, private_key, crypto_sign_SECRETKEYBYTES);
		sodium_bin2hex(pk_display, crypto_sign_PUBLICKEYBYTES * 2 + 1, public_key, crypto_sign_PUBLICKEYBYTES);
		printf_s("Private Key:");
		printf_s(sk_display);
		printf_s("\nPublic Key:");
		printf_s(pk_display);
		printf_s("\n");
	}
	system("pause");
	return true;
}
bool ed_sign_file(void)
{
	printf_s("Enter filename of file that be signed:");
	char sign_filename[128];
	scanf_s(" %s", &sign_filename, 128);
	FILE *sign_file;
	fopen_s(&sign_file, sign_filename, "rb");
	if (sign_file == NULL)
	{
		printf_s("Unable access file");
		system("pause");
		return false;
	}
	//getting file size
	fseek(sign_file, 0, SEEK_END);
	uint64_t sign_file_size = ftell(sign_file);
	fseek(sign_file, 0, SEEK_SET);
	//end
	uint8_t *sign_file_buf = (uint8_t *)malloc(sign_file_size);
	fread_s(sign_file_buf, sign_file_size, sizeof(uint8_t), sign_file_size, sign_file);
	fclose(sign_file);
	//Read private key now
	printf_s("Enter Private key filename:");
	char sk_filename[128];
	scanf_s(" %s", &sk_filename, 128);
	FILE *sk_file;
	fopen_s(&sk_file, sk_filename, "rb");
	if (sk_file == NULL)
	{
		printf_s("Unable access file");
		system("pause");
		return false;
	}
	uint8_t private_key[crypto_sign_SECRETKEYBYTES];
	fread_s(private_key, crypto_sign_SECRETKEYBYTES, sizeof(uint8_t), crypto_sign_SECRETKEYBYTES, sk_file);
	fclose(sk_file);//Close the private key reading.
	printf_s("Save the signed output file name as 'signed.bin?':");
	char display_selection = 0;
	scanf_s(" %c", &display_selection, 1);
	if (display_selection == 'y')
	{
		char output_signed_filename[11] = "signed.bin";
		FILE *output_signed_file;
		fopen_s(&output_signed_file, output_signed_filename, "wb+");
		if (output_signed_file == NULL)
		{
			printf_s("Unable access file");
			system("pause");
			return false;
		}
		uint8_t *output_buf = (uint8_t*)malloc(sign_file_size + crypto_sign_BYTES);
		unsigned long long output_length;
		crypto_sign(output_buf, &output_length, sign_file_buf, sign_file_size, private_key);
		fwrite(output_buf, sizeof(uint8_t), sign_file_size + crypto_sign_BYTES, output_signed_file);
		fclose(output_signed_file);
		printf_s("File output to signed.bin,length:%lld\n", output_length);
	}
	printf_s("Enter Sign Output File Name:");
	char signed_filename[128];
	scanf_s(" %s", &signed_filename, 128);
	FILE *signed_file;
	fopen_s(&signed_file, signed_filename, "wb+");
	if (signed_file == NULL)
	{
		printf_s("Unable access file");
		system("pause");
		return false;
	}
	uint8_t sign[crypto_sign_BYTES];
	crypto_sign_detached(sign, NULL, sign_file_buf, sign_file_size, private_key);
	fwrite(sign, sizeof(uint8_t), crypto_sign_BYTES, signed_file);
	fclose(signed_file);
	printf_s("Display the output?(y or n):");
	char display_selection_output = 0;
	scanf_s(" %c", &display_selection_output, 1);
	if (display_selection_output == 'y')
	{
		char *sign_display = (char*)malloc(crypto_sign_BYTES * 2 + 1);
		sodium_bin2hex(sign_display, crypto_sign_BYTES * 2 + 1, sign, crypto_sign_BYTES);
		printf_s("sign:");
		printf_s(sign_display);
		printf_s("\n");
	}
	system("pause");
	return true;
}
