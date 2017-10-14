// cryptotool.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "stdio.h"
#include "windows.h"
#include "string.h"
#define SODIUM_STATIC
#include "libsodium\include\sodium.h"
bool generate_random_file();
bool generate_ed25519_keypair(void);
bool ed_sign_file(void);
bool util_dfu_ce_v1_fw(void);
void test();
bool main()
{
	if (sodium_init() < 0)
	{
		printf_s("Libsodium not good,press any key to exit");
		system("pause");
		exit(0);
	}
	while (1)
	{
		int selection = 0;
		system("cls");
		printf_s("Crypto Tools Powered by Halry\n");
		printf_s("0:Exit\n");
		printf_s("1:RNG Tools\n");
		printf_s("2:Ed25519 Tools\n");
		printf_s("3:Chacha20(poly1305) Tools\n");
		printf_s("4:AES Tools\n");
		printf_s("5:Utils\n");
		printf_s("Enter your choice:");
		scanf_s("%d", &selection);
		system("cls");
		switch (selection)
		{
		case 0:
			exit(0);
			break;
		case 1:
			printf_s("0:Go back\n");
			printf_s("1:Generate Random Files\n");
			printf_s("Enter your choice:");
			int rng_select ;
			scanf_s("%d", &rng_select);
				if (rng_select == 1)
				{
					system("cls");
					generate_random_file();
				}
				break;
		case 2:
			printf_s("0:Go back\n");
			printf_s("1:Generate Key Pair\n");
			printf_s("2:Sign a file\n");
			printf_s("Enter your choice:");
			int ed_select;
			scanf_s("%d", &ed_select);
				if (ed_select == 1)
				{
					system("cls");
					generate_ed25519_keypair();
				}
				else if (ed_select == 2)
				{
					system("cls");
					ed_sign_file();
				}
				break;
		case 5:
			printf_s("0:Go back\n");
			printf_s("1:Create a dfu firmware for dfu_ce_v1\n");
			printf_s("Enter your choice:");
			int ut_select;
			scanf_s("%d", &ut_select);
			if (ut_select == 1)
			{
				system("cls");
				util_dfu_ce_v1_fw();
			}
			break;
		default:
			break;
		}
	}
	exit(0);
}
bool generate_random_file()
{
	printf_s("Enter random output file name:");
	char filename[20];
	scanf_s(" %s", &filename, 20);
	FILE *random_output_file ;
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
	random_output =(uint8_t*) sodium_malloc(random_length );
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
	fwrite(public_key, sizeof(char), crypto_sign_SECRETKEYBYTES, pk_output_file);
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
		printf_s("\nPublic Key");
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
bool util_dfu_ce_v1_fw(void)
{
	//Open the original fw file
	printf_s("Enter firmware input filename:");
	char input_fw_filename[128];
	scanf_s(" %s", &input_fw_filename, 128);
	FILE * input_fw;
	fopen_s(&input_fw, input_fw_filename, "rb");
	if (input_fw == NULL)
	{
		printf_s("Unable access file");
		system("pause");
		return false;
	}
	//getting original fw file size
	fseek(input_fw, 0, SEEK_END);
	uint64_t input_fw_size = ftell(input_fw);
	fseek(input_fw, 0, SEEK_SET);
	//put original fw file to memory buffer
	uint8_t *input_fw_buf = (uint8_t*)malloc(input_fw_size);
	fread_s(input_fw_buf, input_fw_size, sizeof(uint8_t), input_fw_size, input_fw);
	fclose(input_fw);
	//Open ChaCha20 Encryption Key File
	printf_s("Enter Encryption Key filename:");
	char cc20_key_filename[128];
	scanf_s(" %s", &cc20_key_filename, 128);
	FILE * cc20_key;
	fopen_s(&cc20_key, cc20_key_filename, "rb");
	if (cc20_key == NULL)
	{
		printf_s("Unable access file");
		system("pause");
		return false;
	}
	uint8_t cc20_key_buf[crypto_stream_chacha20_KEYBYTES];
	fread_s(cc20_key_buf, crypto_stream_chacha20_KEYBYTES, sizeof(uint8_t), crypto_stream_chacha20_KEYBYTES, cc20_key);
	fclose(cc20_key);
	//Open Ed25519 Private Key
	printf_s("Enter Signing Key filename:");
	char sign_key_filename[128];
	scanf_s(" %s", &sign_key_filename, 128);
	FILE * sign_key;
	fopen_s(&sign_key, sign_key_filename, "rb");
	if (sign_key == NULL)
	{
		printf_s("Unable access file");
		system("pause");
		return false;
	}
	uint8_t sign_key_buf[crypto_sign_SECRETKEYBYTES];
	fread_s(sign_key_buf, crypto_sign_SECRETKEYBYTES, sizeof(uint8_t), crypto_sign_SECRETKEYBYTES, sign_key);
	fclose(sign_key);
	//Print out fw length and start working
	printf_s("Input firmware length:%lld\nCrypto Work Started\n", input_fw_size);
	//Init output encrypted fw memory
	uint8_t *output_fw_buf = (uint8_t*)sodium_malloc(input_fw_size + 2+ crypto_stream_chacha20_NONCEBYTES +crypto_sign_BYTES);//original fw size+16bit fw size+8bytes iv+64byte ed25519 sign
	if (!output_fw_buf)
	{
		printf_s("Out of memory");
		system("pause");
	}
	//Generate IV
	uint8_t cc20_iv[crypto_stream_chacha20_NONCEBYTES];
	randombytes_buf(cc20_iv, crypto_stream_chacha20_NONCEBYTES);
	memcpy_s(output_fw_buf + 2 + crypto_sign_BYTES, crypto_stream_chacha20_NONCEBYTES, cc20_iv, crypto_stream_chacha20_NONCEBYTES);
	printf_s("Chacha20 IV Generated\n");
	//Sign the fw
	crypto_sign_detached(output_fw_buf + 2, NULL, input_fw_buf, input_fw_size,sign_key_buf);
	printf_s("Firmware Signed\n");
	//Encrypt the fw
	crypto_stream_chacha20_xor(output_fw_buf +2 + crypto_stream_chacha20_NONCEBYTES + crypto_sign_BYTES,
		input_fw_buf, input_fw_size, cc20_iv, cc20_key_buf);
	printf_s("Firmware Encrypted\n");
	//Insert fw size to output
	uint8_t fw_size_h = ((uint8_t)(input_fw_size >> 8));
	uint8_t fw_size_l = ((uint8_t)input_fw_size);
	memcpy_s(output_fw_buf, sizeof(uint8_t), &fw_size_h, sizeof(uint8_t));
	memcpy_s(output_fw_buf+1, sizeof(uint8_t), &fw_size_l, sizeof(uint8_t));
	printf_s("Original fw size inserted\n");
	//Output the file
	printf_s("Enter Encrypted FW Name:");
	char output_filename[128];
	scanf_s(" %s", &output_filename, 128);
	FILE *output_file;
	fopen_s(&output_file, output_filename, "wb+");
	if (output_file == NULL)
	{
		printf_s("Unable access file");
		system("pause");
		return false;
	}
	fwrite(output_fw_buf, sizeof(uint8_t), input_fw_size + 2 + crypto_stream_chacha20_NONCEBYTES + crypto_sign_BYTES, output_file);
	fclose(output_file);
	printf_s("Encrypted Firmware Generated\n");
	system("pause");
}
