// cryptotool.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#define SODIUM_STATIC
#include <libsodium/include/sodium.h>
#include "inc/ed25519.h"
//#include "inc\rng.h"
bool util_dfu_ce_v1_fw(void);
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
					//generate_random_file();
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
	return true;
}
