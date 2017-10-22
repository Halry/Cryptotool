#include "inc\util\dfu_sd_v1_utils.h"
#include "stdafx.h"
#include <libsodium\include\sodium.h>
bool dfu_sd_v1_fw_encrypt(void)
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
	//Open AES128 Encryption Key File
	printf_s("Enter Encryption Key filename:");
	char aes_key_filename[128];
	scanf_s(" %s", &aes_key_filename, 128);
	FILE * aes_key;
	fopen_s(&aes_key, aes_key_filename, "rb");
	if (aes_key == NULL)
	{
		printf_s("Unable access file");
		system("pause");
		return false;
	}
	uint8_t aes_key_buf[crypto_stream_chacha20_KEYBYTES];
	fread_s(aes_key_buf, crypto_stream_chacha20_KEYBYTES, sizeof(uint8_t), crypto_stream_chacha20_KEYBYTES, aes_key);
	fclose(aes_key);
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
	printf_s("Input firmware length:%lld\nCrypto Worker Started\n", input_fw_size);
	
	return true;
}