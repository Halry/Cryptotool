#include <stdafx.h>
#include <inc\util\dfu_ce_v1_fw_handle.h>
#include <libsodium\include\sodium.h>
bool util_dfu_ce_v1_fw_encrypt(void)
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
	printf_s("Input firmware length:%lld\nCrypto Worker Started\n", input_fw_size);
	//Init output encrypted fw memory
	uint8_t *output_fw_buf = (uint8_t*)sodium_malloc(input_fw_size + 2 + crypto_stream_chacha20_NONCEBYTES + crypto_sign_BYTES);//original fw size+16bit fw size+8bytes iv+64byte ed25519 sign
	if (!output_fw_buf)
	{
		printf_s("Out of memory");
		system("pause");
	}
	//Generate IV
	uint8_t cc20_iv[crypto_stream_chacha20_NONCEBYTES];
	randombytes_buf(cc20_iv, crypto_stream_chacha20_NONCEBYTES);
	memcpy_s(output_fw_buf + 2 + crypto_sign_BYTES, crypto_stream_chacha20_NONCEBYTES, cc20_iv, crypto_stream_chacha20_NONCEBYTES);
	printf_s("ChaCha20 IV Generated\n");
	//Sign the fw
	crypto_sign_detached(output_fw_buf + 2, NULL, input_fw_buf, input_fw_size, sign_key_buf);
	printf_s("Firmware Signed\n");
	//Encrypt the fw
	crypto_stream_chacha20_xor(output_fw_buf + 2 + crypto_stream_chacha20_NONCEBYTES + crypto_sign_BYTES,
		input_fw_buf, input_fw_size, cc20_iv, cc20_key_buf);
	printf_s("Firmware Encrypted\n");
	//Insert fw size to output
	uint8_t fw_size_h = ((uint8_t)(input_fw_size >> 8));
	uint8_t fw_size_l = ((uint8_t)input_fw_size);
	memcpy_s(output_fw_buf, sizeof(uint8_t), &fw_size_h, sizeof(uint8_t));
	memcpy_s(output_fw_buf + 1, sizeof(uint8_t), &fw_size_l, sizeof(uint8_t));
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
