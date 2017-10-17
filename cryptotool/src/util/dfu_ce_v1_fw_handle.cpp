#include <stdafx.h>
#include <string.h>
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
	uint8_t *output_fw_buf = (uint8_t*)sodium_malloc(input_fw_size + 64 + crypto_sign_BYTES);//original fw size+16bit fw size+8bytes iv+64byte ed25519 sign
	if (!output_fw_buf)
	{
		printf_s("Out of memory");
		system("pause");
	}
	memset(output_fw_buf, 0, input_fw_size + 64 + crypto_sign_BYTES);
	//Generate IV
	uint8_t cc20_iv[crypto_stream_chacha20_NONCEBYTES];
	randombytes_buf(cc20_iv, crypto_stream_chacha20_NONCEBYTES);
	memcpy_s(output_fw_buf + 2 , crypto_stream_chacha20_NONCEBYTES, cc20_iv, crypto_stream_chacha20_NONCEBYTES);
	printf_s("ChaCha20 IV Generated\n");
	//Sign the fw
	crypto_sign_detached(output_fw_buf + 64, NULL, input_fw_buf, input_fw_size, sign_key_buf);//Padding 64
	printf_s("Firmware Signed\n");
	//Encrypt the fw
	crypto_stream_chacha20_xor(output_fw_buf + 64 + crypto_sign_BYTES,
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
	fwrite(output_fw_buf, sizeof(uint8_t), input_fw_size + 64 + crypto_sign_BYTES, output_file);
	fclose(output_file);
	printf_s("Encrypted Firmware Generated\n");
	system("pause");
	return true;
}
bool Tamper_Reset_Data_Generator(void)
{
	uint8_t output[64];
	char deviceid[25];
	char device_nonce[33];
	uint8_t iv[8];
	printf_s("Enter Device ID:");
	while (fgets(deviceid, 25, stdin))
	{
		if (deviceid[24] == 0)
			break;
	}
	printf_s("Enter Device Nonce:");
	while (fgets(device_nonce, 33, stdin))
	{
		if (device_nonce[32] == 0)
			break;
	}
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
	randombytes_buf(iv, 8);
	memcpy_s(output + 8, 24, deviceid, 24);
	memcpy_s(output + 8+24, 32, device_nonce, 32);
	crypto_stream_chacha20_xor(output + 8, output + 8, 56, iv, cc20_key_buf);
	memcpy_s(output, 8, iv, 8);
	printf_s("Reset Key:");
	char display_output[129];
	sodium_bin2hex(display_output, 129, output, 64);
	printf_s(display_output);
	printf_s("\n");
	system("pause");
	return true;
}
bool generate_encrypted_classroom(void)
{
	uint8_t output[189];
	char deviceid[25];
	char device_nonce[33];
	char classroom[56] = { 0 };
	char format_classroom[60] = { 0 };
	uint8_t classroom_count = 0;
	uint8_t iv[8];
	printf_s("Enter Device ID:");
	while (fgets(deviceid, 25, stdin))
	{
		if (deviceid[24] == 0)
			break;
	}
	printf_s("Enter Device Nonce:");
	while (fgets(device_nonce, 33, stdin))
	{
		if (device_nonce[32] == 0)
			break;
	}
	printf_s("Enter Classroom Count+Classroom+Minor:");
	while (fgets(classroom, 56, stdin))
	{
		if (classroom[strlen(classroom)] == '\0'&&strlen(classroom)>2)
		{
			break;
		}
	}
	classroom_count = classroom[0]-'0';//Get classroom count
	for (uint8_t c = 0; c < classroom_count; c++)//format classroom for fit the dfu program
	{
		memcpy_s(format_classroom + c * 6, 5, classroom + c * 5+1, 5);
	}
	memcpy_s(format_classroom + classroom_count * 6, 4 * classroom_count, classroom + classroom_count * 5 + 1, classroom_count * 4);
	//end format
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
	randombytes_buf(iv, 8);
	memcpy_s(output + 8, 24, deviceid, 24);
	memcpy_s(output + 8 + 24, 32, device_nonce, 32);
	memcpy_s(output + 8 + 24 + 32, 1, &classroom_count, 1);
	memcpy_s(output + 8 + 24 + 32 + 1, 60, format_classroom, 60);
	crypto_sign_detached(output + 125, NULL, output + 8, 117, sign_key_buf);
	crypto_stream_chacha20_xor(output + 8, output + 8, 117, iv, cc20_key_buf);
	memcpy_s(output, 8, iv, 8);
	printf_s("Encrypted Classroom:");
	char display_output[189 * 2+1];
	sodium_bin2hex(display_output, 189 * 2+1, output,189);
	printf_s(display_output);
	printf_s("\n");
	system("pause");
}
bool generate_encrypted_count(void)
{
	uint8_t output[106];
	uint8_t iv[8];
	char device_nonce[33];
	int count = 0;
	printf_s("Enter Count:");
	scanf_s("%I16u", &count);
	printf_s("Entered Count:%d\n",count);
	printf_s("Enter Device Nonce:");
	while (fgets(device_nonce, 33, stdin))
	{
		if (device_nonce[32] == 0)
			break;
	}
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
	randombytes_buf(iv, 8);
	memcpy_s(output + 8, 32, device_nonce, 32);
	memcpy_s(output + 8 + 32, 2, &count, 2);
	crypto_sign_detached(output + 42, NULL, output + 8,34, sign_key_buf);
	crypto_stream_chacha20_xor(output + 8, output + 8, 34, iv, cc20_key_buf);
	memcpy_s(output, 8, iv, 8);
	printf_s("Encrypted Count:");
	char display_output[106 * 2 + 1];
	sodium_bin2hex(display_output, 106 * 2 + 1, output, 106);
	printf_s(display_output);
	printf_s("\n");
	system("pause");
}
