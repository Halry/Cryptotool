// cryptotool.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#define SODIUM_STATIC
#include <libsodium/include/sodium.h>
#include <wolfssl\wolfcrypt\wc_port.h>
#include "inc/ed25519.h"
#include "inc\rng.h"
#include "inc\util\dfu_ce_v1_fw_handle.h"
#include "inc\util\dfu_sd_v1_utils.h"
bool main()
{
	if (sodium_init() < 0)
	{
		printf_s("Libsodium not good,press any key to exit");
		system("pause");
		exit(0);
	}
	if (wolfCrypt_Init() != 0)
	{
		printf_s("wolfCrypt not good,press any key to exit");
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
			printf_s("1:DFU_ce_v1 Utils\n");
			printf_s("2:DFU_sd_v1 Utils\n");
			int ut_select;
			scanf_s("%d", &ut_select);
			if (ut_select == 1)
			{
				printf_s("0:Go back\n");
				printf_s("1:Create DFU Firmware for dfu_ce_v1\n");
				printf_s("2:Tamper Flag Reset\n");
				printf_s("3:Classroom Data Generate\n");
				printf_s("4:Count Data Generate\n");
				printf_s("Enter your choice:");
				int dfuce_select;
				scanf_s("%d", &dfuce_select);
				if (dfuce_select == 1)
				{
					system("cls");
					util_dfu_ce_v1_fw_encrypt();
				}
				else if (dfuce_select == 2)
				{
					system("cls");
					Tamper_Reset_Data_Generator();
				}
				else if (dfuce_select == 3)
				{
					system("cls");
					generate_encrypted_classroom();
				}
				else if (dfuce_select == 4)
				{
					system("cls");
					generate_encrypted_count();
				}
			}
			if (ut_select == 2)
			{
				printf_s("0:Go back\n");
				printf_s("1:Create DFU Firmware for dfu_sd_v1\n");
				int dfusd_select;
				scanf_s("%d", &dfusd_select);
				if (dfusd_select == 1)
				{
					system("cls");
					dfu_sd_v1_fw_encrypt();
				}
			}
			break;
		default:
			break;
		}
	}
	exit(0);
}

