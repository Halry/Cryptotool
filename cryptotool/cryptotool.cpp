// cryptotool.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#define SODIUM_STATIC
#include <libsodium/include/sodium.h>
#include "inc/ed25519.h"
#include "inc\rng.h"
#include "inc\util\dfu_ce_v1_fw_handle.h"
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
				util_dfu_ce_v1_fw_encrypt();
			}
			break;
		default:
			break;
		}
	}
	exit(0);
}

