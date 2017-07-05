#include "stdafx.h"
#include "stdio.h"
#include "winsock2.h" 
#pragma comment(lib,"ws2_32.lib")  

int i = 0;
int num = 0;

DWORD WINAPI workThread(LPVOID lpParam)
{
	while (true) {
		WORD sockVersion = MAKEWORD(2, 2);
		WSADATA data;
		if (WSAStartup(sockVersion, &data) != 0)
		{
			printf("Init Windows Socket Failed");
			return 1;
		}

		SOCKET sclient = socket(AF_INET, SOCK_STREAM, 0);
		if (sclient == INVALID_SOCKET)
		{
			printf("Create Socket Failed");
			return 1;
		}

		sockaddr_in serAddr;
		serAddr.sin_family = AF_INET;
		serAddr.sin_port = htons(9999);
		serAddr.sin_addr.S_un.S_addr = inet_addr("127.0.0.1");
		if (connect(sclient, (sockaddr *)&serAddr, sizeof(serAddr)) == SOCKET_ERROR)
		{
			printf("Connect Server error = %d\n", WSAGetLastError());
			closesocket(sclient);
			return 1;
		}

		send(sclient, "admin#adminadmin", 17, 0);

		char recData[255];
		int ret = recv(sclient, recData, 255, 0);
		if (ret > 0)
		{
			printf("%s", recData);
			num++;
			//printf("%s",recData);
		}
		closesocket(sclient);
		WSACleanup();
	}
	return 0;
}

int main()
{
	for (i = 0; i < 1000; i++) {
		Sleep(50);
		CreateThread(NULL, 0, workThread, NULL, 0, NULL);
	}
	getchar();
	return 0;
}