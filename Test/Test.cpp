#include "stdafx.h"
#include "stdio.h"
#include "winsock2.h" 
#pragma comment(lib,"ws2_32.lib")  

DWORD WINAPI procRECV(LPVOID p);

int main()
{
	for (int i = 0; i < 100; i++) {
		CreateThread(NULL, 0, procRECV, NULL, 0, 0);
	}
	while (true) {
		Sleep(1000);
	}
	return 0;
}
DWORD WINAPI procRECV(LPVOID p) {
	int n = 1;
	int i = 0;
	char buf[100] = "admin#adminadmin";
	char rec[100];
	while (true)
	{
		WORD sockVersion = MAKEWORD(2, 2);
		WSADATA data;
		if (WSAStartup(sockVersion, &data) != 0)
		{
			return 0;
		}
		SOCKET s = socket(AF_INET, SOCK_STREAM, 0);
		SOCKADDR_IN serAddr;
		serAddr.sin_family = AF_INET;
		serAddr.sin_port = htons(9999);
		serAddr.sin_addr.S_un.S_addr = inet_addr("127.0.0.1");
		int re = connect(s, (SOCKADDR*)&serAddr, sizeof(SOCKADDR));
		if (re == SOCKET_ERROR)
		{
			printf("连接失败：%d\n", WSAGetLastError());
			return 0;
		}
		send(s, buf, 100, 0);
		memset(rec, 0, 100);
		recv(s, rec, 100, 0);
		printf("第%d次连接，线程：%d收到消息：%s\n", n, GetCurrentThreadId(), rec);
		closesocket(s);
		WSACleanup();
		n++;
		Sleep(1000);
	}
	return 0;

}