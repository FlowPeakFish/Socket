#include "stdafx.h"
#include "stdio.h"
#include "winsock2.h"
#pragma comment(lib,"ws2_32.lib")

DWORD WINAPI workThread(LPVOID lpParam)
{
	SOCKET client = (SOCKET)lpParam;
	// 循环处理请求
	while (true)
	{
		char recData[4096];
		if (recv(client, recData, 4096, 0) == SOCKET_ERROR)
		{
			break;
		}
		if (recData[0] != '\0')
		{
			printf("%s \n", recData);
		}
	}
	return 0;
}

int main()
{
	while (true)
	{
		WSADATA wsdata;
		if (WSAStartup(MAKEWORD(2, 2), &wsdata) != 0)
		{
			return 1;
		}

		char senddata[4096];
		char username[80];
		char password[40];

		printf("请输入用户名：");
		gets_s(username);

		printf("请输入密码：");
		gets_s(password);

		sprintf_s(senddata, sizeof(senddata), "LOGIN|%s#%s", username, password);

		SOCKET sclient = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		if (sclient == INVALID_SOCKET)
		{
			printf("invalid socket !");
			return 2;
		}

		sockaddr_in serAddr;
		serAddr.sin_family = AF_INET;
		serAddr.sin_port = htons(8600);
		serAddr.sin_addr.S_un.S_addr = inet_addr("127.0.0.1");
		if (connect(sclient, (sockaddr *)&serAddr, sizeof(serAddr)) == SOCKET_ERROR)
		{
			printf("connect error !");
			closesocket(sclient);
			return 3;
		}

		send(sclient, senddata, strlen(senddata), 0);

		char recData[255];
		recv(sclient, recData, 255, 0);
		printf("%s \n", recData);

		if (!strcmp(recData, "登陆失败！"))
		{
			closesocket(sclient);
			continue;
		}
		CreateThread(0, 0, workThread, (LPVOID)sclient, 0, NULL);
		bool run = true;
		while (run)
		{
			char data[4096];
			ZeroMemory(data, 4096);
			ZeroMemory(senddata, 4096);
			gets_s(data);
			if (!strcmp(data, "exit"))
			{
				break;
			}
			if (data[0] == '\0' || (data[0] == '\\' && strstr(data, " ") == NULL))
			{
				continue;
			}

			sprintf_s(senddata, sizeof(senddata), "CHAT|%s", data);
			send(sclient, senddata, strlen(senddata), 0);
		}
		closesocket(sclient);
		WSACleanup();
	}
}
