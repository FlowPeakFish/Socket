#include "stdafx.h"
#include "stdio.h"
#include "winsock2.h" 
#include "ws2tcpip.h" 
#include "mswsock.h"
#pragma comment(lib,"ws2_32.lib") 

//�û�������
char* username[3] = { "admin","root" ,"zz" };
//��������
char* password[3] = { "adminadmin","rootroot" ,"zzzz" };

//�û�������
char* Susername[1] = { "login" };
//��������
char* Spassword[1] = { "login"};

DWORD WINAPI workThread(LPVOID lpParam)
{
	SOCKET client = (SOCKET)lpParam;
	// ѭ����������
	while (true)
	{
		char recData[4096];
		int ret = recv(client, recData, 4096, 0);
		if (ret > 0 && recData[0] != '\0') {
			printf("%s \n", recData);
		}
	}
}

int main()
{
	WORD sockVersion = MAKEWORD(2, 2);
	WSADATA data;
	if (WSAStartup(sockVersion, &data) != 0)
	{
		return 1;
	}
	SOCKET sclient;
	while (true)
	{
		char senddata[4096];
		char username[80];
		char password[40];

		printf("�������û�����");
		gets_s(username);

		printf("���������룺");
		gets_s(password);

		sprintf_s(senddata, sizeof(senddata), "%s#%s", username, password);

		sclient = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		if (sclient == INVALID_SOCKET)
		{
			printf("invalid socket !");
			return 2;
		}

		sockaddr_in serAddr;
		serAddr.sin_family = AF_INET;
		serAddr.sin_port = htons(9999);
		serAddr.sin_addr.S_un.S_addr = inet_addr("127.0.0.1");
		if (connect(sclient, (sockaddr *)&serAddr, sizeof(serAddr)) == SOCKET_ERROR)
		{
			printf("connect error !");
			closesocket(sclient);
			return 3;
		}

		send(sclient, senddata, strlen(senddata), 0);

		char recData[255];
		int ret = recv(sclient, recData, 255, 0);
		printf("%s \n", recData);

		if (!strcmp(recData, "��½ʧ�ܣ�"))
		{
			closesocket(sclient);
			continue;
		}
		CreateThread(0, 0, workThread, (LPVOID)sclient, 0, NULL);
		bool run = true;
		while (run)
		{
			ZeroMemory(senddata, 256);
			gets_s(senddata);
			if (!strcmp(senddata, "exit"))
			{
				break;
			}
			if (senddata[0] == '\0' || (senddata[0] == '\\' &&strstr(senddata, " ") == NULL)) {
				continue;
			}
			send(sclient, senddata, strlen(senddata), 0);
		}
		closesocket(sclient);
	}
	WSACleanup();
	return 0;
}