#include "stdafx.h"
#include "stdio.h"
#include "winsock2.h" 
#include "ws2tcpip.h" 
#include "mswsock.h"
#pragma comment(lib,"ws2_32.lib") 

DWORD WINAPI workThread(LPVOID lpParam);

int main()
{
	CreateThread(0, 0, workThread, NULL, 0, NULL);

	//主线程阻塞，输入exit退出
	bool run = true;
	while (run)
	{
		char st[40];
		gets_s(st);

		if (!strcmp("exit", st))
		{
			run = false;
		}
	}
	WSACleanup();

    return 0;
}

DWORD WINAPI workThread(LPVOID lpParam)
{
	SOCKET ListenSocket;
	sockaddr_in ServerAddress, ClientAddress;
	WSADATA wsdata;
	bool optval;
	//启动SOCKET库，版本为2.0  
	if (WSAStartup(MAKEWORD(2, 2), &wsdata) != 0)
	{
		return 1;
	}
	optval = true;
	//接收广播的地址
	ClientAddress.sin_family = AF_INET;
	ClientAddress.sin_addr.s_addr = 0;
	ClientAddress.sin_port = htons(9000);
	//自身的地址
	ServerAddress.sin_family = AF_INET;
	ServerAddress.sin_addr.s_addr = INADDR_BROADCAST;
	ServerAddress.sin_port = htons(8000);

	//用UDP初始化套接字  
	ListenSocket = socket(AF_INET, SOCK_DGRAM, 0);
	// 设置该套接字为广播类型，  
	setsockopt(ListenSocket, SOL_SOCKET, SO_BROADCAST, (char FAR *)&optval, sizeof(optval));
	// 把该套接字绑定在一个具体的地址上  
	bind(ListenSocket, (sockaddr *)&ClientAddress, sizeof(sockaddr_in));
	int fromlength = sizeof(SOCKADDR);
	char buf[256];
	while (true)
	{
		recvfrom(ListenSocket, buf, 256, 0, (struct sockaddr FAR *)&ServerAddress, (int FAR *)&fromlength);
		printf("接收心跳\n");
		ZeroMemory(buf, 256);
	}
	printf_s("线程退出.\n");
	return 0;
}