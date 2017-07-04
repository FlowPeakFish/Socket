#include "stdafx.h"
#include "stdio.h"
#include "winsock2.h" 
#pragma comment(lib,"ws2_32.lib")

//用户名数组
char *username[] = { "admin","root" };
//密码数组
char *password[] = { "adminadmin","rootroot" };

class SocketList
{
private:
	int num;//记录socket的真实数目  
	SOCKET socketArray[FD_SETSIZE];//存放socket的数组  

public:
	SOCKET getSocket(int i)
	{
		return socketArray[i];
	}

	//构造函数中对两个成员变量进行初始化  
	SocketList()
	{
		num = 0;
		for (int i = 0; i < FD_SETSIZE; i++)
		{
			//因为socket的值是一个非负整数值，所以可以将socketArray初始化为0，让它来表示数组中的这一个元素有没有被使用  
			socketArray[i] = 0;
		}
	}

	//往socketArray中添加一个socket  
	void addSocket(SOCKET s)
	{
		for (int i = 0; i < FD_SETSIZE; i++)
		{
			//如果某一个socketArray[i]为0，表示哪一个位可以放入socket  
			if (socketArray[i] == 0)
			{
				socketArray[i] = s;
				num++;
				break;//这里一定要加上break，不然一个socket会放在socketArray的多个位置上  
			}
		}
	}

	//从socketArray中删除一个socket  
	void delSocket(SOCKET s)
	{
		for (int i = 0; i < FD_SETSIZE; i++)
		{
			if (socketArray[i] == s)
			{
				socketArray[i] = 0;
				num--;
				break;
			}
		}
	}

	//将socketArray中的套接字放入fd_list这个结构体中  
	void makefd(fd_set *fd_list)
	{
		//首先将fd_list清0  
		FD_ZERO(fd_list);
		//将每一个socket加入fd_list中  
		for (int i = 0; i < FD_SETSIZE; i++)
		{
			if (socketArray[i] > 0)
			{
				FD_SET(socketArray[i], fd_list);
			}
		}
	}
};

DWORD WINAPI workThread(LPVOID lpParam)
{
	//传递进来的socketList指针  
	SocketList *socketList = (SocketList *)lpParam;
	int err = 0;
	fd_set fdread;//存在读文件的set，select会检测这个set中是否可以从某些socket中读入信息  

	struct timeval timeout;//设置select超时的时间  
	timeout.tv_sec = 1;
	timeout.tv_usec = 0;

	//输入输出缓冲区  
	char receBuff[MAX_PATH];
	char sendBuf[MAX_PATH];

	SOCKET socket;

	while (true)
	{
		socketList->makefd(&fdread);
		err = select(0, &fdread, NULL, NULL, &timeout);
		if (err == 0)//select返回0表示超时  
		{
			printf("select() is time-out!");
			continue;
		}
		else
		{
			//遍历socketList中的每一个socket，查看那些socket是可读的，处理可读的socket  
			//从中读取数据到缓冲区，并发送数据给客户端  
			for (int i = 0; i < FD_SETSIZE; i++)
			{
				//读取有效的socket  
				if (socketList->getSocket(i) == 0)
					continue;
				socket = socketList->getSocket(i);

				//判断哪些socket是可读的，如果这个socket是可读的，从它里面读取数据  
				if (FD_ISSET(socket, &fdread))
				{
					//接收的用户名
					char *input_username = new char[40];
					//接收的密码
					char *input_password = new char[40];

					//接收数据
					int ret = recv(socket, receBuff, MAX_PATH, 0);

					//如果返回值表示要关闭这个连接，那么关闭它，并将它从sockeList中去掉  
					if (ret > 0) {
						input_username = strtok(receBuff, "#");
						input_password = strtok(NULL, "#");

						//是否登陆成功
						bool ok = false;

						//查找账号是否存在
						for (int i = 0; i < sizeof(username) / sizeof(username[0]); i++) {
							int j = 0;
							for (j = 0; username[i][j] == input_username[j] && input_username[j]; j++);
							if (username[i][j] == input_username[j] && input_username[j] == 0)
							{
								//账号存在查找密码是否正确
								int k;
								for (k = 0; password[i][k] == input_password[k] && input_password[k]; k++);
								if (password[i][k] == input_password[k] && input_password[k] == 0)
								{
									ok = true;
								}
								break;
							}
						}

						char *sendData = new char[40];
						if (ok)
						{
							printf("该客户端登陆成功！\n");
							sendData = "登陆成功\n";
						}
						else {
							printf("该客户端登陆失败！\n");
							sendData = "登陆失败\n";
						}

						//发送数据  
						send(socket, sendData, strlen(sendData), 0);
					}
				}
			}
		}
	}
	return 0;
}

int main()
{

	//1.加载套接字库 
	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
	{
		printf("Init Windows Socket Failed");
		return 1;
	}
	//2.创建socket
	SOCKET serverSocket = socket(AF_INET, SOCK_STREAM, 0);
	if (serverSocket == INVALID_SOCKET)
	{
		printf("Create Socket Failed");
		return 1;
	}
	//服务器端的地址和端口号 
	sockaddr_in serverAddr, clientAddr;
	serverAddr.sin_family = AF_INET;
	serverAddr.sin_port = htons(9999);
	serverAddr.sin_addr.S_un.S_addr = INADDR_ANY;
	//3.绑定Socket，将Socket与某个协议的某个地址绑定  
	if (bind(serverSocket, (LPSOCKADDR)&serverAddr, sizeof(serverAddr)) != 0)
	{
		printf("Bind Socket Failed");
		return 1;
	}
	//4.监听,将套接字由默认的主动套接字转换成被动套接字 
	if (listen(serverSocket, 5) != 0)
	{
		printf("listen Socket Failed");
		return 1;
	}

	printf("服务器端已启动......\n");

	int addrLen = sizeof(clientAddr);
	SOCKET sockConn;
	SocketList socketList;
	HANDLE hThread = CreateThread(NULL, 0, workThread, &socketList, 0, NULL);
	if (hThread == NULL)
	{
		printf("Create Thread Failed!");
	}
	CloseHandle(hThread);

	while (true)
	{
		//5.接收请求，当收到请求后，会将客户端的信息存入clientAdd这个结构体中，并返回描述这个TCP连接的Socket  
		sockConn = accept(serverSocket, (struct sockaddr*)&clientAddr, &addrLen);
		if (sockConn == INVALID_SOCKET)
		{
			printf("Accpet Failed");
			return 1;//asdfasdf
		}
		printf("接收到一个连接：%s \n", inet_ntoa(clientAddr.sin_addr));

		//将之前的第6步替换成了上面启动workThread这个线程函数和下面这一行代码  
		//将socket放入socketList中  
		socketList.addSocket(sockConn);
	}

	closesocket(serverSocket);
	//清理Windows Socket库  
	WSACleanup();
	return 0;
}