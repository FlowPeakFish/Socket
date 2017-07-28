#include "stdafx.h"
#include "stdio.h"
#include "winsock2.h"
#include "ws2tcpip.h"
#include "mswsock.h"
#include <algorithm>
#pragma comment(lib,"ws2_32.lib")

#define c_LISTEN_PORT 8600
#define c_MAX_DATA_LENGTH 4096
#define c_SOCKET_CONTEXT 4096
#define c_MAX_POST_ACCEPT 10

enum enumIoType
{
	ACCEPT,
	RECV,
	SEND,
	NONE,
	ROOT
};

//引用基类
class SocketUnit
{
public:
	volatile int m_sharedCount; //引用计数
	SOCKET m_Socket;

	//初始化
	SocketUnit()
	{
		m_Socket = WSASocket(AF_INET, SOCK_STREAM, 0, NULL, 0, WSA_FLAG_OVERLAPPED);
		m_sharedCount = 0;
	}

	//获得一个的Socket，并将引用计数减一
	SOCKET* Get()
	{
		m_sharedCount++;
		return &m_Socket;
	}

	//释放一个的Socket，将引用计数减一，当为零时，关闭Socket重置
	void Release()
	{
		m_sharedCount--;
		if (m_sharedCount == 0)
		{
			closesocket(m_Socket);
			m_Socket = WSASocket(AF_INET, SOCK_STREAM, 0, NULL, 0, WSA_FLAG_OVERLAPPED);
		}
	}
};


class SocketUnitPool
{
private:
	volatile int num; //总数
public:
	SocketUnit* array_socket_unit[c_SOCKET_CONTEXT];

	// 初始化
	SocketUnitPool(): num(c_SOCKET_CONTEXT)
	{
		for (int i = 0; i < c_SOCKET_CONTEXT; ++i)
		{
			array_socket_unit[i] = new SocketUnit();
		}
	}

	// 获得一个Socket
	SocketUnit* GetSocketUnit()
	{
		for (int i = 0; i < num; ++i)
		{
			if (array_socket_unit[i]->m_sharedCount == 0)
			{
				return array_socket_unit[i];
			}
		}
		return NULL;
	}
};

SocketUnitPool* g_poolSocket;

//网络操作类型，包含Overlapped，关联的socket，缓冲区以及这个操作的类型，accpet，received还是send
class _PER_IO_CONTEXT
{
public:
	SocketUnit* m_SocketUnit;
	SOCKET* m_Socket; // 这个网络操作所使用的Socket
	OVERLAPPED m_overlapped; // 每一个重叠网络操作的重叠结构(针对每一个Socket的每一个操作，都要有一个   
	WSABUF m_wsaBuf; // WSA类型的缓冲区，用于给重叠操作传参数的
	char* m_szBuffer; // 这个是WSABUF里具体存字符的缓冲区
	enumIoType m_IoType; // 标识网络操作的类型(对应上面的枚举)

	_PER_IO_CONTEXT* pPreIoContext; //指向上一个网络操作
	_PER_IO_CONTEXT* pNextIoContext; //指向下一个网络操作

	//传入Socket引用基类和网络操作类型
	_PER_IO_CONTEXT(SocketUnit* p, enumIoType type)
	{
		m_SocketUnit = p;
		m_Socket = (type == ROOT) ? 0 : m_SocketUnit->Get();
		ZeroMemory(&m_overlapped, sizeof(m_overlapped));
		m_szBuffer = new char[c_MAX_DATA_LENGTH];
		m_wsaBuf.buf = m_szBuffer;
		m_wsaBuf.len = c_MAX_DATA_LENGTH;
		m_IoType = type;
		pPreIoContext = nullptr;
		pNextIoContext = nullptr;
	}

	void CloseIoContext()
	{
		if (m_IoType != ROOT)
		{
			if (pNextIoContext)
			{
				pPreIoContext->pNextIoContext = pNextIoContext;
				pNextIoContext->pPreIoContext = pPreIoContext;
			}
			else
			{
				pPreIoContext->pNextIoContext = nullptr;
			}
			delete m_szBuffer;
		}
		m_SocketUnit->Release();
		m_IoType = NONE;
		pPreIoContext = nullptr;
		pNextIoContext = nullptr;
	}
};

class _PER_SOCKET_CONTEXT
{
private:
	_PER_IO_CONTEXT* HeadIoContext;
public:
	SocketUnit* m_SocketUnit;
	SOCKET* m_Socket; // 每一个客户端连接的Socket
	SOCKADDR_IN m_ClientAddr; // 客户端的地址
	char m_username[40];
	volatile int m_timer; //心跳反应计数

	_PER_SOCKET_CONTEXT* pPreSocketContext;
	_PER_SOCKET_CONTEXT* pNextSocketContext;

	//传入一个从池中获得的Socket引用基类，进行初始化
	_PER_SOCKET_CONTEXT(SocketUnit* p)
	{
		m_SocketUnit = p;
		m_Socket = m_SocketUnit->Get();
		m_timer = 0;
		ZeroMemory(m_username, 40);
		HeadIoContext = new _PER_IO_CONTEXT(m_SocketUnit, ROOT);
		pPreSocketContext = nullptr;
		pNextSocketContext = nullptr;
	}

	//传入网络操作类型，初始化一个网络操作
	_PER_IO_CONTEXT* GetNewIoContext(enumIoType IoType)
	{
		_PER_IO_CONTEXT* NewIoContext = new _PER_IO_CONTEXT(m_SocketUnit, IoType);
		if (HeadIoContext->pNextIoContext)
		{
			HeadIoContext->pNextIoContext->pPreIoContext = NewIoContext;
			NewIoContext->pNextIoContext = HeadIoContext->pNextIoContext;
		}
		HeadIoContext->pNextIoContext = NewIoContext;
		NewIoContext->pPreIoContext = HeadIoContext;
		return NewIoContext;
	}

	// 释放资源
	void CloseSocketContext()
	{
		if (*m_Socket != INVALID_SOCKET)
		{
			while (HeadIoContext->pNextIoContext)
			{
				HeadIoContext->pNextIoContext->CloseIoContext();
			}
			HeadIoContext->CloseIoContext();
			HeadIoContext = nullptr;
			m_timer = 0;
			m_SocketUnit->Release();
			m_Socket = nullptr;

			if (pNextSocketContext)
			{
				pPreSocketContext->pNextSocketContext = pNextSocketContext;
				pNextSocketContext->pPreSocketContext = pPreSocketContext;
			}
			else
			{
				pPreSocketContext->pNextSocketContext = nullptr;
			}
		}
	}

	//更新延时次数
	void UpTimer()
	{
		m_timer++;
	}

	//重置延时次数
	void ResetTimer()
	{
		m_timer = 0;
	}
};

//Socket结构体数组的类，包含上面Socket组合结构体数组，并对改数组增删改
class ARRAY_PER_SOCKET_CONTEXT
{
private:
	_PER_SOCKET_CONTEXT* HeadSocketContext;
public:
	volatile int num;

	//从池中获取一个socket初始化一个socketcontext当做头结点
	ARRAY_PER_SOCKET_CONTEXT(): num(0)
	{
		SocketUnit* p = g_poolSocket->GetSocketUnit();
		HeadSocketContext = new _PER_SOCKET_CONTEXT(p);
	}

	//传入连入客户端/服务端名字和地址，初始化一个socketcontext返回
	_PER_SOCKET_CONTEXT* GetNewSocketContext(SOCKADDR_IN pAddressPort, char* szUserName)
	{
		_PER_SOCKET_CONTEXT* temp = new _PER_SOCKET_CONTEXT(g_poolSocket->GetSocketUnit());

		if (HeadSocketContext->pNextSocketContext)
		{
			HeadSocketContext->pNextSocketContext->pPreSocketContext = temp;
			temp->pNextSocketContext = HeadSocketContext->pNextSocketContext;
		}
		HeadSocketContext->pNextSocketContext = temp;
		temp->pPreSocketContext = HeadSocketContext;

		memcpy(&(temp->m_ClientAddr), &pAddressPort, sizeof(SOCKADDR_IN));
		strcpy_s(temp->m_username, strlen(szUserName) + 1, szUserName);
		num++;
		return temp;
	}

	//根据name查找socketcontext并返回
	_PER_SOCKET_CONTEXT* Find(char* name)
	{
		_PER_SOCKET_CONTEXT* temp = HeadSocketContext;
		while (temp->pNextSocketContext)
		{
			temp = temp->pNextSocketContext;
			if (!strcmp(name, temp->m_username))
			{
				return temp;
			}
		}
		return NULL;
	};

	//对所有服务器socket延时计数加一，大于2时，表示掉线
	void UpTimer()
	{
		_PER_SOCKET_CONTEXT* temp = HeadSocketContext;
		while (temp->pNextSocketContext)
		{
			temp = temp->pNextSocketContext;
			temp->UpTimer();
			if (temp->m_timer > 2)
			{
				printf("服务器连接超时...\n");
				num--;
				temp->CloseSocketContext();
			}
		}
	}

	//查看是否连接服务器
	bool ContainAddr(SOCKADDR_IN client_addr)
	{
		_PER_SOCKET_CONTEXT* temp = HeadSocketContext;
		while (temp->pNextSocketContext)
		{
			temp = temp->pNextSocketContext;
			if (!memcmp(&temp->m_ClientAddr, &client_addr, sizeof(SOCKADDR_IN)))
			{
				temp->ResetTimer();
				return true;
			}
		}
		return false;
	}
};

//完成接口
HANDLE g_hIoCompletionPort;

//创建一个Socket结构体数组的句柄
ARRAY_PER_SOCKET_CONTEXT* m_arraySocketContext;

ARRAY_PER_SOCKET_CONTEXT* m_arrayServerSocketContext;

//AcceptEx的GUID，用于导出AcceptEx函数指针
GUID GuidAcceptEx = WSAID_ACCEPTEX;
//AcceptEx函数指针
LPFN_ACCEPTEX m_AcceptEx;
//AcceptExSockaddrs的GUID，用于导出AcceptExSockaddrs函数指针
GUID GuidGetAcceptExSockAddrs = WSAID_GETACCEPTEXSOCKADDRS;
//AcceptExSockaddrs函数指针
LPFN_GETACCEPTEXSOCKADDRS m_AcceptExSockAddrs;

//接下来用来Listen的Socket结构体
_PER_SOCKET_CONTEXT* g_ListenContext;

//声明用来完成端口操作的线程
DWORD WINAPI workThread(LPVOID lpParam);
//声明用来计数的线程
DWORD WINAPI StartTimerCount(LPVOID lpParam);
//声明用来接收心跳的线程
DWORD WINAPI StartHeartBeat(LPVOID lpParam);
//声明投递Send请求，发送完消息后会通知完成端口
bool _PostSend(_PER_IO_CONTEXT* pSendIoContext);
//声明投递Recv请求，接收完请求会通知完成端口
bool _PostRecv(_PER_IO_CONTEXT* pRecvIoContext);
//声明投递Accept请求，收到一个连接请求会通知完成端口
bool _PostAccept(_PER_IO_CONTEXT* pAcceptIoContext);

int main()
{
	WSADATA wsaData;
	if (NO_ERROR != WSAStartup(MAKEWORD(2, 2), &wsaData))
	{
		printf_s("初始化Socket库 失败！\n");
		return 1;
	}

	g_poolSocket = new SocketUnitPool();
	m_arraySocketContext = new ARRAY_PER_SOCKET_CONTEXT();
	m_arrayServerSocketContext = new ARRAY_PER_SOCKET_CONTEXT();

	// 建立完成端口
	g_hIoCompletionPort = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
	if (g_hIoCompletionPort == NULL)
	{
		printf_s("建立完成端口失败！错误代码: %d!\n", WSAGetLastError());
		return 2;
	}

	SYSTEM_INFO si;
	GetSystemInfo(&si);
	// 根据本机中的处理器数量，建立对应的线程数
	int m_nThreads = 2 * si.dwNumberOfProcessors + 2;
	// 初始化线程句柄
	HANDLE* m_phWorkerThreads = new HANDLE[m_nThreads];
	// 根据计算出来的数量建立线程
	for (int i = 0; i < m_nThreads; i++)
	{
		m_phWorkerThreads[i] =
			CreateThread(0, 0, workThread, NULL, 0, NULL);
	}
	printf_s("建立 WorkerThread %d 个.\n", m_nThreads);

	// 服务器地址信息，用于绑定Socket
	struct sockaddr_in ServerAddress;

	// 生成用于监听的Socket的信息
	g_ListenContext = new _PER_SOCKET_CONTEXT(g_poolSocket->GetSocketUnit());

	// 需要使用重叠IO，必须得使用WSASocket来建立Socket，才可以支持重叠IO操作
	if (*g_ListenContext->m_Socket == INVALID_SOCKET)
	{
		printf_s("初始化Socket失败，错误代码: %d.\n", WSAGetLastError());
	}
	else
	{
		printf_s("初始化Socket完成.\n");
	}

	// 填充地址信息
	ServerAddress.sin_family = AF_INET;
	ServerAddress.sin_addr.s_addr = htonl(INADDR_ANY);
	ServerAddress.sin_port = htons(c_LISTEN_PORT);


	// 绑定地址和端口
	if (bind(*g_ListenContext->m_Socket, (LPSOCKADDR)&ServerAddress, sizeof(ServerAddress)) == SOCKET_ERROR)
	{
		printf_s("bind()函数执行错误.\n");
		return 3;
	}

	// 开始对这个ListenContext里面的socket所绑定的地址端口进行监听
	if (listen(*g_ListenContext->m_Socket, SOMAXCONN) == SOCKET_ERROR)
	{
		printf_s("Listen()函数执行出现错误.\n");
		return 4;
	}

	DWORD dwBytes = 0;
	//使用WSAIoctl，通过GuidAcceptEx(AcceptEx的GUID)，获取AcceptEx函数指针
	if (SOCKET_ERROR == WSAIoctl(
		*g_ListenContext->m_Socket,
		SIO_GET_EXTENSION_FUNCTION_POINTER,
		&GuidAcceptEx,
		sizeof(GuidAcceptEx),
		&m_AcceptEx,
		sizeof(m_AcceptEx),
		&dwBytes,
		NULL,
		NULL))
	{
		printf_s("WSAIoctl 未能获取AcceptEx函数指针。错误代码: %d\n", WSAGetLastError());
		return 5;
	}

	//使用WSAIoctl，通过GuidGetAcceptExSockAddrs(AcceptExSockaddrs的GUID)，获取AcceptExSockaddrs函数指针
	if (SOCKET_ERROR == WSAIoctl(
		*g_ListenContext->m_Socket,
		SIO_GET_EXTENSION_FUNCTION_POINTER,
		&GuidGetAcceptExSockAddrs,
		sizeof(GuidGetAcceptExSockAddrs),
		&m_AcceptExSockAddrs,
		sizeof(m_AcceptExSockAddrs),
		&dwBytes,
		NULL,
		NULL))
	{
		printf_s("WSAIoctl 未能获取GuidGetAcceptExSockAddrs函数指针。错误代码: %d\n", WSAGetLastError());
		return 6;
	}

	//将这个将ListenSocket结构体放到完成端口中，有结果告诉我，并将监听ListenContext传进去
	if ((CreateIoCompletionPort((HANDLE)*g_ListenContext->m_Socket, g_hIoCompletionPort, (DWORD)g_ListenContext, 0) == NULL))
	{
		printf_s("绑定服务端SocketContext至完成端口失败！错误代码: %d/n", WSAGetLastError());
		if (*g_ListenContext->m_Socket != INVALID_SOCKET)
		{
			closesocket(*g_ListenContext->m_Socket);
			*g_ListenContext->m_Socket = INVALID_SOCKET;
		}
		return 7;
	}
	printf_s("Listen Socket绑定完成端口 完成.\n");


	//循环10次
	for (int i = 0; i < c_MAX_POST_ACCEPT; i++)
	{
		//通过网络操作结构体数组获得一个新的网络操作结构体
		_PER_IO_CONTEXT* newAcceptIoContext = g_ListenContext->GetNewIoContext(ACCEPT);
		//投递Send请求，发送完消息后会通知完成端口，
		if (_PostAccept(newAcceptIoContext) == false)
		{
			newAcceptIoContext->CloseIoContext();
			return 8;
		}
	}
	printf_s("投递 %d 个AcceptEx请求完毕 \n", c_MAX_POST_ACCEPT);


	CreateThread(0, 0, StartHeartBeat, NULL, 0, NULL);
	CreateThread(0, 0, StartTimerCount, NULL, 0, NULL);

	printf_s("网关服务器端已启动......\n");

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

//定义用来完成端口操作的线程
DWORD WINAPI workThread(LPVOID lpParam)
{
	//网络操作完成后接收的网络操作结构体里面的Overlapped
	OVERLAPPED* pOverlapped = NULL;
	//网络操作完成后接收的Socket结构体，第一次是ListenSocket的结构体
	_PER_SOCKET_CONTEXT* pSocketContext = NULL;
	//网络操作完成后接收的字节数 
	DWORD dwBytesTransfered = 0;

	bool run = true;
	// 循环处理请求
	while (run)
	{
		BOOL bReturn = GetQueuedCompletionStatus(
			g_hIoCompletionPort,//这个就是我们建立的那个唯一的完成端口  
			&dwBytesTransfered,//这个是操作完成后返回的字节数 
			(PULONG_PTR)&pSocketContext,//这个是我们建立完成端口的时候绑定的那个sockt结构体
			&pOverlapped,//这个是我们在连入Socket的时候一起建立的那个重叠结构  
			INFINITE);//等待完成端口的超时时间，如果线程不需要做其他的事情，那就INFINITE

		//通过这个Overlapped，得到包含这个的网错操作结构体
		_PER_IO_CONTEXT* pIoContext = CONTAINING_RECORD(pOverlapped, _PER_IO_CONTEXT, m_overlapped);

		char IPAddr[16];
		inet_ntop(AF_INET, &pSocketContext->m_ClientAddr.sin_addr, IPAddr, 16);
		// 判断是否有客户端断开了
		if (!bReturn)
		{
			DWORD dwErr = GetLastError();
			//错误代码64，客户端closesocket
			if (dwErr == 64)
			{
				printf_s("%s:%d 断开连接！\n", IPAddr, ntohs(pSocketContext->m_ClientAddr.sin_port));
				pSocketContext->CloseSocketContext();
			}
			else
			{
				printf_s("客户端异常断开 %d", dwErr);
			}
		}
		else
		{
			pIoContext->m_szBuffer[dwBytesTransfered] = 0x00;

			//判断这个网络操作的类型
			switch (pIoContext->m_IoType)
			{
			case ACCEPT:
				{
					// 1. 首先取得连入客户端的地址信息(查看业务员接待的客户信息)
					SOCKADDR_IN* pClientAddr = NULL;
					SOCKADDR_IN* pLocalAddr = NULL;
					int remoteLen = sizeof(SOCKADDR_IN), localLen = sizeof(SOCKADDR_IN);
					m_AcceptExSockAddrs(pIoContext->m_wsaBuf.buf, pIoContext->m_wsaBuf.len - ((sizeof(SOCKADDR_IN) + 16) * 2),
					                    sizeof(SOCKADDR_IN) + 16, sizeof(SOCKADDR_IN) + 16, (LPSOCKADDR*)&pLocalAddr, &localLen, (LPSOCKADDR*)&pClientAddr, &remoteLen);

					inet_ntop(AF_INET, &pClientAddr->sin_addr, IPAddr, 16);
					printf_s("客户端 %s:%d 连接.\n", IPAddr, ntohs(pClientAddr->sin_port));

					char* data = new char[40];

					char* type = strtok_s(pIoContext->m_wsaBuf.buf, "|", &data);

					switch (atoi(type))
					{
					case 10:
						{
							//接收的密码
							char* input_password = new char[40];

							//接收字符串为 用户名#密码 的结构，需要strtok_s分割开
							char* input_username = strtok_s(data, "#", &input_password);

							//无论是否登陆成功，都要反馈一个结果给客户端 登陆成功 or 登陆失败
							//通过Socket结构体数组得到一个新的Socket结构体，并将用户信息保存进去
							_PER_SOCKET_CONTEXT* pNewClientSocketContext = m_arraySocketContext->GetNewSocketContext(*pClientAddr, input_username);
							//将Socket结构体保存到Socket结构体数组中新获得的Socket结构体中
							pNewClientSocketContext->m_SocketUnit = pIoContext->m_SocketUnit;
							pNewClientSocketContext->m_Socket = pNewClientSocketContext->m_SocketUnit->Get();
							//将这个新得到的Socket结构体放到完成端口中，有结果告诉我
							HANDLE hTemp = CreateIoCompletionPort((HANDLE)*pNewClientSocketContext->m_Socket, g_hIoCompletionPort, (DWORD)pNewClientSocketContext, 0);
							if (NULL == hTemp)
							{
								printf_s("执行CreateIoCompletionPort出现错误.错误代码: %d \n", GetLastError());
								break;
							}

							_PER_SOCKET_CONTEXT* pServerSocketContext = m_arrayServerSocketContext->Find("LOGIN");

							char* Senddata = new char[c_MAX_DATA_LENGTH];
							if (pServerSocketContext)
							{
								_PER_IO_CONTEXT* pNewSendIoContext = pServerSocketContext->GetNewIoContext(SEND);
								sprintf_s(Senddata, c_MAX_DATA_LENGTH, "%s|%s#%s", input_username, input_username, input_password);
								strcpy_s(pNewSendIoContext->m_szBuffer, strlen(Senddata) + 1, Senddata);
								pNewSendIoContext->m_wsaBuf.len = strlen(Senddata) + 1;
								// Send投递出去
								_PostSend(pNewSendIoContext);
							}
							else
							{
								_PER_IO_CONTEXT* pClientSendIoContext = pNewClientSocketContext->GetNewIoContext(NONE);
								char IpPort[16];
								inet_ntop(AF_INET, &pNewClientSocketContext->m_ClientAddr.sin_addr, IpPort, 16);
								printf_s("客户端 %s(%s:%d) 登陆失败！\n", type, IpPort, ntohs(pNewClientSocketContext->m_ClientAddr.sin_port));
								sprintf_s(Senddata, c_MAX_DATA_LENGTH, "登陆失败！");
								strcpy_s(pClientSendIoContext->m_szBuffer, strlen(Senddata) + 1, Senddata);
								pClientSendIoContext->m_wsaBuf.len = strlen(Senddata) + 1;
								// Send投递出去
								_PostSend(pClientSendIoContext);
							}
						}
						break;
					default:
						// 不应该执行到这里
						printf_s("_WorkThread中的 pIoContext->IoType 参数异常.\n");
					}

					//将之前的Accept的网络操作结构体重置buffer，让该网络操作继续Accept
					_PostAccept(pIoContext);
				}
				break;
			case RECV:
				{
					char Senddata[4096];
					char* data = new char[c_MAX_DATA_LENGTH];
					//ZeroMemory(data, c_MAX_DATA_LENGTH);
					char* type = strtok_s(pIoContext->m_wsaBuf.buf, "|", &data);
					switch (atoi(type))
					{
					case 0:
						{
							printf_s("连接%s服务器(%s:%d)%s\n", pSocketContext->m_username, IPAddr, ntohs(pSocketContext->m_ClientAddr.sin_port), data);
						}
						break;
					case 12:
						{
							bool ok = false;

							char* name = strtok_s(data, "|", &data);

							if (!strcmp(data, "登陆成功！"))
							{
								ok = true;
							}
							_PER_SOCKET_CONTEXT* ClientSocketContext = m_arraySocketContext->Find(name);

							//给这个新得到的Socket结构体绑定一个PostSend操作，将客户端是否登陆成功的结果发送回去，发送操作完成，通知完成端口

							if (ok)
							{
								_PER_IO_CONTEXT* pClientSendIoContext = ClientSocketContext->GetNewIoContext(SEND);
								printf_s("客户端 %s(%s:%d) 登陆成功！\n", name, IPAddr, ntohs(ClientSocketContext->m_ClientAddr.sin_port));
								strcpy_s(pClientSendIoContext->m_szBuffer, strlen(data) + 1, data);
								pClientSendIoContext->m_wsaBuf.len = strlen(data) + 1;
								_PostSend(pClientSendIoContext);

								_PER_IO_CONTEXT* pNewClientRecvIoContext = ClientSocketContext->GetNewIoContext(RECV);
								if (!_PostRecv(pNewClientRecvIoContext))
								{
									pNewClientRecvIoContext->CloseIoContext();
								}
							}
							else
							{
								_PER_IO_CONTEXT* pClientSendIoContext = ClientSocketContext->GetNewIoContext(NONE);
								printf_s("客户端 %s(%s:%d) 登陆失败！\n", type, IPAddr, ntohs(ClientSocketContext->m_ClientAddr.sin_port));
								strcpy_s(pClientSendIoContext->m_szBuffer, strlen(data) + 1, data);
								pClientSendIoContext->m_wsaBuf.len = strlen(data) + 1;
								_PostSend(pClientSendIoContext);
							}
						}
						break;
					case 20:
						{
							inet_ntop(AF_INET, &pSocketContext->m_ClientAddr.sin_addr, IPAddr, 16);
							printf_s("客户端 %s(%s:%d) 向大家发送:%s\n", pSocketContext->m_username, IPAddr, ntohs(pSocketContext->m_ClientAddr.sin_port), data);
							sprintf_s(Senddata, c_MAX_DATA_LENGTH, "%s(%s:%d)向大家发送:\n%s", pSocketContext->m_username, IPAddr, ntohs(pSocketContext->m_ClientAddr.sin_port), data);

							_PER_SOCKET_CONTEXT* ServerSocketContext = m_arrayServerSocketContext->Find("CHAT");

							_PER_IO_CONTEXT* pClientSendIoContext = pSocketContext->GetNewIoContext(SEND);
							if (ServerSocketContext)
							{
								_PER_IO_CONTEXT* pNewServerSendIoContext = ServerSocketContext->GetNewIoContext(SEND);
								// 给这个客户端SocketContext绑定一个Recv的计划
								strcpy_s(pNewServerSendIoContext->m_szBuffer, strlen(Senddata) + 1, Senddata);
								pNewServerSendIoContext->m_wsaBuf.len = strlen(Senddata) + 1;
								_PostSend(pNewServerSendIoContext);

								strcpy_s(pClientSendIoContext->m_szBuffer, 12, "已发送成功");
							}
							else
							{
								strcpy_s(pClientSendIoContext->m_szBuffer, 12, "未发送成功");
							}
							pClientSendIoContext->m_wsaBuf.len = 12;
							_PostSend(pClientSendIoContext);
						}
						break;
					default:
						break;
					}
					_PostRecv(pIoContext);
				}
				break;
			case SEND:
				//发送完消息后，将包含网络操作的结构体删除
				pIoContext->CloseIoContext();
				break;
			case NONE:
				//发送完消息后，将包含网络操作的结构体删除
				pSocketContext->CloseSocketContext();
				break;
			default:
				// 不应该执行到这里
				printf_s("_WorkThread中的 pIoContext->IoType 参数异常.\n");
				run = false;
				break;
			} //switch
		}
	}

	printf_s(

		"线程退出.\n"
	);
	return
		0;
}

//定义用来接收心跳的线程
DWORD WINAPI StartHeartBeat(LPVOID lpParam)
{
	SOCKADDR_IN form, ClientAddress;
	WSADATA wsdata;
	//启动SOCKET库，版本为2.0  
	WSAStartup(MAKEWORD(2, 2), &wsdata);
	bool optval = true;

	ClientAddress.sin_family = AF_INET;
	ClientAddress.sin_addr.s_addr = 0;
	ClientAddress.sin_port = htons(9000);

	//用UDP初始化套接字  
	SOCKET ListenSocket = socket(AF_INET, SOCK_DGRAM, 0);
	// 设置该套接字为广播类型，  
	setsockopt(ListenSocket, SOL_SOCKET, SO_BROADCAST, (char FAR *)&optval, sizeof(optval));
	// 把该套接字绑定在一个具体的地址上  
	bind(ListenSocket, (sockaddr *)&ClientAddress, sizeof(sockaddr_in));
	int fromlength = sizeof(SOCKADDR);
	char buf[256];
	while (true)
	{
		recvfrom(ListenSocket, buf, 256, 0, (struct sockaddr FAR *)&form, (int FAR *)&fromlength);

		char* port = new char[6];
		//接收字符串为 用户名#密码 的结构，需要strtok_s分割开
		char* type = strtok_s(buf, "#", &port);

		char IPAddr[16];
		inet_ntop(AF_INET, &form.sin_addr, IPAddr, 16);

		SOCKADDR_IN ClientAddr;
		ZeroMemory(&ClientAddr, sizeof(&ClientAddr));
		ClientAddr.sin_family = AF_INET;
		ClientAddr.sin_addr.S_un = form.sin_addr.S_un;
		ClientAddr.sin_port = htons(atoi(port));

		if (!m_arrayServerSocketContext->ContainAddr(ClientAddr))
		{
			_PER_SOCKET_CONTEXT* newSocketContext = m_arrayServerSocketContext->GetNewSocketContext(ClientAddr, type);
			newSocketContext->m_SocketUnit->m_Socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
			if (connect(*newSocketContext->m_Socket, (sockaddr *)&ClientAddr, sizeof(ClientAddr)) == SOCKET_ERROR)
			{
				printf_s("connect error，错误代码: %d\n", WSAGetLastError());
				newSocketContext->m_Socket;
			}
			send(*newSocketContext->m_Socket, "GATEWAY|online", 8, 0);

			_PER_IO_CONTEXT* pNewRecvIoContext = newSocketContext->GetNewIoContext(RECV);

			HANDLE hTemp = CreateIoCompletionPort((HANDLE)*newSocketContext->m_Socket, g_hIoCompletionPort, (DWORD)newSocketContext, 0);
			if (NULL == hTemp)
			{
				printf_s("执行CreateIoCompletionPort出现错误.错误代码: %d \n", GetLastError());
				break;
			}

			if (!_PostRecv(pNewRecvIoContext))
			{
				pNewRecvIoContext->CloseIoContext();
			}
		}
	}
	return 0;
}

DWORD WINAPI StartTimerCount(LPVOID lpParam)
{
	while (true)
	{
		m_arrayServerSocketContext->UpTimer();
		Sleep(10000);
	}
}

//定义投递Send请求，发送完消息后会通知完成端口
bool _PostSend(_PER_IO_CONTEXT* pSendIoContext)
{
	// 初始化变量
	DWORD dwFlags = 0;
	DWORD dwBytes = 0;

	if ((WSASend(*pSendIoContext->m_Socket, &pSendIoContext->m_wsaBuf, 1, &dwBytes, dwFlags, &pSendIoContext->m_overlapped,
	             NULL) == SOCKET_ERROR) && (WSAGetLastError() != WSA_IO_PENDING))
	{
		printf_s("投递一个WSASend失败！%d \n", WSAGetLastError());
		return false;
	}
	return true;
}

//定义投递Recv请求，接收完请求会通知完成端口
bool _PostRecv(_PER_IO_CONTEXT* pRecvIoContext)
{
	// 初始化变量
	DWORD dwFlags = 0;
	DWORD dwBytes = 0;
	WSABUF* p_wbuf = &pRecvIoContext->m_wsaBuf;
	OVERLAPPED* p_ol = &pRecvIoContext->m_overlapped;

	int nBytesRecv = WSARecv(*pRecvIoContext->m_Socket, p_wbuf, 1, &dwBytes, &dwFlags, p_ol, NULL);

	// 如果返回值错误，并且错误的代码并非是Pending的话，那就说明这个重叠请求失败了
	if (nBytesRecv == SOCKET_ERROR && (WSAGetLastError() != WSA_IO_PENDING))
	{
		if (WSAGetLastError() != 10054)
		{
			printf_s("投递一个WSARecv失败！%d \n", WSAGetLastError());
		}
		return false;
	}
	return true;
}

//定义投递Accept请求，收到一个连接请求会通知完成端口
bool _PostAccept(_PER_IO_CONTEXT* pAcceptIoContext)
{
	// 准备参数
	DWORD dwBytes = 0;
	WSABUF* p_wbuf = &pAcceptIoContext->m_wsaBuf;
	OVERLAPPED* p_ol = &pAcceptIoContext->m_overlapped;

	// 为以后新连入的客户端先准备好Socket(准备好接待客户的业务员，而不是像传统Accept现场new一个出来
	pAcceptIoContext->m_SocketUnit->Release();
	pAcceptIoContext->m_SocketUnit = g_poolSocket->GetSocketUnit();
	pAcceptIoContext->m_Socket = pAcceptIoContext->m_SocketUnit->Get();
	if (*pAcceptIoContext->m_Socket == INVALID_SOCKET)
	{
		printf_s("创建用于Accept的Socket失败！错误代码: %d", WSAGetLastError());
		return false;
	}

	// 投递AcceptEx
	if (m_AcceptEx(*g_ListenContext->m_Socket, *pAcceptIoContext->m_Socket, p_wbuf->buf, p_wbuf->len - ((sizeof(SOCKADDR_IN) + 16) * 2),
	               sizeof(SOCKADDR_IN) + 16, sizeof(SOCKADDR_IN) + 16, &dwBytes, p_ol) == FALSE)
	{
		if (WSAGetLastError() != WSA_IO_PENDING)
		{
			printf_s("投递 AcceptEx 请求失败，错误代码: %d", WSAGetLastError());
			return false;
		}
	}
	return true;
}
