#include "stdafx.h"
#include "stdio.h"
#include "winsock2.h" 
#include "ws2tcpip.h" 
#include "mswsock.h"
#pragma comment(lib,"ws2_32.lib") 

enum OPERATION_TYPE { ACCEPT, RECV, SEND, NONE };

typedef struct _PER_SOCKET_CONTEXT
{
	SOCKET      m_Socket;                                  // 每一个客户端连接的Socket
	SOCKADDR_IN m_ClientAddr;                              // 客户端的地址
	char m_username[40];
	// 初始化
	_PER_SOCKET_CONTEXT()
	{
		m_Socket = INVALID_SOCKET;
		memset(&m_ClientAddr, 0, sizeof(m_ClientAddr));
		ZeroMemory(m_username, 40);
	}

	// 释放资源
	~_PER_SOCKET_CONTEXT()
	{
		if (m_Socket != INVALID_SOCKET)
		{
			closesocket(m_Socket);
			m_Socket = INVALID_SOCKET;
		}
	}
} PER_SOCKET_CONTEXT;

class PER_SOCKET_CONTEXT_ARR
{
private:
	PER_SOCKET_CONTEXT *SOCKET_CONTEXT_ARR[2048];
public:
	int num = 0;//记录数目  

	PER_SOCKET_CONTEXT* GetNewSocketContext(SOCKADDR_IN* addr, char* u)
	{
		for (int i = 0; i < 2048; i++)
		{
			//如果某一个IO_CONTEXT_ARRAY[i]为0，表示哪一个位可以放入PER_IO_CONTEXT  
			if (SOCKET_CONTEXT_ARR[i] == 0)
			{
				SOCKET_CONTEXT_ARR[num] = new PER_SOCKET_CONTEXT();
				memcpy(&(SOCKET_CONTEXT_ARR[num]->m_ClientAddr), addr, sizeof(SOCKADDR_IN));
				strcpy(SOCKET_CONTEXT_ARR[num]->m_username, u);
				num++;
				return SOCKET_CONTEXT_ARR[num - 1];
			}
		}
	}

	PER_SOCKET_CONTEXT* getARR(int i)
	{
		return SOCKET_CONTEXT_ARR[i];
	}

	void AddSocketArray(SOCKET S, SOCKADDR_IN* addr, char* u)
	{
		SOCKET_CONTEXT_ARR[num] = new PER_SOCKET_CONTEXT();
		SOCKET_CONTEXT_ARR[num]->m_Socket = S;
		memcpy(&(SOCKET_CONTEXT_ARR[num]->m_ClientAddr), addr, sizeof(SOCKADDR_IN));
		strcpy(SOCKET_CONTEXT_ARR[num]->m_username, u);
		num++;
	}

	// 从数组中移除一个指定的IoContext
	void RemoveContext(PER_SOCKET_CONTEXT* S)
	{
		for (int i = 0; i < num; i++)
		{
			if (SOCKET_CONTEXT_ARR[i] == S)
			{
				closesocket(SOCKET_CONTEXT_ARR[i]->m_Socket);
				SOCKET_CONTEXT_ARR[i] = 0;
				num--;
				break;
			}
		}
	}
};

typedef struct _PER_IO_CONTEXT
{
	OVERLAPPED     m_Overlapped;                               // 每一个重叠网络操作的重叠结构(针对每一个Socket的每一个操作，都要有一个)              
	SOCKET         m_socket;                                     // 这个网络操作所使用的Socket
	WSABUF         m_wsaBuf;                                   // WSA类型的缓冲区，用于给重叠操作传参数的
	char           m_szBuffer[4096];                           // 这个是WSABUF里具体存字符的缓冲区
	OPERATION_TYPE m_OpType;                                   // 标识网络操作的类型(对应上面的枚举)

															   // 初始化
	_PER_IO_CONTEXT()
	{
		ZeroMemory(&m_Overlapped, sizeof(m_Overlapped));
		ZeroMemory(m_szBuffer, 4096);
		m_socket = INVALID_SOCKET;
		m_wsaBuf.buf = m_szBuffer;
		m_wsaBuf.len = 4096;
		m_OpType = NONE;
	}

	// 释放掉Socket
	~_PER_IO_CONTEXT()
	{
		if (m_socket != INVALID_SOCKET)
		{
			ZeroMemory(&m_Overlapped, sizeof(m_Overlapped));
			ZeroMemory(&m_szBuffer, 4096);
			m_wsaBuf.buf = m_szBuffer;
			m_wsaBuf.len = 4096;
			m_OpType = NONE;
		}
	}

	// 重置缓冲区内容
	void ResetBuffer()
	{
		ZeroMemory(m_szBuffer, 4096);
	}
} PER_IO_CONTEXT;

class PER_IO_CONTEXT_ARR
{
private:
	PER_IO_CONTEXT *IO_CONTEXT_ARRAY[2048];//存放数组  
public:
	int num = 0;//记录数目  
	PER_IO_CONTEXT* getARR(int i)
	{
		return IO_CONTEXT_ARRAY[i];
	}

	PER_IO_CONTEXT* GetNewIoContext()
	{
		for (int i = 0; i < 2048; i++)
		{
			//如果某一个IO_CONTEXT_ARRAY[i]为0，表示哪一个位可以放入PER_IO_CONTEXT  
			if (IO_CONTEXT_ARRAY[i] == 0)
			{
				IO_CONTEXT_ARRAY[i] = new PER_IO_CONTEXT();
				num++;
				return IO_CONTEXT_ARRAY[i];
			}
		}
	}

	// 从数组中移除一个指定的IoContext
	void RemoveContext(PER_IO_CONTEXT* pContext)
	{
		for (int i = 0; i < num; i++)
		{
			if (IO_CONTEXT_ARRAY[i] == pContext)
			{
				IO_CONTEXT_ARRAY[i]->~_PER_IO_CONTEXT();
				IO_CONTEXT_ARRAY[i] = 0;
				num--;
				break;
			}
		}
	}
};

//用户名数组
char* username[3] = { "admin","root" ,"zz" };
//密码数组
char* password[3] = { "adminadmin","rootroot" ,"zz" };

// 同时投递的Accept请求的数量(这个要根据实际的情况灵活设置)
#define MAX_POST_ACCEPT 10

HANDLE mIoCompletionPort;

PER_IO_CONTEXT_ARR ArrayIoContext;
PER_SOCKET_CONTEXT_ARR ArraySocketContext;

GUID GuidAcceptEx = WSAID_ACCEPTEX; // AcceptEx 的GUID，用于导出函数指针
LPFN_ACCEPTEX mAcceptEx;// AcceptEx函数指针
GUID GuidGetAcceptExSockAddrs = WSAID_GETACCEPTEXSOCKADDRS;// GetAcceptExSockaddrs 的GUID，用于导出函数指针
LPFN_GETACCEPTEXSOCKADDRS mAcceptExSockAddrs;// AcceptEx函数指针

PER_SOCKET_CONTEXT* ListenContext;

DWORD WINAPI workThread(LPVOID lpParam);
bool _PostSend(PER_IO_CONTEXT* pIoContext);
bool _PostRecv(PER_IO_CONTEXT* pIoContext);
bool _PostAccept(PER_IO_CONTEXT* pAcceptIoContext);

int main()
{
	WSADATA wsaData;
	if (NO_ERROR != WSAStartup(MAKEWORD(2, 2), &wsaData))
	{
		printf("初始化Socket库 失败！\n");
		return 1;
	}

	// 建立完成端口
	mIoCompletionPort = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
	if (mIoCompletionPort == NULL)
	{
		printf("建立完成端口失败！错误代码: %d!\n", WSAGetLastError());
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
	printf("建立 WorkerThread %d 个.\n", m_nThreads);

	// 服务器地址信息，用于绑定Socket
	struct sockaddr_in ServerAddress;

	// 生成用于监听的Socket的信息
	ListenContext = new PER_SOCKET_CONTEXT;

	// 需要使用重叠IO，必须得使用WSASocket来建立Socket，才可以支持重叠IO操作
	ListenContext->m_Socket = WSASocket(AF_INET, SOCK_STREAM, 0, NULL, 0, WSA_FLAG_OVERLAPPED);
	if (ListenContext->m_Socket == INVALID_SOCKET)
	{
		printf("初始化Socket失败，错误代码: %d.\n", WSAGetLastError());
	}
	else
	{
		printf("初始化Socket完成.\n", WSAGetLastError());
	}

	// 填充地址信息
	ZeroMemory(&ServerAddress, sizeof(ServerAddress));
	ServerAddress.sin_family = AF_INET;
	ServerAddress.sin_addr.s_addr = htonl(INADDR_ANY);
	ServerAddress.sin_port = htons(9999);

	// 绑定地址和端口
	if (bind(ListenContext->m_Socket, (struct sockaddr *) &ServerAddress, sizeof(ServerAddress)) == SOCKET_ERROR)
	{
		printf("bind()函数执行错误.\n");
		return 4;
	}

	// 开始对这个ListenContext里面的socket所绑定的地址端口进行监听
	if (listen(ListenContext->m_Socket, SOMAXCONN) == SOCKET_ERROR)
	{
		printf("Listen()函数执行出现错误.\n");
		return 5;
	}

	// 将这个将服务端SocketContext放到完成端口中，有结果告诉我，并将监听ListenContext传进去
	if ((CreateIoCompletionPort((HANDLE)ListenContext->m_Socket, mIoCompletionPort, (DWORD)ListenContext, 0) == NULL))
	{
		printf("绑定服务端SocketContext至完成端口失败！错误代码: %d/n", WSAGetLastError());
		if (ListenContext->m_Socket != INVALID_SOCKET)
		{
			closesocket(ListenContext->m_Socket);
			ListenContext->m_Socket = INVALID_SOCKET;
		}
		return 3;
	}
	else
	{
		printf("Listen Socket绑定完成端口 完成.\n");
	}

	// 使用AcceptEx函数，因为这个是属于WinSock2规范之外的微软另外提供的扩展函数
	// 所以需要额外获取一下函数的指针，
	// 获取AcceptEx函数指针
	DWORD dwBytes = 0;
	if (SOCKET_ERROR == WSAIoctl(
		ListenContext->m_Socket,
		SIO_GET_EXTENSION_FUNCTION_POINTER,
		&GuidAcceptEx,
		sizeof(GuidAcceptEx),
		&mAcceptEx,
		sizeof(mAcceptEx),
		&dwBytes,
		NULL,
		NULL))
	{
		printf("WSAIoctl 未能获取AcceptEx函数指针。错误代码: %d\n", WSAGetLastError());
		return 6;
	}

	// 获取GetAcceptExSockAddrs函数指针，也是同理
	if (SOCKET_ERROR == WSAIoctl(
		ListenContext->m_Socket,
		SIO_GET_EXTENSION_FUNCTION_POINTER,
		&GuidGetAcceptExSockAddrs,
		sizeof(GuidGetAcceptExSockAddrs),
		&mAcceptExSockAddrs,
		sizeof(mAcceptExSockAddrs),
		&dwBytes,
		NULL,
		NULL))
	{
		printf("WSAIoctl 未能获取GuidGetAcceptExSockAddrs函数指针。错误代码: %d\n", WSAGetLastError());
		return 7;
	}

	// 为AcceptEx 准备参数，然后投递AcceptEx I/O请求
	for (int i = 0; i < MAX_POST_ACCEPT; i++)
	{
		// 给这个服务端SocketContext绑定一个Accept的计划
		PER_IO_CONTEXT* newAcceptIoContext = ArrayIoContext.GetNewIoContext();

		if (_PostAccept(newAcceptIoContext) == false)
		{
			ArrayIoContext.RemoveContext(newAcceptIoContext);
			return false;
		}
	}
	printf("投递 %d 个AcceptEx请求完毕 \n", MAX_POST_ACCEPT);

	printf("INFO:服务器端已启动......\n");

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
	OVERLAPPED           *pOverlapped = NULL;
	PER_SOCKET_CONTEXT   *pListenContext = NULL;
	DWORD                dwBytesTransfered = 0;

	// 循环处理请求
	while (true)
	{
		BOOL bReturn = GetQueuedCompletionStatus(
			mIoCompletionPort,//这个就是我们建立的那个唯一的完成端口  
			&dwBytesTransfered,//这个是操作完成后返回的字节数 
			(PULONG_PTR)&pListenContext,//这个是我们建立完成端口的时候绑定的那个自定义结构体参数  
			&pOverlapped,//这个是我们在连入Socket的时候一起建立的那个重叠结构  
			INFINITE);//等待完成端口的超时时间，如果线程不需要做其他的事情，那就INFINITE就行了  

					  // 读取传入的参数  读取业务员信息
		PER_IO_CONTEXT* pIoContext = CONTAINING_RECORD(pOverlapped, PER_IO_CONTEXT, m_Overlapped);

		// 判断是否有客户端断开了
		if (!bReturn)
		{
			DWORD dwErr = GetLastError();
			if (dwErr == 64) {

				ArrayIoContext.RemoveContext(pIoContext);
				ArraySocketContext.RemoveContext(pListenContext);
				printf("客户端 %s:%d 断开连接！\n", inet_ntoa(pListenContext->m_ClientAddr.sin_addr), ntohs(pListenContext->m_ClientAddr.sin_port));
			}
			else {
				printf("客户端异常 %d", dwErr);
			}
			continue;
		}
		else
		{
			switch (pIoContext->m_OpType)
			{
			case ACCEPT:
			{
				// 1. 首先取得连入客户端的地址信息(查看业务员接待的客户信息)
				SOCKADDR_IN* ClientAddr = NULL;
				SOCKADDR_IN* LocalAddr = NULL;
				int remoteLen = sizeof(SOCKADDR_IN), localLen = sizeof(SOCKADDR_IN);
				mAcceptExSockAddrs(pIoContext->m_wsaBuf.buf, pIoContext->m_wsaBuf.len - ((sizeof(SOCKADDR_IN) + 16) * 2),
					sizeof(SOCKADDR_IN) + 16, sizeof(SOCKADDR_IN) + 16, (LPSOCKADDR*)&LocalAddr, &localLen, (LPSOCKADDR*)&ClientAddr, &remoteLen);

				printf("客户端 %s:%d 连接.\n", inet_ntoa(ClientAddr->sin_addr), ntohs(ClientAddr->sin_port));

				//接收的用户名
				char *input_username = new char[40];
				//接收的密码
				char *input_password = new char[40];

				input_username = strtok(pIoContext->m_wsaBuf.buf, "#");
				input_password = strtok(NULL, "");

				char *user = new char[40];
				strcpy(user, input_username);

				//是否登陆成功
				bool ok = false;

				if (input_username != NULL && input_password != NULL)
				{
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
				}

				if (ok)
				{
					printf("客户端 %s(%s:%d) 登陆成功！\n", user, inet_ntoa(ClientAddr->sin_addr), ntohs(ClientAddr->sin_port));
					strcpy(pIoContext->m_wsaBuf.buf, "登陆成功！");
				}
				else {
					printf("客户端 %s(%s:%d) 登陆失败！\n", user, inet_ntoa(ClientAddr->sin_addr), ntohs(ClientAddr->sin_port));
					strcpy(pIoContext->m_wsaBuf.buf, "登陆失败！");
				}

				//添加客户端信息
				PER_SOCKET_CONTEXT* newSocketContext = ArraySocketContext.GetNewSocketContext(ClientAddr, user);
				newSocketContext->m_Socket = pIoContext->m_socket;
				memcpy(&(newSocketContext->m_ClientAddr), ClientAddr, sizeof(SOCKADDR_IN));

				HANDLE hTemp = CreateIoCompletionPort((HANDLE)newSocketContext->m_Socket, mIoCompletionPort, (DWORD)newSocketContext, 0);
				if (NULL == hTemp)
				{
					printf("执行CreateIoCompletionPort出现错误.错误代码: %d \n", GetLastError());
					break;
				}
				// 给这个客户端SocketContext绑定一个Recv的计划
				PER_IO_CONTEXT* pNewSendIoContext = ArrayIoContext.GetNewIoContext();
				memcpy(&(pNewSendIoContext->m_wsaBuf.buf), &pIoContext->m_wsaBuf.buf, sizeof(pIoContext->m_wsaBuf.len));
				pNewSendIoContext->m_socket = newSocketContext->m_Socket;
				// Send投递出去
				_PostSend(pNewSendIoContext);

				//查看是否登陆成功
				if (ok) {

					PER_IO_CONTEXT* pNewRecvIoContext = ArrayIoContext.GetNewIoContext();
					pNewRecvIoContext->m_socket = newSocketContext->m_Socket;

					if (!_PostRecv(pNewRecvIoContext))
					{
						ArrayIoContext.RemoveContext(pNewRecvIoContext);
					}
				}
				// 给这个服务端SocketContext重置已绑定的Accept计划
				pIoContext->ResetBuffer();
				_PostAccept(pIoContext);
			}
			break;
			case RECV:
			{
				if (dwBytesTransfered > 1) {
					char *Senddata = new char[4096];
					ZeroMemory(Senddata, 4096);

					char *temp = new char[4096];
					ZeroMemory(temp, 4096);

					char *sendname = new char[40];
					ZeroMemory(sendname, 40);
					if (pIoContext->m_wsaBuf.buf[0] == '\\') {

						int i = 0;
						while (pIoContext->m_wsaBuf.buf[i + 1] != ' ') {
							sendname[i] = pIoContext->m_wsaBuf.buf[i + 1];
							i++;
						}
						sendname[i + 1] = '\0';

						strtok(pIoContext->m_wsaBuf.buf, " ");
						temp = strtok(NULL, "#");
						if (temp != NULL) {
							printf("客户端 %s(%s:%d) 向 %s 发送:%s\n", pListenContext->m_username, inet_ntoa(pListenContext->m_ClientAddr.sin_addr), ntohs(pListenContext->m_ClientAddr.sin_port), sendname, temp);
							sprintf(Senddata, "%s(%s:%d)向你发送:\n%s", pListenContext->m_username, inet_ntoa(pListenContext->m_ClientAddr.sin_addr), ntohs(pListenContext->m_ClientAddr.sin_port), temp);
						}
					}
					else {
						temp = strtok(pIoContext->m_wsaBuf.buf, "#");
						printf("客户端 %s(%s:%d) 向大家发送:%s\n", pListenContext->m_username, inet_ntoa(pListenContext->m_ClientAddr.sin_addr), ntohs(pListenContext->m_ClientAddr.sin_port), temp);
						sprintf(Senddata, "%s(%s:%d)向大家发送:\n%s", pListenContext->m_username, inet_ntoa(pListenContext->m_ClientAddr.sin_addr), ntohs(pListenContext->m_ClientAddr.sin_port), temp);
					}


					for (int i = 0; i < ArraySocketContext.num; i++)
					{
						PER_SOCKET_CONTEXT* cSocketContext = ArraySocketContext.getARR(i);
						if (cSocketContext->m_Socket == pListenContext->m_Socket) {
							continue;
						}
						//判断是否是单对单信息
						if (sizeof(sendname) > 0 && !strcmp(sendname, cSocketContext->m_username) && strcmp(Senddata, "")) {
							// 给这个客户端SocketContext绑定一个Recv的计划
							PER_IO_CONTEXT* pNewSendIoContext = ArrayIoContext.GetNewIoContext();
							memcpy(&(pNewSendIoContext->m_wsaBuf.buf), &Senddata, sizeof(Senddata));
							pNewSendIoContext->m_socket = cSocketContext->m_Socket;
							// Send投递出去
							_PostSend(pNewSendIoContext);
						}
						else if (!strcmp(sendname, "") && strcmp(Senddata, "")) {
							// 给这个客户端SocketContext绑定一个Recv的计划
							PER_IO_CONTEXT* pNewSendIoContext = ArrayIoContext.GetNewIoContext();
							memcpy(&(pNewSendIoContext->m_wsaBuf.buf), &Senddata, sizeof(Senddata));
							pNewSendIoContext->m_socket = cSocketContext->m_Socket;
							// Send投递出去
							_PostSend(pNewSendIoContext);
						}
					}
				}
				pIoContext->ResetBuffer();
				_PostRecv(pIoContext);
			}
			break;
			case SEND:
				ArrayIoContext.RemoveContext(pIoContext);
				break;
			default:
				// 不应该执行到这里
				printf("_WorkThread中的 pIoContext->m_OpType 参数异常.\n");
				break;
			} //switch
		}
	}
	printf("线程退出.\n");
	return 0;
}

// 投递Send请求
bool _PostSend(PER_IO_CONTEXT* SendIoContext)
{
	// 初始化变量
	DWORD dwFlags = 0;
	DWORD dwBytes = 0;
	SendIoContext->m_OpType = SEND;
	WSABUF *p_wbuf = &SendIoContext->m_wsaBuf;
	OVERLAPPED *p_ol = &SendIoContext->m_Overlapped;

	SendIoContext->ResetBuffer();

	if ((WSASend(SendIoContext->m_socket, p_wbuf, 1, &dwBytes, dwFlags, p_ol,
		NULL) == SOCKET_ERROR) && (WSAGetLastError() != WSA_IO_PENDING))
	{
		ArrayIoContext.RemoveContext(SendIoContext);
		return false;
	}
	return true;
}

// 投递Recv请求
bool _PostRecv(PER_IO_CONTEXT* RecvIoContext)
{
	// 初始化变量
	DWORD dwFlags = 0;
	DWORD dwBytes = 0;
	RecvIoContext->m_OpType = RECV;
	WSABUF *p_wbuf = &RecvIoContext->m_wsaBuf;
	OVERLAPPED *p_ol = &RecvIoContext->m_Overlapped;

	RecvIoContext->ResetBuffer();

	int nBytesRecv = WSARecv(RecvIoContext->m_socket, p_wbuf, 1, &dwBytes, &dwFlags, p_ol, NULL);

	// 如果返回值错误，并且错误的代码并非是Pending的话，那就说明这个重叠请求失败了
	if (nBytesRecv == SOCKET_ERROR && (WSAGetLastError() != WSA_IO_PENDING))
	{
		if (WSAGetLastError() != 10054) {
			printf("投递一个WSARecv失败！%d \n", WSAGetLastError());
		}
		return false;
	}
	return true;
}

// 投递Accept请求 传入的可能是新的一个accept 也可能是一个accept处理完后，要接着下一个accept
bool _PostAccept(PER_IO_CONTEXT* AcceptIoContext)
{
	// 准备参数
	DWORD dwBytes = 0;
	AcceptIoContext->m_OpType = ACCEPT;
	WSABUF *p_wbuf = &AcceptIoContext->m_wsaBuf;
	OVERLAPPED *p_ol = &AcceptIoContext->m_Overlapped;

	// 为以后新连入的客户端先准备好Socket(准备好接待客户的业务员，而不是像传统Accept现场new一个出来)
	AcceptIoContext->m_socket = WSASocket(AF_INET, SOCK_STREAM, 0, NULL, 0, WSA_FLAG_OVERLAPPED);
	if (AcceptIoContext->m_socket == INVALID_SOCKET)
	{
		printf("创建用于Accept的Socket失败！错误代码: %d", WSAGetLastError());
		return false;
	}

	// 投递AcceptEx
	if (mAcceptEx(ListenContext->m_Socket, AcceptIoContext->m_socket, p_wbuf->buf, p_wbuf->len - ((sizeof(SOCKADDR_IN) + 16) * 2),
		sizeof(SOCKADDR_IN) + 16, sizeof(SOCKADDR_IN) + 16, &dwBytes, p_ol) == FALSE)
	{
		if (WSAGetLastError() != WSA_IO_PENDING)
		{
			printf("投递 AcceptEx 请求失败，错误代码: %d", WSAGetLastError());
			return false;
		}
	}
	return true;
}