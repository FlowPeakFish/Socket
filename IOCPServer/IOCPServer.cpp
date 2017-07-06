#include "stdafx.h"
#include "stdio.h"
#include "winsock2.h" 
#include "ws2tcpip.h" 
#include "mswsock.h"
#pragma comment(lib,"ws2_32.lib") 

enum OPERATION_TYPE { ACCEPT, RECV, SEND, NONE };

typedef struct _PER_SOCKET_CONTEXT
{
	SOCKET      m_Socket;                                  // ÿһ���ͻ������ӵ�Socket
	SOCKADDR_IN m_ClientAddr;                              // �ͻ��˵ĵ�ַ
	char m_username[40];
	// ��ʼ��
	_PER_SOCKET_CONTEXT()
	{
		m_Socket = INVALID_SOCKET;
		memset(&m_ClientAddr, 0, sizeof(m_ClientAddr));
		ZeroMemory(m_username, 40);
	}

	// �ͷ���Դ
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
	int num = 0;//��¼��Ŀ  

	PER_SOCKET_CONTEXT* GetNewSocketContext(SOCKADDR_IN* addr, char* u)
	{
		for (int i = 0; i < 2048; i++)
		{
			//���ĳһ��IO_CONTEXT_ARRAY[i]Ϊ0����ʾ��һ��λ���Է���PER_IO_CONTEXT  
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

	// ���������Ƴ�һ��ָ����IoContext
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
	OVERLAPPED     m_Overlapped;                               // ÿһ���ص�����������ص��ṹ(���ÿһ��Socket��ÿһ����������Ҫ��һ��)              
	SOCKET         m_socket;                                     // ������������ʹ�õ�Socket
	WSABUF         m_wsaBuf;                                   // WSA���͵Ļ����������ڸ��ص�������������
	char           m_szBuffer[4096];                           // �����WSABUF�������ַ��Ļ�����
	OPERATION_TYPE m_OpType;                                   // ��ʶ�������������(��Ӧ�����ö��)

															   // ��ʼ��
	_PER_IO_CONTEXT()
	{
		ZeroMemory(&m_Overlapped, sizeof(m_Overlapped));
		ZeroMemory(m_szBuffer, 4096);
		m_socket = INVALID_SOCKET;
		m_wsaBuf.buf = m_szBuffer;
		m_wsaBuf.len = 4096;
		m_OpType = NONE;
	}

	// �ͷŵ�Socket
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

	// ���û���������
	void ResetBuffer()
	{
		ZeroMemory(m_szBuffer, 4096);
	}
} PER_IO_CONTEXT;

class PER_IO_CONTEXT_ARR
{
private:
	PER_IO_CONTEXT *IO_CONTEXT_ARRAY[2048];//�������  
public:
	int num = 0;//��¼��Ŀ  
	PER_IO_CONTEXT* getARR(int i)
	{
		return IO_CONTEXT_ARRAY[i];
	}

	PER_IO_CONTEXT* GetNewIoContext()
	{
		for (int i = 0; i < 2048; i++)
		{
			//���ĳһ��IO_CONTEXT_ARRAY[i]Ϊ0����ʾ��һ��λ���Է���PER_IO_CONTEXT  
			if (IO_CONTEXT_ARRAY[i] == 0)
			{
				IO_CONTEXT_ARRAY[i] = new PER_IO_CONTEXT();
				num++;
				return IO_CONTEXT_ARRAY[i];
			}
		}
	}

	// ���������Ƴ�һ��ָ����IoContext
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

//�û�������
char* username[3] = { "admin","root" ,"zz" };
//��������
char* password[3] = { "adminadmin","rootroot" ,"zz" };

// ͬʱͶ�ݵ�Accept���������(���Ҫ����ʵ�ʵ�����������)
#define MAX_POST_ACCEPT 10

HANDLE mIoCompletionPort;

PER_IO_CONTEXT_ARR ArrayIoContext;
PER_SOCKET_CONTEXT_ARR ArraySocketContext;

GUID GuidAcceptEx = WSAID_ACCEPTEX; // AcceptEx ��GUID�����ڵ�������ָ��
LPFN_ACCEPTEX mAcceptEx;// AcceptEx����ָ��
GUID GuidGetAcceptExSockAddrs = WSAID_GETACCEPTEXSOCKADDRS;// GetAcceptExSockaddrs ��GUID�����ڵ�������ָ��
LPFN_GETACCEPTEXSOCKADDRS mAcceptExSockAddrs;// AcceptEx����ָ��

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
		printf("��ʼ��Socket�� ʧ�ܣ�\n");
		return 1;
	}

	// ������ɶ˿�
	mIoCompletionPort = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
	if (mIoCompletionPort == NULL)
	{
		printf("������ɶ˿�ʧ�ܣ��������: %d!\n", WSAGetLastError());
		return 2;
	}

	SYSTEM_INFO si;
	GetSystemInfo(&si);
	// ���ݱ����еĴ�����������������Ӧ���߳���
	int m_nThreads = 2 * si.dwNumberOfProcessors + 2;
	// ��ʼ���߳̾��
	HANDLE* m_phWorkerThreads = new HANDLE[m_nThreads];
	// ���ݼ�����������������߳�
	for (int i = 0; i < m_nThreads; i++)
	{
		m_phWorkerThreads[i] =
			CreateThread(0, 0, workThread, NULL, 0, NULL);
	}
	printf("���� WorkerThread %d ��.\n", m_nThreads);

	// ��������ַ��Ϣ�����ڰ�Socket
	struct sockaddr_in ServerAddress;

	// �������ڼ�����Socket����Ϣ
	ListenContext = new PER_SOCKET_CONTEXT;

	// ��Ҫʹ���ص�IO�������ʹ��WSASocket������Socket���ſ���֧���ص�IO����
	ListenContext->m_Socket = WSASocket(AF_INET, SOCK_STREAM, 0, NULL, 0, WSA_FLAG_OVERLAPPED);
	if (ListenContext->m_Socket == INVALID_SOCKET)
	{
		printf("��ʼ��Socketʧ�ܣ��������: %d.\n", WSAGetLastError());
	}
	else
	{
		printf("��ʼ��Socket���.\n", WSAGetLastError());
	}

	// ����ַ��Ϣ
	ZeroMemory(&ServerAddress, sizeof(ServerAddress));
	ServerAddress.sin_family = AF_INET;
	ServerAddress.sin_addr.s_addr = htonl(INADDR_ANY);
	ServerAddress.sin_port = htons(9999);

	// �󶨵�ַ�Ͷ˿�
	if (bind(ListenContext->m_Socket, (struct sockaddr *) &ServerAddress, sizeof(ServerAddress)) == SOCKET_ERROR)
	{
		printf("bind()����ִ�д���.\n");
		return 4;
	}

	// ��ʼ�����ListenContext�����socket���󶨵ĵ�ַ�˿ڽ��м���
	if (listen(ListenContext->m_Socket, SOMAXCONN) == SOCKET_ERROR)
	{
		printf("Listen()����ִ�г��ִ���.\n");
		return 5;
	}

	// ������������SocketContext�ŵ���ɶ˿��У��н�������ң���������ListenContext����ȥ
	if ((CreateIoCompletionPort((HANDLE)ListenContext->m_Socket, mIoCompletionPort, (DWORD)ListenContext, 0) == NULL))
	{
		printf("�󶨷����SocketContext����ɶ˿�ʧ�ܣ��������: %d/n", WSAGetLastError());
		if (ListenContext->m_Socket != INVALID_SOCKET)
		{
			closesocket(ListenContext->m_Socket);
			ListenContext->m_Socket = INVALID_SOCKET;
		}
		return 3;
	}
	else
	{
		printf("Listen Socket����ɶ˿� ���.\n");
	}

	// ʹ��AcceptEx��������Ϊ���������WinSock2�淶֮���΢�������ṩ����չ����
	// ������Ҫ�����ȡһ�º�����ָ�룬
	// ��ȡAcceptEx����ָ��
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
		printf("WSAIoctl δ�ܻ�ȡAcceptEx����ָ�롣�������: %d\n", WSAGetLastError());
		return 6;
	}

	// ��ȡGetAcceptExSockAddrs����ָ�룬Ҳ��ͬ��
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
		printf("WSAIoctl δ�ܻ�ȡGuidGetAcceptExSockAddrs����ָ�롣�������: %d\n", WSAGetLastError());
		return 7;
	}

	// ΪAcceptEx ׼��������Ȼ��Ͷ��AcceptEx I/O����
	for (int i = 0; i < MAX_POST_ACCEPT; i++)
	{
		// ����������SocketContext��һ��Accept�ļƻ�
		PER_IO_CONTEXT* newAcceptIoContext = ArrayIoContext.GetNewIoContext();

		if (_PostAccept(newAcceptIoContext) == false)
		{
			ArrayIoContext.RemoveContext(newAcceptIoContext);
			return false;
		}
	}
	printf("Ͷ�� %d ��AcceptEx������� \n", MAX_POST_ACCEPT);

	printf("INFO:��������������......\n");

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

	// ѭ����������
	while (true)
	{
		BOOL bReturn = GetQueuedCompletionStatus(
			mIoCompletionPort,//����������ǽ������Ǹ�Ψһ����ɶ˿�  
			&dwBytesTransfered,//����ǲ�����ɺ󷵻ص��ֽ��� 
			(PULONG_PTR)&pListenContext,//��������ǽ�����ɶ˿ڵ�ʱ��󶨵��Ǹ��Զ���ṹ�����  
			&pOverlapped,//���������������Socket��ʱ��һ�������Ǹ��ص��ṹ  
			INFINITE);//�ȴ���ɶ˿ڵĳ�ʱʱ�䣬����̲߳���Ҫ�����������飬�Ǿ�INFINITE������  

					  // ��ȡ����Ĳ���  ��ȡҵ��Ա��Ϣ
		PER_IO_CONTEXT* pIoContext = CONTAINING_RECORD(pOverlapped, PER_IO_CONTEXT, m_Overlapped);

		// �ж��Ƿ��пͻ��˶Ͽ���
		if (!bReturn)
		{
			DWORD dwErr = GetLastError();
			if (dwErr == 64) {

				ArrayIoContext.RemoveContext(pIoContext);
				ArraySocketContext.RemoveContext(pListenContext);
				printf("�ͻ��� %s:%d �Ͽ����ӣ�\n", inet_ntoa(pListenContext->m_ClientAddr.sin_addr), ntohs(pListenContext->m_ClientAddr.sin_port));
			}
			else {
				printf("�ͻ����쳣 %d", dwErr);
			}
			continue;
		}
		else
		{
			switch (pIoContext->m_OpType)
			{
			case ACCEPT:
			{
				// 1. ����ȡ������ͻ��˵ĵ�ַ��Ϣ(�鿴ҵ��Ա�Ӵ��Ŀͻ���Ϣ)
				SOCKADDR_IN* ClientAddr = NULL;
				SOCKADDR_IN* LocalAddr = NULL;
				int remoteLen = sizeof(SOCKADDR_IN), localLen = sizeof(SOCKADDR_IN);
				mAcceptExSockAddrs(pIoContext->m_wsaBuf.buf, pIoContext->m_wsaBuf.len - ((sizeof(SOCKADDR_IN) + 16) * 2),
					sizeof(SOCKADDR_IN) + 16, sizeof(SOCKADDR_IN) + 16, (LPSOCKADDR*)&LocalAddr, &localLen, (LPSOCKADDR*)&ClientAddr, &remoteLen);

				printf("�ͻ��� %s:%d ����.\n", inet_ntoa(ClientAddr->sin_addr), ntohs(ClientAddr->sin_port));

				//���յ��û���
				char *input_username = new char[40];
				//���յ�����
				char *input_password = new char[40];

				input_username = strtok(pIoContext->m_wsaBuf.buf, "#");
				input_password = strtok(NULL, "");

				char *user = new char[40];
				strcpy(user, input_username);

				//�Ƿ��½�ɹ�
				bool ok = false;

				if (input_username != NULL && input_password != NULL)
				{
					//�����˺��Ƿ����
					for (int i = 0; i < sizeof(username) / sizeof(username[0]); i++) {
						int j = 0;
						for (j = 0; username[i][j] == input_username[j] && input_username[j]; j++);
						if (username[i][j] == input_username[j] && input_username[j] == 0)
						{
							//�˺Ŵ��ڲ��������Ƿ���ȷ
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
					printf("�ͻ��� %s(%s:%d) ��½�ɹ���\n", user, inet_ntoa(ClientAddr->sin_addr), ntohs(ClientAddr->sin_port));
					strcpy(pIoContext->m_wsaBuf.buf, "��½�ɹ���");
				}
				else {
					printf("�ͻ��� %s(%s:%d) ��½ʧ�ܣ�\n", user, inet_ntoa(ClientAddr->sin_addr), ntohs(ClientAddr->sin_port));
					strcpy(pIoContext->m_wsaBuf.buf, "��½ʧ�ܣ�");
				}

				//��ӿͻ�����Ϣ
				PER_SOCKET_CONTEXT* newSocketContext = ArraySocketContext.GetNewSocketContext(ClientAddr, user);
				newSocketContext->m_Socket = pIoContext->m_socket;
				memcpy(&(newSocketContext->m_ClientAddr), ClientAddr, sizeof(SOCKADDR_IN));

				HANDLE hTemp = CreateIoCompletionPort((HANDLE)newSocketContext->m_Socket, mIoCompletionPort, (DWORD)newSocketContext, 0);
				if (NULL == hTemp)
				{
					printf("ִ��CreateIoCompletionPort���ִ���.�������: %d \n", GetLastError());
					break;
				}
				// ������ͻ���SocketContext��һ��Recv�ļƻ�
				PER_IO_CONTEXT* pNewSendIoContext = ArrayIoContext.GetNewIoContext();
				memcpy(&(pNewSendIoContext->m_wsaBuf.buf), &pIoContext->m_wsaBuf.buf, sizeof(pIoContext->m_wsaBuf.len));
				pNewSendIoContext->m_socket = newSocketContext->m_Socket;
				// SendͶ�ݳ�ȥ
				_PostSend(pNewSendIoContext);

				//�鿴�Ƿ��½�ɹ�
				if (ok) {

					PER_IO_CONTEXT* pNewRecvIoContext = ArrayIoContext.GetNewIoContext();
					pNewRecvIoContext->m_socket = newSocketContext->m_Socket;

					if (!_PostRecv(pNewRecvIoContext))
					{
						ArrayIoContext.RemoveContext(pNewRecvIoContext);
					}
				}
				// ����������SocketContext�����Ѱ󶨵�Accept�ƻ�
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
							printf("�ͻ��� %s(%s:%d) �� %s ����:%s\n", pListenContext->m_username, inet_ntoa(pListenContext->m_ClientAddr.sin_addr), ntohs(pListenContext->m_ClientAddr.sin_port), sendname, temp);
							sprintf(Senddata, "%s(%s:%d)���㷢��:\n%s", pListenContext->m_username, inet_ntoa(pListenContext->m_ClientAddr.sin_addr), ntohs(pListenContext->m_ClientAddr.sin_port), temp);
						}
					}
					else {
						temp = strtok(pIoContext->m_wsaBuf.buf, "#");
						printf("�ͻ��� %s(%s:%d) ���ҷ���:%s\n", pListenContext->m_username, inet_ntoa(pListenContext->m_ClientAddr.sin_addr), ntohs(pListenContext->m_ClientAddr.sin_port), temp);
						sprintf(Senddata, "%s(%s:%d)���ҷ���:\n%s", pListenContext->m_username, inet_ntoa(pListenContext->m_ClientAddr.sin_addr), ntohs(pListenContext->m_ClientAddr.sin_port), temp);
					}


					for (int i = 0; i < ArraySocketContext.num; i++)
					{
						PER_SOCKET_CONTEXT* cSocketContext = ArraySocketContext.getARR(i);
						if (cSocketContext->m_Socket == pListenContext->m_Socket) {
							continue;
						}
						//�ж��Ƿ��ǵ��Ե���Ϣ
						if (sizeof(sendname) > 0 && !strcmp(sendname, cSocketContext->m_username) && strcmp(Senddata, "")) {
							// ������ͻ���SocketContext��һ��Recv�ļƻ�
							PER_IO_CONTEXT* pNewSendIoContext = ArrayIoContext.GetNewIoContext();
							memcpy(&(pNewSendIoContext->m_wsaBuf.buf), &Senddata, sizeof(Senddata));
							pNewSendIoContext->m_socket = cSocketContext->m_Socket;
							// SendͶ�ݳ�ȥ
							_PostSend(pNewSendIoContext);
						}
						else if (!strcmp(sendname, "") && strcmp(Senddata, "")) {
							// ������ͻ���SocketContext��һ��Recv�ļƻ�
							PER_IO_CONTEXT* pNewSendIoContext = ArrayIoContext.GetNewIoContext();
							memcpy(&(pNewSendIoContext->m_wsaBuf.buf), &Senddata, sizeof(Senddata));
							pNewSendIoContext->m_socket = cSocketContext->m_Socket;
							// SendͶ�ݳ�ȥ
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
				// ��Ӧ��ִ�е�����
				printf("_WorkThread�е� pIoContext->m_OpType �����쳣.\n");
				break;
			} //switch
		}
	}
	printf("�߳��˳�.\n");
	return 0;
}

// Ͷ��Send����
bool _PostSend(PER_IO_CONTEXT* SendIoContext)
{
	// ��ʼ������
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

// Ͷ��Recv����
bool _PostRecv(PER_IO_CONTEXT* RecvIoContext)
{
	// ��ʼ������
	DWORD dwFlags = 0;
	DWORD dwBytes = 0;
	RecvIoContext->m_OpType = RECV;
	WSABUF *p_wbuf = &RecvIoContext->m_wsaBuf;
	OVERLAPPED *p_ol = &RecvIoContext->m_Overlapped;

	RecvIoContext->ResetBuffer();

	int nBytesRecv = WSARecv(RecvIoContext->m_socket, p_wbuf, 1, &dwBytes, &dwFlags, p_ol, NULL);

	// �������ֵ���󣬲��Ҵ���Ĵ��벢����Pending�Ļ����Ǿ�˵������ص�����ʧ����
	if (nBytesRecv == SOCKET_ERROR && (WSAGetLastError() != WSA_IO_PENDING))
	{
		if (WSAGetLastError() != 10054) {
			printf("Ͷ��һ��WSARecvʧ�ܣ�%d \n", WSAGetLastError());
		}
		return false;
	}
	return true;
}

// Ͷ��Accept���� ����Ŀ������µ�һ��accept Ҳ������һ��accept�������Ҫ������һ��accept
bool _PostAccept(PER_IO_CONTEXT* AcceptIoContext)
{
	// ׼������
	DWORD dwBytes = 0;
	AcceptIoContext->m_OpType = ACCEPT;
	WSABUF *p_wbuf = &AcceptIoContext->m_wsaBuf;
	OVERLAPPED *p_ol = &AcceptIoContext->m_Overlapped;

	// Ϊ�Ժ�������Ŀͻ�����׼����Socket(׼���ýӴ��ͻ���ҵ��Ա����������ͳAccept�ֳ�newһ������)
	AcceptIoContext->m_socket = WSASocket(AF_INET, SOCK_STREAM, 0, NULL, 0, WSA_FLAG_OVERLAPPED);
	if (AcceptIoContext->m_socket == INVALID_SOCKET)
	{
		printf("��������Accept��Socketʧ�ܣ��������: %d", WSAGetLastError());
		return false;
	}

	// Ͷ��AcceptEx
	if (mAcceptEx(ListenContext->m_Socket, AcceptIoContext->m_socket, p_wbuf->buf, p_wbuf->len - ((sizeof(SOCKADDR_IN) + 16) * 2),
		sizeof(SOCKADDR_IN) + 16, sizeof(SOCKADDR_IN) + 16, &dwBytes, p_ol) == FALSE)
	{
		if (WSAGetLastError() != WSA_IO_PENDING)
		{
			printf("Ͷ�� AcceptEx ����ʧ�ܣ��������: %d", WSAGetLastError());
			return false;
		}
	}
	return true;
}