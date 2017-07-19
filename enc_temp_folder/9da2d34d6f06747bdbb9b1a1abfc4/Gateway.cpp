#include "stdafx.h"
#include "stdio.h"
#include "winsock2.h"
#include "ws2tcpip.h"
#include "mswsock.h"
#pragma comment(lib,"ws2_32.lib")

#define c_LISTEN_PORT 8600
#define c_MAX_DATA_LENGTH 4096
#define c_SOCKET_CONTEXT 2048
#define c_MAX_POST_ACCEPT 10

enum enumIoType
{
	ACCEPT,
	RECV,
	SEND,
	NONE,
	ROOT
};

//��������ṹ�壬����Overlapped��������socket���������Լ�������������ͣ�accpet��received����send
struct _PER_IO_CONTEXT
{
	OVERLAPPED m_overlapped; // ÿһ���ص�����������ص��ṹ(���ÿһ��Socket��ÿһ����������Ҫ��һ��           
	SOCKET m_socket; // ������������ʹ�õ�Socket
	WSABUF m_wsaBuf; // WSA���͵Ļ����������ڸ��ص�������������
	char* m_szBuffer; // �����WSABUF�������ַ��Ļ�����
	enumIoType m_IoType; // ��ʶ�������������(��Ӧ�����ö��)

	_PER_IO_CONTEXT* pPreIoContext;
	_PER_IO_CONTEXT* pNextIoContext;

	_PER_IO_CONTEXT()
	{
		ZeroMemory(&m_overlapped, sizeof(m_overlapped));
		m_szBuffer = new char[c_MAX_DATA_LENGTH];
		ZeroMemory(m_szBuffer, c_MAX_DATA_LENGTH);
		m_socket = NULL;
		m_wsaBuf.buf = m_szBuffer;
		m_wsaBuf.len = c_MAX_DATA_LENGTH;
		m_IoType = NONE;
		pPreIoContext = NULL;
		pNextIoContext = NULL;
	}

	void CloseIoContext()
	{
		if (pNextIoContext)
		{
			pPreIoContext->pNextIoContext = pNextIoContext;
			pNextIoContext->pPreIoContext = pPreIoContext;
		}
		else
		{
			pPreIoContext->pNextIoContext = NULL;
		}
		delete m_szBuffer;
		ZeroMemory(&m_overlapped, sizeof(m_overlapped));
		m_socket = NULL;
		m_IoType = NONE;
		pPreIoContext = NULL;
		pNextIoContext = NULL;
	}

	// ���û���������
	void ResetBuffer()
	{
		ZeroMemory(m_szBuffer, c_MAX_DATA_LENGTH);
	}
};

struct _PER_SOCKET_CONTEXT
{
	SOCKET m_Socket; // ÿһ���ͻ������ӵ�Socket
	SOCKADDR_IN m_ClientAddr; // �ͻ��˵ĵ�ַ
	char m_username[40];
	_PER_IO_CONTEXT* HeadIoContext;
	int m_timer;

	_PER_SOCKET_CONTEXT()
	{
		m_timer = 0;
		m_Socket = INVALID_SOCKET;
		memset(&m_ClientAddr, 0, sizeof(m_ClientAddr));
		ZeroMemory(m_username, 40);
		HeadIoContext = new _PER_IO_CONTEXT();
		HeadIoContext->m_IoType = ROOT;
	}

	_PER_IO_CONTEXT* GetNewIoContext()
	{
		_PER_IO_CONTEXT* temp = new _PER_IO_CONTEXT();
		if (HeadIoContext->pNextIoContext)
		{
			HeadIoContext->pNextIoContext->pPreIoContext = temp;
			temp->pNextIoContext = HeadIoContext->pNextIoContext;
		}
		HeadIoContext->pNextIoContext = temp;
		temp->pPreIoContext = HeadIoContext;
		return temp;
	}

	// �ͷ���Դ
	void CloseSocketContext()
	{
		if (m_Socket != INVALID_SOCKET)
		{
			while (HeadIoContext->pNextIoContext)
			{
				HeadIoContext->pNextIoContext->CloseIoContext();
			}
			m_timer = 0;
			HeadIoContext = NULL;
			closesocket(m_Socket);
			m_Socket = NULL;
			memset(&m_ClientAddr, 0, sizeof(m_ClientAddr));
			ZeroMemory(m_username, 40);
		}
	}

	void UpTimer()
	{
		m_timer++;
	}

	void ResetTimer()
	{
		m_timer = 0;
	}
};

//Socket�ṹ��������࣬��������Socket��Ͻṹ�����飬���Ը�������ɾ��
class ARRAY_PER_SOCKET_CONTEXT
{
private:
	_PER_SOCKET_CONTEXT* m_arrayPerSocketContext[c_SOCKET_CONTEXT];
public:
	int num = 0;

	_PER_SOCKET_CONTEXT* GetNewSocketContext(SOCKADDR_IN pAddressPort, char* szUserName)
	{
		for (int i = 0; i < c_SOCKET_CONTEXT; i++)
		{
			//���ĳһ��IO_CONTEXT_ARRAY[i]Ϊ0����ʾ��һ��λ���Է���PER_IO_CONTEXT  
			if (!m_arrayPerSocketContext[i])
			{
				m_arrayPerSocketContext[i] = new _PER_SOCKET_CONTEXT();
				memcpy(&(m_arrayPerSocketContext[i]->m_ClientAddr), &pAddressPort, sizeof(SOCKADDR_IN));
				strcpy_s(m_arrayPerSocketContext[i]->m_username, strlen(szUserName) + 1, szUserName);
				num++;
				return m_arrayPerSocketContext[i];
			}
		}
		return NULL;
	}

	_PER_SOCKET_CONTEXT* getARR(int i)
	{
		return m_arrayPerSocketContext[i];
	}

	// ���������Ƴ�һ��ָ����IoContext
	void RemoveContext(_PER_SOCKET_CONTEXT* pRemoveSokcetContext)
	{
		for (int i = 0; i < c_SOCKET_CONTEXT; i++)
		{
			if (m_arrayPerSocketContext[i] == pRemoveSokcetContext)
			{
				num--;
				m_arrayPerSocketContext[i]->CloseSocketContext();
				m_arrayPerSocketContext[i] = NULL;
				break;
			}
		}
	}

	void UpTimer()
	{
		int temp = num;
		for (int i = 0; i < c_SOCKET_CONTEXT; i++)
		{
			if (m_arrayPerSocketContext[i])
			{
				m_arrayPerSocketContext[i]->UpTimer();
				if (m_arrayPerSocketContext[i]->m_timer > 2)
				{
					num--;
					m_arrayPerSocketContext[i]->CloseSocketContext();
					m_arrayPerSocketContext[i] = NULL;
				}
				temp--;
				if (temp == 0)
				{
					break;
				}
			}
		}
	}

	bool ContainAddr(SOCKADDR_IN client_addr)
	{
		int temp = 0;
		for (int i = 0; i < c_SOCKET_CONTEXT; i++)
		{
			if (m_arrayPerSocketContext[i])
			{
				if (!memcmp(&m_arrayPerSocketContext[i]->m_ClientAddr, &client_addr, sizeof(SOCKADDR_IN)))
				{
					m_arrayPerSocketContext[i]->ResetTimer();
					printf("%d", m_arrayPerSocketContext[i]->m_timer);
					return true;
				}
				temp++;
				if (temp == num)
				{
					break;
				}
			}
		}
		return false;
	};
};

//��ɽӿ�
HANDLE g_hIoCompletionPort;

//����һ��Socket�ṹ������ľ��
ARRAY_PER_SOCKET_CONTEXT m_arraySocketContext;

ARRAY_PER_SOCKET_CONTEXT m_arrayServerSocketContext;

//AcceptEx��GUID�����ڵ���AcceptEx����ָ��
GUID GuidAcceptEx = WSAID_ACCEPTEX;
//AcceptEx����ָ��
LPFN_ACCEPTEX m_AcceptEx;
//AcceptExSockaddrs��GUID�����ڵ���AcceptExSockaddrs����ָ��
GUID GuidGetAcceptExSockAddrs = WSAID_GETACCEPTEXSOCKADDRS;
//AcceptExSockaddrs����ָ��
LPFN_GETACCEPTEXSOCKADDRS m_AcceptExSockAddrs;

//����������Listen��Socket�ṹ��
_PER_SOCKET_CONTEXT* g_ListenContext;

//����������ɶ˿ڲ������߳�
DWORD WINAPI workThread(LPVOID lpParam);
//���������������߳�
DWORD WINAPI StartTimerCount(LPVOID lpParam);
//�������������������߳�
DWORD WINAPI StartHeartBeat(LPVOID lpParam);
//����Ͷ��Send���󣬷�������Ϣ���֪ͨ��ɶ˿�
bool _PostSend(_PER_IO_CONTEXT* pSendIoContext);
//����Ͷ��Recv���󣬽����������֪ͨ��ɶ˿�
bool _PostRecv(_PER_IO_CONTEXT* pRecvIoContext);
//����Ͷ��Accept�����յ�һ�����������֪ͨ��ɶ˿�
bool _PostAccept(_PER_IO_CONTEXT* pAcceptIoContext);
//����Ͷ�ݽ������󣬷����������Ϣ��֪ͨ��ɶ˿�
bool _PostEnd(_PER_IO_CONTEXT* pEndIoContext);

int main()
{
	WSADATA wsaData;
	if (NO_ERROR != WSAStartup(MAKEWORD(2, 2), &wsaData))
	{
		printf_s("��ʼ��Socket�� ʧ�ܣ�\n");
		return 1;
	}

	// ������ɶ˿�
	g_hIoCompletionPort = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
	if (g_hIoCompletionPort == NULL)
	{
		printf_s("������ɶ˿�ʧ�ܣ��������: %d!\n", WSAGetLastError());
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
	printf_s("���� WorkerThread %d ��.\n", m_nThreads);

	// ��������ַ��Ϣ�����ڰ�Socket
	struct sockaddr_in ServerAddress;

	// �������ڼ�����Socket����Ϣ
	g_ListenContext = new _PER_SOCKET_CONTEXT;

	// ��Ҫʹ���ص�IO�������ʹ��WSASocket������Socket���ſ���֧���ص�IO����
	g_ListenContext->m_Socket = WSASocket(AF_INET, SOCK_STREAM, 0, NULL, 0, WSA_FLAG_OVERLAPPED);
	if (g_ListenContext->m_Socket == INVALID_SOCKET)
	{
		printf_s("��ʼ��Socketʧ�ܣ��������: %d.\n", WSAGetLastError());
	}
	else
	{
		printf_s("��ʼ��Socket���.\n");
	}

	// ����ַ��Ϣ
	ZeroMemory(&ServerAddress, sizeof(ServerAddress));
	ServerAddress.sin_family = AF_INET;
	ServerAddress.sin_addr.s_addr = htonl(INADDR_ANY);
	ServerAddress.sin_port = htons(c_LISTEN_PORT);

	// �󶨵�ַ�Ͷ˿�
	if (bind(g_ListenContext->m_Socket, (LPSOCKADDR)&ServerAddress, sizeof(ServerAddress)) == SOCKET_ERROR)
	{
		printf_s("bind()����ִ�д���.\n");
		return 4;
	}

	// ��ʼ�����ListenContext�����socket���󶨵ĵ�ַ�˿ڽ��м���
	if (listen(g_ListenContext->m_Socket, SOMAXCONN) == SOCKET_ERROR)
	{
		printf_s("Listen()����ִ�г��ִ���.\n");
		return 5;
	}

	DWORD dwBytes = 0;
	//ʹ��WSAIoctl��ͨ��GuidAcceptEx(AcceptEx��GUID)����ȡAcceptEx����ָ��
	if (SOCKET_ERROR == WSAIoctl(
		g_ListenContext->m_Socket,
		SIO_GET_EXTENSION_FUNCTION_POINTER,
		&GuidAcceptEx,
		sizeof(GuidAcceptEx),
		&m_AcceptEx,
		sizeof(m_AcceptEx),
		&dwBytes,
		NULL,
		NULL))
	{
		printf_s("WSAIoctl δ�ܻ�ȡAcceptEx����ָ�롣�������: %d\n", WSAGetLastError());
		return 6;
	}

	//ʹ��WSAIoctl��ͨ��GuidGetAcceptExSockAddrs(AcceptExSockaddrs��GUID)����ȡAcceptExSockaddrs����ָ��
	if (SOCKET_ERROR == WSAIoctl(
		g_ListenContext->m_Socket,
		SIO_GET_EXTENSION_FUNCTION_POINTER,
		&GuidGetAcceptExSockAddrs,
		sizeof(GuidGetAcceptExSockAddrs),
		&m_AcceptExSockAddrs,
		sizeof(m_AcceptExSockAddrs),
		&dwBytes,
		NULL,
		NULL))
	{
		printf_s("WSAIoctl δ�ܻ�ȡGuidGetAcceptExSockAddrs����ָ�롣�������: %d\n", WSAGetLastError());
		return 7;
	}

	//�������ListenSocket�ṹ��ŵ���ɶ˿��У��н�������ң���������ListenContext����ȥ
	if ((CreateIoCompletionPort((HANDLE)g_ListenContext->m_Socket, g_hIoCompletionPort, (DWORD)g_ListenContext, 0) == NULL))
	{
		printf_s("�󶨷����SocketContext����ɶ˿�ʧ�ܣ��������: %d/n", WSAGetLastError());
		if (g_ListenContext->m_Socket != INVALID_SOCKET)
		{
			closesocket(g_ListenContext->m_Socket);
			g_ListenContext->m_Socket = INVALID_SOCKET;
		}
		return 3;
	}
	printf_s("Listen Socket����ɶ˿� ���.\n");


	//ѭ��10��
	for (int i = 0; i < c_MAX_POST_ACCEPT; i++)
	{
		//ͨ����������ṹ��������һ���µ���������ṹ��
		_PER_IO_CONTEXT* newAcceptIoContext = g_ListenContext->GetNewIoContext();
		//Ͷ��Send���󣬷�������Ϣ���֪ͨ��ɶ˿ڣ�
		if (_PostAccept(newAcceptIoContext) == false)
		{
			newAcceptIoContext->CloseIoContext();
			return 4;
		}
	}
	printf_s("Ͷ�� %d ��AcceptEx������� \n", c_MAX_POST_ACCEPT);


	CreateThread(0, 0, StartHeartBeat, NULL, 0, NULL);
	CreateThread(0, 0, StartTimerCount, NULL, 0, NULL);

	printf_s("���ط�������������......\n");

	//���߳�����������exit�˳�
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

//����������ɶ˿ڲ������߳�
DWORD WINAPI workThread(LPVOID lpParam)
{
	//���������ɺ���յ���������ṹ�������Overlapped
	OVERLAPPED* pOverlapped = NULL;
	//���������ɺ���յ�Socket�ṹ�壬��һ����ListenSocket�Ľṹ��
	_PER_SOCKET_CONTEXT* pListenContext = NULL;
	//���������ɺ���յ��ֽ��� 
	DWORD dwBytesTransfered = 0;

	bool run = true;
	// ѭ����������
	while (run)
	{
		BOOL bReturn = GetQueuedCompletionStatus(
			g_hIoCompletionPort,//����������ǽ������Ǹ�Ψһ����ɶ˿�  
			&dwBytesTransfered,//����ǲ�����ɺ󷵻ص��ֽ��� 
			(PULONG_PTR)&pListenContext,//��������ǽ�����ɶ˿ڵ�ʱ��󶨵��Ǹ�sockt�ṹ��
			&pOverlapped,//���������������Socket��ʱ��һ�������Ǹ��ص��ṹ  
			INFINITE);//�ȴ���ɶ˿ڵĳ�ʱʱ�䣬����̲߳���Ҫ�����������飬�Ǿ�INFINITE

		//ͨ�����Overlapped���õ������������������ṹ��
		_PER_IO_CONTEXT* pIoContext = CONTAINING_RECORD(pOverlapped, _PER_IO_CONTEXT, m_overlapped);

		char IPAddr[16];
		// �ж��Ƿ��пͻ��˶Ͽ���
		if (!bReturn)
		{
			DWORD dwErr = GetLastError();
			//�������64���ͻ���closesocket
			if (dwErr == 64)
			{
				inet_ntop(AF_INET, &pListenContext->m_ClientAddr.sin_addr, IPAddr, 16);
				printf_s("%s:%d �Ͽ����ӣ�\n", IPAddr, ntohs(pListenContext->m_ClientAddr.sin_port));
				m_arraySocketContext.RemoveContext(pListenContext);
				m_arrayServerSocketContext.RemoveContext(pListenContext);
			}
			else
			{
				printf_s("�ͻ����쳣�Ͽ� %d", dwErr);
			}
		}
		else
		{
			//�ж�����������������
			switch (pIoContext->m_IoType)
			{
			case ACCEPT:
				{
					// 1. ����ȡ������ͻ��˵ĵ�ַ��Ϣ(�鿴ҵ��Ա�Ӵ��Ŀͻ���Ϣ)
					SOCKADDR_IN* pClientAddr = NULL;
					SOCKADDR_IN* pLocalAddr = NULL;
					int remoteLen = sizeof(SOCKADDR_IN), localLen = sizeof(SOCKADDR_IN);
					m_AcceptExSockAddrs(pIoContext->m_wsaBuf.buf, pIoContext->m_wsaBuf.len - ((sizeof(SOCKADDR_IN) + 16) * 2),
					                    sizeof(SOCKADDR_IN) + 16, sizeof(SOCKADDR_IN) + 16, (LPSOCKADDR*)&pLocalAddr, &localLen, (LPSOCKADDR*)&pClientAddr, &remoteLen);

					inet_ntop(AF_INET, &pClientAddr->sin_addr, IPAddr, 16);
					printf_s("�ͻ��� %s:%d ����.\n", IPAddr, ntohs(pClientAddr->sin_port));

					char* data = new char[40];

					char* type = strtok_s(pIoContext->m_wsaBuf.buf, "|", &data);

					switch (type[0])
					{
					case 'L':
						{
							//���յ�����
							char* input_password = new char[40];

							//�����ַ���Ϊ �û���#���� �Ľṹ����Ҫstrtok_s�ָ
							char* input_username = strtok_s(data, "#", &input_password);

							//�����Ƿ��½�ɹ�����Ҫ����һ��������ͻ��� ��½�ɹ� or ��½ʧ��
							//ͨ��Socket�ṹ������õ�һ���µ�Socket�ṹ�壬�����û���Ϣ�����ȥ
							_PER_SOCKET_CONTEXT* newSocketContext = m_arraySocketContext.GetNewSocketContext(*pClientAddr, input_username);
							//��Socket�ṹ�屣�浽Socket�ṹ���������»�õ�Socket�ṹ����
							newSocketContext->m_Socket = pIoContext->m_socket;
							//������µõ���Socket�ṹ��ŵ���ɶ˿��У��н��������
							HANDLE hTemp = CreateIoCompletionPort((HANDLE)newSocketContext->m_Socket, g_hIoCompletionPort, (DWORD)newSocketContext, 0);
							if (NULL == hTemp)
							{
								printf_s("ִ��CreateIoCompletionPort���ִ���.�������: %d \n", GetLastError());
								break;
							}

							int count = m_arrayServerSocketContext.num;
							bool online = false;
							_PER_SOCKET_CONTEXT* cSocketContext = nullptr;
							for (int i = 0; i < c_SOCKET_CONTEXT; i++)
							{
								cSocketContext = m_arrayServerSocketContext.getARR(i);
								if (count == 0)
								{
									break;
								}
								if (cSocketContext)
								{
									//�ж��Ƿ��ǵ��Ե���Ϣ
									if (!strcmp(type, cSocketContext->m_username))
									{
										online = true;
										break;
									}
									count--;
								}
							}

							char* Senddata = new char[c_MAX_DATA_LENGTH];
							ZeroMemory(Senddata, c_MAX_DATA_LENGTH);
							if (online)
							{
								//������µõ���Socket�ṹ���һ��PostRevc���������ͻ����Ƿ��½�ɹ��Ľ�����ͻ�ȥ�����Ͳ�����ɣ�֪ͨ��ɶ˿�
								_PER_IO_CONTEXT* pNewSendIoContext = cSocketContext->GetNewIoContext();
								pNewSendIoContext->m_socket = cSocketContext->m_Socket;
								// ������ͻ���SocketContext��һ��Recv�ļƻ�
								sprintf_s(Senddata, c_MAX_DATA_LENGTH, "%s|%s#%s", input_username, input_username, input_password);
								strcpy_s(pNewSendIoContext->m_szBuffer, strlen(Senddata) + 1, Senddata);
								pNewSendIoContext->m_wsaBuf.len = strlen(Senddata) + 1;
								// SendͶ�ݳ�ȥ
								_PostSend(pNewSendIoContext);
							}
							else
							{
								char IpPort[16];
								inet_ntop(AF_INET, &newSocketContext->m_ClientAddr.sin_addr, IpPort, 16);
								printf_s("�ͻ��� %s(%s:%d) ��½ʧ�ܣ�\n", type, IpPort, ntohs(newSocketContext->m_ClientAddr.sin_port));
								sprintf_s(Senddata, c_MAX_DATA_LENGTH, "��½ʧ�ܣ�");
								_PER_IO_CONTEXT* pNewSendIoContext = newSocketContext->GetNewIoContext();
								strcpy_s(pNewSendIoContext->m_szBuffer, strlen(Senddata) + 1, Senddata);
								pNewSendIoContext->m_wsaBuf.len = strlen(Senddata) + 1;
								pNewSendIoContext->m_socket = newSocketContext->m_Socket;
								// SendͶ�ݳ�ȥ
								_PostEnd(pNewSendIoContext);
							}

							//��֮ǰ��Accept����������ṹ������buffer���ø������������Accept
							pIoContext->ResetBuffer();
							_PostAccept(pIoContext);
						}
						break;
					default:
						// ��Ӧ��ִ�е�����
						printf_s("_WorkThread�е� pIoContext->IoType �����쳣.\n");
					}

					//��֮ǰ��Accept����������ṹ������buffer���ø������������Accept
					pIoContext->ResetBuffer();
					_PostAccept(pIoContext);
				}
				break;
			case RECV:
				{
					char senddata[4096];
					ZeroMemory(senddata, 4096);
					char* data = new char[c_MAX_DATA_LENGTH];
					ZeroMemory(data, c_MAX_DATA_LENGTH);
					char* type = strtok_s(pIoContext->m_wsaBuf.buf, "|", &data);

					switch (type[0])
					{
					case 'G':
						{
							inet_ntop(AF_INET, &pListenContext->m_ClientAddr.sin_addr, IPAddr, 16);
							printf_s("����%s������(%s:%d)%s\n", pListenContext->m_username, IPAddr, ntohs(pListenContext->m_ClientAddr.sin_port), data);
						}
						break;
					case 'C':
						{
							inet_ntop(AF_INET, &pListenContext->m_ClientAddr.sin_addr, IPAddr, 16);
							printf_s("�ͻ��� %s(%s:%d) ���ҷ���:%s\n", pListenContext->m_username, IPAddr, ntohs(pListenContext->m_ClientAddr.sin_port), data);
							sprintf_s(senddata, c_MAX_DATA_LENGTH, "%s(%s:%d)���ҷ���:\n%s", pListenContext->m_username, IPAddr, ntohs(pListenContext->m_ClientAddr.sin_port), data);

							int count = m_arrayServerSocketContext.num;
							bool online = false;
							_PER_SOCKET_CONTEXT* cSocketContext = nullptr;
							for (int i = 0; i < c_SOCKET_CONTEXT; i++)
							{
								cSocketContext = m_arrayServerSocketContext.getARR(i);
								if (count == 0)
								{
									break;
								}
								if (cSocketContext)
								{
									//�ж��Ƿ��ǵ��Ե���Ϣ
									if (!strcmp(type, cSocketContext->m_username))
									{
										online = true;
										break;
									}
									count--;
								}
							}

							_PER_IO_CONTEXT* pNewIoContext = pListenContext->GetNewIoContext();
							pNewIoContext->m_socket = pListenContext->m_Socket;
							if (online)
							{
								_PER_IO_CONTEXT* pNewSendIoContext = cSocketContext->GetNewIoContext();
								pNewSendIoContext->m_socket = cSocketContext->m_Socket;
								// ������ͻ���SocketContext��һ��Recv�ļƻ�
								strcpy_s(pNewSendIoContext->m_szBuffer, strlen(senddata) + 1, senddata);
								pNewSendIoContext->m_wsaBuf.len = strlen(senddata) + 1;
								// SendͶ�ݳ�ȥ
								_PostSend(pNewSendIoContext);

								strcpy_s(pNewIoContext->m_szBuffer, 12, "�ѷ��ͳɹ�");
							}
							else
							{
								strcpy_s(pNewIoContext->m_szBuffer, 12, "δ���ͳɹ�");
							}
							pNewIoContext->m_wsaBuf.len = 12;
							_PostSend(pNewIoContext);
						}
						break;
					default:

						bool ok = false;

						if (!strcmp(data, "��½�ɹ���"))
						{
							ok = true;
						}

						int count = m_arraySocketContext.num;
						for (int i = 0; i < c_SOCKET_CONTEXT; i++)
						{
							_PER_SOCKET_CONTEXT* cSocketContext = m_arraySocketContext.getARR(i);
							if (count == 0)
							{
								break;
							}
							//�ж��Ƿ��ǵ��Ե���Ϣ
							if (!strcmp(type, cSocketContext->m_username))
							{
								//������µõ���Socket�ṹ���һ��PostSend���������ͻ����Ƿ��½�ɹ��Ľ�����ͻ�ȥ�����Ͳ�����ɣ�֪ͨ��ɶ˿�
								_PER_IO_CONTEXT* pNewSendIoContext = cSocketContext->GetNewIoContext();
								pNewSendIoContext->m_socket = cSocketContext->m_Socket;
								char IpPort[16];
								inet_ntop(AF_INET, &cSocketContext->m_ClientAddr.sin_addr, IpPort, 16);
								if (ok)
								{
									printf_s("�ͻ��� %s(%s:%d) ��½�ɹ���\n", type, IpPort, ntohs(cSocketContext->m_ClientAddr.sin_port));
									strcpy_s(pNewSendIoContext->m_szBuffer, strlen(data) + 1, data);
									pNewSendIoContext->m_wsaBuf.len = strlen(data) + 1;

									_PostSend(pNewSendIoContext);
									_PER_IO_CONTEXT* pNewRecvIoContext = cSocketContext->GetNewIoContext();
									pNewRecvIoContext->m_socket = cSocketContext->m_Socket;

									if (!_PostRecv(pNewRecvIoContext))
									{
										pNewRecvIoContext->CloseIoContext();
									}
								}
								else
								{
									printf_s("�ͻ��� %s(%s:%d) ��½ʧ�ܣ�\n", type, IpPort, ntohs(cSocketContext->m_ClientAddr.sin_port));
									strcpy_s(pNewSendIoContext->m_szBuffer, strlen(data) + 1, data);
									pNewSendIoContext->m_wsaBuf.len = strlen(data) + 1;
									_PostEnd(pNewSendIoContext);
								}
							}
							count--;
						}
						break;
					}


					pIoContext->ResetBuffer();
					_PostRecv(pIoContext);
				}
				break;
			case SEND:
				//��������Ϣ�󣬽�������������Ľṹ��ɾ��
				pIoContext->CloseIoContext();
				break;
			case NONE:
				//��������Ϣ�󣬽�������������Ľṹ��ɾ��
				m_arraySocketContext.RemoveContext(pListenContext);
				break;
			default:
				// ��Ӧ��ִ�е�����
				printf_s("_WorkThread�е� pIoContext->IoType �����쳣.\n");
				run = false;
				break;
			} //switch
		}
	}

	printf_s(

		"�߳��˳�.\n"
	);
	return
		0;
}

//�������������������߳�
DWORD WINAPI StartHeartBeat(LPVOID lpParam)
{
	SOCKADDR_IN form, ClientAddress;
	WSADATA wsdata;
	//����SOCKET�⣬�汾Ϊ2.0  
	WSAStartup(MAKEWORD(2, 2), &wsdata);
	bool optval = true;

	ClientAddress.sin_family = AF_INET;
	ClientAddress.sin_addr.s_addr = 0;
	ClientAddress.sin_port = htons(9000);

	//��UDP��ʼ���׽���  
	SOCKET ListenSocket = socket(AF_INET, SOCK_DGRAM, 0);
	// ���ø��׽���Ϊ�㲥���ͣ�  
	setsockopt(ListenSocket, SOL_SOCKET, SO_BROADCAST, (char FAR *)&optval, sizeof(optval));
	// �Ѹ��׽��ְ���һ������ĵ�ַ��  
	bind(ListenSocket, (sockaddr *)&ClientAddress, sizeof(sockaddr_in));
	int fromlength = sizeof(SOCKADDR);
	char buf[256];
	while (true)
	{
		recvfrom(ListenSocket, buf, 256, 0, (struct sockaddr FAR *)&form, (int FAR *)&fromlength);

		char* port = new char[6];
		//�����ַ���Ϊ �û���#���� �Ľṹ����Ҫstrtok_s�ָ
		char* type = strtok_s(buf, "#", &port);

		char IPAddr[16];
		inet_ntop(AF_INET, &form.sin_addr, IPAddr, 16);

		SOCKADDR_IN ClientAddr;
		ZeroMemory(&ClientAddr, sizeof(&ClientAddr));
		ClientAddr.sin_family = AF_INET;
		ClientAddr.sin_addr.S_un = form.sin_addr.S_un;
		ClientAddr.sin_port = htons(atoi(port));

		if (!m_arrayServerSocketContext.ContainAddr(ClientAddr))
		{
			_PER_SOCKET_CONTEXT* newSocketContext = m_arrayServerSocketContext.GetNewSocketContext(ClientAddr, type);
			newSocketContext->m_Socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
			if (connect(newSocketContext->m_Socket, (sockaddr *)&ClientAddr, sizeof(ClientAddr)) == SOCKET_ERROR)
			{
				printf_s("connect error���������: %d\n", WSAGetLastError());
				m_arrayServerSocketContext.RemoveContext(newSocketContext);
			}
			send(newSocketContext->m_Socket, "GATEWAY|online", 8, 0);

			_PER_IO_CONTEXT* pNewRecvIoContext = newSocketContext->GetNewIoContext();
			pNewRecvIoContext->m_socket = newSocketContext->m_Socket;

			HANDLE hTemp = CreateIoCompletionPort((HANDLE)newSocketContext->m_Socket, g_hIoCompletionPort, (DWORD)newSocketContext, 0);
			if (NULL == hTemp)
			{
				printf_s("ִ��CreateIoCompletionPort���ִ���.�������: %d \n", GetLastError());
				break;
			}

			if (!_PostRecv(pNewRecvIoContext))
			{
				pNewRecvIoContext->CloseIoContext();
			}
		}
		ZeroMemory(buf, 256);
	}
	return 0;
}

DWORD WINAPI StartTimerCount(LPVOID lpParam)
{
	while (true)
	{
		if (m_arrayServerSocketContext.num > 0)
		{
			m_arrayServerSocketContext.UpTimer();
		}
		Sleep(10000);
	}
}

//����Ͷ��Send���󣬷�������Ϣ���֪ͨ��ɶ˿�
bool _PostEnd(_PER_IO_CONTEXT* pSendIoContext)
{
	// ��ʼ������
	DWORD dwFlags = 0;
	DWORD dwBytes = 0;
	pSendIoContext->m_IoType = NONE;

	if ((WSASend(pSendIoContext->m_socket, &pSendIoContext->m_wsaBuf, 1, &dwBytes, dwFlags, &pSendIoContext->m_overlapped,
	             NULL) == SOCKET_ERROR) && (WSAGetLastError() != WSA_IO_PENDING))
	{
		return false;
	}
	pSendIoContext->ResetBuffer();
	return true;
}

//����Ͷ��Send���󣬷�������Ϣ���֪ͨ��ɶ˿�
bool _PostSend(_PER_IO_CONTEXT* pSendIoContext)
{
	// ��ʼ������
	DWORD dwFlags = 0;
	DWORD dwBytes = 0;
	pSendIoContext->m_IoType = SEND;

	if ((WSASend(pSendIoContext->m_socket, &pSendIoContext->m_wsaBuf, 1, &dwBytes, dwFlags, &pSendIoContext->m_overlapped,
	             NULL) == SOCKET_ERROR) && (WSAGetLastError() != WSA_IO_PENDING))
	{
		//.RemoveContext(SendIoContext);
		return false;
	}
	pSendIoContext->ResetBuffer();
	return true;
}

//����Ͷ��Recv���󣬽����������֪ͨ��ɶ˿�
bool _PostRecv(_PER_IO_CONTEXT* pRecvIoContext)
{
	// ��ʼ������
	DWORD dwFlags = 0;
	DWORD dwBytes = 0;
	pRecvIoContext->m_IoType = RECV;
	WSABUF* p_wbuf = &pRecvIoContext->m_wsaBuf;
	OVERLAPPED* p_ol = &pRecvIoContext->m_overlapped;

	pRecvIoContext->ResetBuffer();

	int nBytesRecv = WSARecv(pRecvIoContext->m_socket, p_wbuf, 1, &dwBytes, &dwFlags, p_ol, NULL);

	// �������ֵ���󣬲��Ҵ���Ĵ��벢����Pending�Ļ����Ǿ�˵������ص�����ʧ����
	if (nBytesRecv == SOCKET_ERROR && (WSAGetLastError() != WSA_IO_PENDING))
	{
		if (WSAGetLastError() != 10054)
		{
			printf_s("Ͷ��һ��WSARecvʧ�ܣ�%d \n", WSAGetLastError());
		}
		return false;
	}
	return true;
}

//����Ͷ��Accept�����յ�һ�����������֪ͨ��ɶ˿�
bool _PostAccept(_PER_IO_CONTEXT* pAcceptIoContext)
{
	// ׼������
	DWORD dwBytes = 0;
	pAcceptIoContext->m_IoType = ACCEPT;
	WSABUF* p_wbuf = &pAcceptIoContext->m_wsaBuf;
	OVERLAPPED* p_ol = &pAcceptIoContext->m_overlapped;

	// Ϊ�Ժ�������Ŀͻ�����׼����Socket(׼���ýӴ��ͻ���ҵ��Ա����������ͳAccept�ֳ�newһ������)
	pAcceptIoContext->m_socket = WSASocket(AF_INET, SOCK_STREAM, 0, NULL, 0, WSA_FLAG_OVERLAPPED);
	if (pAcceptIoContext->m_socket == INVALID_SOCKET)
	{
		printf_s("��������Accept��Socketʧ�ܣ��������: %d", WSAGetLastError());
		return false;
	}

	// Ͷ��AcceptEx
	if (m_AcceptEx(g_ListenContext->m_Socket, pAcceptIoContext->m_socket, p_wbuf->buf, p_wbuf->len - ((sizeof(SOCKADDR_IN) + 16) * 2),
	               sizeof(SOCKADDR_IN) + 16, sizeof(SOCKADDR_IN) + 16, &dwBytes, p_ol) == FALSE)
	{
		if (WSAGetLastError() != WSA_IO_PENDING)
		{
			printf_s("Ͷ�� AcceptEx ����ʧ�ܣ��������: %d", WSAGetLastError());
			return false;
		}
	}
	return true;
}
