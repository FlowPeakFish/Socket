#include "stdafx.h"
#include "stdio.h"
#include "winsock2.h"
#include "ws2tcpip.h"
#include "mswsock.h"
#pragma comment(lib,"ws2_32.lib")

#define c_LISTEN_PORT 8601
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

//���û���
class SocketUnit
{
public:
	volatile int m_sharedCount; //���ü���
	SOCKET m_Socket;

	//��ʼ��
	SocketUnit()
	{
		m_Socket = WSASocket(AF_INET, SOCK_STREAM, 0, NULL, 0, WSA_FLAG_OVERLAPPED);
		m_sharedCount = 0;
	}

	//���һ����Socket���������ü�����һ
	SOCKET* Get()
	{
		m_sharedCount++;
		return &m_Socket;
	}

	//�ͷ�һ����Socket�������ü�����һ����Ϊ��ʱ���ر�Socket����
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
	volatile int num; //����
public:
	SocketUnit* array_socket_unit[c_SOCKET_CONTEXT];

	// ��ʼ��
	SocketUnitPool() : num(c_SOCKET_CONTEXT)
	{
		for (int i = 0; i < c_SOCKET_CONTEXT; ++i)
		{
			array_socket_unit[i] = new SocketUnit();
		}
	}

	// ���һ��Socket
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

//����������ͣ�����Overlapped��������socket���������Լ�������������ͣ�accpet��received����send
class _PER_IO_CONTEXT
{
public:
	SocketUnit* m_SocketUnit;
	SOCKET* m_Socket; // ������������ʹ�õ�Socket
	OVERLAPPED m_overlapped; // ÿһ���ص�����������ص��ṹ(���ÿһ��Socket��ÿһ����������Ҫ��һ��   
	WSABUF m_wsaBuf; // WSA���͵Ļ����������ڸ��ص�������������
	char* m_szBuffer; // �����WSABUF�������ַ��Ļ�����
	enumIoType m_IoType; // ��ʶ�������������(��Ӧ�����ö��)

	_PER_IO_CONTEXT* pPreIoContext; //ָ����һ���������
	_PER_IO_CONTEXT* pNextIoContext; //ָ����һ���������

	//����Socket���û���������������
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
	SOCKET* m_Socket; // ÿһ���ͻ������ӵ�Socket
	SOCKADDR_IN m_ClientAddr; // �ͻ��˵ĵ�ַ
	char m_username[40];
	volatile int m_timer; //������Ӧ����

	_PER_SOCKET_CONTEXT* pPreSocketContext;
	_PER_SOCKET_CONTEXT* pNextSocketContext;

	//����һ���ӳ��л�õ�Socket���û��࣬���г�ʼ��
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

	//��������������ͣ���ʼ��һ���������
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

	// �ͷ���Դ
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

	//������ʱ����
	void UpTimer()
	{
		m_timer++;
	}

	//������ʱ����
	void ResetTimer()
	{
		m_timer = 0;
	}
};

//Socket�ṹ��������࣬��������Socket��Ͻṹ�����飬���Ը�������ɾ��
class ARRAY_PER_SOCKET_CONTEXT
{
private:
	_PER_SOCKET_CONTEXT* HeadSocketContext;
public:
	volatile int num;

	//�ӳ��л�ȡһ��socket��ʼ��һ��socketcontext����ͷ���
	ARRAY_PER_SOCKET_CONTEXT() : num(0)
	{
		SocketUnit* p = g_poolSocket->GetSocketUnit();
		HeadSocketContext = new _PER_SOCKET_CONTEXT(p);
	}

	//��������ͻ���/��������ֺ͵�ַ����ʼ��һ��socketcontext����
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

	//����name����socketcontext������
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

	//�����з�����socket��ʱ������һ������2ʱ����ʾ����
	void UpTimer()
	{
		_PER_SOCKET_CONTEXT* temp = HeadSocketContext;
		while (temp->pNextSocketContext)
		{
			temp = temp->pNextSocketContext;
			temp->UpTimer();
			if (temp->m_timer > 2)
			{
				printf("���������ӳ�ʱ...\n");
				num--;
				temp->CloseSocketContext();
			}
		}
	}

	//�鿴�Ƿ����ӷ�����
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

//�û�������
char* g_saUsername[3] = {"admin","root" ,"zz"};
//��������
char* g_saPassword[3] = {"adminadmin","rootroot" ,"zzzz"};


//��ɽӿ�
HANDLE g_hIoCompletionPort;

//����һ��Socket�ṹ������ľ��
ARRAY_PER_SOCKET_CONTEXT* m_arraySocketContext;

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
DWORD WINAPI StartHeartBeat(LPVOID lpParam);
//����Ͷ��Send���󣬷�������Ϣ���֪ͨ��ɶ˿�
bool _PostSend(_PER_IO_CONTEXT* pSendIoContext);
//����Ͷ��Recv���󣬽����������֪ͨ��ɶ˿�
bool _PostRecv(_PER_IO_CONTEXT* pRecvIoContext);
//����Ͷ��Accept�����յ�һ�����������֪ͨ��ɶ˿�
bool _PostAccept(_PER_IO_CONTEXT* pAcceptIoContext);

int main()
{
	WSADATA wsaData;
	if (NO_ERROR != WSAStartup(MAKEWORD(2, 2), &wsaData))
	{
		printf_s("��ʼ��Socket�� ʧ�ܣ�\n");
		return 1;
	}

	g_poolSocket = new SocketUnitPool();
	m_arraySocketContext = new ARRAY_PER_SOCKET_CONTEXT();

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
	g_ListenContext = new _PER_SOCKET_CONTEXT(g_poolSocket->GetSocketUnit());

	// ��Ҫʹ���ص�IO�������ʹ��WSASocket������Socket���ſ���֧���ص�IO����
	if (*g_ListenContext->m_Socket == INVALID_SOCKET)
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
	if (bind(*g_ListenContext->m_Socket, (LPSOCKADDR)&ServerAddress, sizeof(ServerAddress)) == SOCKET_ERROR)
	{
		printf_s("bind()����ִ�д���.\n");
		return 3;
	}

	// ��ʼ�����ListenContext�����socket���󶨵ĵ�ַ�˿ڽ��м���
	if (listen(*g_ListenContext->m_Socket, SOMAXCONN) == SOCKET_ERROR)
	{
		printf_s("Listen()����ִ�г��ִ���.\n");
		return 4;
	}

	DWORD dwBytes = 0;
	//ʹ��WSAIoctl��ͨ��GuidAcceptEx(AcceptEx��GUID)����ȡAcceptEx����ָ��
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
		printf_s("WSAIoctl δ�ܻ�ȡAcceptEx����ָ�롣�������: %d\n", WSAGetLastError());
		return 5;
	}

	//ʹ��WSAIoctl��ͨ��GuidGetAcceptExSockAddrs(AcceptExSockaddrs��GUID)����ȡAcceptExSockaddrs����ָ��
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
		printf_s("WSAIoctl δ�ܻ�ȡGuidGetAcceptExSockAddrs����ָ�롣�������: %d\n", WSAGetLastError());
		return 6;
	}

	//�������ListenSocket�ṹ��ŵ���ɶ˿��У��н�������ң���������ListenContext����ȥ
	if ((CreateIoCompletionPort((HANDLE)*g_ListenContext->m_Socket, g_hIoCompletionPort, (DWORD)g_ListenContext, 0) == NULL))
	{
		printf_s("�󶨷����SocketContext����ɶ˿�ʧ�ܣ��������: %d/n", WSAGetLastError());
		if (*g_ListenContext->m_Socket != INVALID_SOCKET)
		{
			closesocket(*g_ListenContext->m_Socket);
			*g_ListenContext->m_Socket = INVALID_SOCKET;
		}
		return 7;
	}
	printf_s("Listen Socket����ɶ˿� ���.\n");

	//ѭ��10��
	for (int i = 0; i < c_MAX_POST_ACCEPT; i++)
	{
		//ͨ����������ṹ��������һ���µ���������ṹ��
		_PER_IO_CONTEXT* newAcceptIoContext = g_ListenContext->GetNewIoContext(ACCEPT);
		//Ͷ��Send���󣬷�������Ϣ���֪ͨ��ɶ˿ڣ�
		if (_PostAccept(newAcceptIoContext) == false)
		{
			newAcceptIoContext->CloseIoContext();
			return 8;
		}
	}
	printf_s("Ͷ�� %d ��AcceptEx������� \n", c_MAX_POST_ACCEPT);

	CreateThread(0, 0, StartHeartBeat, NULL, 0, NULL);

	printf_s("��½��������������......\n");

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
	_PER_SOCKET_CONTEXT* pSocketContext = NULL;
	//���������ɺ���յ��ֽ��� 
	DWORD dwBytesTransfered = 0;

	bool run = true;
	// ѭ����������
	while (run)
	{
		BOOL bReturn = GetQueuedCompletionStatus(
			g_hIoCompletionPort,//����������ǽ������Ǹ�Ψһ����ɶ˿�  
			&dwBytesTransfered,//����ǲ�����ɺ󷵻ص��ֽ��� 
			(PULONG_PTR)&pSocketContext,//��������ǽ�����ɶ˿ڵ�ʱ��󶨵��Ǹ�sockt�ṹ��
			&pOverlapped,//���������������Socket��ʱ��һ�������Ǹ��ص��ṹ  
			INFINITE);//�ȴ���ɶ˿ڵĳ�ʱʱ�䣬����̲߳���Ҫ�����������飬�Ǿ�INFINITE

		//ͨ�����Overlapped���õ������������������ṹ��
		_PER_IO_CONTEXT* pIoContext = CONTAINING_RECORD(pOverlapped, _PER_IO_CONTEXT, m_overlapped);

		char IPAddr[16];
		inet_ntop(AF_INET, &pSocketContext->m_ClientAddr.sin_addr, IPAddr, 16);
		// �ж��Ƿ��пͻ��˶Ͽ���
		if (!bReturn)
		{
			DWORD dwErr = GetLastError();
			//�������64���ͻ���closesocket
			if (dwErr == 64)
			{
				printf_s("%s:%d �Ͽ����ӣ�\n", IPAddr, ntohs(pSocketContext->m_ClientAddr.sin_port));
				pSocketContext->CloseSocketContext();
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
					printf_s("%s:%d ����.\n", IPAddr, ntohs(pClientAddr->sin_port));

					char* data = new char[40];

					char* type = strtok_s(pIoContext->m_wsaBuf.buf, "|", &data);

					_PER_SOCKET_CONTEXT* pNewClientSocketContext = m_arraySocketContext->GetNewSocketContext(*pClientAddr, type);
					//��Socket�ṹ�屣�浽Socket�ṹ���������»�õ�Socket�ṹ����
					pNewClientSocketContext->m_SocketUnit = pIoContext->m_SocketUnit;
					pNewClientSocketContext->m_Socket = pNewClientSocketContext->m_SocketUnit->Get();
					//������µõ���Socket�ṹ��ŵ���ɶ˿��У��н��������
					HANDLE hTemp = CreateIoCompletionPort((HANDLE)*pNewClientSocketContext->m_Socket, g_hIoCompletionPort, (DWORD)pNewClientSocketContext, 0);
					if (NULL == hTemp)
					{
						printf_s("ִ��CreateIoCompletionPort���ִ���.�������: %d \n", GetLastError());
						break;
					}


					switch (type[0])
					{
					case 'G':
						{//������µõ���Socket�ṹ���һ��PostSend���������ͻ����Ƿ��½�ɹ��Ľ�����ͻ�ȥ�����Ͳ�����ɣ�֪ͨ��ɶ˿�
							_PER_IO_CONTEXT* pNewSendIoContext = pNewClientSocketContext->GetNewIoContext(SEND);
							printf_s("%s������(%s:%d)���ӳɹ���\n", type, IPAddr, ntohs(pClientAddr->sin_port));
							strcpy_s(pNewSendIoContext->m_szBuffer, 10, "00|�ɹ���");
							pNewSendIoContext->m_wsaBuf.len = 10;
							_PostSend(pNewSendIoContext);

							//������µõ���Socket�ṹ���һ��PostRevc���������ͻ����Ƿ��½�ɹ��Ľ�����ͻ�ȥ�����Ͳ�����ɣ�֪ͨ��ɶ˿�
							_PER_IO_CONTEXT* pNewClientRecvIoContext = pNewClientSocketContext->GetNewIoContext(RECV);
							if (!_PostRecv(pNewClientRecvIoContext))
							{
								pNewClientRecvIoContext->CloseIoContext();
							}
						}
						break;
					default:
						{
							_PER_IO_CONTEXT* pClientSendIoContext = pNewClientSocketContext->GetNewIoContext(NONE);
							printf_s("δ֪������(%s:%d)���ӳɹ�����ʧ�ܣ�\n", IPAddr, ntohs(pClientAddr->sin_port));
							strcpy_s(pClientSendIoContext->m_szBuffer, 10, "00|ʧ�ܣ�");
							pClientSendIoContext->m_wsaBuf.len = 10;
							_PostSend(pClientSendIoContext);
						}
						break;
					}
					_PostAccept(pIoContext);
				}
				break;
			case RECV:
				{
					char* data = new char[40];
					char* userid = strtok_s(pIoContext->m_wsaBuf.buf, "|", &data);
					//���յ�����
					char* input_password = new char[40];
					//�����ַ���Ϊ �û���#���� �Ľṹ����Ҫstrtok_s�ָ
					char* input_username = strtok_s(data, "#", &input_password);

					//�Ƿ��½�ɹ�
					bool ok = false;

					if (strlen(input_username) > 0 && strlen(input_password) > 0)
					{
						//�����˺��Ƿ����
						for (int i = 0; i < sizeof(g_saUsername) / sizeof(g_saUsername[0]); i++)
						{
							int j;
							for (j = 0; g_saUsername[i][j] == input_username[j] && input_username[j]; j++);
							if (g_saUsername[i][j] == input_username[j] && input_username[j] == 0)
							{
								//�˺Ŵ��ڲ��������Ƿ���ȷ
								int k;
								for (k = 0; g_saPassword[i][k] == input_password[k] && input_password[k]; k++);
								if (g_saPassword[i][k] == input_password[k] && input_password[k] == 0)
								{
									ok = true;
								}
								break;
							}
						}
					}

					//������µõ���Socket�ṹ���һ��PostSend���������ͻ����Ƿ��½�ɹ��Ľ�����ͻ�ȥ�����Ͳ�����ɣ�֪ͨ��ɶ˿�
					_PER_IO_CONTEXT* pClientSendIoContext = pSocketContext->GetNewIoContext(SEND);

					char* Senddata = new char[c_MAX_DATA_LENGTH];
					ZeroMemory(Senddata, c_MAX_DATA_LENGTH);
					if (ok)
					{
						printf_s("�ͻ���%s��½�ɹ���\n", userid);
						sprintf_s(Senddata, c_MAX_DATA_LENGTH, "12|%s|%s", userid, "��½�ɹ���");
					}
					else
					{
						printf_s("�ͻ���%s��½ʧ�ܣ�\n", userid);
						sprintf_s(Senddata, c_MAX_DATA_LENGTH, "12|%s|%s", userid, "��½ʧ�ܣ�");
					}
					strcpy_s(pClientSendIoContext->m_szBuffer, strlen(Senddata) + 1, Senddata);
					pClientSendIoContext->m_wsaBuf.len = strlen(Senddata) + 1;
					_PostSend(pClientSendIoContext);

					_PostRecv(pIoContext);
				}
				break;
			case SEND:
				//��������Ϣ�󣬽�������������Ľṹ��ɾ��
				pIoContext->CloseIoContext();
				break;
			case NONE:
				pSocketContext->CloseSocketContext();
				break;
			default:
				// ��Ӧ��ִ�е�����
				printf_s("_WorkThread�е� pIoContext->IoType �����쳣.\n");
				run = false;
				break;
			} //switch
		}
	}
	printf_s("�߳��˳�.\n");
	return 0;
}

DWORD WINAPI StartHeartBeat(LPVOID lpParam)
{
	sockaddr_in ServerAddress;
	WSADATA wsdata;

	WSAStartup(MAKEWORD(2, 2), &wsdata);
	SOCKET sock = WSASocket(AF_INET, SOCK_DGRAM, 0, NULL, 0, WSA_FLAG_OVERLAPPED);
	//Ȼ��ֵ����ַ�������������ϵĹ㲥��ַ������Ϣ��  
	ServerAddress.sin_family = AF_INET;
	ServerAddress.sin_addr.s_addr = INADDR_BROADCAST;
	ServerAddress.sin_port = htons(9000);
	bool opt = true;
	//���ø��׽���Ϊ�㲥���ͣ�  
	setsockopt(sock, SOL_SOCKET, SO_BROADCAST, (char FAR *)&opt, sizeof(opt));
	char smsg[256];
	sprintf_s(smsg, 256, "LOGIN#%d", c_LISTEN_PORT);
	while (true)
	{
		int ret = sendto(sock, smsg, 256, 0, (sockaddr*)&ServerAddress, sizeof(ServerAddress));
		if (ret == SOCKET_ERROR)
		{
			printf("%d \n", WSAGetLastError());
		}
		Sleep(2000);
	}
}

//����Ͷ��Send���󣬷�������Ϣ���֪ͨ��ɶ˿�
bool _PostSend(_PER_IO_CONTEXT* pSendIoContext)
{
	// ��ʼ������
	DWORD dwFlags = 0;
	DWORD dwBytes = 0;

	if ((WSASend(*pSendIoContext->m_Socket, &pSendIoContext->m_wsaBuf, 1, &dwBytes, dwFlags, &pSendIoContext->m_overlapped,
	             NULL) == SOCKET_ERROR) && (WSAGetLastError() != WSA_IO_PENDING))
	{
		printf_s("Ͷ��һ��WSASendʧ�ܣ�%d \n", WSAGetLastError());
		return false;
	}
	return true;
}

//����Ͷ��Recv���󣬽����������֪ͨ��ɶ˿�
bool _PostRecv(_PER_IO_CONTEXT* pRecvIoContext)
{
	// ��ʼ������
	DWORD dwFlags = 0;
	DWORD dwBytes = 0;
	WSABUF* p_wbuf = &pRecvIoContext->m_wsaBuf;
	OVERLAPPED* p_ol = &pRecvIoContext->m_overlapped;

	int nBytesRecv = WSARecv(*pRecvIoContext->m_Socket, p_wbuf, 1, &dwBytes, &dwFlags, p_ol, NULL);

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
	WSABUF* p_wbuf = &pAcceptIoContext->m_wsaBuf;
	OVERLAPPED* p_ol = &pAcceptIoContext->m_overlapped;

	// Ϊ�Ժ�������Ŀͻ�����׼����Socket(׼���ýӴ��ͻ���ҵ��Ա����������ͳAccept�ֳ�newһ������
	pAcceptIoContext->m_SocketUnit->Release();
	pAcceptIoContext->m_SocketUnit = g_poolSocket->GetSocketUnit();
	pAcceptIoContext->m_Socket = pAcceptIoContext->m_SocketUnit->Get();
	if (*pAcceptIoContext->m_Socket == INVALID_SOCKET)
	{
		printf_s("��������Accept��Socketʧ�ܣ��������: %d", WSAGetLastError());
		return false;
	}

	// Ͷ��AcceptEx
	if (m_AcceptEx(*g_ListenContext->m_Socket, *pAcceptIoContext->m_Socket, p_wbuf->buf, p_wbuf->len - ((sizeof(SOCKADDR_IN) + 16) * 2),
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
