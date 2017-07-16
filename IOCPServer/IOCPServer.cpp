#include "stdafx.h"
#include "stdio.h"
#include "winsock2.h" 
#include "ws2tcpip.h" 
#include "mswsock.h"
#pragma comment(lib,"ws2_32.lib") 

#define MAX_DATA_LENGTH 4096

enum OPERATION_TYPE { ACCEPT, RECV, SEND, NONE };
enum NET_TYPE { Intranet,Extranet};

//��������ṹ�壬����Overlapped��������socket���������Լ�������������ͣ�accpet��received����send
struct PER_IO_CONTEXT
{
	OVERLAPPED     m_Overlapped;                               // ÿһ���ص�����������ص��ṹ(���ÿһ��Socket��ÿһ����������Ҫ��һ��           
	SOCKET         m_socket;                                     // ������������ʹ�õ�Socket
	WSABUF         m_wsaBuf;                                   // WSA���͵Ļ����������ڸ��ص�������������
	char           m_szBuffer[MAX_DATA_LENGTH];                           // �����WSABUF�������ַ��Ļ�����
	OPERATION_TYPE m_OpType;                                   // ��ʶ�������������(��Ӧ�����ö��)

															   // ��ʼ��
	PER_IO_CONTEXT()
	{
		ZeroMemory(&m_Overlapped, sizeof(m_Overlapped));
		ZeroMemory(m_szBuffer, MAX_DATA_LENGTH);
		m_socket = INVALID_SOCKET;
		m_wsaBuf.buf = m_szBuffer;
		m_wsaBuf.len = MAX_DATA_LENGTH;
		m_OpType = NONE;
	}

	// �ͷŵ�Socket
	void CLOSE()
	{
		if (m_socket != INVALID_SOCKET)
		{
			ZeroMemory(&m_Overlapped, sizeof(m_Overlapped));
			ZeroMemory(&m_szBuffer, MAX_DATA_LENGTH);
			m_wsaBuf.buf = m_szBuffer;
			m_wsaBuf.len = MAX_DATA_LENGTH;
			m_OpType = NONE;
		}
	}

	// ���û���������
	void Buffer()
	{
		ZeroMemory(m_szBuffer, MAX_DATA_LENGTH);
	}
};

struct PER_SOCKET_CONTEXT {
	SOCKET      m_Socket;                                  // ÿһ���ͻ������ӵ�Socket
	SOCKADDR_IN m_ClientAddr;                              // �ͻ��˵ĵ�ַ
	char m_username[40];

	//����һ����������ṹ������ľ��
	PER_IO_CONTEXT *ArrayIoContext[64];

	int num;

	PER_IO_CONTEXT* getARR(int i)
	{
		return ArrayIoContext[i];
	}

	PER_IO_CONTEXT* GetNewIoContext()
	{
		for (int i = 0; i < 64; i++)
		{
			//���ĳһ��IO_CONTEXT_ARRAY[i]Ϊ0����ʾ��һ��λ���Է���PER_IO_CONTEXT  
			if (ArrayIoContext[i] == NULL)
			{
				ArrayIoContext[i] = new PER_IO_CONTEXT();
				num++;
				return ArrayIoContext[i];
			}
		}
		return NULL;
	}

	// ���������Ƴ�һ��ָ����IoContext
	void DEL()
	{
		for (int i = 0; i < 64; i++)
		{
			if (ArrayIoContext[i] != 0)
			{
				ArrayIoContext[i]->CLOSE();
				ArrayIoContext[i] = 0;
				num--;
				if (num == 0) {
					break;
				}
			}
		}
	}

	// ���������Ƴ�һ��ָ����IoContext
	void RemoveContext(PER_IO_CONTEXT* pContext)
	{
		for (int i = 0; i < 64; i++)
		{
			if (ArrayIoContext[i] == pContext)
			{
				ArrayIoContext[i]->CLOSE();
				ArrayIoContext[i] = 0;
				num--;
				break;
			}
		}
	}

	PER_SOCKET_CONTEXT()
	{
		num = 0;
		m_Socket = INVALID_SOCKET;
		memset(&m_ClientAddr, 0, sizeof(m_ClientAddr));
		ZeroMemory(m_username, 40);
		for (int i = 0; i < 64; i++) {
			ArrayIoContext[i] = 0;
		}
	}

	// �ͷ���Դ
	~PER_SOCKET_CONTEXT()
	{
		if (m_Socket != INVALID_SOCKET)
		{
			DEL();
			closesocket(m_Socket);
			m_Socket = INVALID_SOCKET;
			memset(&m_ClientAddr, 0, sizeof(m_ClientAddr));
			ZeroMemory(m_username, 40);
		}
	}
};

//Socket�ṹ��������࣬��������Socket��Ͻṹ�����飬���Ը�������ɾ��
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
				strcpy_s(SOCKET_CONTEXT_ARR[num]->m_username, strlen(u) + 1, u);
				num++;
				return SOCKET_CONTEXT_ARR[i];
			}
		}
		return NULL;
	}

	PER_SOCKET_CONTEXT* getARR(int i)
	{
		return SOCKET_CONTEXT_ARR[i];
	}

	// ���������Ƴ�һ��ָ����IoContext
	void RemoveContext(PER_SOCKET_CONTEXT* S)
	{
		for (int i = 0; i < num; i++)
		{
			if (SOCKET_CONTEXT_ARR[i] == S)
			{
				SOCKET_CONTEXT_ARR[i]->~PER_SOCKET_CONTEXT();
				num--;
				break;
			}
		}
	}
};
//�û�������
char* username[3] = { "admin","root" ,"zz" };
//��������
char* password[3] = { "adminadmin","rootroot" ,"zzzz" };

//ͬʱͶ�ݵ�AcceptEx���������
#define MAX_POST_ACCEPT 10
//��ɽӿ�
HANDLE mIoCompletionPort;

//����һ��Socket�ṹ������ľ��
PER_SOCKET_CONTEXT_ARR ArraySocketContext;

//AcceptEx��GUID�����ڵ���AcceptEx����ָ��
GUID GuidAcceptEx = WSAID_ACCEPTEX;
//AcceptEx����ָ��
LPFN_ACCEPTEX mAcceptEx;
//AcceptExSockaddrs��GUID�����ڵ���AcceptExSockaddrs����ָ��
GUID GuidGetAcceptExSockAddrs = WSAID_GETACCEPTEXSOCKADDRS;
//AcceptExSockaddrs����ָ��
LPFN_GETACCEPTEXSOCKADDRS mAcceptExSockAddrs;

//����������Listen��Socket�ṹ��
PER_SOCKET_CONTEXT* tListenContext;
//����������Listen��Socket�ṹ��
PER_SOCKET_CONTEXT* uListenContext;

//����������ɶ˿ڲ������߳�
DWORD WINAPI workThread(LPVOID lpParam);
//����Ͷ��Send���󣬷�������Ϣ���֪ͨ��ɶ˿�
bool _PostSend(PER_IO_CONTEXT* pIoContext);
//����Ͷ��Recv���󣬽����������֪ͨ��ɶ˿�
bool _PostRecv(PER_IO_CONTEXT* pIoContext);
//����Ͷ��Accept�����յ�һ�����������֪ͨ��ɶ˿�
bool _PostAccept(PER_IO_CONTEXT* pAcceptIoContext);
//����Ͷ�ݽ������󣬷����������Ϣ��֪ͨ��ɶ˿�
bool _PostEnd(PER_IO_CONTEXT* pAcceptIoContext);

int main()
{
	WSADATA wsaData;
	if (NO_ERROR != WSAStartup(MAKEWORD(2, 2), &wsaData))
	{
		printf_s("��ʼ��Socket�� ʧ�ܣ�\n");
		return 1;
	}

	// ������ɶ˿�
	mIoCompletionPort = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
	if (mIoCompletionPort == NULL)
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
	tListenContext = new PER_SOCKET_CONTEXT;

	// ��Ҫʹ���ص�IO�������ʹ��WSASocket������Socket���ſ���֧���ص�IO����
	tListenContext->m_Socket = WSASocket(AF_INET, SOCK_STREAM, 0, NULL, 0, WSA_FLAG_OVERLAPPED);
	if (tListenContext->m_Socket == INVALID_SOCKET)
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
	ServerAddress.sin_port = htons(9999);

	// �󶨵�ַ�Ͷ˿�
	if (bind(tListenContext->m_Socket, (struct sockaddr *) &ServerAddress, sizeof(ServerAddress)) == SOCKET_ERROR)
	{
		printf_s("bind()����ִ�д���.\n");
		return 4;
	}

	// ��ʼ�����ListenContext�����socket���󶨵ĵ�ַ�˿ڽ��м���
	if (listen(tListenContext->m_Socket, SOMAXCONN) == SOCKET_ERROR)
	{
		printf_s("Listen()����ִ�г��ִ���.\n");
		return 5;
	}

	DWORD dwBytes = 0;
	//ʹ��WSAIoctl��ͨ��GuidAcceptEx(AcceptEx��GUID)����ȡAcceptEx����ָ��
	if (SOCKET_ERROR == WSAIoctl(
		tListenContext->m_Socket,
		SIO_GET_EXTENSION_FUNCTION_POINTER,
		&GuidAcceptEx,
		sizeof(GuidAcceptEx),
		&mAcceptEx,
		sizeof(mAcceptEx),
		&dwBytes,
		NULL,
		NULL))
	{
		printf_s("WSAIoctl δ�ܻ�ȡAcceptEx����ָ�롣�������: %d\n", WSAGetLastError());
		return 6;
	}

	//ʹ��WSAIoctl��ͨ��GuidGetAcceptExSockAddrs(AcceptExSockaddrs��GUID)����ȡAcceptExSockaddrs����ָ��
	if (SOCKET_ERROR == WSAIoctl(
		tListenContext->m_Socket,
		SIO_GET_EXTENSION_FUNCTION_POINTER,
		&GuidGetAcceptExSockAddrs,
		sizeof(GuidGetAcceptExSockAddrs),
		&mAcceptExSockAddrs,
		sizeof(mAcceptExSockAddrs),
		&dwBytes,
		NULL,
		NULL))
	{
		printf_s("WSAIoctl δ�ܻ�ȡGuidGetAcceptExSockAddrs����ָ�롣�������: %d\n", WSAGetLastError());
		return 7;
	}

	//�������ListenSocket�ṹ��ŵ���ɶ˿��У��н�������ң���������ListenContext����ȥ
	if ((CreateIoCompletionPort((HANDLE)tListenContext->m_Socket, mIoCompletionPort, (DWORD)tListenContext, 0) == NULL))
	{
		printf_s("�󶨷����SocketContext����ɶ˿�ʧ�ܣ��������: %d/n", WSAGetLastError());
		if (tListenContext->m_Socket != INVALID_SOCKET)
		{
			closesocket(tListenContext->m_Socket);
			tListenContext->m_Socket = INVALID_SOCKET;
		}
		return 3;
	}
	else
	{
		printf_s("Listen Socket����ɶ˿� ���.\n");
	}

	

	//ѭ��10��
	for (int i = 0; i < MAX_POST_ACCEPT; i++)
	{
		//ͨ����������ṹ��������һ���µ���������ṹ��
		PER_IO_CONTEXT* newAcceptIoContext = tListenContext->GetNewIoContext();
		//Ͷ��Send���󣬷�������Ϣ���֪ͨ��ɶ˿ڣ�
		if (_PostAccept(newAcceptIoContext) == false)
		{
			tListenContext->RemoveContext(newAcceptIoContext);
			return false;
		}
	}
	printf_s("Ͷ�� %d ��AcceptEx������� \n", MAX_POST_ACCEPT);

	printf_s("INFO:��������������......\n");

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
	OVERLAPPED           *pOverlapped = NULL;
	//���������ɺ���յ�Socket�ṹ�壬��һ����ListenSocket�Ľṹ��
	PER_SOCKET_CONTEXT   *pListenContext = NULL;
	//���������ɺ���յ��ֽ��� 
	DWORD                dwBytesTransfered = 0;

	// ѭ����������
	while (true)
	{
		BOOL bReturn = GetQueuedCompletionStatus(
			mIoCompletionPort,//����������ǽ������Ǹ�Ψһ����ɶ˿�  
			&dwBytesTransfered,//����ǲ�����ɺ󷵻ص��ֽ��� 
			(PULONG_PTR)&pListenContext,//��������ǽ�����ɶ˿ڵ�ʱ��󶨵��Ǹ�sockt�ṹ��
			&pOverlapped,//���������������Socket��ʱ��һ�������Ǹ��ص��ṹ  
			INFINITE);//�ȴ���ɶ˿ڵĳ�ʱʱ�䣬����̲߳���Ҫ�����������飬�Ǿ�INFINITE

					  //ͨ�����Overlapped���õ������������������ṹ��
		PER_IO_CONTEXT* pIoContext = CONTAINING_RECORD(pOverlapped, PER_IO_CONTEXT, m_Overlapped);

		// �ж��Ƿ��пͻ��˶Ͽ���
		if (!bReturn)
		{
			DWORD dwErr = GetLastError();
			//�������64���ͻ���closesocket
			if (dwErr == 64) {
				char IPAddr[20];
				inet_ntop(AF_INET, &pListenContext->m_ClientAddr.sin_addr, IPAddr, 16);
				printf_s("�ͻ��� %s:%d �Ͽ����ӣ�\n", IPAddr, ntohs(pListenContext->m_ClientAddr.sin_port));
				ArraySocketContext.RemoveContext(pListenContext);
			}
			else {
				printf_s("�ͻ����쳣�Ͽ� %d", dwErr);
			}
			continue;
		}
		else
		{
			//�ж�����������������
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

				char IPAddr[16];
				inet_ntop(AF_INET, &ClientAddr->sin_addr, IPAddr, 16);
				printf_s("�ͻ��� %s:%d ����.\n", IPAddr, ntohs(ClientAddr->sin_port));

				//���յ��û���
				char *input_username = new char[40];
				//���յ�����
				char *input_password = new char[40];

				//�����ַ���Ϊ �û���#���� �Ľṹ����Ҫstrtok_s�ָ
				input_username = strtok_s(pIoContext->m_wsaBuf.buf, "#", &input_password);

				//�������ӿͻ��˵��û���
				char *user = new char[40];
				strcpy_s(user, strlen(input_username) + 1, input_username);

				//�Ƿ��½�ɹ�
				bool ok = false;

				if (strlen(input_username) > 0 && strlen(input_password) > 0)
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
					char IPAddr[20];
					inet_ntop(AF_INET, &ClientAddr->sin_addr, IPAddr, 16);
					printf_s("�ͻ��� %s(%s:%d) ��½�ɹ���\n", user, IPAddr, ntohs(ClientAddr->sin_port));
					strcpy_s(pIoContext->m_wsaBuf.buf, 11, "��½�ɹ���");
				}
				else {
					char IPAddr[20];
					inet_ntop(AF_INET, &ClientAddr->sin_addr, IPAddr, 16);
					printf_s("�ͻ��� %s(%s:%d) ��½ʧ�ܣ�\n", user, IPAddr, ntohs(ClientAddr->sin_port));
					strcpy_s(pIoContext->m_wsaBuf.buf, 11, "��½ʧ�ܣ�");
				}

				//�����Ƿ��½�ɹ�����Ҫ����һ��������ͻ��� ��½�ɹ� or ��½ʧ��
				//ͨ��Socket�ṹ������õ�һ���µ�Socket�ṹ�壬�����û���Ϣ�����ȥ
				PER_SOCKET_CONTEXT* newSocketContext = ArraySocketContext.GetNewSocketContext(ClientAddr, user);
				//��Socket�ṹ�屣�浽Socket�ṹ���������»�õ�Socket�ṹ����
				newSocketContext->m_Socket = pIoContext->m_socket;
				//���ͻ��˵ĵ�ַ���浽Socket�ṹ���������»�õ�Socket�ṹ����
				memcpy(&(newSocketContext->m_ClientAddr), ClientAddr, sizeof(SOCKADDR_IN));

				//������µõ���Socket�ṹ��ŵ���ɶ˿��У��н��������
				HANDLE hTemp = CreateIoCompletionPort((HANDLE)newSocketContext->m_Socket, mIoCompletionPort, (DWORD)newSocketContext, 0);
				if (NULL == hTemp)
				{
					printf_s("ִ��CreateIoCompletionPort���ִ���.�������: %d \n", GetLastError());
					break;
				}
				//������µõ���Socket�ṹ���һ��PostSend���������ͻ����Ƿ��½�ɹ��Ľ�����ͻ�ȥ�����Ͳ�����ɣ�֪ͨ��ɶ˿�
				PER_IO_CONTEXT* pNewSendIoContext = newSocketContext->GetNewIoContext();
				memcpy(&(pNewSendIoContext->m_wsaBuf.buf), &pIoContext->m_wsaBuf.buf, sizeof(pIoContext->m_wsaBuf.len));
				pNewSendIoContext->m_socket = newSocketContext->m_Socket;

				//�鿴�Ƿ��½�ɹ�
				if (ok) {
					_PostSend(pNewSendIoContext);
					//������µõ���Socket�ṹ���һ��PostRevc���������ͻ����Ƿ��½�ɹ��Ľ�����ͻ�ȥ�����Ͳ�����ɣ�֪ͨ��ɶ˿�
					PER_IO_CONTEXT* pNewRecvIoContext = newSocketContext->GetNewIoContext();
					pNewRecvIoContext->m_socket = newSocketContext->m_Socket;

					if (!_PostRecv(pNewRecvIoContext))
					{
						newSocketContext->RemoveContext(pNewRecvIoContext);
					}
				}
				else {
					_PostEnd(pNewSendIoContext);
				}
				//��֮ǰ��Accept����������ṹ������buffer���ø������������Accept
				pIoContext->Buffer();
				_PostAccept(pIoContext);
			}
			break;
			case RECV:
			{
				//ִ��recv�󣬽��н������ݵĴ���������Ŀͻ��ˣ�����recv
				if (dwBytesTransfered > 1) {
					char *Senddata = new char[MAX_DATA_LENGTH];
					ZeroMemory(Senddata, MAX_DATA_LENGTH);

					char *temp = new char[MAX_DATA_LENGTH];
					ZeroMemory(temp, MAX_DATA_LENGTH);

					char *sendname = new char[40];
					ZeroMemory(sendname, 40);
					if (pIoContext->m_wsaBuf.buf[0] == '\\') {
						sendname = strtok_s(pIoContext->m_wsaBuf.buf, "\\", &temp);
						strtok_s(sendname, " ", &temp);
						if (temp != NULL) {
							char IPAddr[20];
							inet_ntop(AF_INET, &pListenContext->m_ClientAddr.sin_addr, IPAddr, 16);
							printf_s("�ͻ��� %s(%s:%d) �� %s ����:%s\n", pListenContext->m_username, IPAddr, ntohs(pListenContext->m_ClientAddr.sin_port), sendname, temp);
							sprintf_s(Senddata, MAX_DATA_LENGTH, "%s(%s:%d)���㷢��:\n%s", pListenContext->m_username, IPAddr, ntohs(pListenContext->m_ClientAddr.sin_port), temp);
						}
					}
					else {
						char IPAddr[20];
						inet_ntop(AF_INET, &pListenContext->m_ClientAddr.sin_addr, IPAddr, 16);
						printf_s("�ͻ��� %s(%s:%d) ���ҷ���:%s\n", pListenContext->m_username, IPAddr, ntohs(pListenContext->m_ClientAddr.sin_port), pIoContext->m_szBuffer);
						sprintf_s(Senddata, MAX_DATA_LENGTH, "%s(%s:%d)���ҷ���:\n%s", pListenContext->m_username, IPAddr, ntohs(pListenContext->m_ClientAddr.sin_port), pIoContext->m_szBuffer);
					}
					for (int i = 0; i < ArraySocketContext.num; i++)
					{
						PER_SOCKET_CONTEXT* cSocketContext = ArraySocketContext.getARR(i);
						if (cSocketContext->m_Socket == pListenContext->m_Socket) {
							continue;
						}
						//�ж��Ƿ��ǵ��Ե���Ϣ
						if (strlen(sendname) > 0 && !strcmp(sendname, cSocketContext->m_username) && strlen(Senddata) > 0) {
							// ������ͻ���SocketContext��һ��Recv�ļƻ�
							PER_IO_CONTEXT* pNewSendIoContext = cSocketContext->GetNewIoContext();
							memcpy(&(pNewSendIoContext->m_wsaBuf.buf), &Senddata, sizeof(Senddata));
							pNewSendIoContext->m_socket = cSocketContext->m_Socket;
							// SendͶ�ݳ�ȥ
							_PostSend(pNewSendIoContext);
						}//�ж��Ƿ��ǵ��Ե���Ϣ������Ϣ�г���
						else if (strlen(sendname) == 0 && strlen(Senddata) > 0) {
							// ������ͻ���SocketContext��һ��Recv�ļƻ�
							PER_IO_CONTEXT* pNewSendIoContext = cSocketContext->GetNewIoContext();
							memcpy((pNewSendIoContext->m_szBuffer), Senddata, strlen(Senddata) + 1);
							pNewSendIoContext->m_socket = cSocketContext->m_Socket;
							// SendͶ�ݳ�ȥ
							_PostSend(pNewSendIoContext);
						}
					}
				}
				pIoContext->Buffer();
				_PostRecv(pIoContext);
			}
			break;
			case SEND:
				//��������Ϣ�󣬽�������������Ľṹ��ɾ��
				pListenContext->RemoveContext(pIoContext);
				break;
			case NONE:
				//��������Ϣ�󣬽�������������Ľṹ��ɾ��
				ArraySocketContext.RemoveContext(pListenContext);
				break;
			default:
				// ��Ӧ��ִ�е�����
				printf_s("_WorkThread�е� pIoContext->m_OpType �����쳣.\n");
				break;
			} //switch
		}
	}
	printf_s("�߳��˳�.\n");
	return 0;
}

//����Ͷ��Send���󣬷�������Ϣ���֪ͨ��ɶ˿�
bool _PostEnd(PER_IO_CONTEXT* SendIoContext)
{
	// ��ʼ������
	DWORD dwFlags = 0;
	DWORD dwBytes = 0;
	SendIoContext->m_OpType = NONE;

	if ((WSASend(SendIoContext->m_socket, &SendIoContext->m_wsaBuf, 1, &dwBytes, dwFlags, &SendIoContext->m_Overlapped,
		NULL) == SOCKET_ERROR) && (WSAGetLastError() != WSA_IO_PENDING))
	{
		//.RemoveContext(SendIoContext);
		return false;
	}
	SendIoContext->Buffer();
	return true;
}

//����Ͷ��Send���󣬷�������Ϣ���֪ͨ��ɶ˿�
bool _PostSend(PER_IO_CONTEXT* SendIoContext)
{
	// ��ʼ������
	DWORD dwFlags = 0;
	DWORD dwBytes = 0;
	SendIoContext->m_OpType = SEND;

	if ((WSASend(SendIoContext->m_socket, &SendIoContext->m_wsaBuf, 1, &dwBytes, dwFlags, &SendIoContext->m_Overlapped,
		NULL) == SOCKET_ERROR) && (WSAGetLastError() != WSA_IO_PENDING))
	{
		//.RemoveContext(SendIoContext);
		return false;
	}
	SendIoContext->Buffer();
	return true;
}

//����Ͷ��Recv���󣬽����������֪ͨ��ɶ˿�
bool _PostRecv(PER_IO_CONTEXT* RecvIoContext)
{
	// ��ʼ������
	DWORD dwFlags = 0;
	DWORD dwBytes = 0;
	RecvIoContext->m_OpType = RECV;
	WSABUF *p_wbuf = &RecvIoContext->m_wsaBuf;
	OVERLAPPED *p_ol = &RecvIoContext->m_Overlapped;

	RecvIoContext->Buffer();

	int nBytesRecv = WSARecv(RecvIoContext->m_socket, p_wbuf, 1, &dwBytes, &dwFlags, p_ol, NULL);

	// �������ֵ���󣬲��Ҵ���Ĵ��벢����Pending�Ļ����Ǿ�˵������ص�����ʧ����
	if (nBytesRecv == SOCKET_ERROR && (WSAGetLastError() != WSA_IO_PENDING))
	{
		if (WSAGetLastError() != 10054) {
			printf_s("Ͷ��һ��WSARecvʧ�ܣ�%d \n", WSAGetLastError());
		}
		return false;
	}
	return true;
}

//����Ͷ��Accept�����յ�һ�����������֪ͨ��ɶ˿�
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
		printf_s("��������Accept��Socketʧ�ܣ��������: %d", WSAGetLastError());
		return false;
	}

	// Ͷ��AcceptEx
	if (mAcceptEx(tListenContext->m_Socket, AcceptIoContext->m_socket, p_wbuf->buf, p_wbuf->len - ((sizeof(SOCKADDR_IN) + 16) * 2),
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