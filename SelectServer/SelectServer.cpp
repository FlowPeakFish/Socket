#include "stdafx.h"
#include "stdio.h"
#include "winsock2.h" 
#pragma comment(lib,"ws2_32.lib")

//�û�������
char *username[] = { "admin","root" };
//��������
char *password[] = { "adminadmin","rootroot" };

class SocketList
{
private:
	int num;//��¼socket����ʵ��Ŀ  
	SOCKET socketArray[FD_SETSIZE];//���socket������  

public:
	SOCKET getSocket(int i)
	{
		return socketArray[i];
	}

	//���캯���ж�������Ա�������г�ʼ��  
	SocketList()
	{
		num = 0;
		for (int i = 0; i < FD_SETSIZE; i++)
		{
			//��Ϊsocket��ֵ��һ���Ǹ�����ֵ�����Կ��Խ�socketArray��ʼ��Ϊ0����������ʾ�����е���һ��Ԫ����û�б�ʹ��  
			socketArray[i] = 0;
		}
	}

	//��socketArray�����һ��socket  
	void addSocket(SOCKET s)
	{
		for (int i = 0; i < FD_SETSIZE; i++)
		{
			//���ĳһ��socketArray[i]Ϊ0����ʾ��һ��λ���Է���socket  
			if (socketArray[i] == 0)
			{
				socketArray[i] = s;
				num++;
				break;//����һ��Ҫ����break����Ȼһ��socket�����socketArray�Ķ��λ����  
			}
		}
	}

	//��socketArray��ɾ��һ��socket  
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

	//��socketArray�е��׽��ַ���fd_list����ṹ����  
	void makefd(fd_set *fd_list)
	{
		//���Ƚ�fd_list��0  
		FD_ZERO(fd_list);
		//��ÿһ��socket����fd_list��  
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
	//���ݽ�����socketListָ��  
	SocketList *socketList = (SocketList *)lpParam;
	int err = 0;
	fd_set fdread;//���ڶ��ļ���set��select�������set���Ƿ���Դ�ĳЩsocket�ж�����Ϣ  

	struct timeval timeout;//����select��ʱ��ʱ��  
	timeout.tv_sec = 1;
	timeout.tv_usec = 0;

	//�������������  
	char receBuff[MAX_PATH];
	char sendBuf[MAX_PATH];

	SOCKET socket;

	while (true)
	{
		socketList->makefd(&fdread);
		err = select(0, &fdread, NULL, NULL, &timeout);
		if (err == 0)//select����0��ʾ��ʱ  
		{
			printf("select() is time-out!");
			continue;
		}
		else
		{
			//����socketList�е�ÿһ��socket���鿴��Щsocket�ǿɶ��ģ�����ɶ���socket  
			//���ж�ȡ���ݵ������������������ݸ��ͻ���  
			for (int i = 0; i < FD_SETSIZE; i++)
			{
				//��ȡ��Ч��socket  
				if (socketList->getSocket(i) == 0)
					continue;
				socket = socketList->getSocket(i);

				//�ж���Щsocket�ǿɶ��ģ�������socket�ǿɶ��ģ����������ȡ����  
				if (FD_ISSET(socket, &fdread))
				{
					//���յ��û���
					char *input_username = new char[40];
					//���յ�����
					char *input_password = new char[40];

					//��������
					int ret = recv(socket, receBuff, MAX_PATH, 0);

					//�������ֵ��ʾҪ�ر�������ӣ���ô�ر�������������sockeList��ȥ��  
					if (ret > 0) {
						input_username = strtok(receBuff, "#");
						input_password = strtok(NULL, "#");

						//�Ƿ��½�ɹ�
						bool ok = false;

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

						char *sendData = new char[40];
						if (ok)
						{
							printf("�ÿͻ��˵�½�ɹ���\n");
							sendData = "��½�ɹ�\n";
						}
						else {
							printf("�ÿͻ��˵�½ʧ�ܣ�\n");
							sendData = "��½ʧ��\n";
						}

						//��������  
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

	//1.�����׽��ֿ� 
	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
	{
		printf("Init Windows Socket Failed");
		return 1;
	}
	//2.����socket
	SOCKET serverSocket = socket(AF_INET, SOCK_STREAM, 0);
	if (serverSocket == INVALID_SOCKET)
	{
		printf("Create Socket Failed");
		return 1;
	}
	//�������˵ĵ�ַ�Ͷ˿ں� 
	sockaddr_in serverAddr, clientAddr;
	serverAddr.sin_family = AF_INET;
	serverAddr.sin_port = htons(9999);
	serverAddr.sin_addr.S_un.S_addr = INADDR_ANY;
	//3.��Socket����Socket��ĳ��Э���ĳ����ַ��  
	if (bind(serverSocket, (LPSOCKADDR)&serverAddr, sizeof(serverAddr)) != 0)
	{
		printf("Bind Socket Failed");
		return 1;
	}
	//4.����,���׽�����Ĭ�ϵ������׽���ת���ɱ����׽��� 
	if (listen(serverSocket, 5) != 0)
	{
		printf("listen Socket Failed");
		return 1;
	}

	printf("��������������......\n");

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
		//5.�������󣬵��յ�����󣬻Ὣ�ͻ��˵���Ϣ����clientAdd����ṹ���У��������������TCP���ӵ�Socket  
		sockConn = accept(serverSocket, (struct sockaddr*)&clientAddr, &addrLen);
		if (sockConn == INVALID_SOCKET)
		{
			printf("Accpet Failed");
			return 1;//asdfasdf
		}
		printf("���յ�һ�����ӣ�%s \n", inet_ntoa(clientAddr.sin_addr));

		//��֮ǰ�ĵ�6���滻������������workThread����̺߳�����������һ�д���  
		//��socket����socketList��  
		socketList.addSocket(sockConn);
	}

	closesocket(serverSocket);
	//����Windows Socket��  
	WSACleanup();
	return 0;
}