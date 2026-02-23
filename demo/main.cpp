#include <winsock2.h>
#include <ws2tcpip.h>
#include <iostream>
#include <string>
#include <fstream>
#include <vector>

#define WINPE_IMPLEMENTATION
#define WINPE_NOASM
#include "winpe.h"

#include <cstring>

#define DNS_IP "1.1.1.1"
#define TEST_TCP_PORT    9080
#define TEST_UDP_PORT    9081

#pragma comment(lib, "ws2_32.lib")

static std::string g_test_server_ip = "127.0.0.1";

void printError(const std::string& msg) {
  std::cerr << msg << " Error code: " << WSAGetLastError() << std::endl;
}

void testDNS() {
  std::cout << "\n--- Testing DNS Resolution (getaddrinfo) ---" << std::endl;
  struct addrinfo hints = {0}, *res = nullptr;
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;

  if (getaddrinfo("retrocogni.com", "80", &hints, &res) != 0) {
    printError("getaddrinfo failed.");
    return;
  }

  for (struct addrinfo* ptr = res; ptr != nullptr; ptr = ptr->ai_next) {
    struct sockaddr_in* ipv4 = (struct sockaddr_in*)ptr->ai_addr;
    char ipStr[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ipv4->sin_addr), ipStr, INET_ADDRSTRLEN);
    std::cout << "Resolved retrocogni.com to: " << ipStr << std::endl;
  }
  freeaddrinfo(res);
}

void testTCPClient() {
  std::cout << "\n--- Testing TCP Client (socket, connect, send, recv) ---" << std::endl;
  SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (sock == INVALID_SOCKET) {
    printError("socket failed.");
    return;
  }

  struct sockaddr_in serverAddr;
  serverAddr.sin_family = AF_INET;
  serverAddr.sin_port = htons(TEST_TCP_PORT);
  inet_pton(AF_INET, g_test_server_ip.c_str(), &serverAddr.sin_addr);

  if (connect(sock, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
    printError("connect failed.");
    closesocket(sock);
    return;
  }
  std::cout << "Connected to " << g_test_server_ip << ":" << TEST_TCP_PORT << std::endl;

  const char* request = "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
  if (send(sock, request, strlen(request), 0) == SOCKET_ERROR) {
    printError("send failed.");
  } else {
    std::cout << "Sent HTTP GET request." << std::endl;
  }

  char buffer[512];
  int bytesReceived = recv(sock, buffer, sizeof(buffer) - 1, 0);
  if (bytesReceived > 0) {
    buffer[bytesReceived] = '\0';
    std::cout << "Received " << bytesReceived << " bytes. First line:\n";
    std::string response(buffer);
    std::cout << response.substr(0, response.find("\r\n")) << std::endl;
  } else if (bytesReceived == 0) {
    std::cout << "Connection closed by server." << std::endl;
  } else {
    printError("recv failed.");
  }

  closesocket(sock);
}

void testUDP() {
  std::cout << "\n--- Testing UDP (socket, sendto, recvfrom) ---" << std::endl;
  SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (sock == INVALID_SOCKET) {
    printError("socket failed.");
    return;
  }

  // Set a receive timeout so we don't block forever if no response
  DWORD timeout = 2000; // 2 seconds
  setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));

  struct sockaddr_in serverAddr;
  serverAddr.sin_family = AF_INET;
  serverAddr.sin_port = htons(TEST_UDP_PORT);
  inet_pton(AF_INET, g_test_server_ip.c_str(), &serverAddr.sin_addr);

  // Simple UDP message
  const char* udpMsg = "Hello UDP Server!";

  if (sendto(sock, udpMsg, strlen(udpMsg), 0, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
    printError("sendto failed.");
    closesocket(sock);
    return;
  }
  std::cout << "Sent UDP message to " << g_test_server_ip << ":" << TEST_UDP_PORT << std::endl;

  char buffer[512];
  struct sockaddr_in fromAddr;
  int fromLen = sizeof(fromAddr);
  int bytesReceived = recvfrom(sock, buffer, sizeof(buffer), 0, (struct sockaddr*)&fromAddr, &fromLen);
    
  if (bytesReceived > 0) {
    char ipStr[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(fromAddr.sin_addr), ipStr, INET_ADDRSTRLEN);
    std::cout << "Received " << bytesReceived << " bytes from " << ipStr << ":" << ntohs(fromAddr.sin_port) << std::endl;
  } else {
    printError("recvfrom failed (timeout expected if network blocks UDP 53).");
  }

  closesocket(sock);
}

void testSelect() {
  std::cout << "\n--- Testing I/O Multiplexing (select) ---" << std::endl;
  SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (sock == INVALID_SOCKET) {
    printError("socket failed.");
    return;
  }

  // Make socket non-blocking
  u_long mode = 1;
  ioctlsocket(sock, FIONBIO, &mode);

  struct sockaddr_in serverAddr;
  serverAddr.sin_family = AF_INET;
  serverAddr.sin_port = htons(80);
  inet_pton(AF_INET, DNS_IP, &serverAddr.sin_addr);

  std::cout << "Initiating non-blocking connect..." << std::endl;
  connect(sock, (struct sockaddr*)&serverAddr, sizeof(serverAddr));
  // connect will likely return WSAEWOULDBLOCK

  fd_set writefds;
  FD_ZERO(&writefds);
  FD_SET(sock, &writefds);

  struct timeval tv;
  tv.tv_sec = 10;
  tv.tv_usec = 0;

  std::cout << "Waiting for socket to become writable (connected)..." << std::endl;
  int result = select(0, NULL, &writefds, NULL, &tv);
    
  if (result > 0) {
    if (FD_ISSET(sock, &writefds)) {
      std::cout << "Socket is writable! Connection established." << std::endl;
    }
  } else if (result == 0) {
    std::cout << "select timed out." << std::endl;
  } else {
    printError("select failed.");
  }

  closesocket(sock);
}

// Function that manually maps a replacement DLL using win-MemoryModule and patches the target module's IAT
void ReplaceAllMatchingImportsManualMap(HMODULE hTargetModule, const char* replacementDllPath) {
  if (!hTargetModule || !replacementDllPath) return;

  size_t mempesize = 0;
  void *mempe = winpe_memload_file(replacementDllPath, &mempesize, TRUE);
  if (!mempe) {
    std::cerr << "winpe_memload_file failed for " << replacementDllPath << std::endl;
    return;
  }

  // Load the DLL from memory using win-MemoryModule
  void* hReplacementModule = winpe_memLoadLibrary(mempe);
  if (!hReplacementModule) {
    std::cerr << "winpe_memLoadLibrary failed for " << replacementDllPath << std::endl;
    free(mempe);
    return;
  }
  std::cout << "Successfully manually mapped '" << replacementDllPath << "' using win-MemoryModule." << std::endl;

  PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hTargetModule;
  PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hTargetModule + pDosHeader->e_lfanew);
  IMAGE_DATA_DIRECTORY importDataDir = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
  if (importDataDir.Size == 0 || importDataDir.VirtualAddress == 0) return;

  PIMAGE_IMPORT_DESCRIPTOR pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)hTargetModule + importDataDir.VirtualAddress);

  std::cout << "Replacing ALL matching imports in Target Module with Manually Mapped DLL..." << std::endl;
  std::cout << "--------------------------------------------------" << std::endl;

  int replaceCount = 0;

  while (pImportDesc->Name != 0) {
    char* dllName = (char*)((BYTE*)hTargetModule + pImportDesc->Name);
    PIMAGE_THUNK_DATA pThunkILT = (PIMAGE_THUNK_DATA)((BYTE*)hTargetModule + pImportDesc->OriginalFirstThunk);
    PIMAGE_THUNK_DATA pThunkIAT = (PIMAGE_THUNK_DATA)((BYTE*)hTargetModule + pImportDesc->FirstThunk);
    if (pImportDesc->OriginalFirstThunk == 0) pThunkILT = pThunkIAT; 

    // Only patch imports from ws2_32.dll
    if (_stricmp(dllName, "ws2_32.dll") == 0) {
      while (pThunkILT->u1.AddressOfData != 0) {
	FARPROC pReplacementFunc = NULL;
	char* functionName = NULL;
	char ordinalName[32];

	if (!(pThunkILT->u1.Ordinal & IMAGE_ORDINAL_FLAG)) {
	  PIMAGE_IMPORT_BY_NAME pImportByName = (PIMAGE_IMPORT_BY_NAME)((BYTE*)hTargetModule + pThunkILT->u1.AddressOfData);
	  functionName = (char*)pImportByName->Name;
	  pReplacementFunc = (FARPROC)winpe_memGetProcAddress(hReplacementModule, functionName);
	} else {
	  WORD ordinal = IMAGE_ORDINAL(pThunkILT->u1.Ordinal);
	  pReplacementFunc = (FARPROC)winpe_memGetProcAddress(hReplacementModule, (LPCSTR)(uintptr_t)ordinal);
	  snprintf(ordinalName, sizeof(ordinalName), "Ordinal%u", ordinal);
	  functionName = ordinalName;
	}

	if (pReplacementFunc != NULL) {
	  DWORD oldProtect;
	  if (VirtualProtect(&pThunkIAT->u1.Function, sizeof(ULONG_PTR), PAGE_READWRITE, &oldProtect)) {
	    pThunkIAT->u1.Function = (ULONG_PTR)pReplacementFunc;
	    VirtualProtect(&pThunkIAT->u1.Function, sizeof(ULONG_PTR), oldProtect, &oldProtect);
	    std::cout << "[REPLACED IAT -> MANUAL MAP] " << dllName << "!" << functionName << std::endl;
	    replaceCount++;
	  }
	}
	pThunkILT++;
	pThunkIAT++;
      }
    }
    pImportDesc++;
  }

  std::cout << "--------------------------------------------------" << std::endl;
  std::cout << "Total IAT entries replaced with manual map: " << replaceCount << std::endl;
    
  // Note: We don't call MemoryFreeLibrary here because we want the patched functions 
  // to remain available in memory for the target module to use.
}


int main(int argc, char* argv[]) {
  if (argc > 1) {
    g_test_server_ip = argv[1];
    std::cout << "Using server IP from argv: " << g_test_server_ip << std::endl;
  }
  else
  {
    std::cout << "Please provide an ip string." << std::endl;
    return 1;
  }
  
  std::cout << "Press enter to attempt winsock2 export patching." << std::endl;
  getchar();

  // Unload winsock2... ?
  HMODULE hMain = GetModuleHandleA(NULL); // get handle to this process

  ReplaceAllMatchingImportsManualMap(hMain, "wsx_32.dll");
  
  std::cout << "Press enter when ready to run the test." << std::endl;
  getchar();

  std::cout << "Initializing WinSock2..." << std::endl;
  WSADATA wsaData;
  if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
    std::cerr << "WSAStartup failed." << std::endl;
    return 1;
  }
  
  testDNS();
  testTCPClient();
  testUDP();
  testSelect();

  std::cout << "\nCleaning up WinSock2..." << std::endl;
  WSACleanup();
  return 0;
}
