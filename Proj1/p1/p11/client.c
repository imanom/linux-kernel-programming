#include <unistd.h>
#include <stdio.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <string.h>
#include <arpa/inet.h>

#define PORT 5984
#define BUFF_SIZE 4096

int main(int argc, const char *argv[])
{
	int sock = 0;
	struct sockaddr_in serv_addr;
	char *hello = "Hello from client";
	char buffer[BUFF_SIZE] = {0};

	/* [C1: point 1]
	 * The following piece of code is creating a socket connection and providing three arguments - domain, type and protocol.
	 * Domain = AF_INET (PF_INET) which stands for IPv4 protocol.
	 * Type = SOCK_STREAM which means the connection type is TCP, that is reliable and connection-oriented.
	 * Protocol = 0, which is the value for Internet Protocol.
	 * The integer  server_fd is the file descriptor value which is returned by the socket connection.
	 *  
	 */
	if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		printf("\n Socket creation error \n");
		return -1;
	}

	/* [C2: point 1]
	 * memset() used to fill the memory with a constant byte, here it sets the memory region to 0. 
	 * Sets the memory area (first parameter) to a specified number of bytes (3rd parameter) with the value provided in the second parameter.
	 * Here, the memory area serv_addr is filled with value '0' upto the size of the memory area serv_addr.
	 * 
	 * sin_family = sets the family to AF_INET family, to refer to the AF_INET address familt used by TCP/IP networks.
	 * sin_port = sets the port. htons() takes a 16-bit IP port number in host byte order and returns a 16-bit IP port number in network byte order.
	 */
	memset(&serv_addr, '0', sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(PORT);

	/* [C3: point 1]
	 * inet_pton() converts the character string into a network address structure, then copies the network address structure to the destination.
	 * Takes in parameters - af, const char* src and void *dst.
	 * af has to be AF_INET or AF_INET6. In our case, af = AF_INET.
	 * src = "127.0.0.1", pointing to local host.
	 * src points to the character string containing the IPV4 network address, and converted to a struct in_addr format and copied to dst.
	 * dst = &serv_addr.sin_addr (struct in_addr)
	 * 
	 * Returns 1 on success, 0 if src does not contain valid network format and -1 on errors.
	 */
	if(inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr) <= 0) {
		printf("\nInvalid address/ Address not supported \n");
		return -1;
	}

	/* [C4: point 1]
	 * connect() connects the socket referred to by sock fd to the address specified by serv_addr.
	 * Takes in the socket fd, address and size of address as parameters.
	 * Returns 0 on success and -1 on errors.
	 */
	if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
		printf("\nConnection Failed \n");
		return -1;
	}


	/* [C5: point 1]
	 * Waits for user input. getchar() is used to wait for user input and executes the send() statement after that.
	 */
	printf("Press any key to continue...\n");
	getchar();

	/* [C6: point 1]
	 * Sends a message to the server. 
	 * Works only when socket is in connected state.
	 * Takes arguments as the connected socket fd, buffer containing the message, length of the buffer and flags.
	 * Here, flags = 0, indicating no flag is set.
	 * After sending the message, we execute a print statement.
	 */
	send(sock , hello , strlen(hello) , 0 );
	printf("Hello message sent\n");

	/* [C7: point 1]
	 * Reads 1024 bytes of data from server into the buffer from the newly connected socket.
	 * Prints the message from the buffer into stdout.
	 */
	read( sock , buffer, 1024);
	printf("Message from a server: %s\n",buffer );
	return 0;
}
