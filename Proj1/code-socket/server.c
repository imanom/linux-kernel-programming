#include <unistd.h>
#include <stdio.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <string.h>

#define PORT 5984
#define BUFF_SIZE 4096

int main(int argc, const char *argv[])
{
	int server_fd, new_socket;
	struct sockaddr_in address;
	int opt = 1;
	int addrlen = sizeof(address);
	char buffer[BUFF_SIZE] = {0};
	char *hello = "Hello from server";

	/* [S1: point 1]
	 * The following piece of code is creating a socket connection and providing three arguments - domain, type and protocol.
	 * Domain = AF_INET (PF_INET) which stands for IPv4 protocol.
	 * Type = SOCK_STREAM which means the connection type is TCP, that is reliable and connection-oriented.
	 * Protocol = 0, which is the value for Internet Protocol.
	 * The integer  server_fd is the file descriptor value which is returned by the socket connection.
	 *  
	 */
	if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
		perror("socket failed");
		exit(EXIT_FAILURE);
	}

	/* [S2: point 1]
	 * setsockopt is used to manipulate options for the socket referred to by server_fd.
	 * The arguments passed are sockfd, level, optname, *optval, optlen
	 * sockfd = sercer_fd that is the file descriptor returned in the previous step.
	 * level = SOL_SOCKET, specified to manipulate socket options at the API level.
	 * optname = SO_REUSEADDR, that is the option name.
	 * optval = &opt, address of a buffer to which optname is set.
	 * optlen = size of the buffer
	 * 
	 * Returns 0 on success. If it is not 0, then the error inside the if-loop is printed.
	 */
	if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
		perror("setsockopt");
		exit(EXIT_FAILURE);
	}

	/* [S3: point 1]
	 * 
	 * We specify the values for the custom sockaddr structure here.
	 * sin_family = AF_INET, to refer to the AF_INET address familt used by TCP/IP networks.
	 * We set the s_addr to INADDR_ANY to accept any incoming messages. It expands to a 32 bit integer holding 0x00000000.
	 * sin_port = sets the port. htons() takes a 16-bit IP port number in host byte order and returns a 16-bit IP port number in network byte order.
	 */
	address.sin_family = AF_INET;
	address.sin_addr.s_addr = INADDR_ANY;
	address.sin_port = htons( PORT );

	/* [S4: point 1]
	 * When a socket is created, it exists in an address space but does not have an address assigned to it.
	 * bind() assigns the address specified by "address" to the socket referred to by "server_fd".
	 * Returns 0 on success and -1 on failure.
	 * 
	 */
	if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
		perror("bind failed");
		exit(EXIT_FAILURE);
	}

	/* [S5: point 1]
	 * listen() makes the socket referred to by server_fd listen for incoming connection requests, putting it in passive mode.
	 * Takes in the arguments socket fd and backlog. 
	 * Socket fd = server_fd, file descriptor of the socket connection.
	 * backlog = 3, specifies the max number of pending connection requests in the queue. 
	 * 
	 * Returns 0 on success, -1 on error.
	 */
	if (listen(server_fd, 3) < 0) {
		perror("listen");
		exit(EXIT_FAILURE);
	}

	/* [S6: point 1]
	 * accept() takes the first pending connection request from the listening socket (server_fd).
	 * It is used with connection based socket types such as SOCK_STREAM.
	 * Creates a new connected socket and returns the new socket file descriptor.
	 * Connection is established between client and server.
	 * Returns a non-negative integer on success, which is the file descriptor of the newly created socket.
	 */
	if ((new_socket = accept(server_fd, (struct sockaddr *)&address,
				 (socklen_t*)&addrlen)) < 0) {
		perror("accept");
		exit(EXIT_FAILURE);
	}

	/* [S7: point 1]
	 * Waits for user input. getchar() is used to wait for user input and executes the read() statement after that.
	 */
	printf("Press any key to continue...\n");
	getchar();

	/* [S8: point 1]
	 * Reads 1024 bytes of data from client into the buffer from the newly connected socket.
	 * Prints the message from the buffer into stdout.
	 */
	read( new_socket , buffer, 1024);
	printf("Message from a client: %s\n",buffer );

	/* [S9: point 1]
	 * Sends a message to the client.
	 * Works only when socket is in connected state.
	 * Takes arguments as the connected socket fd, buffer containing the message, length of the buffer and flags.
	 * Here, flags = 0, indicating no flag is set.
	 * After sending the message, we execute a print statement.
	 */
	send(new_socket , hello , strlen(hello) , 0 );
	printf("Hello message sent\n");
	return 0;
}
