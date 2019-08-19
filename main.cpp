#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <unistd.h>

#define MAXFDS 1024

typedef struct socket_data {
	unsigned char buf[16 * 1024];
} socket_data; 

// Struct for managint the poll list.
typedef struct poll_list {
	struct pollfd pfd[MAXFDS];
	nfds_t nfds;
} poll_list;

static void poll_list_init(struct poll_list* pl)
{
	memset(pl, 0, sizeof(*pl));
}

static void poll_list_add(struct poll_list* pl, struct pollfd pfd) {
	if (pl->nfds < MAXFDS)
		pl->pfd[pl->nfds++] = pfd;
}

static void poll_list_remove(struct poll_list* pl, struct pollfd pfd) {
	for (nfds_t i = 0; i < pl->nfds; i++)
	{
		if (pl->pfd[i].fd == pfd.fd)
		{
			pl->pfd[i] = pl->pfd[pl->nfds - 1];
			pl->nfds--;
			break;
		}
	}
}

// Globals for managing state.
static socket_data slist[MAXFDS];
static poll_list plist;

int make_nonblock(int fd)
{
	int fd_flags = fcntl(fd, F_GETFL, 0);
	if (fd_flags == -1)
	{
		perror("make_nonblock::fcntl_get failed");
		return -1;
	}

	if (fcntl(fd, F_SETFL, fd_flags | O_NONBLOCK) != 0)
	{
		perror("make_nonblock::fcntl_set failed");
		return -1;
	}

	return 0;
}

int create_accept_socket(const char* addr, int port)
{
	int fd = -1;
	struct sockaddr_in saddr = { 0 };

	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0)
		goto done;
	
	if (make_nonblock(fd) != 0)
		goto done;

	saddr.sin_family = AF_INET;
	if (inet_pton(AF_INET, addr, &saddr.sin_addr) != 1)
		goto done;
	saddr.sin_port = htons((unsigned short)port);

	if (bind(fd, (struct sockaddr*) & saddr, sizeof(saddr)) < 0)
		goto done;

	if (listen(fd, 32) < 0)
		goto done;

done:
	return fd;
}

#if 0
int connect_to_enclave_blocking(int fd, int* send_fd)
{
	ssize_t bytes_read = 0;
	unsigned char buf[4096];
	char prev = '\0';
	ssize_t hdr_end = -1;
	struct addrinfo* result;
	int error;

	while (bytes_read < sizeof(buf))
	{
		ssize_t tmp = recv(fd, buf + bytes_read, sizeof(buf) - bytes_read, 0);
		if (tmp == -1)
		{
			if (errno == EINTR)
				continue;

			perror("connect_to_proxy_blocking::recv failed");
			return -1;
		}

		// Not an error, just EOF.
		if (tmp == 0)
		{
			fprintf(stderr, "connect_to_proxy_blocking::recv: Got EOF. Closing socket...\n");
			return -1;
		}

		for (ssize_t i = 0; i < tmp; i++)
		{
			if (buf[i + bytes_read] == '\n' && prev == '\r')
			{
				hdr_end = i + bytes_read;
				break;
			}
			prev = buf[i + bytes_read];
		}

		bytes_read += tmp;

		if (hdr_end != -1)
			break;
	}

	if (hdr_end == -1)
	{
		fprintf(stderr, "connect_to_proxy_blocking. Could not find HTTP request end.\n");
		return -1;
	}

	// Convert the \r\n to a null so that we can do string ops on it.
	buf[hdr_end - 1] = '\0';
	buf[hdr_end] = '\0';
	printf("HTTP request: %s\n", (const char*)buf);

	// Format of header line is COMMAND http... so find it.
	char* url_start = strstr((char*)buf, "http");
	if (url_start == NULL)
	{
		fprintf(stderr, "connect_to_proxy_blocking. Could not find http(s):// in header.\n");
		return -1;
	}

	char* url_end = url_start;
	while (*url_end != ' ' && *url_end != '\0')
		url_end++;

	if (*url_end == '\0')
	{
		// Header is messed up.
		fprintf(stderr, "connect_to_proxy_blocking. Could not find end of http(s):// in header.\n");
		return -1;
	}

	*url_end = '\0';
	printf("HTTP url is: %s\n", url_start);

	error = getaddrinfo((const char*)url_start, NULL, NULL, &result);
	if (error != 0) {
		if (error == EAI_SYSTEM) {
			perror("connect_to_proxy_blocking::getaddrinfo failed");
		}
		else {
			fprintf(stderr, "connect_to_proxy_blocking::getaddrinfo failed: %s\n", gai_strerror(error));
		}
		return -1;
	}

	int fd2 = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
	if (fd2 == -1)
	{
		perror("connect_to_proxy_blocking::socket failed");
		freeaddrinfo(result);
		return -1;
	}

	if (connect(fd2, result->ai_addr, result->ai_addrlen) != 0)
	{
		perror("connect_to_proxy_blocking::connect failed");
		close(fd2);
		freeaddrinfo(result);
		return -1;
	}

	// Restore the HTTP header to it's original state.
	*url_end = ' ';
	buf[hdr_end - 1] = '\r';
	buf[hdr_end] = '\n';

	// Write the http request to the server now.
	if (write(fd2, buf, bytes_read) != bytes_read)
	{
		perror("connect_to_proxy_blocking::write failed");
		close(fd2);
		freeaddrinfo(result);
		return -1;
	}

	freeaddrinfo(result);
	*send_fd = fd2;
	return 0;
}
#endif

int get_server_info(const char* raddr, int rport, struct addrinfo** result)
{
	struct addrinfo* local = NULL;
	int ret = -1;
	int gai_res;

	gai_res = getaddrinfo(raddr, NULL, NULL, &local);
	if (gai_res != 0) {
		if (gai_res == EAI_SYSTEM) {
			perror("create_tls_socket::getaddrinfo failed");
		}
		else {
			fprintf(stderr, "create_tls_socket::getaddrinfo failed: %s\n", gai_strerror(gai_res));
		}
		goto done;
	}

	if (local->ai_family != AF_INET && local->ai_family != AF_INET6)
	{
		fprintf(stderr, "get_server_info::getaddrinfo: proxy only supports IP protocol.\n");
		goto done;
	}

	if (local->ai_family == AF_INET)
	{
		struct sockaddr_in* in = ((struct sockaddr_in*) local->ai_addr);
		in->sin_port = htons((unsigned short)rport);
	}
	else
		((struct sockaddr_in6*) local->ai_addr)->sin6_port = htons((unsigned short)rport);

	ret = 0;
	*result = local;
	local = NULL;

done:
	return ret;
}

int handle_new_connection(int server_fd, struct addrinfo* info)
{
	int client_fd = -1;
	struct sockaddr_in addr;
	socklen_t addrlen = sizeof(addr);
	char addrstr[INET_ADDRSTRLEN];

	// We got a connection request from poll. Start accepting connections.
	// We don't know how many we got, so we need to do this in a loop.
	while (1)
	{
		client_fd = accept(server_fd, (struct sockaddr*) & addr, &addrlen);
		if (client_fd == -1)
		{
			// Signal interrupt, just try again.
			if (errno == EINTR)
				continue;

			// Out of connections to accept. Just go back to epolling.
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				break;

			// Fatal error, return.
			perror("handle_new_connection::accept failed");
			return -1;
		}

		// Got a valid fd, so let's start the proxy connection.
		if (inet_ntop(AF_INET, &addr.sin_addr, addrstr, sizeof(addrstr)) == NULL)
		{
			perror("handle_new_connection::inet_ntop failed");
			close(client_fd);
			return -1;
		}

		printf("Client connected from: %s:%d\n", addrstr, ntohs(addr.sin_port));
		

		// Connect to server enclave.


		// Add to the poll list.
		struct pollfd pfd = { client_fd, POLLIN | POLLOUT, 0 };
		poll_list_add(&plist, pfd);






	}

	return 0;
}

int handle_existing_connection(struct pollfd pfd)
{
}

void server_loop(int server_fd, struct addrinfo* info)
{
	int ret = -1;

	/* Add server_fd to pollfd struct. */
	struct pollfd server_pfd = { server_fd, POLLIN, 0 };
	poll_list_init(&plist);
	poll_list_add(&plist, server_pfd);

	/* Now, loop with poll. */
	while (1)
	{
		int num_fd = poll(plist.pfd, plist.nfds, -1);

		if (num_fd < 0)
		{
			perror("server_loop::poll failed");
			goto done;
		}
		else if (num_fd == 0)
		{
			/* Shouldn't happen? */
			fprintf(stderr, "poll returned 0 for some reason.\n");
			goto done;
		}

		printf("poll got %d\n fd events.\n", num_fd);
		for (int i = 0; i < num_fd; i++)
		{
			if (plist.pfd[i].revents == 0)
				continue;

			if (plist.pfd[i].fd == server_fd)
				ret = handle_new_connection(server_fd, info);
			else
				ret = handle_existing_connection(plist.pfd[i]);
		}
	}

done:
	/* Close all file descriptors. */
	for (nfds_t i = 0; i < plist.nfds; i++)
		close(plist.pfd[i].fd);
}

int main(int argc, char** argv)
{
	int server_fd = -1;
	int ret = -1;
	const char* laddr;
	const char* raddr;
	int lport;
	int rport;
	struct addrinfo* result = NULL;
	char addrstr[INET_ADDRSTRLEN];

	if (argc != 3) {
		fprintf(stderr, "Usage: %s local_addr port remote_addr port\n", argv[0]);
		goto done;
	}

	laddr = argv[1];
	lport = atoi(argv[2]);
	raddr = argv[3];
	rport = atoi(argv[4]);

	// Get server info so we don't need to keep doing the lookup.
	printf("Getting server information...\n");
	if (get_server_info(raddr, rport, &result) != 0)
	{
		fprintf(stderr, "get_server_info failed.\n");
		goto done;
	}

	// Create accept socket.
	printf("Creating accept socket...\n");
	server_fd = create_accept_socket(laddr, lport);
	if (server_fd < 0) {
		perror("failed to make server socket.");
		goto done;
	}

	// Start looping for connections.
	printf("Starting accept loop...\n");
	server_loop(server_fd, result);
	ret = 0;

done:
	if (server_fd != -1)
		close(server_fd);
	if (result != NULL)
		freeaddrinfo(result);
	
	return ret;
}