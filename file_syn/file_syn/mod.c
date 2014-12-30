#include<netinet/in.h>  
#include<sys/types.h>  
#include<sys/socket.h>  
#include<stdio.h>  
#include<stdlib.h>  
#include<string.h>  
  
#define HELLO_WORLD_SERVER_PORT    6666  
#define LENGTH_OF_LISTEN_QUEUE     20  
#define BUFFER_SIZE                1024  
#define FILE_NAME_MAX_SIZE         512  
  
int main(int argc, char **argv)  
{  
    struct sockaddr_in   server_addr;  
    bzero(&server_addr, sizeof(server_addr));  
    server_addr.sin_family = AF_INET;  
    server_addr.sin_addr.s_addr = htons(INADDR_ANY);  
    server_addr.sin_port = htons(HELLO_WORLD_SERVER_PORT);  
  
    int server_socket = socket(PF_INET, SOCK_STREAM, 0);  
    if (server_socket < 0)  
    {  
        printf("Create Socket Failed!\n");  
        exit(1);  
    }  
  
    if (bind(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)))  
    {  
        printf("Server Bind Port: %d Failed!\n", HELLO_WORLD_SERVER_PORT);  
        exit(1);  
    }  
  
    if (listen(server_socket, LENGTH_OF_LISTEN_QUEUE))  
    {  
        printf("Server Listen Failed!\n");  
        exit(1);  
    }  
  
    while(1)  
    {  

	}
}
  
