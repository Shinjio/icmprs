#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/ip_icmp.h>

#define PACKET_SIZE 64


unsigned short checksum(void *b, int len); 

int main(int argc, char *argv[]) {
    //Check for arguments
    if (argc != 2) {
        printf("Usage: %s <destination IP address>\n", argv[0]);
        return 1;
    }

    //Create a raw socket for ICMP
    int sd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sd < 0) {
        perror("socket() error");
        return 1;
    }

    //Prepare the ICMP packet
    char packet[PACKET_SIZE];
    memset(packet, 0, PACKET_SIZE);

    struct icmphdr *icmp = (struct icmphdr*) packet;
    icmp->type = ICMP_ECHO; //ICMP echo request message type
    icmp->code = 0; //no information needed
    icmp->checksum = 0;
    icmp->un.echo.id = getpid(); //Set the ICMP identifier to the current process ID
    icmp->un.echo.sequence = 0; //Set the ICMP sequence number to 0
    char *data = packet + sizeof(struct icmphdr);
    strcpy(data, "touch test.txt"); //payload

    icmp->checksum = checksum(packet, PACKET_SIZE);

    //Prepare destination address
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(argv[1]);

    //Send packet to the destination
    int sent = sendto(sd, packet, PACKET_SIZE, 0, (struct sockaddr*)&addr, sizeof(addr));
    if (sent < 0) {
        perror("sendto() error");
        return 1;
    }

    printf("Sent %d bytes to %s\n", sent, argv[1]);

    close(sd);

    return 0;
}

unsigned short checksum(void *b, int len) {
    unsigned short *buf = b;
    unsigned int sum = 0;
    unsigned short result;

    for (sum = 0; len > 1; len -= 2)
        sum += *buf++;

    if (len == 1)
        sum += *(unsigned char*)buf;

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;

    return result;
}

