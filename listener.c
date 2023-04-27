#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <sys/time.h>
#include <stdbool.h>

#define PACKET_SIZE 2048
#define ICMP_ECHO_REQUEST 8
#define ICMP_ECHO_REPLY 0
#define MASTER_ADDRESS "192.168.1.112"
#define TIMEOUT_SECONDS 2 

int process_packet(char *buffer, int size, int sd);
unsigned short checksum(void *b, int len);
int send_icmp_echo_request(int sd, struct sockaddr_in* dest, int seq_num);
void send_icmp_echo_reply(char *buffer, int size, int sd);
int wait_for_icmp_echo_reply(int sd, struct sockaddr_in *dest, unsigned int timeout_sec);

int main(int argc, char *argv[]) {
	//Create socket
    int sd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sd < 0) {
        perror("socket() error");
        return -1;
    }

	//Set up destination address
    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    if (inet_pton(AF_INET, MASTER_ADDRESS, &dest.sin_addr) <= 0) {
        perror("inet_pton() error");
        return -1;
    }

    /*
     * What this does is: this basically starts sending echo requests every 2 seconds
     * Once we get a reply from the master, we know he's ready for commands
    */
    int seq_num = 0;
    while (true) {
        if (send_icmp_echo_request(sd, &dest, seq_num) < 0) {
            printf("Error sending ICMP echo request.\n");
            return -1;
        }

        int reply_seq_num = wait_for_icmp_echo_reply(sd, &dest, TIMEOUT_SECONDS);
        if (reply_seq_num == -1) {
            printf("Error waiting for ICMP echo reply.\n");
            return -1;
        } else if (reply_seq_num == 0) {
            printf("No reply received.\n");
        } else {
            printf("Received reply with sequence number %d.\n", reply_seq_num);
            break;
        }

        sleep(TIMEOUT_SECONDS);
        seq_num++;
    }


	close(sd);
    return 0;
}

int send_icmp_echo_request(int sd, struct sockaddr_in* dest, int seq_num) {
    char buffer[PACKET_SIZE];
    memset(buffer, 0, PACKET_SIZE);

    // Prepare the ICMP packet
    struct icmphdr icmp;
    icmp.type = ICMP_ECHO_REQUEST;
    icmp.code = 0;
    icmp.un.echo.id = getpid();
    icmp.un.echo.sequence = seq_num;
    //icmp.checksum = 0;
    icmp.checksum = checksum(&icmp, sizeof(icmp));

    memcpy(buffer, &icmp, sizeof(icmp));

    // Send the ICMP packet
	printf("\n\nSending shit with PID: %d\n", icmp.un.echo.id);
    if (sendto(sd, buffer, sizeof(icmp), 0, (struct sockaddr*) dest, sizeof(*dest)) < 0) {
        perror("sendto() error");
        return -1;
    }

    return 0;
}

int wait_for_icmp_echo_reply(int sd, struct sockaddr_in *dest, unsigned int timeout_sec) {
    struct timeval timeout;
    timeout.tv_sec = timeout_sec;
    timeout.tv_usec = 0;

    fd_set read_fds;
    FD_ZERO(&read_fds);
    FD_SET(sd, &read_fds);

    int ready = select(sd+1, &read_fds, NULL, NULL, &timeout);
    if (ready == -1) {
        perror("select error");
        return -1;
    } else if (ready == 0) {
        printf("Timeout exceeded.\n");
        return 0;
    }

    char buffer[PACKET_SIZE];
    struct sockaddr_in recv_addr;
    socklen_t recv_addr_len = sizeof(recv_addr);
    ssize_t bytes = recvfrom(sd, buffer, sizeof(buffer), 0, (struct sockaddr*)&recv_addr, &recv_addr_len);
    if (bytes < 0) {
        perror("recvfrom error");
        return -1;
    }

	return process_packet(buffer, PACKET_SIZE, sd);

}


/*
 * This prints info about the packets received and returns the sequence value, used to
 * recognize the master's response
*/
int process_packet(char *buffer, int size, int sd) {
    struct iphdr *iph = (struct iphdr*) buffer;
    struct icmphdr *icmp = (struct icmphdr*) (buffer + iph->ihl*4);

    printf("Received ICMP packet from %s\n", inet_ntoa(*(struct in_addr*)&iph->saddr));
    printf("Type: %d, Code: %d\n", icmp->type, icmp->code);
    printf("Checksum: %x\n", icmp->checksum);
	printf("ICMP ID: %d\n", icmp->un.echo.id);

    char *cmd = buffer + iph->ihl*4 + sizeof(struct icmphdr);
    printf("Payload: %s\n", cmd);

    return icmp->un.echo.sequence;
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

void send_icmp_echo_reply(char *buffer, int size, int sd) {
    struct iphdr *iph = (struct iphdr*) buffer;
    struct icmphdr *icmp = (struct icmphdr*) (buffer + iph->ihl*4);

    // Create a new packet
    char packet[size];
    memset(packet, 0, size);

    // Copy the received packet's source IP address to the new packet's destination IP address
    struct in_addr dst_addr;
    dst_addr.s_addr = iph->saddr;
    memcpy(&((struct iphdr*) packet)->daddr, &dst_addr, sizeof(dst_addr));

    // Copy the received packet's destination IP address to the new packet's source IP address
    struct in_addr src_addr;
    src_addr.s_addr = iph->daddr;
    memcpy(&((struct iphdr*) packet)->saddr, &src_addr, sizeof(src_addr));

    // Set the new packet's type to ICMP_ECHOREPLY and the code to 0
    icmp->type = ICMP_ECHOREPLY;
    icmp->code = 0;

    // Copy the received packet's identifier and sequence number to the new packet's identifier and sequence number
    icmp->un.echo.id = htons(icmp->un.echo.id);
    icmp->un.echo.sequence = htons(icmp->un.echo.sequence);
    memcpy(packet + iph->ihl*4 + sizeof(struct icmphdr), buffer + iph->ihl*4 + sizeof(struct icmphdr), size - iph->ihl*4 - sizeof(struct icmphdr));

    // Calculate the ICMP packet's checksum
    icmp->checksum = 0;
    icmp->checksum = checksum(icmp, size - iph->ihl*4);

    // Send the ICMP packet
    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = iph->saddr;
    if (sendto(sd, packet, size, 0, (struct sockaddr*) &dest, sizeof(dest)) < 0) {
        perror("sendto() error");
    }
}
