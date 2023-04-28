#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/ip_icmp.h>

#define PACKET_SIZE 1024
#define ICMP_ECHO_REPLY 0
#define IP_HDR_SIZE sizeof(struct iphdr)
#define ICMP_HDR_SIZE sizeof(struct icmphdr)

void process_packet(char *buffer, int size); 
unsigned short checksum(void *b, int len);
void send_icmp_echo_reply(int sockfd, char *packet, int packet_size, struct sockaddr_in dest_addr); 
void process_icmp_echo_request(char *packet, int packetlen); 

int main() {
    int sockfd;
    struct sockaddr_in dest_addr, src_addr;
    socklen_t addrlen = sizeof(struct sockaddr_in);
    char packet[IP_MAXPACKET];
    int bytes_received;

    // Create raw socket
    sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sockfd < 0) {
        perror("Failed to create socket");
        exit(1);
    }

    while (1) {
        // Receive ICMP echo request
        bytes_received = recvfrom(sockfd, packet, IP_MAXPACKET, 0,
                                  (struct sockaddr *) &src_addr, &addrlen);
        if (bytes_received < 0) {
            perror("Failed to receive ICMP echo request");
            continue;
        }

        // Process received packet
        process_icmp_echo_request(packet, bytes_received);

        // Send ICMP echo reply
        send_icmp_echo_reply(sockfd, packet, bytes_received, src_addr);
    }

    // Close socket
    close(sockfd);

    return 0;
}


void process_packet(char *buffer, int size) {
    struct iphdr *iph = (struct iphdr*) buffer;
    struct icmphdr *icmp = (struct icmphdr*) (buffer + iph->ihl*4);

    printf("Received ICMP packet from %s\n", inet_ntoa(*(struct in_addr*)&iph->saddr));
    printf("Type: %d, Code: %d\n", icmp->type, icmp->code);
    printf("Checksum: %x\n", icmp->checksum);

    char *cmd = buffer + iph->ihl*4 + sizeof(struct icmphdr);
    printf("Payload: %s\n", cmd);

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
void send_icmp_echo_reply(int sockfd, char *packet, int packet_size, struct sockaddr_in dest_addr) {
    char reply_packet[IP_MAXPACKET];
    struct iphdr *ip_hdr, *reply_ip_hdr;
    struct icmphdr *icmp_hdr, *reply_icmp_hdr;
    int ip_hdr_len;

    // Copy received packet to reply packet
    memcpy(reply_packet, packet, packet_size);

    // Update IP header fields
    ip_hdr = (struct iphdr *) reply_packet;
    ip_hdr_len = ip_hdr->ihl * 4;
    ip_hdr->daddr = dest_addr.sin_addr.s_addr;
    ip_hdr->saddr = inet_addr("192.168.1.175");
    ip_hdr->check = 0;
    ip_hdr->check = checksum((unsigned short *) ip_hdr, ip_hdr_len);

    // Update ICMP header fields
    icmp_hdr = (struct icmphdr *) (reply_packet + ip_hdr_len);
    icmp_hdr->type = ICMP_ECHOREPLY;
    icmp_hdr->code = 0;
    icmp_hdr->checksum = 0;
    icmp_hdr->un.echo.id = getpid();
    icmp_hdr->un.echo.sequence = 0;

    // Add payload to ICMP reply
    char *payload = "hello icmp";
    memcpy(reply_packet + ip_hdr_len + ICMP_HDR_SIZE, payload, strlen(payload));

    // Update ICMP checksum
    icmp_hdr->checksum = checksum((unsigned short *) icmp_hdr, ICMP_HDR_SIZE + strlen(payload));

    // Send ICMP reply
    if (sendto(sockfd, reply_packet, packet_size, 0, (struct sockaddr *) &dest_addr, sizeof(struct sockaddr_in)) < 0) {
        perror("Failed to send ICMP echo reply");
        exit(1);
    }
}

void process_icmp_echo_request(char *packet, int packetlen) {
    struct iphdr *ip_header = (struct iphdr *) packet;
    struct icmphdr *icmp_header = (struct icmphdr *) (packet + (ip_header->ihl * 4));

    // Check that the packet is an ICMP echo request
    if (icmp_header->type != ICMP_ECHO) {
        printf("Received packet is not an ICMP echo request\n");
        return;
    }

    // Extract payload data (if any) from the packet
    char *payload = packet + (ip_header->ihl * 4) + sizeof(struct icmphdr);
    int payload_len = packetlen - (ip_header->ihl * 4) - sizeof(struct icmphdr);
    
    // Print payload data to console
    if (payload_len > 0) {
        printf("Received ICMP echo request with payload: %s\n", payload);
    } else {
        printf("Received ICMP echo request with no payload\n");
    }
}

