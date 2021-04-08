#include <stdio.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <stdint.h>
#include <arpa/inet.h>

uint16_t extern_udp_checksum(const void* buff, size_t len, in_addr_t src_addr, in_addr_t dest_addr) {
  const uint16_t *buf = buff;
  uint16_t *ip_src = (void *)&src_addr, *ip_dst=(void *)&dest_addr;
  uint32_t sum;
  size_t length=len;

  sum = 0;
  while ( len > 1 )
  {
    sum += *buf++;
    if ( sum & 0x80000000 )
      sum = (sum & 0xFFFF) + (sum >> 16);
    len -= 2;
  }

  if ( len & 1 )
    sum += *((uint8_t *)buf);

  sum += *(ip_src++);
  sum += *ip_src;

  sum += *(ip_dst++);
  sum += *ip_dst;

  sum += htons(IPPROTO_UDP);
  sum += htons(length);

  while ( sum >> 16 )
    sum = (sum & 0xFFFF) + ( sum >> 16 );

  return ( (uint16_t)(~sum) );
}

uint16_t _udp_checksum(struct iphdr* ip, struct udphdr* udp) {
	uint32_t sum = 0;
	uint16_t* u_data = (uint16_t *) udp, udp_len = ntohs(udp->len);

  sum +=  *((uint16_t *)  (&ip->saddr))       +
          *((uint16_t *)  (&ip->saddr) + 1)   +
          *((uint16_t *)  (&ip->daddr))       +
          *((uint16_t *)  (&ip->daddr) + 1)   ;

  sum += htons(ip->protocol) + udp->len;

	while ( udp_len > 1 ) {
		sum += *(u_data++);
    udp_len -= 2;
	}

	if ( udp_len & 1 )
		sum += *((uint8_t *) u_data);

  while ( sum >> 16 )
    sum = (sum & 0xFFFF) + ( sum >> 16 );

	return ( (uint16_t) (~sum) );
}

uint16_t udp_checksum(struct iphdr* ip, struct udphdr* udp) {
	uint32_t check = 0;
	uint16_t* u_data = (uint16_t *) udp, data_len = ntohs(udp->len);

  check += ntohs((ip->saddr >> 16) & 0xFFFF) + ntohs(ip->saddr & 0xFFFF) + ntohs((ip->daddr >> 16) & 0xFFFF) + ntohs(ip->daddr & 0xFFFF);
  check += ip->protocol + ntohs(udp->len);

	while ( data_len > 1 ) {
		check += ntohs(*(u_data++));
		if ( check > 0xFFFF )
			check %= 0xFFFF;
    data_len -= 2;
	}

	if ( data_len & 1 )
		check += *((uint8_t *) u_data);

	return (uint16_t) ~check;
}

int main(void) {
	const char* pk = "\x45\x00\x00\x38\x1f\xbd\x00\x00\x80\x11\x49\x27\xc0\xa8\x01\x19\x08\x08\x08\x08\xdb\xdb\x00\x35\x00\x24\x00\x00\xda\x55\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x06\x67\x6f\x6f\x67\x6c\x65\x03\x63\x6f\x6d\x00\x00\x01\x00\x01";

	struct iphdr* ip = (struct iphdr *) pk;
	struct udphdr* udp = (struct udphdr *) (pk + sizeof(struct iphdr));

	printf("udp source: %d, dest: %d\n", ntohs(udp->source), ntohs(udp->dest));
	printf("checksum: 0x%x\n", udp_checksum(ip, udp));
  printf("_checksum: 0x%x\n", ntohs(_udp_checksum(ip, udp)));
  printf("extern_checksum: 0x%x\n", ntohs(extern_udp_checksum(udp, ntohs(udp->len), ip->saddr, ip->daddr)));
	return 0;
}
