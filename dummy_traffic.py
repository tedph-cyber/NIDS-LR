from scapy.all import IP, TCP, wrpcap

# Create a list to store packets
packets = []

# Generate some dummy packets
for i in range(10):
    packet = IP(dst="192.168.1.1", src="192.168.1.2")/TCP(dport=80, sport=1024+i)
    packets.append(packet)

# Write the packets to a pcap file
wrpcap('dummy_traffic.pcap', packets)

print("Dummy pcap file 'dummy_traffic.pcap' created successfully.")

