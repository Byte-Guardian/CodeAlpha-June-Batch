#c𝗼𝗱𝗲𝗮𝗹𝗽𝗵𝗮_𝘁𝗮𝘀𝗸𝘀 

from scapy.all import sniff, Packet

def analyze_packet(packet):
  """Analyzes a captured packet and prints basic information"""
  # Check if the packet has an IP layer
  if packet.haslayer('IP'):
    # Extract source and destination IP addresses
    src_ip = packet[packet.getlayer('IP')].src
    dst_ip = packet[packet.getlayer('IP')].dst

    # Check for specific protocols (e.g., TCP, UDP)
    if packet.haslayer('TCP'):
      protocol = 'TCP'
      src_port = packet[packet.getlayer('TCP')].sport
      dst_port = packet[packet.getlayer('TCP')].dport
    elif packet.haslayer('UDP'):
      protocol = 'UDP'
      src_port = packet[packet.getlayer('UDP')].sport
      dst_port = packet[packet.getlayer('UDP')].dport
    else:
      protocol = 'Other'
      src_port = None
      dst_port = None

    # Print basic information about the packet
    print(f"Protocol: {protocol}")
    print(f"Source IP: {src_ip}")
    print(f"Destination IP: {dst_ip}")
    if src_port and dst_port:
      print(f"Source Port: {src_port}")
      print(f"Destination Port: {dst_port}")
    print('-'*20)

def main():
  """Sniffs packets and calls analyze_packet function"""
  # Specify network interface (optional, defaults to first)
  # iface = 'eth0'  # Replace with your desired interface
  sniff(iface=None, prn=analyze_packet)  # Capture packets on all interfaces

if __name__ == "__main__":
  main()


