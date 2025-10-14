import random
import time
import json
from collections import deque
from datetime import datetime

class CircularBuffer:
    """Circular Buffer for storing recent packets (DSA: Circular Buffer)"""
    def __init__(self, capacity=1000):
        self.capacity = capacity
        self.buffer = [None] * capacity
        self.head = 0
        self.tail = 0
        self.size = 0
    
    def add(self, packet):
        """Add a packet to the buffer"""
        self.buffer[self.tail] = packet
        self.tail = (self.tail + 1) % self.capacity
        
        if self.size == self.capacity:
            self.head = (self.head + 1) % self.capacity
        else:
            self.size += 1
    
    def get_recent(self, count=10):
        """Get most recent packets (DSA: Buffer traversal)"""
        if count > self.size:
            count = self.size
        
        result = []
        current = (self.tail - 1) % self.capacity
        
        for _ in range(count):
            if self.buffer[current] is not None:
                result.append(self.buffer[current])
            current = (current - 1) % self.capacity
            if current == self.head:
                break
        
        return result
    
    def __len__(self):
        return self.size

class ProtocolAnalyzer:
    """Analyze protocols using Hash Tables (DSA: Hash Table)"""
    def __init__(self):
        self.protocol_count = {}
        self.source_stats = {}
        self.destination_stats = {}
    
    def add_packet(self, packet):
        """Update protocol and address statistics"""
        # Count protocols
        protocol = packet.get('protocol', 'UNKNOWN')
        self.protocol_count[protocol] = self.protocol_count.get(protocol, 0) + 1
        
        # Count source addresses
        src = packet.get('source_ip', 'UNKNOWN')
        if src not in self.source_stats:
            self.source_stats[src] = {'count': 0, 'protocols': set()}
        self.source_stats[src]['count'] += 1
        self.source_stats[src]['protocols'].add(protocol)
        
        # Count destination addresses
        dst = packet.get('destination_ip', 'UNKNOWN')
        if dst not in self.destination_stats:
            self.destination_stats[dst] = {'count': 0, 'protocols': set()}
        self.destination_stats[dst]['count'] += 1
        self.destination_stats[dst]['protocols'].add(protocol)
    
    def get_top_protocols(self, n=5):
        """Get top N protocols by count"""
        return sorted(self.protocol_count.items(), key=lambda x: x[1], reverse=True)[:n]
    
    def get_top_sources(self, n=5):
        """Get top N source IPs"""
        return sorted(self.source_stats.items(), key=lambda x: x[1]['count'], reverse=True)[:n]
    
    def get_top_destinations(self, n=5):
        """Get top N destination IPs"""
        return sorted(self.destination_stats.items(), key=lambda x: x[1]['count'], reverse=True)[:n]

class PacketTree:
    """Tree structure for organizing packets hierarchically (DSA: Tree)"""
    class TreeNode:
        def __init__(self, key, packet=None):
            self.key = key
            self.packets = []
            self.children = {}
            if packet:
                self.packets.append(packet)
    
    def __init__(self):
        self.root = self.TreeNode("root")
    
    def add_packet_by_hierarchy(self, packet, hierarchy_keys):
        """Add packet to tree based on hierarchy (e.g., [protocol, source_ip])"""
        current = self.root
        
        for key in hierarchy_keys:
            hierarchy_value = packet.get(key, 'unknown')
            if hierarchy_value not in current.children:
                current.children[hierarchy_value] = self.TreeNode(hierarchy_value)
            current = current.children[hierarchy_value]
        
        current.packets.append(packet)
    
    def print_tree(self, node=None, level=0):
        """Print tree structure (DFS traversal)"""
        if node is None:
            node = self.root
        
        indent = "  " * level
        print(f"{indent}└─ {node.key} ({len(node.packets)} packets)")
        
        for child in node.children.values():
            self.print_tree(child, level + 1)

class NetworkPacketAnalyzer:
    """Main analyzer class integrating all DSA components"""
    
    def __init__(self, buffer_capacity=1000):
        self.packet_buffer = CircularBuffer(buffer_capacity)
        self.protocol_analyzer = ProtocolAnalyzer()
        self.packet_tree = PacketTree()
        self.packet_count = 0
        self.start_time = datetime.now()
        
        # Common data for packet generation
        self.protocols = ['TCP', 'UDP', 'HTTP', 'HTTPS', 'DNS', 'ICMP', 'SSH']
        self.source_ips = [f'192.168.1.{i}' for i in range(1, 50)]
        self.destination_ips = [
            '8.8.8.8', '1.1.1.1', '151.101.1.69', '142.250.181.174',
            '13.107.42.14', '104.16.249.249', '192.168.1.1'
        ]
        self.ports = [80, 443, 22, 53, 25, 110, 993, 995]
    
    def generate_sample_packet(self):
        """Generate a sample network packet for simulation"""
        protocol = random.choice(self.protocols)
        source_ip = random.choice(self.source_ips)
        dest_ip = random.choice(self.destination_ips)
        
        packet = {
            'timestamp': datetime.now(),
            'protocol': protocol,
            'source_ip': source_ip,
            'destination_ip': dest_ip,
            'source_port': random.choice(self.ports),
            'destination_port': random.choice(self.ports),
            'packet_size': random.randint(64, 1500),
            'flags': random.choice(['SYN', 'ACK', 'FIN', 'PSH', 'RST']),
            'sequence_number': random.randint(1000, 9999),
            'id': self.packet_count
        }
        
        self.packet_count += 1
        return packet
    
    def process_packet(self, packet):
        """Process a single packet through all analyzers"""
        # Add to circular buffer
        self.packet_buffer.add(packet)
        
        # Update protocol statistics
        self.protocol_analyzer.add_packet(packet)
        
        # Add to tree (organized by protocol -> source_ip)
        self.packet_tree.add_packet_by_hierarchy(packet, ['protocol', 'source_ip'])
    
    def start_capture(self, duration=30, packet_rate=10):
        """Start simulated packet capture"""
        print(f"🚀 Starting packet capture for {duration} seconds...")
        print(f"📦 Target rate: {packet_rate} packets/second")
        print("-" * 60)
        
        end_time = time.time() + duration
        packets_captured = 0
        
        try:
            while time.time() < end_time:
                # Generate and process packets
                packets_this_second = random.randint(packet_rate//2, packet_rate*2)
                
                for _ in range(packets_this_second):
                    packet = self.generate_sample_packet()
                    self.process_packet(packet)
                    packets_captured += 1
                
                # Display real-time stats every 2 seconds
                if int(time.time()) % 2 == 0:
                    self.display_realtime_stats(packets_captured)
                
                time.sleep(1)  # Simulate real-time capture
                
        except KeyboardInterrupt:
            print("\n⏹️  Capture stopped by user")
        
        print("\n" + "="*60)
        print("📊 CAPTURE COMPLETE - FINAL ANALYSIS")
        print("="*60)
        self.display_comprehensive_analysis()
    
    def display_realtime_stats(self, total_packets):
        """Display real-time statistics"""
        recent_packets = self.packet_buffer.get_recent(5)
        
        print(f"\n🕒 {datetime.now().strftime('%H:%M:%S')} | "
              f"Total: {total_packets} packets | "
              f"Buffer: {len(self.packet_buffer)}/{self.packet_buffer.capacity}")
        
        if recent_packets:
            print("📨 Recent packets:")
            for packet in reversed(recent_packets):
                print(f"   {packet['protocol']}: {packet['source_ip']}:{packet['source_port']} → "
                      f"{packet['destination_ip']}:{packet['destination_port']} "
                      f"({packet['packet_size']} bytes)")
    
    def display_comprehensive_analysis(self):
        """Display comprehensive analysis using all DSA components"""
        # Protocol Analysis
        print("\n🔍 PROTOCOL ANALYSIS (Hash Table Statistics):")
        print("-" * 40)
        top_protocols = self.protocol_analyzer.get_top_protocols()
        for protocol, count in top_protocols:
            percentage = (count / self.packet_count) * 100
            print(f"   {protocol:8} : {count:4} packets ({percentage:5.1f}%)")
        
        # Source IP Analysis
        print("\n🌐 TOP SOURCE IPs (Hash Table Analysis):")
        print("-" * 40)
        top_sources = self.protocol_analyzer.get_top_sources(5)
        for ip, stats in top_sources:
            print(f"   {ip:15} : {stats['count']:4} packets")
        
        # Destination IP Analysis
        print("\n🎯 TOP DESTINATION IPs:")
        print("-" * 40)
        top_destinations = self.protocol_analyzer.get_top_destinations(5)
        for ip, stats in top_destinations:
            print(f"   {ip:15} : {stats['count']:4} packets")
        
        # Packet Tree Structure
        print("\n🌳 PACKET TREE STRUCTURE (Tree Data Structure):")
        print("-" * 40)
        self.packet_tree.print_tree()
        
        # Buffer Statistics
        print(f"\n💾 CIRCULAR BUFFER STATISTICS:")
        print("-" * 40)
        print(f"   Buffer usage: {len(self.packet_buffer)}/{self.packet_buffer.capacity}")
        print(f"   Total packets processed: {self.packet_count}")
        
        # Performance Metrics
        capture_duration = (datetime.now() - self.start_time).total_seconds()
        packets_per_second = self.packet_count / capture_duration if capture_duration > 0 else 0
        print(f"\n📈 PERFORMANCE METRICS:")
        print("-" * 40)
        print(f"   Capture duration: {capture_duration:.1f} seconds")
        print(f"   Packets per second: {packets_per_second:.1f}")
        print(f"   Memory efficiency: Excellent (fixed buffer size)")
    
    def search_packets(self, criteria):
        """Search packets based on criteria (DSA: Linear Search in Buffer)"""
        print(f"\n🔎 SEARCHING PACKETS: {criteria}")
        print("-" * 40)
        
        matches = []
        recent_packets = self.packet_buffer.get_recent(len(self.packet_buffer))
        
        for packet in recent_packets:
            match = True
            for key, value in criteria.items():
                if key in packet and str(packet[key]) != str(value):
                    match = False
                    break
            if match:
                matches.append(packet)
        
        print(f"Found {len(matches)} matching packets:")
        for i, packet in enumerate(matches[:10]):  # Show first 10 matches
            print(f"  {i+1}. {packet['protocol']}: {packet['source_ip']} → {packet['destination_ip']}")
        
        if len(matches) > 10:
            print(f"  ... and {len(matches) - 10} more")
        
        return matches

def main():
    """Main function to demonstrate the packet analyzer"""
    analyzer = NetworkPacketAnalyzer(buffer_capacity=500)
    
    print("🚀 NETWORK PACKET ANALYZER - DSA MINI PROJECT")
    print("=" * 60)
    print("This simulator demonstrates:")
    print("• Circular Buffer - For storing recent packets efficiently")
    print("• Hash Tables - For protocol and IP statistics")
    print("• Tree Structures - For hierarchical packet organization")
    print("• Searching Algorithms - For packet analysis")
    print("=" * 60)
    
    # Start the capture
    analyzer.start_capture(duration=20, packet_rate=15)
    
    # Demonstrate search functionality
    print("\n" + "=" * 60)
    print("🔍 DEMONSTRATING SEARCH FUNCTIONALITY")
    print("=" * 60)
    
    # Search for TCP packets
    analyzer.search_packets({'protocol': 'TCP'})
    
    # Search for packets from a specific IP
    analyzer.search_packets({'source_ip': '192.168.1.1'})
    
    print("\n" + "=" * 60)
    print("✅ ANALYSIS COMPLETE!")
    print("This project demonstrates real-world application of:")
    print("• Circular Buffer for memory-efficient storage")
    print("• Hash Tables for O(1) lookups and statistics")
    print("• Tree Structures for hierarchical data organization")
    print("• Efficient searching and traversal algorithms")
    print("=" * 60)

if __name__ == "__main__":
    main()