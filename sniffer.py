from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP, get_if_list
from datetime import datetime
from collections import deque
import threading

PORT_SERVICES = {
    20:"FTP-DATA", 21:"FTP", 22:"SSH", 23:"TELNET", 25:"SMTP",
    53:"DNS", 67:"DHCP", 68:"DHCP", 69:"TFTP", 80:"HTTP",
    110:"POP3", 123:"NTP", 135:"RPC", 143:"IMAP", 161:"SNMP",
    179:"BGP", 389:"LDAP", 443:"HTTPS", 445:"SMB", 465:"SMTPS",
    514:"SYSLOG", 587:"SMTP", 636:"LDAPS", 993:"IMAPS", 995:"POP3S",
    1080:"SOCKS", 1194:"OpenVPN", 1433:"MSSQL", 1521:"Oracle",
    1723:"PPTP", 3000:"Dev-Server", 3306:"MySQL", 3389:"RDP",
    4444:"Metasploit", 5000:"Flask", 5432:"PostgreSQL", 5900:"VNC",
    6379:"Redis", 6881:"BitTorrent", 8080:"HTTP-Alt", 8443:"HTTPS-Alt",
    8888:"Jupyter", 9200:"Elasticsearch", 27017:"MongoDB", 32400:"Plex"
}

class PacketSniffer:
    def __init__(self):
        self.packets      = deque(maxlen=5000)
        self.is_running   = False
        self.packet_id    = 1
        self.lock         = threading.Lock()
        self.sniff_thread = None

    def start(self, interface=None):
        if self.is_running:
            return
        self.is_running = True
        self.packets.clear()
        self.packet_id  = 1
        self.sniff_thread = threading.Thread(
            target=self._sniff_worker, args=(interface,), daemon=True)
        self.sniff_thread.start()

    def stop(self):
        self.is_running = False

    def _sniff_worker(self, interface):
        try:
            sniff(iface=interface, prn=self._process_packet,
                  stop_filter=lambda p: not self.is_running, store=False)
        except Exception as e:
            print(f"[Sniffer] Error: {e}")
            print("[Sniffer] Run as Administrator + install Npcap")
            self.is_running = False

    def _process_packet(self, packet):
        src_ip = dst_ip = ""
        ttl = 0
        flags = "---"
        src_port = dst_port = 0

        if packet.haslayer(IP):
            src_ip, dst_ip, ttl = packet[IP].src, packet[IP].dst, packet[IP].ttl
        elif packet.haslayer(IPv6):
            src_ip, dst_ip, ttl = packet[IPv6].src, packet[IPv6].dst, packet[IPv6].hlim
        else:
            return

        if packet.haslayer(TCP):
            protocol = "TCP"
            src_port, dst_port = packet[TCP].sport, packet[TCP].dport
            flag_map = {0x02:"SYN", 0x10:"ACK", 0x12:"SYN-ACK",
                        0x18:"PSH-ACK", 0x01:"FIN", 0x04:"RST", 0x11:"FIN-ACK"}
            flags = flag_map.get(int(packet[TCP].flags), str(packet[TCP].flags))
        elif packet.haslayer(UDP):
            protocol = "UDP"
            src_port, dst_port = packet[UDP].sport, packet[UDP].dport
        elif packet.haslayer(ICMP):
            protocol = "ICMP"
        else:
            return

        service = "ICMP-PING" if protocol == "ICMP" else (
            PORT_SERVICES.get(dst_port) or PORT_SERVICES.get(src_port) or "UNKNOWN")

        with self.lock:
            self.packets.append({
                "id":          self.packet_id,
                "time":        datetime.now().strftime("%H:%M:%S.%f")[:12],
                "src_ip":      src_ip,
                "dst_ip":      dst_ip,
                "protocol":    protocol,
                "src_port":    src_port,
                "dst_port":    dst_port,
                "packet_size": len(packet),
                "service":     service,
                "ttl":         ttl,
                "flags":       flags
            })
            self.packet_id += 1

    @staticmethod
    def list_interfaces():
        return get_if_list()

sniffer = PacketSniffer()