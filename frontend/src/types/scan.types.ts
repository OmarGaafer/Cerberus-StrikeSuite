export type ScanType =
  | 'host_discovery' | 'ping_sweep' | 'arp_scan'
  | 'tcp_syn' | 'tcp_connect' | 'tcp_ack' | 'tcp_fin' | 'tcp_null' | 'tcp_xmas'
  | 'udp' | 'sctp_init' | 'ip_protocol' | 'idle'
  | 'service' | 'os'
  | 'script_vuln' | 'script_auth' | 'script_brute' | 'script_discovery' | 'script_exploit'
  | 'quick' | 'full' | 'aggressive' | 'intense' | 'comprehensive' | 'stealth' | 'pentest'
  | 'traceroute' | 'custom';

export const SCAN_TYPE_LABELS: Record<ScanType, string> = {
  host_discovery: 'Host Discovery',
  ping_sweep: 'Ping Sweep',
  arp_scan: 'ARP Scan',
  tcp_syn: 'TCP SYN Scan',
  tcp_connect: 'TCP Connect Scan',
  tcp_ack: 'TCP ACK Scan',
  tcp_fin: 'TCP FIN Scan',
  tcp_null: 'TCP NULL Scan',
  tcp_xmas: 'TCP Xmas Scan',
  udp: 'UDP Scan',
  sctp_init: 'SCTP INIT Scan',
  ip_protocol: 'IP Protocol Scan',
  idle: 'Idle Scan',
  service: 'Service Detection',
  os: 'OS Detection',
  script_vuln: 'NSE Vulnerability Scan',
  script_auth: 'NSE Auth Scan',
  script_brute: 'NSE Brute Scan',
  script_discovery: 'NSE Discovery Scan',
  script_exploit: 'NSE Exploit Scan',
  quick: 'Quick Scan',
  full: 'Full Port Scan',
  aggressive: 'Aggressive Scan',
  intense: 'Intense Scan',
  comprehensive: 'Comprehensive Scan',
  stealth: 'Stealth Scan',
  pentest: 'Pentest Scan',
  traceroute: 'Traceroute',
  custom: 'Custom',
};
