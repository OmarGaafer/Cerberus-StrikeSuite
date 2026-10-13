/**
 * Nmap Scanning API client.
 */
import axiosInstance from './axiosInstance';

export type ScanType =
  | 'host_discovery' | 'ping_sweep' | 'arp_scan'
  | 'tcp_syn' | 'tcp_connect' | 'tcp_ack' | 'tcp_fin' | 'tcp_null' | 'tcp_xmas'
  | 'udp' | 'sctp_init' | 'ip_protocol' | 'idle'
  | 'service' | 'os'
  | 'script_vuln' | 'script_auth' | 'script_brute' | 'script_discovery' | 'script_exploit'
  | 'quick' | 'full' | 'aggressive' | 'intense' | 'comprehensive' | 'stealth' | 'pentest'
  | 'traceroute' | 'custom';

export interface ScanRequest {
  target: string;
  scan_type: ScanType;
  ports?: string;
  custom_args?: string;
  timing?: string;
  scripts?: string[];
  script_args?: Record<string, string>;
  exclude?: string;
  engagement_id?: string;
  roe_acknowledged: boolean;
}

export interface PortResult {
  port: number;
  protocol: string;
  state: string;
  reason?: string;
  service?: string;
  product?: string;
  version?: string;
  extrainfo?: string;
  cpe?: string[];
  scripts?: Record<string, string>;
}

export interface HostResult {
  ip: string;
  mac?: string;
  vendor?: string;
  hostname?: string;
  state: string;
  os_matches?: Array<{ name: string; accuracy: string }>;
  ports?: PortResult[];
  host_scripts?: Record<string, string>;
  traceroute?: Array<Record<string, string>>;
}

export interface ScanResponse {
  scan_id: string;
  status: string;
  target: string;
  command?: string;
  elapsed?: number;
  nmap_version?: string;
  hosts_count?: number;
  error?: string;
  hosts?: HostResult[];
}

export const scanApi = {
  listTypes: async (): Promise<string[]> => {
    const { data } = await axiosInstance.get('/scanning/types/available');
    return data;
  },

  startScan: async (req: ScanRequest): Promise<ScanResponse> => {
    const { data } = await axiosInstance.post('/scanning/nmap', req);
    return data;
  },

  getScan: async (scanId: string): Promise<ScanResponse> => {
    const { data } = await axiosInstance.get(`/scanning/${scanId}`);
    return data;
  },

  listScans: async (limit: number = 50): Promise<any[]> => {
    const { data } = await axiosInstance.get(`/scanning/?limit=${limit}`);
    return data;
  },
};

export default scanApi;
