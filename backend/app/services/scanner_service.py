import xml.etree.ElementTree as ET

class ScannerService:
    @staticmethod
    def parse_openvas_xml(xml_content: str) -> list[dict]:
        """
        Parses OpenVAS XML report content and extracts vulnerability findings.
        """
        vulnerabilities = []
        root = ET.fromstring(xml_content)
        
        # Traverse results in OpenVAS XML format
        for result in root.findall(".//result"):
            name = result.findtext("name", "Unknown Vulnerability")
            severity = result.findtext("severity", "0.0")
            host = result.findtext("host", "Unknown")
            port = result.findtext("port", "Unknown")
            description = result.findtext("description", "")
            
            vulnerabilities.append({
                "name": name,
                "severity": float(severity) if severity else 0.0,
                "host": host,
                "port": port,
                "description": description,
            })
            
        return vulnerabilities
