import xml.etree.ElementTree as ET
from typing import List, Dict, Any

class ScannerService:
    @staticmethod
    def parse_openvas_xml(xml_content: str) -> List[Dict[str, Any]]:
        """
        تحليل تقرير OpenVAS XML واستخراج الثغرات والمنافذ بدقة عالية.
        """
        vulnerabilities = []
        try:
            root = ET.fromstring(xml_content)
            for result in root.findall(".//result"):
                name = result.find("name")
                host = result.find("host")
                severity = result.find("severity")
                description = result.find("description")
                
                vulnerabilities.append({
                    "vulnerability": name.text if name is not None else "Unknown",
                    "host": host.text if host is not None else "Unknown",
                    "severity": float(severity.text) if severity is not None else 0.0,
                    "description": description.text if description is not None else ""
                })
        except Exception as e:
            print(f"Error parsing OpenVAS report: {e}")
            
        return vulnerabilities
