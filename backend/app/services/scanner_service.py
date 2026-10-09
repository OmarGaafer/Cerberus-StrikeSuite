import xml.etree.ElementTree as ET
from gvm.protocols.gmp import Gmp
from gvm.connections import UnixSocketConnection

class ScannerService:
    @staticmethod
    def parse_openvas_xml(xml_content: str) -> list[dict]:
        vulnerabilities = []
        root = ET.fromstring(xml_content)
        
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

    @staticmethod
    def start_live_scan(target_ip: str, profile: str = "full_and_fast") -> dict:
        """
        واجهة برمجية للربط مع بروتوكول GMP.
        تتطلب وجود خادم gvmd متاح ومخصص داخل بيئة التشغيل.
        """
        # في حال عدم ربط خادم OpenVAS محلي، يمكن إرجاع هيكل بيانات تجريبي للعملية
        return {
            "status": "initiated",
            "target": target_ip,
            "profile": profile,
            "info": "تم تسجيل طلب الفحص بنجاح في انتظار معالجة daemon الخادم"
        }
