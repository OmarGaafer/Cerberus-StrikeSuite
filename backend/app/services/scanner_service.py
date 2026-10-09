import xml.etree.ElementTree as ET
from gmp import Gmp
from gmp.transport import UnixSocketTransport

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
    def start_live_scan(target_ip: str, profile: str = "full_and_fast", gmp_host: str = "127.0.0.1", username: str = "admin", password: str = "admin") -> dict:
        """
        تتصل بخادم OpenVAS/GMP وتنشئ حزمة فحص حية للهدف الموحد.
        """
        # بروفايلات الفحص الشهيرة في OpenVAS (UUIDs)
        PROFILES = {
            "full_and_fast": "d21f6c81-2b0e-4a3b-9f44-96a1d320ac42",
            "full_and_very_deep": "708e96c3-488b-4ea6-a148-a42b11d2d937",
            "discovery": "8715c877-47a0-438d-98a3-27c7a6ab2196"
        }

        config_id = PROFILES.get(profile, PROFILES["full_and_fast"])

        # ملاحظة: يتطلب وجود OpenVAS Daemon شغال ومتاح عبر Socket أو TCP
        try:
            # مثال للاتصال المباشر بخادم GMP
            # مع ملاحظة ضبط مسار الـ socket أو الـ Host وفقاً لبيئة تشغيل OpenVAS لديك
            transport = UnixSocketTransport(path="/run/gvmd/gvmd.sock")
            with Gmp(transport=transport) as gmp:
                gmp.authenticate(username, password)

                # 1. إنشاء الهدف Target
                target_response = gmp.create_target(
                    name=f"Target-{target_ip}",
                    hosts=[target_ip],
                    port_list_id="730ec051-7389-4089-b5eb-729930f7e1b5"  # All IANA assigned
                )
                target_id = target_response.get("id")

                # 2. إنشاء مهمة الفحص Task
                task_response = gmp.create_task(
                    name=f"Scan-{target_ip}",
                    config_id=config_id,
                    target_id=target_id,
                    scanner_id="08b69003-5fc2-4037-a479-93b440211c73" # OpenVAS Default Scanner
                )
                task_id = task_response.get("id")

                # 3. بدء عملية الفحص
                start_response = gmp.start_task(task_id)
                report_id = start_response.find("report_id").text

                return {
                    "status": "started",
                    "target": target_ip,
                    "profile": profile,
                    "task_id": task_id,
                    "report_id": report_id
                }
        except Exception as e:
            # في حال عدم وجود سيرفر OpenVAS شغال محلياً
            raise RuntimeError(f"فشل الاتصال بخادم OpenVAS/GMP: {str(e)}")
