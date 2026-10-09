import subprocess
import json
import tempfile
import os

class ScannerService:
    @staticmethod
    def run_nuclei_scan(target_url: str) -> dict:
        """
        تقوم بتشغيل فحص أمني باستخدام Nuclei وتستخرج مخرجات منظمة وقوية للثغرات المكتشفة.
        """
        if not target_url.startswith("http"):
            target_url = f"https://{target_url}"

        results = {
            "target": target_url,
            "status": "success",
            "total_vulnerabilities": 0,
            "findings": []
        }

        # استخدام ملف مؤقت لحفظ النتائج بصيغة JSON
        with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as temp_output:
            temp_output_path = temp_output.name

        try:
            # أمر تشغيل Nuclei وتوجيه المخرجات إلى ملف JSON
            # ملاحظة: يتطلب وجود أداة nuclei مثبتة كأداة سطر قيادة خفيفة
            command = ["nuclei", "-u", target_url, "-json", "-o", temp_output_path]
            
            # تنفيذ الأمر بمهلة زمنية لتجنب التعليق
            process = subprocess.run(command, capture_output=True, text=True, timeout=30)
            
            if process.returncode != 0 and not os.path.exists(temp_output_path):
                return {
                    "target": target_url,
                    "status": "error",
                    "message": "فشل تنفيذ أداة الفحص. تأكد من تثبيت nuclei على الجهاز."
                }

            # قراءة النتائج المخرجة من ملف الـ JSON
            if os.path.exists(temp_output_path):
                with open(temp_output_path, "r", encoding="utf-8") as f:
                    for line in f:
                        if line.strip():
                            data = json.loads(line)
                            results["findings"].append({
                                "template_id": data.get("template-id", "Unknown"),
                                "name": data.get("info", {}).get("name", "Vulnerability"),
                                "severity": data.get("info", {}).get("severity", "info"),
                                "matched_at": data.get("matched-at", target_url),
                                "description": data.get("info", {}).get("description", "")
                            })
                
                results["total_vulnerabilities"] = len(results["findings"])

        except subprocess.TimeoutExpired:
            results["status"] = "timeout"
            results["message"] = "انتهت مهلة الفحص المسموحة."
        except Exception as e:
            results["status"] = "error"
            results["message"] = str(e)
        finally:
            # تنظيف الملف المؤقت
            if os.path.exists(temp_output_path):
                os.remove(temp_output_path)

        return results
