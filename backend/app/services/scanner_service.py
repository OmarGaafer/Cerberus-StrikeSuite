from fastapi import APIRouter, UploadFile, File, HTTPException
from app.services.scanner_service import ScannerService

router = APIRouter()

@router.post("/parse-report")
async def parse_openvas_report_endpoint(file: UploadFile = File(...)):
    """
    مسار API لرفع تقرير OpenVAS XML وتحليله واستخراج الثغرات والمنافذ برمجياً.
    """
    if not file.filename.endswith(".xml"):
        raise HTTPException(
            status_code=400, 
            detail="يجب رفع ملف تقرير بامتداد XML حصراً."
        )
    
    try:
        content = await file.read()
        xml_text = content.decode("utf-8")
        
        # استدعاء دالة التحليل من ScannerService
        vulnerabilities = ScannerService.parse_openvas_xml(xml_text)
        
        return {
            "filename": file.filename,
            "total_findings": len(vulnerabilities),
            "vulnerabilities": vulnerabilities
        }
    except Exception as e:
        raise HTTPException(
            status_code=500, 
            detail=f"حدث خطأ أثناء معالجة الملف: {str(e)}"
        )
