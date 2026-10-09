from fastapi import APIRouter, UploadFile, File, HTTPException, Query
from pydantic import BaseModel, Field
from app.services.scanner_service import ScannerService

router = APIRouter()

class LiveScanRequest(BaseModel):
    target: str = Field(..., example="192.168.1.100", description="IP Target or Domain")
    profile: str = Field("full_and_very_deep", example="full_and_very_deep", description="full_and_fast | full_and_very_deep | discovery")

@router.post("/parse-report")
async def parse_openvas_report_endpoint(file: UploadFile = File(...)):
    if not file.filename.endswith(".xml"):
        raise HTTPException(
            status_code=400, 
            detail="يجب رفع ملف تقرير بامتداد XML حصراً."
        )
    
    try:
        content = await file.read()
        xml_text = content.decode("utf-8")
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

@router.post("/scan")
async def start_live_openvas_scan(request: LiveScanRequest):
    """
    مسار API لإرسال أمر فحص حي إلى خادم OpenVAS المباشر بأسلوب Full / Deep Scan.
    """
    try:
        result = ScannerService.start_live_scan(
            target_ip=request.target,
            profile=request.profile
        )
        return {
            "message": "تم بدء الفحص الحي بنجاح على OpenVAS",
            "data": result
        }
    except RuntimeError as e:
        raise HTTPException(
            status_code=503,
            detail=str(e)
        )
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"حدث خطأ غـير متوقع: {str(e)}"
        )
