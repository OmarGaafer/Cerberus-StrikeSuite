from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from app.services.scanner_service import ScannerService

router = APIRouter()

class NucleiScanRequest(BaseModel):
    target: str = Field(..., example="pua.edu.eg", description="Target URL or Domain")

@router.post("/scan")
async def start_nuclei_scan(request: NucleiScanRequest):
    """
    مسار فحص أمني متقدم باستخدام محرك Nuclei لإرجاع تقرير ثغرات قوي ومنظم.
    """
    try:
        scan_results = ScannerService.run_nuclei_scan(request.target)
        return {
            "message": "تم تنفيذ الفحص الأمني بنجاح",
            "data": scan_results
        }
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"حدث خطأ أثناء تشغيل الفحص: {str(e)}"
        )
