"""
API v1 Router — Aggregates all endpoint routers under /api/v1.
"""

from fastapi import APIRouter

from app.api.v1.endpoints import (
    admin,
    ai_conversation,
    attack_planning,
    auth,
    dashboard,
    defense,
    documents,
    engagements,
    notifications,
    osint,
    red_team,
    reports,
    risk_assessment,
    rules_of_engagement,
    scanner,
    scanning,
    scope,
    users,
)

api_v1_router = APIRouter()

api_v1_router.include_router(auth.router, prefix="/auth", tags=["Authentication"])
api_v1_router.include_router(users.router, prefix="/users", tags=["Users"])
api_v1_router.include_router(engagements.router, prefix="/engagements", tags=["Engagements"])
api_v1_router.include_router(ai_conversation.router, prefix="/ai", tags=["AI Conversation"])
api_v1_router.include_router(scope.router, prefix="/scope", tags=["Scope of Engagement"])
api_v1_router.include_router(rules_of_engagement.router, prefix="/rules", tags=["Rules of Engagement"])
api_v1_router.include_router(documents.router, prefix="/documents", tags=["Documents"])
api_v1_router.include_router(osint.router, prefix="/osint", tags=["OSINT"])
api_v1_router.include_router(attack_planning.router, prefix="/attack-planning", tags=["Attack Planning"])
api_v1_router.include_router(red_team.router, prefix="/red-team", tags=["Red Team"])
api_v1_router.include_router(risk_assessment.router, prefix="/risk-assessment", tags=["Risk Assessment"])
api_v1_router.include_router(reports.router, prefix="/reports", tags=["Reports"])
api_v1_router.include_router(dashboard.router, prefix="/dashboard", tags=["Dashboard"])
api_v1_router.include_router(notifications.router, prefix="/notifications", tags=["Notifications"])
api_v1_router.include_router(defense.router, prefix="/defense", tags=["Blue Team Defense"])
api_v1_router.include_router(scanner.router, prefix="/scanner", tags=["OpenVAS Scanner"])
api_v1_router.include_router(scanning.router, tags=["Nmap Scanner"])
api_v1_router.include_router(admin.router, prefix="/admin", tags=["Admin"])
