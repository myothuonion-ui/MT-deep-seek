"""API boundary for the persistent Web assessment worker."""
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import PlainTextResponse
from adapters.base import AdapterPolicyError
from core.web_assessment import AssessmentError


def assessment_router(service):
    router = APIRouter(prefix="/api/web-assessments", tags=["Web assessments"])

    def call(function, *args):
        try:
            return function(*args)
        except (AssessmentError, AdapterPolicyError, ValueError, TypeError, KeyError) as exc:
            if isinstance(exc, AssessmentError) and str(exc) == "Assessment not found":
                raise HTTPException(404, "Assessment not found") from exc
            # Don't echo malformed user data or credentials in errors.
            raise HTTPException(400, "Invalid assessment input or state; check scope, budgets and account references") from exc

    @router.get("")
    async def list_assessments():
        return {"assessments": service.list()}

    @router.post("", status_code=202)
    async def create_assessment(request: Request):
        raw = bytearray()
        async for chunk in request.stream():
            raw.extend(chunk)
            if len(raw) > 6_000_000:
                raise HTTPException(413, "Assessment input exceeds 6 MB")
        import json
        try:
            payload = json.loads(raw)
        except (ValueError, UnicodeError) as exc:
            raise HTTPException(400, "Invalid JSON") from exc
        return call(service.create, payload)

    @router.get("/{job_id}")
    async def get_assessment(job_id: str):
        return call(service.get, job_id)

    @router.post("/{job_id}/cancel")
    async def cancel_assessment(job_id: str):
        return call(service.cancel, job_id)

    @router.post("/{job_id}/resume")
    async def resume_assessment(job_id: str):
        return call(service.resume, job_id)

    @router.post("/{job_id}/retest", status_code=202)
    async def retest_assessment(job_id: str):
        previous = call(service.get, job_id)
        if previous["state"] not in {"completed", "partial", "cancelled"}:
            raise HTTPException(409, "Wait for the previous assessment to finish")
        spec = dict(previous["spec"])
        spec.pop("source_analysis", None)
        # The original explicit authorization applies to the same immutable
        # target/checks. Global scope is still revalidated by create().
        return call(service.create, spec)

    @router.get("/{job_id}/report", response_class=PlainTextResponse)
    async def assessment_report(job_id: str):
        report = call(service.report, job_id)
        return PlainTextResponse(report, media_type="text/markdown", headers={
            "Content-Disposition": f'attachment; filename="mt-web-{job_id}.md"',
            "X-Content-Type-Options": "nosniff",
        })

    return router
