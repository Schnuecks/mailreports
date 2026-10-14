# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Schnuecks
"""Web app: pages, access check, background fetch."""
from __future__ import annotations

import ipaddress
import logging
import math
import os
import re
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import quote, urlsplit

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import JSONResponse, PlainTextResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from . import __version__, accounts, i18n, queries, routes_auth, web
from .explain import explain_record
from .ingest import Outcome, ingest_payload
from .parsing import Payload
from .service import Service
from .sources import classify

logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO").upper(),
                    format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("mailreports")

_SECRET_PARAMS = re.compile(r"([?&](?:code|state|token)=)[^&\s]*")


class _MaskSecrets(logging.Filter):
    """Keeps authorization codes and state values of single sign-on out of the access log."""

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.args, tuple):
            record.args = tuple(_SECRET_PARAMS.sub(lambda m: m.group(1) + "***", a) if isinstance(a, str) else a
                                for a in record.args)
        return True


logging.getLogger("uvicorn.access").addFilter(_MaskSecrets())

MAX_UPLOAD = 20 * 1024 * 1024
# Reachable without a session (built-in accounts)
PUBLIC_PATHS = ("/static/", "/login", "/setup", "/oidc/callback", "/lang/")
# Only for admins
ADMIN_PATHS = ("/users", "/sign-ins", "/fetch", "/upload")


def create_app(service: Service | None = None) -> FastAPI:
    svc = service or Service()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        svc.start()
        yield
        svc.stop()

    app = FastAPI(title="mailreports", version=__version__, lifespan=lifespan,
                  docs_url=None, redoc_url=None, openapi_url=None)
    app.state.svc = svc
    web.setup(svc)
    app.mount("/static", StaticFiles(directory=str(Path(__file__).parent / "static")), name="static")
    settings = svc.settings

    # ------------------------------------------------------------ access and language

    @app.middleware("http")
    async def guard(request: Request, call_next):
        path = request.url.path
        if path == "/healthz":
            return await call_next(request)
        if settings.trusted_proxies:
            try:
                addr = ipaddress.ip_address(web.client_ip(request))
            except ValueError:
                addr = None
            if addr is None or not any(addr in net for net in settings.trusted_proxies):
                return PlainTextResponse("Forbidden", status_code=403)
        i18n.set_language(i18n.pick_language(request.cookies.get("lang"), settings.default_language,
                                             request.headers.get("accept-language")))
        request.state.user, request.state.account, request.state.is_admin = "", None, False
        if request.method == "POST" and not same_origin(request):
            return PlainTextResponse("Forbidden: cross-site request", status_code=403)
        if settings.auth_header:
            user = request.headers.get(settings.auth_header, "").strip()
            if not user:
                return PlainTextResponse("Unauthorized: no login information from the proxy", status_code=401)
            if settings.allowed_groups:
                groups = {g.strip() for g in request.headers.get("Remote-Groups", "").split(",")}
                if not groups & set(settings.allowed_groups):
                    return PlainTextResponse("Forbidden: not in an allowed group", status_code=403)
            request.state.user = request.headers.get("Remote-Name", "").strip() or user
            request.state.is_admin = True
        elif settings.auth_disabled:
            request.state.is_admin = True
        else:
            with svc.db.connect() as con:
                acc = accounts.resolve_session(con, request.cookies.get(web.session_cookie(request, settings), ""))
                no_users = acc is None and not accounts.has_users(con)
            if acc is not None:
                request.state.account = acc
                request.state.user = acc["display_name"] or acc["username"]
                request.state.is_admin = bool(acc["is_admin"])
            elif not path.startswith(PUBLIC_PATHS):
                if no_users:
                    return RedirectResponse("/setup", status_code=303)
                if request.method == "GET":
                    target = path + (f"?{request.url.query}" if request.url.query else "")
                    return RedirectResponse(f"/login?next={quote(target)}", status_code=303)
                return PlainTextResponse("Unauthorized", status_code=401)
        if path.startswith(ADMIN_PATHS) and not request.state.is_admin:
            return web.render(request, "error.html", status=403,
                              message=i18n._("Für diese Seite fehlt die Berechtigung."))
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Referrer-Policy", "same-origin")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Cache-Control", "no-store")
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; img-src 'self' https: data:; style-src 'self'; script-src 'self'; "
            "frame-ancestors 'none'; form-action 'self' https:")
        return response

    def same_origin(request: Request) -> bool:
        """Form posts only from our own pages (Sec-Fetch-Site, otherwise Origin against Host)."""
        site = request.headers.get("sec-fetch-site")
        if site:
            return site in ("same-origin", "none")
        origin = request.headers.get("origin")
        return not origin or urlsplit(origin).netloc == request.headers.get("host")

    days_of, page_of, render = web.days_of, web.page_of, web.render

    def explained(records, report_rows: dict):
        """Records with classification and plain-language explanation."""
        info = svc.db.ip_info(sorted({r["source_ip"] for r in records}))
        out = []
        for r in records:
            inf = info.get(r["source_ip"])
            verdict = classify(svc.sources, r, inf)
            rep = report_rows[r["report_id"]]
            out.append({"r": r, "info": inf, "verdict": verdict, "report": rep,
                        "ex": explain_record(r, verdict, inf, rep)})
        return out

    # ------------------------------------------------------------ pages

    @app.get("/healthz")
    def healthz():
        try:
            svc.db.get_meta("schema")
        except Exception as exc:  # pragma: no cover
            return JSONResponse({"status": "error", "detail": str(exc)}, status_code=503)
        return {"status": "ok", "version": __version__}

    @app.get("/")
    def overview(request: Request):
        days = days_of(request)
        summaries = queries.domain_summaries(svc.db, days, svc.tz, settings.domains or None)
        problems = []
        found = queries.problems(svc.db, days)
        info = svc.db.ip_info(sorted({p.record["source_ip"] for p in found}))
        for p in found:
            inf = info.get(p.record["source_ip"])
            verdict = classify(svc.sources, p.record, inf)
            problems.append({"p": p, "ex": explain_record(p.record, verdict, inf, p.report)})
        return render(request, "overview.html", summaries=summaries, problems=problems,
                      counts=queries.counts(svc.db), last_fetch=svc.db.get_meta("last_fetch"),
                      fetch_error=svc.db.get_meta("last_fetch_error"), imap=settings.imap_enabled)

    @app.get("/domain/{domain}")
    def domain_page(request: Request, domain: str):
        days = days_of(request)
        domain = domain.lower()
        summaries = [s for s in queries.domain_summaries(svc.db, days, svc.tz) if s.domain == domain]
        if not summaries and domain not in queries.all_domains(svc.db):
            raise HTTPException(404)
        summary = summaries[0] if summaries else queries.DomainSummary(domain)
        sources = queries.sources_for(svc.db, svc.sources, days, domain, limit=25)
        tls = [t for t in queries.tls_overview(svc.db, days) if t["policy_domain"] == domain]
        reports, total = queries.list_reports(svc.db, days, domain=domain)
        return render(request, "domain.html", s=summary, sources=sources, tls=tls,
                      reports=reports[:10], total=total)

    @app.get("/reports")
    def reports_page(request: Request):
        days = days_of(request)
        page = page_of(request)
        domain = request.query_params.get("domain", "")
        org = request.query_params.get("org", "")
        failed = request.query_params.get("failed") == "1"
        rows, total = queries.list_reports(svc.db, days, domain, org, failed, page)
        return render(request, "reports.html", rows=rows, total=total, page=page,
                      pages=max(1, math.ceil(total / queries.PAGE_SIZE)), domain=domain, org=org,
                      failed=failed, domains=queries.all_domains(svc.db), orgs=queries.organisations(svc.db))

    @app.get("/reports/{report_id}")
    def report_page(request: Request, report_id: int):
        rep, records = queries.report_detail(svc.db, report_id)
        if not rep:
            raise HTTPException(404)
        items = explained(records, {rep["id"]: rep})
        total = sum(r["count"] for r in records)
        passed = sum(r["count"] for r in records if r["dmarc_pass"])
        return render(request, "report.html", rep=rep, items=items, total=total, passed=passed)

    @app.get("/sources")
    def sources_page(request: Request):
        days = days_of(request)
        domain = request.query_params.get("domain", "")
        rows = queries.sources_for(svc.db, svc.sources, days, domain or None)
        return render(request, "sources.html", rows=rows, domain=domain, domains=queries.all_domains(svc.db),
                      known=svc.sources)

    @app.get("/tls")
    def tls_page(request: Request):
        days = days_of(request)
        page = page_of(request)
        domain = request.query_params.get("domain", "")
        failed = request.query_params.get("failed") == "1"
        rows, total = queries.list_tls(svc.db, days, domain, failed, page)
        return render(request, "tls.html", overview=queries.tls_overview(svc.db, days), rows=rows, total=total,
                      page=page, pages=max(1, math.ceil(total / queries.PAGE_SIZE)), domain=domain, failed=failed,
                      domains=queries.all_domains(svc.db))

    @app.get("/tls/{report_id}")
    def tls_report_page(request: Request, report_id: int):
        rep, policies = queries.tls_detail(svc.db, report_id)
        if not rep:
            raise HTTPException(404)
        return render(request, "tls_report.html", rep=rep, policies=policies)

    @app.get("/help")
    def help_page(request: Request):
        return render(request, "help.html")

    @app.get("/status")
    def status_page(request: Request):
        summary = (svc.db.get_meta("last_fetch_summary") or "0|0|0|0|0").split("|")
        return render(request, "status.html", mails=queries.recent_mails(svc.db), counts=queries.counts(svc.db),
                      last_fetch=svc.db.get_meta("last_fetch"), last_ok=svc.db.get_meta("last_fetch_ok"),
                      fetch_error=svc.db.get_meta("last_fetch_error"), summary=summary,
                      notify_error=svc.db.get_meta("last_notify_error"), settings=settings,
                      geo=svc.geo, sources=svc.sources, uploaded=request.query_params.get("uploaded"))

    @app.post("/fetch")
    def fetch_now(request: Request, csrf: str = Form("")):
        if not web.check_csrf(request, csrf):
            raise HTTPException(403)
        if settings.imap_enabled:
            svc.trigger()
        return RedirectResponse("/status?triggered=1", status_code=303)

    @app.post("/upload")
    async def upload(request: Request, files: list[UploadFile] = File(...), csrf: str = Form("")):
        if not web.check_csrf(request, csrf):
            raise HTTPException(403)
        total = Outcome()
        for f in files[:50]:
            data = await f.read(MAX_UPLOAD + 1)
            if len(data) > MAX_UPLOAD:
                total.errors.append(f"{f.filename}: too large")
                continue
            total.merge(ingest_payload(svc.db, Payload(f.filename or "upload", data)))
        svc.after_import(total)
        return RedirectResponse(
            f"/status?uploaded={len(total.new_dmarc)}-{len(total.new_tls)}-{total.duplicates}-{len(total.errors)}",
            status_code=303)

    @app.get("/lang/{code}")
    def set_lang(request: Request, code: str):
        ref = urlsplit(request.headers.get("referer", ""))
        same_host = ref.netloc and ref.netloc == request.headers.get("host")
        target = (ref.path or "/") + (f"?{ref.query}" if ref.query else "") if same_host else "/"
        resp = RedirectResponse(target, status_code=303)
        if code in i18n.LANGUAGES:
            resp.set_cookie("lang", code, max_age=365 * 86400, samesite="lax", httponly=True)
        return resp

    @app.exception_handler(404)
    async def not_found(request: Request, exc):
        return render(request, "error.html", status=404, message=i18n._("Die angeforderte Seite wurde nicht gefunden."))

    @app.exception_handler(403)
    async def forbidden(request: Request, exc):
        return render(request, "error.html", status=403, message=i18n._("Diese Aktion ist nicht erlaubt."))

    app.include_router(routes_auth.router)

    return app
