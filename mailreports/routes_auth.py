# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Schnuecks
"""Sign-in with built-in accounts: first-run setup, password, second factor (authenticator
app, passkey, recovery code), passkeys without password, single sign-on, the own account,
user management and the sign-in log."""
from __future__ import annotations

import logging
import math
import secrets
from typing import Any

from fastapi import APIRouter, Body, Form, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse, Response

from . import accounts, oidc, passkeys, secretbox, totp, web
from .i18n import N_, _

log = logging.getLogger(__name__)
router = APIRouter()

OIDC_COOKIE = "mailreports_oidc"
PAGE_SIZE = 25


def _svc(request: Request):
    return request.app.state.svc


def _cfg(request: Request):
    return request.app.state.svc.settings


def _require_accounts(request: Request) -> None:
    if not _cfg(request).accounts_enabled:
        raise HTTPException(404)


def _require_csrf(request: Request, token: str) -> None:
    if not web.check_csrf(request, token):
        raise HTTPException(403)


def _me(request: Request):
    acc = web.account(request)
    if acc is None:
        raise HTTPException(403)
    return acc


def _rp(request: Request) -> tuple[str, str]:
    return passkeys.relying_party(_cfg(request).public_url, str(request.base_url))


def redirect(url: str, ok: str = "") -> RedirectResponse:
    return RedirectResponse(url + (("&" if "?" in url else "?") + f"ok={ok}" if ok else ""), status_code=303)


def _start_session(request: Request, con, user_id: int, target: str) -> Response:
    token = accounts.start_session(con, user_id, web.client_ip(request), request.headers.get("user-agent", ""))
    resp = redirect(web.safe_next(target))
    resp.set_cookie(web.session_cookie(request, _cfg(request)), token, max_age=accounts.SESSION_SECONDS,
                    httponly=True, secure=web.cookie_secure(request, _cfg(request)), samesite="lax")
    return resp


def _login_page(request: Request, next_url: str = "/", error: str = "", status: int = 200) -> Response:
    with _svc(request).db.connect() as con:
        passkey_login = passkeys.any_registered(con)
    return web.render(request, "login.html", status=status, next=web.safe_next(next_url), error=error,
                      passkey_login=passkey_login)


TOO_MANY = N_("Zu viele fehlgeschlagene Anmeldungen. Bitte später erneut versuchen.")


# ---------------------------------------------------------------- first-run setup

@router.get("/setup")
def setup_form(request: Request):
    _require_accounts(request)
    with _svc(request).db.connect() as con:
        if accounts.has_users(con):
            return redirect("/")
        accounts.setup_code(con)
    return web.render(request, "setup.html", username="")


@router.post("/setup")
def setup_submit(request: Request, code: str = Form(""), username: str = Form(""), password: str = Form(""),
                 repeat: str = Form("")):
    _require_accounts(request)
    svc, ip, username = _svc(request), web.client_ip(request), username.strip()

    def page(error: str, status: int):
        return web.render(request, "setup.html", status=status, username=username, error=_(error))

    if svc.limiter.blocked(ip):
        return page(TOO_MANY, 429)
    with svc.db.connect() as con:
        if accounts.has_users(con):
            return redirect("/")
        if not accounts.setup_code_valid(con, code):
            svc.limiter.failure(ip)
            return page(N_("Der Einrichtungscode stimmt nicht. Er steht im Container-Log."), 401)
        problem = accounts.username_problem(username) or accounts.password_problem(password)
        if problem:
            return page(problem, 400)
        if password != repeat:
            return page(N_("Die Passwörter stimmen nicht überein."), 400)
        user_id = accounts.create_user(con, username, password, is_admin=True)
        accounts.clear_setup_code(con)
        accounts.log_login(con, username, user_id, ip, True, "setup")
        return _start_session(request, con, user_id, "/")


# ---------------------------------------------------------------- password and second factor

@router.get("/login")
def login_form(request: Request, next: str = "/"):
    _require_accounts(request)
    if web.account(request) is not None:
        return redirect(web.safe_next(next))
    return _login_page(request, next)


@router.post("/login")
def login_submit(request: Request, username: str = Form(""), password: str = Form(""), next: str = Form("/")):
    _require_accounts(request)
    svc, ip, username = _svc(request), web.client_ip(request), username.strip()[:64]
    with svc.db.connect() as con:
        if svc.limiter.blocked(ip, username, known_ip=accounts.known_login_ip(con, username, ip)):
            return _login_page(request, next, _(TOO_MANY), 429)
        user = accounts.authenticate(con, username, password) if username and password else None
        if user is None:
            accounts.log_login(con, username, None, ip, False)
        elif accounts.second_factor_required(con, user):
            pending = accounts.start_pending_login(con, user["id"])
            return _code_page(request, con, user, pending, next)
        else:
            accounts.log_login(con, user["username"], user["id"], ip, True)
            svc.limiter.success(ip, username)
            return _start_session(request, con, user["id"], next)
    svc.limiter.failure(ip, username)
    log.warning("failed sign-in for %r from %s", username, ip)
    return _login_page(request, next, _("Benutzername oder Passwort ist falsch."), 401)


def _code_page(request: Request, con, user, pending: str, next_url: str, error: str = "") -> Response:
    return web.render(request, "login_code.html", status=401 if error else 200, pending=pending,
                      next=web.safe_next(next_url), totp=bool(user["totp_enabled"]),
                      keys=accounts.has_passkeys(con, user["id"]), error=error)


@router.post("/login/code")
def login_code_submit(request: Request, pending: str = Form(""), code: str = Form(""), next: str = Form("/")):
    _require_accounts(request)
    svc, ip = _svc(request), web.client_ip(request)
    with svc.db.connect() as con:
        user = accounts.resolve_pending_login(con, pending)
        if user is None:
            return _login_page(request, next, _(oidc.EXPIRED), 401)
        ok = (user["totp_enabled"] and totp.verify_user_code(con, user, code, svc.settings.secret_key)) \
            or accounts.use_recovery_code(con, user["id"], code)
        if ok:
            accounts.finish_pending_login(con, user["p_id"])
            accounts.log_login(con, user["username"], user["id"], ip, True, "2FA")
            svc.limiter.success(ip, user["username"])
            return _start_session(request, con, user["id"], next)
        accounts.log_login(con, user["username"], user["id"], ip, False, "wrong 2FA code")
        svc.limiter.failure(ip, user["username"])
        return _code_page(request, con, user, pending, next, _("Der Code stimmt nicht. Bitte erneut versuchen."))


def _json_error(message: str, status: int = 400) -> JSONResponse:
    return JSONResponse({"error": _(message)}, status_code=status)


@router.post("/login/code/passkey/options")
def second_passkey_options(request: Request, body: dict[str, Any] = Body(...)):
    _require_accounts(request)
    with _svc(request).db.connect() as con:
        user = accounts.resolve_pending_login(con, str(body.get("pending", "")), count_attempt=False)
        if user is None:
            return _json_error(oidc.EXPIRED, 401)
        return passkeys.authentication_options(con, _rp(request)[0], user["id"])


@router.post("/login/code/passkey")
def second_passkey(request: Request, body: dict[str, Any] = Body(...)):
    _require_accounts(request)
    svc, ip = _svc(request), web.client_ip(request)
    rp_id, origin = _rp(request)
    with svc.db.connect() as con:
        user = accounts.resolve_pending_login(con, str(body.get("pending", "")))
        if user is None:
            return _json_error(oidc.EXPIRED, 401)
        try:
            passkeys.authenticate(con, str(body.get("token", "")), body.get("credential") or {}, rp_id, origin,
                                  user["id"])
        except passkeys.PasskeyError as exc:
            accounts.log_login(con, user["username"], user["id"], ip, False, "passkey failed")
            return _json_error(passkeys.public_message(exc))
        accounts.finish_pending_login(con, user["p_id"])
        accounts.log_login(con, user["username"], user["id"], ip, True, "2FA passkey")
        return _start_session(request, con, user["id"], str(body.get("next", "/")))


@router.post("/login/passkey/options")
def passkey_login_options(request: Request):
    _require_accounts(request)
    if not _svc(request).limiter.blocked(web.client_ip(request)):
        with _svc(request).db.connect() as con:
            return passkeys.authentication_options(con, _rp(request)[0])
    return _json_error(TOO_MANY, 429)


@router.post("/login/passkey")
def passkey_login(request: Request, body: dict[str, Any] = Body(...)):
    _require_accounts(request)
    svc, ip = _svc(request), web.client_ip(request)
    rp_id, origin = _rp(request)
    if svc.limiter.blocked(ip):
        return _json_error(TOO_MANY, 429)
    with svc.db.connect() as con:
        try:
            user_id = passkeys.authenticate(con, str(body.get("token", "")), body.get("credential") or {}, rp_id,
                                            origin)
        except passkeys.PasskeyError as exc:
            svc.limiter.failure(ip)
            accounts.log_login(con, "", None, ip, False, "passkey failed")
            return _json_error(passkeys.public_message(exc))
        user = con.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        if user is None or not user["enabled"]:
            return _json_error(oidc.DISABLED, 403)
        accounts.log_login(con, user["username"], user["id"], ip, True, "passkey")
        return _start_session(request, con, user["id"], str(body.get("next", "/")))


# ---------------------------------------------------------------- single sign-on

@router.get("/login/oidc")
def oidc_start(request: Request, next: str = "/"):
    _require_accounts(request)
    cfg = _cfg(request)
    if not cfg.oidc_enabled:
        return redirect("/login")
    if _svc(request).limiter.blocked(web.client_ip(request)):
        return _login_page(request, next, _(TOO_MANY), 429)
    try:
        with _svc(request).db.connect() as con:
            url, state = oidc.start_flow(con, cfg, str(request.base_url), web.safe_next(next))
    except oidc.OidcError as exc:
        return _login_page(request, next, _(oidc.public_message(exc)), 502)
    resp = RedirectResponse(url, status_code=303)
    # Binds the return to this browser; otherwise someone could slip in a foreign sign-in
    resp.set_cookie(OIDC_COOKIE, state, max_age=oidc.FLOW_SECONDS, httponly=True,
                    secure=web.cookie_secure(request, cfg), samesite="lax")
    return resp


@router.get("/oidc/callback")
def oidc_callback(request: Request, state: str = "", code: str = "", error: str = ""):
    _require_accounts(request)
    svc, cfg, ip = _svc(request), _cfg(request), web.client_ip(request)
    if not cfg.oidc_enabled or not state or not secrets.compare_digest(request.cookies.get(OIDC_COOKIE, ""), state):
        return _login_page(request, "/", _(oidc.EXPIRED), 401)
    with svc.db.connect() as con:
        flow = oidc.take_flow(con, state)
    if flow is None:
        return _login_page(request, "/", _(oidc.EXPIRED), 401)
    if flow["link_user_id"] is not None:
        return _oidc_link_callback(request, flow, code, error)
    try:
        if error or not code:
            raise oidc.OidcError(oidc.FAILED)
        who = oidc.person(oidc.exchange(cfg, str(request.base_url), flow, code))
        with svc.db.connect() as con:
            user = oidc.user_for(con, cfg, who)
            accounts.log_login(con, user["username"], user["id"], ip, True, "SSO")
            resp = _start_session(request, con, user["id"], flow["next"])
    except oidc.OidcError as exc:
        with svc.db.connect() as con:
            accounts.log_login(con, "", None, ip, False, f"SSO: {exc}")
        return _login_page(request, "/", _(oidc.public_message(exc)), 401)
    resp.delete_cookie(OIDC_COOKIE)
    return resp


def _oidc_link_callback(request: Request, flow, code: str, error: str) -> Response:
    """Return from the provider after "link with …" on the account page."""
    me = web.account(request)
    if me is None or me["id"] != flow["link_user_id"]:
        return _login_page(request, "/", _(oidc.EXPIRED), 401)
    try:
        if error or not code:
            raise oidc.OidcError(oidc.FAILED)
        who = oidc.person(oidc.exchange(_cfg(request), str(request.base_url), flow, code))
        with _svc(request).db.connect() as con:
            oidc.link(con, _cfg(request), me["id"], who)
    except oidc.OidcError as exc:
        resp = _account_page(request, _(oidc.public_message(exc)), 400)
        resp.delete_cookie(OIDC_COOKIE)
        return resp
    resp = redirect("/account", "linked")
    resp.delete_cookie(OIDC_COOKIE)
    return resp


@router.post("/account/oidc/link")
def oidc_link_start(request: Request, csrf: str = Form("")):
    _require_accounts(request)
    _require_csrf(request, csrf)
    cfg, me = _cfg(request), _me(request)
    if not cfg.oidc_enabled:
        return redirect("/account")
    try:
        with _svc(request).db.connect() as con:
            url, state = oidc.start_flow(con, cfg, str(request.base_url), "/account", link_user_id=me["id"])
    except oidc.OidcError as exc:
        return _account_page(request, _(oidc.public_message(exc)), 502)
    resp = RedirectResponse(url, status_code=303)
    resp.set_cookie(OIDC_COOKIE, state, max_age=oidc.FLOW_SECONDS, httponly=True,
                    secure=web.cookie_secure(request, cfg), samesite="lax")
    return resp


@router.post("/account/oidc/unlink")
def oidc_unlink(request: Request, csrf: str = Form("")):
    _require_accounts(request)
    _require_csrf(request, csrf)
    with _svc(request).db.connect() as con:
        con.execute("UPDATE users SET oidc_sub = '' WHERE id = ?", (_me(request)["id"],))
    return redirect("/account", "unlinked")


@router.post("/logout")
def logout(request: Request, csrf: str = Form("")):
    cfg = _cfg(request)
    if not cfg.accounts_enabled:
        return redirect("/")
    _require_csrf(request, csrf)
    name = web.session_cookie(request, cfg)
    with _svc(request).db.connect() as con:
        accounts.end_session(con, request.cookies.get(name, ""))
    resp = redirect("/login")
    resp.delete_cookie(name)
    return resp


# ---------------------------------------------------------------- own account

MESSAGES = {
    "password": N_("Das Passwort wurde geändert."),
    "session": N_("Die Sitzung wurde beendet."),
    "totp": N_("Die Zwei-Faktor-Anmeldung ist eingerichtet."),
    "totp_off": N_("Die Anmeldung mit Authenticator-App ist ausgeschaltet."),
    "passkey": N_("Der Passkey wurde hinzugefügt."),
    "passkey_off": N_("Der Passkey wurde entfernt."),
    "saved": N_("Die Änderungen wurden gespeichert."),
    "user_new": N_("Das Konto wurde angelegt."),
    "user_deleted": N_("Das Konto wurde gelöscht."),
    "reset": N_("Zwei-Faktor-Anmeldung und Passkeys wurden zurückgesetzt."),
    "linked": N_("Das Konto ist jetzt mit dem Anbieter verknüpft."),
    "unlinked": N_("Die Verknüpfung mit dem Anbieter wurde gelöst."),
}


def _message(request: Request) -> str:
    text = MESSAGES.get(request.query_params.get("ok", ""))
    return _(text) if text else ""


def _account_page(request: Request, error: str = "", status: int = 200, codes: list[str] | None = None) -> Response:
    _require_accounts(request)
    me = _me(request)
    with _svc(request).db.connect() as con:
        sessions = accounts.sessions_of(con, me["id"])
        keys = passkeys.for_user(con, me["id"])
        recovery = accounts.unused_recovery_codes(con, me["id"])
    return web.render(request, "account.html", status=status, error=error, sessions=sessions, keys=keys,
                      recovery=recovery, codes=codes or [], message=_message(request))


@router.get("/account")
def account_page(request: Request):
    return _account_page(request)


def _password_ok(con, me, password: str) -> bool:
    return accounts.authenticate(con, me["username"], password) is not None


@router.post("/account/password")
def account_password(request: Request, csrf: str = Form(""), current: str = Form(""), password: str = Form(""),
                     repeat: str = Form("")):
    _require_accounts(request)
    _require_csrf(request, csrf)
    me = _me(request)
    with _svc(request).db.connect() as con:
        if not _password_ok(con, me, current):
            return _account_page(request, _("Das aktuelle Passwort stimmt nicht."), 400)
        problem = accounts.password_problem(password)
        if problem:
            return _account_page(request, _(problem), 400)
        if password != repeat:
            return _account_page(request, _("Die Passwörter stimmen nicht überein."), 400)
        accounts.set_password(con, me["id"], password)   # ends all sessions
        return _start_session(request, con, me["id"], "/account?ok=password")


@router.post("/account/sessions/{session_id}/end")
def account_end_session(request: Request, session_id: int, csrf: str = Form("")):
    _require_accounts(request)
    _require_csrf(request, csrf)
    with _svc(request).db.connect() as con:
        con.execute("DELETE FROM sessions WHERE id = ? AND user_id = ?", (session_id, _me(request)["id"]))
    return redirect("/account", "session")


@router.post("/account/2fa/start")
def totp_start(request: Request, csrf: str = Form("")):
    _require_accounts(request)
    _require_csrf(request, csrf)
    me = _me(request)
    secret = totp.new_secret()
    with _svc(request).db.connect() as con:
        con.execute("UPDATE users SET totp_secret = ?, totp_enabled = 0 WHERE id = ?",
                    (secretbox.seal(_cfg(request).secret_key, secret), me["id"]))
    return _totp_page(request, secret)


def _totp_page(request: Request, secret: str, error: str = "") -> Response:
    me = _me(request)
    uri = totp.provisioning_uri(secret, me["username"], _cfg(request).app_title or "mailreports")
    return web.render(request, "totp_setup.html", status=400 if error else 200, qr=totp.qr_svg(uri),
                      secret=totp.format_secret(secret), error=error)


@router.post("/account/2fa/confirm")
def totp_confirm(request: Request, csrf: str = Form(""), code: str = Form("")):
    _require_accounts(request)
    _require_csrf(request, csrf)
    me = _me(request)
    svc = _svc(request)
    with svc.db.connect() as con:
        user = con.execute("SELECT * FROM users WHERE id = ?", (me["id"],)).fetchone()
        secret = totp.secret_of(user, svc.settings.secret_key)
        if not secret:
            return redirect("/account")
        if not totp.verify_user_code(con, user, code, svc.settings.secret_key):
            return _totp_page(request, secret, _("Der Code stimmt nicht. Bitte erneut versuchen."))
        con.execute("UPDATE users SET totp_enabled = 1 WHERE id = ?", (me["id"],))
        codes = accounts.new_recovery_codes(con, me["id"]) if not accounts.unused_recovery_codes(con, me["id"]) \
            else []
    if codes:
        return web.render(request, "recovery_codes.html", codes=codes)
    return redirect("/account", "totp")


@router.post("/account/2fa/recovery")
def totp_recovery(request: Request, csrf: str = Form(""), password: str = Form("")):
    _require_accounts(request)
    _require_csrf(request, csrf)
    me = _me(request)
    with _svc(request).db.connect() as con:
        if not _password_ok(con, me, password):
            return _account_page(request, _("Das aktuelle Passwort stimmt nicht."), 400)
        if not accounts.second_factor_required(con, me):
            return redirect("/account")
        codes = accounts.new_recovery_codes(con, me["id"])
    return web.render(request, "recovery_codes.html", codes=codes)


@router.post("/account/2fa/disable")
def totp_disable(request: Request, csrf: str = Form(""), password: str = Form("")):
    _require_accounts(request)
    _require_csrf(request, csrf)
    me = _me(request)
    with _svc(request).db.connect() as con:
        if not _password_ok(con, me, password):
            return _account_page(request, _("Das aktuelle Passwort stimmt nicht."), 400)
        accounts.disable_totp(con, me["id"])
    return redirect("/account", "totp_off")


@router.post("/account/passkeys/options")
def passkey_options(request: Request, body: dict[str, Any] = Body(...)):
    _require_accounts(request)
    _require_csrf(request, str(body.get("csrf", "")))
    me = _me(request)
    try:
        with _svc(request).db.connect() as con:
            return passkeys.registration_options(con, me, _rp(request)[0], _cfg(request).app_title or "mailreports")
    except passkeys.PasskeyError as exc:
        return _json_error(passkeys.public_message(exc))


@router.post("/account/passkeys")
def passkey_add(request: Request, body: dict[str, Any] = Body(...)):
    _require_accounts(request)
    _require_csrf(request, str(body.get("csrf", "")))
    me = _me(request)
    rp_id, origin = _rp(request)
    with _svc(request).db.connect() as con:
        try:
            passkeys.register(con, me, str(body.get("token", "")), body.get("credential") or {},
                              str(body.get("name", "")), rp_id, origin)
        except passkeys.PasskeyError as exc:
            return _json_error(passkeys.public_message(exc))
        codes = accounts.new_recovery_codes(con, me["id"]) if not accounts.unused_recovery_codes(con, me["id"]) \
            else []
    if codes:
        return web.render(request, "recovery_codes.html", codes=codes)
    return redirect("/account", "passkey")


@router.post("/account/passkeys/{key_id}/delete")
def passkey_delete(request: Request, key_id: int, csrf: str = Form("")):
    _require_accounts(request)
    _require_csrf(request, csrf)
    me = _me(request)
    with _svc(request).db.connect() as con:
        con.execute("DELETE FROM passkeys WHERE id = ? AND user_id = ?", (key_id, me["id"]))
        if not accounts.second_factor_required(con, me):
            con.execute("DELETE FROM recovery_codes WHERE user_id = ?", (me["id"],))
    return redirect("/account", "passkey_off")


# ---------------------------------------------------------------- user management (admins)

def _users_page(request: Request, error: str = "", status: int = 200, form: dict | None = None) -> Response:
    _require_accounts(request)
    with _svc(request).db.connect() as con:
        users = con.execute(
            "SELECT u.*, (SELECT COUNT(*) FROM passkeys p WHERE p.user_id = u.id) AS passkey_count FROM users u"
            " ORDER BY username COLLATE NOCASE").fetchall()
    return web.render(request, "users.html", status=status, users=users, error=error, form=form or {},
                      message=_message(request))


@router.get("/users")
def users_list(request: Request):
    return _users_page(request)


@router.post("/users/new")
def users_create(request: Request, csrf: str = Form(""), username: str = Form(""), password: str = Form(""),
                 display_name: str = Form(""), email: str = Form(""), is_admin: str = Form("")):
    _require_accounts(request)
    _require_csrf(request, csrf)
    username = username.strip()
    form = {"username": username, "display_name": display_name, "email": email, "is_admin": bool(is_admin)}
    problem = accounts.username_problem(username) or accounts.password_problem(password)
    if problem:
        return _users_page(request, _(problem), 400, form)
    with _svc(request).db.connect() as con:
        if con.execute("SELECT 1 FROM users WHERE username = ?", (username,)).fetchone():
            return _users_page(request, _("Diesen Benutzernamen gibt es schon."), 400, form)
        accounts.create_user(con, username, password, is_admin=bool(is_admin), display_name=display_name.strip()[:100],
                             email=email.strip()[:200])
    return redirect("/users", "user_new")


def _target(con, user_id: int):
    row = con.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if row is None:
        raise HTTPException(404)
    return row


def _user_page(request: Request, user_id: int, error: str = "", status: int = 200) -> Response:
    with _svc(request).db.connect() as con:
        target = _target(con, user_id)
        keys = passkeys.for_user(con, user_id)
    return web.render(request, "user.html", status=status, target=target, keys=keys, error=error,
                      message=_message(request))


@router.get("/users/{user_id}")
def users_detail(request: Request, user_id: int):
    _require_accounts(request)
    return _user_page(request, user_id)


@router.post("/users/{user_id}")
def users_update(request: Request, user_id: int, csrf: str = Form(""), display_name: str = Form(""),
                 email: str = Form(""), is_admin: str = Form(""), enabled: str = Form(""), password: str = Form("")):
    _require_accounts(request)
    _require_csrf(request, csrf)
    me = _me(request)
    with _svc(request).db.connect() as con:
        target = _target(con, user_id)
        make_admin, active = bool(is_admin), bool(enabled)
        if target["id"] == me["id"] and (not make_admin or not active):
            return _user_page(request, user_id, _("Das eigene Konto kann nicht deaktiviert oder herabgestuft werden."),
                              400)
        if target["is_admin"] and (not make_admin or not active) and not accounts.admin_count(con, target["id"]):
            return _user_page(request, user_id, _("Es muss mindestens ein aktives Administratorkonto geben."), 400)
        if password:
            problem = accounts.password_problem(password)
            if problem:
                return _user_page(request, user_id, _(problem), 400)
            accounts.set_password(con, user_id, password)
        con.execute("UPDATE users SET display_name = ?, email = ?, is_admin = ?, enabled = ? WHERE id = ?",
                    (display_name.strip()[:100], email.strip()[:200], int(make_admin), int(active), user_id))
        if not active:
            con.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
    return redirect(f"/users/{user_id}", "saved")


@router.post("/users/{user_id}/2fa/reset")
def users_reset_factors(request: Request, user_id: int, csrf: str = Form("")):
    _require_accounts(request)
    _require_csrf(request, csrf)
    with _svc(request).db.connect() as con:
        _target(con, user_id)
        accounts.reset_second_factors(con, user_id)
    return redirect(f"/users/{user_id}", "reset")


@router.post("/users/{user_id}/delete")
def users_delete(request: Request, user_id: int, csrf: str = Form("")):
    _require_accounts(request)
    _require_csrf(request, csrf)
    me = _me(request)
    with _svc(request).db.connect() as con:
        target = _target(con, user_id)
        if target["id"] == me["id"]:
            return _user_page(request, user_id, _("Das eigene Konto kann nicht gelöscht werden."), 400)
        if target["is_admin"] and not accounts.admin_count(con, target["id"]):
            return _user_page(request, user_id, _("Es muss mindestens ein aktives Administratorkonto geben."), 400)
        con.execute("DELETE FROM users WHERE id = ?", (user_id,))
    return redirect("/users", "user_deleted")


@router.get("/sign-ins")
def sign_ins(request: Request):
    _require_accounts(request)
    page = web.page_of(request)
    with _svc(request).db.connect() as con:
        total = con.execute("SELECT COUNT(*) FROM login_events").fetchone()[0]
        rows = con.execute("SELECT * FROM login_events ORDER BY id DESC LIMIT ? OFFSET ?",
                           (PAGE_SIZE, (page - 1) * PAGE_SIZE)).fetchall()
    return web.render(request, "sign_ins.html", rows=rows, page=page, pages=max(1, math.ceil(total / PAGE_SIZE)),
                      total=total)

