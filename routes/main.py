from fastapi import APIRouter, Request, Response, Form, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from datetime import datetime, timedelta
import asyncio

from config import CANDIDATES, DELAY_PER_FAIL
from database import get_db
from utils.security import client_ip, get_or_set_session_id
from utils.rate_limit import apply_fail_delay, rate_limit_key, check_rate_limit
from utils.logging import log_attempt

router = APIRouter()
templates = Jinja2Templates(directory="templates")

@router.get("/", response_class=HTMLResponse)
async def home(request: Request):
    response = templates.TemplateResponse(
        "home.html",
        {"request": request, "candidates": CANDIDATES}
    )
    get_or_set_session_id(request, response)
    return response

@router.post("/verificar", response_class=HTMLResponse)
async def verificar(request: Request, response: Response,
                    matricula: str = Form(...), token: str = Form(...)):
    ip = client_ip(request)
    ua = request.headers.get("user-agent", "?")
    sid = get_or_set_session_id(request, response)
    token = token.strip().upper()
    matricula = matricula.strip()

    with get_db() as conn:
        key = rate_limit_key(ip, sid)
        check_rate_limit(conn, key)
        await apply_fail_delay(conn, sid)
        cur = conn.execute("SELECT id, used FROM tokens WHERE token=?", (token,))
        row = cur.fetchone()
        if not row:
            log_attempt(conn, token=token, matricula=matricula, ip=ip,user_agent=ua, session_id=sid, success=False, reason="token_inexistente")
            return templates.TemplateResponse(
                "error.html",
                {
                    "request": request,
                    "error_title": "Token inválido",
                    "error_message": "Token não encontrado. Verifique e tente novamente."
                }
            )

        if row["used"]:
            log_attempt(conn, token=token, matricula=matricula, ip=ip,user_agent=ua, session_id=sid, success=False, reason="token_ja_usado")
            return templates.TemplateResponse(
                "error.html",
                {
                    "request": request,
                    "error_title": "Token já utilizado",
                    "error_message": "Este token já foi usado anteriormente."
                }
            )

        log_attempt(conn, token=token, matricula=matricula, ip=ip, user_agent=ua, session_id=sid, success=True, reason="token_ok")

    return templates.TemplateResponse(
        "cedula.html",
        {
            "request": request,
            "token": token,
            "matricula": matricula,
            "candidates": CANDIDATES
        }
    )

@router.post("/votar", response_class=HTMLResponse)
async def votar(request: Request, response: Response,
               token: str = Form(...), matricula: str = Form(...), opcao: str = Form(...)):
    ip = client_ip(request)
    ua = request.headers.get("user-agent", "?")
    sid = get_or_set_session_id(request, response)
    token = token.strip().upper()
    matricula = matricula.strip()

    with get_db() as conn:
        try:
            conn.execute("BEGIN IMMEDIATE")
            cur = conn.execute("SELECT used FROM tokens WHERE token=?", (token,))
            row = cur.fetchone()
            if not row:
                conn.execute("ROLLBACK")
                log_attempt(conn, token=token, matricula=matricula, ip=ip, user_agent=ua, session_id=sid, success=False, reason="token_inexistente_no_voto")
                return templates.TemplateResponse(
                    "error.html",
                    {
                        "request": request,
                        "error_title": "Erro",
                        "error_message": "Token inválido."
                    }
                )
            if row["used"]:
                conn.execute("ROLLBACK")
                log_attempt(conn, token=token, matricula=matricula, ip=ip, user_agent=ua, session_id=sid, success=False, reason="token_ja_usado_no_voto")
                return templates.TemplateResponse(
                    "error.html",
                    {
                        "request": request,
                        "error_title": "Token já utilizado",
                        "error_message": "Este token já foi usado."
                    }
                )
            
            # Tenta atualizar se já existir
            cursor_v = conn.execute(
                "UPDATE votes SET vote_count = vote_count + 1 WHERE candidate_id = ?",
                (opcao,)
            )
            # Se nenhuma linha foi afetada (não existia), insere nova
            if cursor_v.rowcount == 0:
                conn.execute(
                    "INSERT INTO votes (candidate_id, vote_count) VALUES (?, 1)",
                    (opcao,)
                )
            
            conn.execute(
                "UPDATE tokens SET used=1, used_at=?, used_ip=?, used_session=?, matricula=?, vote=? WHERE token=?",
                (datetime.utcnow().isoformat(), ip, sid, matricula, "Segredo", token)
            )
            conn.execute("COMMIT")
        except Exception as e:
            try:
                conn.execute("ROLLBACK")
            except Exception:
                pass
            raise

        log_attempt(conn, token=token, matricula=matricula, ip=ip, user_agent=ua, session_id=sid, success=True, reason=f"voto_ok")

    return templates.TemplateResponse("sucesso.html", {"request": request})
