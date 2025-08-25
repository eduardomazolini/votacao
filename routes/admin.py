from datetime import datetime, timezone
import os
from fastapi import APIRouter, Path, Request, HTTPException
from fastapi.responses import PlainTextResponse, JSONResponse
import sqlite3
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


from database import get_db
from config import ADMIN_SECRET, CANDIDATES, KEY_PRIV_PATH, KEY_PUB_PATH
from utils.security import ensure_keys, gen_token, load_keys

router = APIRouter()

def require_admin(request: Request):
    """Middleware para verificar autenticação admin"""
    secret = request.headers.get("X-Admin-Secret")
    if secret != ADMIN_SECRET:
        raise HTTPException(status_code=401, detail="unauthorized")

@router.post("/admin/generate", response_class=PlainTextResponse)
async def admin_generate(request: Request, n: int = 1500, length: int = 7):
    require_admin(request)
    tokens = [gen_token(length) for _ in range(n)]
    with get_db() as conn:
        for t in tokens:
            try:
                conn.execute("INSERT INTO tokens(token) VALUES(?)", (t,))
            except sqlite3.IntegrityError:
                # Colisão improvável; gera outro
                nt = gen_token(length)
                conn.execute("INSERT INTO tokens(token) VALUES(?)", (nt,))
    # CSV simples para impressão: token por linha
    return PlainTextResponse("\n".join(tokens))

@router.get("/admin/stats", response_class=JSONResponse)
async def admin_stats(request: Request):
    require_admin(request)
    with get_db() as conn:
        total = conn.execute("SELECT COUNT(*) FROM tokens").fetchone()[0]
        usados = conn.execute("SELECT COUNT(*) FROM tokens WHERE used=1").fetchone()[0]
        por_candidato = conn.execute("SELECT * FROM votes").fetchall()
        parcial = [{row["candidate_id"]: row["vote_count"]} for row in por_candidato]
    return {"total_tokens": total, "usados": usados, "nao_usados": total - usados, "votos": parcial}

@router.post("/admin/genkeys", response_class=PlainTextResponse)
async def admin_genkeys(request: Request):
    require_admin(request)
    ensure_keys()
    return PlainTextResponse("Par de chaves gerado/garantido. Baixe a pública em /admin/pubkey")

@router.get("/admin/pubkey", response_class=PlainTextResponse)
async def admin_pubkey(request: Request):
    require_admin(request)
    if not KEY_PUB_PATH.exists():
        raise HTTPException(status_code=404, detail="public key not found")
    return PlainTextResponse(KEY_PUB_PATH.read_text())

@router.get("/admin/export_results", response_class=JSONResponse)
async def admin_export_results(request: Request):
    require_admin(request)
    with get_db() as conn:
        # Contagem simples por candidato
        por_candidato = conn.execute("SELECT * FROM votes").fetchall()
        result = [{row["candidate_id"]: row["vote_count"]} for row in por_candidato]
        total = conn.execute("SELECT COUNT(*) FROM tokens WHERE used=1").fetchone()[0]
        payload = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "candidates": [{"id": c["id"], "nome": c["nome"]} for c in CANDIDATES],
            "totals": result,
            "total_votos": total,
            "algorithm": "ed25519",
        }

    # Assina JSON canônico (ordenado por chave)
    import json
    canonical = json.dumps(payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode()

    if not KEY_PRIV_PATH.exists():
        raise HTTPException(status_code=500, detail="private key not found; gere com /admin/genkeys")

    priv, pub = load_keys()
    assert isinstance(priv, Ed25519PrivateKey)
    signature = priv.sign(canonical)

    return JSONResponse({
        "payload": payload,
        "signature_hex": signature.hex(),
        "public_key_pem": KEY_PUB_PATH.read_text(),
        "how_to_verify": "Verifique carregando a chave pública e assinando o JSON canônico (chaves ordenadas, separadores ',',':'). Compare a assinatura Ed25519."
    })
