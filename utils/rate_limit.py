import asyncio
import time
from datetime import datetime, timedelta, timezone
from fastapi import HTTPException
from config import RATE_LIMIT_MAX, RATE_LIMIT_SECONDS, DELAY_PER_FAIL
from utils.security import client_ip

def rate_limit_key(ip: str, session_id: str) -> str:
    """Gera chave única para rate limiting"""
    return f"ip:{ip}|sid:{session_id}"

def check_rate_limit(conn, key: str):
    """Verifica se o cliente excedeu o limite de requisições"""
    now = int(time.time())
    cutoff = now - RATE_LIMIT_SECONDS
    conn.execute("DELETE FROM ratelimit WHERE ts < ?", (cutoff,))
    cur = conn.execute("SELECT COUNT(*) AS c FROM ratelimit WHERE key = ?", (key,))
    count = cur.fetchone()[0]
    if count >= RATE_LIMIT_MAX:
        raise HTTPException(status_code=429, detail="Muitas tentativas. Tente novamente em breve.")
    conn.execute("INSERT INTO ratelimit(key, ts) VALUES(?, ?)", (key, now))

async def apply_fail_delay(conn, session_id: str):
    """Aplica delay incremental para tentativas recentes falhas"""
    cur = conn.execute(
        "SELECT COUNT(*) FROM logs WHERE success=0 AND session_id=? AND timestamp > ?",
        (session_id, (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat())
    )
    fail_recent = cur.fetchone()[0]
    if fail_recent:
        await asyncio.sleep(min(5.0, fail_recent * DELAY_PER_FAIL))