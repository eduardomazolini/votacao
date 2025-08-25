from datetime import datetime, timezone
from .security import sha256

def log_attempt(conn, *, token: str, matricula: str, ip: str, user_agent: str, 
                session_id: str, success: bool, reason: str):
    """Registra tentativa de acesso no log"""
    conn.execute(
        "INSERT INTO logs(token_hash, matricula_hash, ip, user_agent, session_id, timestamp, success, reason) VALUES(?,?,?,?,?,?,?,?)",
        (sha256(token) if token else None, 
         sha256(matricula) if matricula else None, 
         ip, 
         user_agent[:400], 
         session_id, 
         datetime.now(timezone.utc).isoformat(), 
         1 if success else 0, 
         reason[:200])
    )