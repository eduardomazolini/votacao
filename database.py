import sqlite3
from config import DB_PATH

def get_db():
    """Retorna uma conexão com o banco de dados"""
    conn = sqlite3.connect(DB_PATH, timeout=10, isolation_level=None)
    conn.row_factory = sqlite3.Row
    return conn

def init_database():
    """Inicializa o banco de dados com as tabelas necessárias"""
    conn = get_db()
    try:
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA busy_timeout=10000;")
        conn.execute("PRAGMA foreign_keys=ON;")

        # Tabela de tokens
        conn.execute("""
            CREATE TABLE IF NOT EXISTS tokens (
                id INTEGER PRIMARY KEY,
                token TEXT UNIQUE NOT NULL,
                used INTEGER DEFAULT 0,
                used_at TEXT,
                used_ip TEXT,
                used_session TEXT,
                matricula TEXT,
                vote TEXT
            );
        """)
        
        # Criar tabela
        conn.execute("""
            CREATE TABLE IF NOT EXISTS votes (
                candidate_id TEXT PRIMARY KEY,
                vote_count INTEGER DEFAULT 0
            );
        """)
        
        # Tabela de logs
        conn.execute("""
            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY,
                token_hash TEXT,
                matricula_hash TEXT,
                ip TEXT,
                user_agent TEXT,
                session_id TEXT,
                timestamp TEXT,
                success INTEGER,
                reason TEXT
            );
        """)
        
        # Tabela de rate limiting
        conn.execute("""
            CREATE TABLE IF NOT EXISTS ratelimit (
                id INTEGER PRIMARY KEY,
                key TEXT,
                ts INTEGER
            );
        """)
        
    finally:
        conn.close()