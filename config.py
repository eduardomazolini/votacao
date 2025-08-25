import os
from pathlib import Path

# Configurações básicas
DB_PATH = os.getenv("VOTE_DB", "vote.db")
ADMIN_SECRET = os.getenv("ADMIN_SECRET", "troque-este-segredo")
RATE_LIMIT_MAX = int(os.getenv("RATE_LIMIT_MAX", "15"))
RATE_LIMIT_SECONDS = int(os.getenv("RATE_LIMIT_SECONDS", "60"))
DELAY_PER_FAIL = float(os.getenv("DELAY_PER_FAIL", "1.0"))
SESSION_COOKIE = "vsess"

# Candidatos
CANDIDATES = [
    {"id": "11111-47", "nome": "Keli-11111-47", "foto": "/static/Keli-11111-47.jpg"},
    {"id": "3333-18", "nome": "Larissa-3333-18", "foto": "/static/Larissa-3333-18.jpg"},
    {"id": "4444-71", "nome": "Suellen-4444-71", "foto": "/static/Suellen-4444-71.jpg"},
    {"id": "branco", "nome": "Branco / Nulo", "foto": "/static/branco.png"},
]

# Chaves de criptografia
KEY_PRIV_PATH = Path(os.getenv("KEY_PRIV", "ed25519_private.pem"))
KEY_PUB_PATH = Path(os.getenv("KEY_PUB", "ed25519_public.pem"))