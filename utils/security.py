import hashlib
import secrets
from fastapi import APIRouter, Request, Response, Form, HTTPException
from typing import Optional
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from config import SESSION_COOKIE

from config import KEY_PRIV_PATH, KEY_PUB_PATH

SAFE_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"

def sha256(s: str) -> str:
    """Calcula hash SHA256 de uma string"""
    return hashlib.sha256(s.encode()).hexdigest()

def gen_token(length: int = 7) -> str:
    """Gera um token seguro"""
    return ''.join(secrets.choice(SAFE_ALPHABET) for _ in range(length))

def get_or_set_session_id(request: Request, response: Response) -> str:
    """Obtém ou cria ID de sessão"""
    sid = request.cookies.get(SESSION_COOKIE)
    if not sid:
        sid = gen_token(16)
        response.set_cookie(
            SESSION_COOKIE, 
            sid, 
            httponly=True, 
            samesite="Lax", 
            max_age=60*60*24*14  # 14 dias
        )
    return sid

def client_ip(request) -> str:
    """Obtém o IP do cliente considerando proxies"""
    xff = request.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()
    return request.client.host if request.client else "?"

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization

def ensure_keys():
    if KEY_PRIV_PATH.exists() and KEY_PUB_PATH.exists():
        return
    # Gera um par novo
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    with KEY_PRIV_PATH.open("wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ))
    with KEY_PUB_PATH.open("wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ))


def load_keys():
    with KEY_PRIV_PATH.open("rb") as f:
        priv = serialization.load_pem_private_key(f.read(), password=None)
    with KEY_PUB_PATH.open("rb") as f:
        pub = serialization.load_pem_public_key(f.read())
    return priv, pub
