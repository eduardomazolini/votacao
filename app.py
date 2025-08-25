from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pathlib import Path

from database import init_database
from routes import main, admin, health
from config import KEY_PRIV_PATH, KEY_PUB_PATH

# Inicializa aplicação
app = FastAPI(title="Votação Simples")

# Middleware CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Inicializa banco de dados
init_database()

# Configura arquivos estáticos
static_dir = Path(__file__).parent / "static"
static_dir.mkdir(exist_ok=True)
app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

# Registra rotas
app.include_router(main.router)
app.include_router(admin.router)
app.include_router(health.router)

# Garante que as chaves existam
if not KEY_PRIV_PATH.exists() or not KEY_PUB_PATH.exists():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    
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

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)