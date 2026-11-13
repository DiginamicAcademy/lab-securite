"""
DIGICHEESE — application SÉCURISÉE (support pédagogique).

Correspondance 1:1 avec lab/vulnerable/app.py : chaque faille est corrigée
au même endroit. Sert de référence pour les exercices J7-J9 (secure coding)
et pour comparer côte à côte les deux comportements.

Fil rouge : fromagerie TPE, API de gestion des produits et des commandes.
"""

import os
import re

import bcrypt
import pymysql
from fastapi import Depends, FastAPI, Form, Header, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from itsdangerous import BadSignature, URLSafeTimedSerializer

app = FastAPI(title="DIGICHEESE — secure")

DB_CONFIG = {
    "host": os.getenv("DB_HOST", "localhost"),
    "user": os.getenv("DB_USER", "root"),
    "password": os.getenv("DB_PASSWORD", "root"),
    "database": os.getenv("DB_NAME", "fromagerie"),
}

SECRET = os.getenv("APP_SECRET_KEY", "dev-only-secret-change-me-32chars")
_serializer = URLSafeTimedSerializer(SECRET)

# Rate limiting minimal pour les tentatives de connexion.
_LOGIN_ATTEMPTS: dict[str, int] = {}
MAX_ATTEMPTS = 5


def get_db():
    return pymysql.connect(**DB_CONFIG, cursorclass=pymysql.cursors.DictCursor)


def get_current_user(authorization: str = Header(default="")):
    """Extrait et valide l'utilisateur depuis le token signé."""
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="token manquant")
    token = authorization.removeprefix("Bearer ").strip()
    try:
        username = _serializer.loads(token, max_age=3600)
    except BadSignature:
        raise HTTPException(status_code=401, detail="token invalide ou expiré")
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, role FROM users WHERE username = %s", (username,))
    user = cursor.fetchone()
    conn.close()
    if not user:
        raise HTTPException(status_code=401, detail="utilisateur inconnu")
    return user


def require_admin(user: dict = Depends(get_current_user)):
    """Contrôle d'autorisation explicite (A01)."""
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="accès réservé aux administrateurs")
    return user


# --------------------------------------------------------------------------
# CORRECTION 1 — Injection SQL : requête paramétrée (A03).
# --------------------------------------------------------------------------
@app.get("/products/search")
def search_products(q: str = ""):
    if len(q) > 64 or not re.fullmatch(r"[\w\s\-']*", q or ""):
        raise HTTPException(status_code=400, detail="requête invalide")
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM products WHERE name LIKE %s", (f"%{q}%",))
    rows = cursor.fetchall()
    conn.close()
    return {"query": q, "results": rows}


# --------------------------------------------------------------------------
# CORRECTION 2 — Mots de passe : bcrypt avec sel, token signé, rate limit (A07).
# --------------------------------------------------------------------------
@app.post("/login")
def login(username: str = Form(...), password: str = Form(...)):
    attempts = _LOGIN_ATTEMPTS.get(username, 0)
    if attempts >= MAX_ATTEMPTS:
        raise HTTPException(status_code=429, detail="trop de tentatives, réessayez plus tard")

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
    user = cursor.fetchone()
    conn.close()

    stored = user["password_hash"] if user else ""
    # bcrypt ; les comptes de démo (hash non bcrypt) refusent la connexion
    ok = False
    if stored.startswith("$2"):
        ok = bcrypt.checkpw(password.encode(), stored.encode())
    if not ok:
        _LOGIN_ATTEMPTS[username] = attempts + 1
        raise HTTPException(status_code=401, detail="identifiants invalides")

    _LOGIN_ATTEMPTS.pop(username, None)
    token = _serializer.dumps(user["username"])
    return {"message": f"bienvenue {user['username']}", "role": user["role"], "token": token}


# --------------------------------------------------------------------------
# CORRECTION 3 — XSS : échappement des sorties HTML (A03).
# --------------------------------------------------------------------------
@app.get("/comments", response_class=HTMLResponse)
def comments(q: str = ""):
    from html import escape

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT username, body FROM comments ORDER BY id DESC")
    rows = cursor.fetchall()
    conn.close()
    safe_q = escape(q or "")
    html = f"<h3>Commentaires — recherche : {safe_q}</h3><ul>"
    for r in rows:
        html += f"<li><b>{escape(r['username'])}</b> : {escape(r['body'])}</li>"
    html += "</ul>"
    return HTMLResponse(html, headers={"Content-Security-Policy": "default-src 'self'"})


# --------------------------------------------------------------------------
# CORRECTION 4 — Broken Access Control : contrôle de rôle (A01).
# Les données exposées sont aussi minimisées (RGPD) : plus de hash.
# --------------------------------------------------------------------------
@app.get("/admin/users")
def admin_users(user: dict = Depends(require_admin)):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, role FROM users")
    rows = cursor.fetchall()
    conn.close()
    return {"users": rows}


# --------------------------------------------------------------------------
# CORRECTION 5 — Suppression de la fuite de config (A05).
# --------------------------------------------------------------------------
# L'endpoint /debug/config a été supprimé volontairement.
# En cas de besoin, un endpoint de santé minimal ne révèle rien de sensible :
@app.get("/healthz")
def healthz():
    return {"status": "ok"}


# --------------------------------------------------------------------------
# Page d'accueil
# --------------------------------------------------------------------------
@app.get("/", response_class=HTMLResponse)
def home():
    return """
    <h1>DIGICHEESE — lab (secure)</h1>
    <ul>
        <li><a href="/products/search?q=Comté">/products/search?q=…</a></li>
        <li><a href="/comments">/comments</a></li>
        <li>GET /admin/users (token admin requis)</li>
        <li>POST /login (form : username, password) → renvoie un token</li>
        <li><a href="/healthz">/healthz</a></li>
    </ul>
    """
