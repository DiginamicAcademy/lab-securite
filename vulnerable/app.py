"""
DIGICHEESE — application VOLNÉRABLE (support pédagogique).

⚠️ Ce code contient volontairement des failles OWASP étudiées en J2-J3.
Il ne doit JAMAIS être déployé en production. Usage strictement limité
au lab local du cours (docker compose).

Fil rouge : fromagerie TPE, API de gestion des produits et des commandes.
"""

import hashlib
import os

import pymysql
from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse

app = FastAPI(title="DIGICHEESE — vulnerable")

DB_CONFIG = {
    "host": os.getenv("DB_HOST", "localhost"),
    "user": os.getenv("DB_USER", "root"),
    "password": os.getenv("DB_PASSWORD", "root"),
    "database": os.getenv("DB_NAME", "fromagerie"),
}


def get_db():
    return pymysql.connect(**DB_CONFIG, cursorclass=pymysql.cursors.DictCursor)


# --------------------------------------------------------------------------
# FAILLE 1 — Injection SQL (A03:2021)
# Requête construite par concaténation de chaînes.
# --------------------------------------------------------------------------
@app.get("/products/search")
def search_products(q: str = ""):
    conn = get_db()
    cursor = conn.cursor()
    # vulnérable : pas de requête paramétrée
    query = f"SELECT * FROM products WHERE name LIKE '%{q}%'"
    cursor.execute(query)
    rows = cursor.fetchall()
    conn.close()
    return {"query": q, "results": rows}


# --------------------------------------------------------------------------
# FAILLE 2 — Stockage de mots de passe (A07:2021) + contournement possible
# Hash MD5 sans sel, voire mots de passe en clair en base.
# --------------------------------------------------------------------------
@app.post("/login")
def login(username: str = Form(...), password: str = Form(...)):
    conn = get_db()
    cursor = conn.cursor()
    # vulnérable : concaténation + MD5
    hashed = hashlib.md5(password.encode()).hexdigest()
    query = (
        f"SELECT * FROM users WHERE username = '{username}' "
        f"AND (password_hash = '{password}' OR password_hash = '{hashed}')"
    )
    cursor.execute(query)
    user = cursor.fetchone()
    conn.close()
    if not user:
        return {"error": "identifiants invalides"}
    return {"message": f"bienvenue {user['username']}", "role": user["role"]}


# --------------------------------------------------------------------------
# FAILLE 3 — XSS réfléchi (A03:2021) : saisie réinjectée sans échappement.
# --------------------------------------------------------------------------
@app.get("/comments", response_class=HTMLResponse)
def comments(q: str = ""):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT username, body FROM comments ORDER BY id DESC")
    rows = cursor.fetchall()
    conn.close()
    # vulnérable : la requête utilisateur est renvoyée telle quelle dans le HTML
    html = f"<h3>Commentaires — recherche : {q}</h3><ul>"
    for r in rows:
        html += f"<li><b>{r['username']}</b> : {r['body']}</li>"
    html += "</ul>"
    return html


# --------------------------------------------------------------------------
# FAILLE 4 — Broken Access Control (A01:2021) : pas de contrôle du rôle.
# --------------------------------------------------------------------------
@app.get("/admin/users")
def admin_users():
    conn = get_db()
    cursor = conn.cursor()
    # vulnérable : aucun contrôle d'autorisation
    cursor.execute("SELECT id, username, role, password_hash FROM users")
    rows = cursor.fetchall()
    conn.close()
    return {"users": rows}


# --------------------------------------------------------------------------
# FAILLE 5 — Debug / info leak (A05:2021) : erreur exposée au client.
# --------------------------------------------------------------------------
@app.get("/debug/config")
def debug_config():
    # vulnérable : fuite de configuration et de secrets
    return {"db": DB_CONFIG, "env": dict(os.environ)}


# --------------------------------------------------------------------------
# Page d'accueil
# --------------------------------------------------------------------------
@app.get("/", response_class=HTMLResponse)
def home():
    return """
    <h1>DIGICHEESE — lab (vulnerable)</h1>
    <ul>
        <li><a href="/products/search?q=Comté">/products/search?q=…</a></li>
        <li><a href="/comments">/comments</a></li>
        <li><a href="/admin/users">/admin/users</a></li>
        <li><a href="/debug/config">/debug/config</a></li>
        <li>POST /login (form : username, password)</li>
    </ul>
    """
