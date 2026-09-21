"""Maison Verdier -- a mock luxury fashion catalog site used to demo a
real-time bot/scraper/credential-stuffing defense layer.

Run with:
    uvicorn app.main:app --reload --port 8000
"""
import json
import os
import time

from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from itsdangerous import BadSignature, Signer

from .security.middleware import BotDefenseMiddleware
from .security.store import SecurityStore

BASE_DIR = os.path.dirname(__file__)
DATA_PATH = os.path.join(BASE_DIR, "data", "products.json")

with open(DATA_PATH) as f:
    DATA = json.load(f)

CATALOG = {p["id"]: p for p in DATA["catalog"]}
UNRELEASED = {p["id"]: p for p in DATA["unreleased"]}
USERS = {u["username"]: u["password"] for u in DATA["users"]}

store = SecurityStore()
signer = Signer("fashion-catalog-guard-demo-secret")

app = FastAPI(title="Maison Verdier")
app.add_middleware(BotDefenseMiddleware, store=store)
app.mount("/static", StaticFiles(directory=os.path.join(BASE_DIR, "static")), name="static")
templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "templates"))


def current_user(request: Request) -> str | None:
    token = request.cookies.get("session")
    if not token:
        return None
    try:
        return signer.unsign(token).decode()
    except BadSignature:
        return None


@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse(request, "catalog.html", {
        "products": DATA["catalog"],
        "user": current_user(request),
    })


@app.get("/product/{product_id}", response_class=HTMLResponse)
async def product_detail(request: Request, product_id: int):
    product = CATALOG.get(product_id)
    if not product:
        return HTMLResponse("Not found", status_code=404)
    return templates.TemplateResponse(request, "product.html", {
        "product": product, "user": current_user(request),
    })


@app.get("/collection/unreleased", response_class=HTMLResponse)
async def unreleased_collection(request: Request):
    user = current_user(request)
    if not user:
        return RedirectResponse("/login?next=/collection/unreleased", status_code=303)
    return templates.TemplateResponse(request, "unreleased.html", {
        "products": DATA["unreleased"], "user": user,
    })


@app.get("/collection/unreleased/{product_id}", response_class=HTMLResponse)
async def unreleased_detail(request: Request, product_id: int):
    user = current_user(request)
    if not user:
        return RedirectResponse("/login?next=/collection/unreleased", status_code=303)
    product = UNRELEASED.get(product_id)
    if not product:
        return HTMLResponse("Not found", status_code=404)
    return templates.TemplateResponse(request, "product.html", {
        "product": product, "user": user, "unreleased": True,
    })


@app.get("/trap/secret-preview", response_class=HTMLResponse)
async def honeypot(request: Request):
    # Linked only via an invisible <a> in catalog.html. No legitimate
    # browser click path reaches this -- any hit here is a script
    # blindly following every <a href> it can find.
    return HTMLResponse("<h1>Preview access</h1>", status_code=200)


@app.get("/login", response_class=HTMLResponse)
async def login_form(request: Request, next: str = "/"):
    return templates.TemplateResponse(request, "login.html", {
        "error": None, "next": next,
    })


@app.post("/login", response_class=HTMLResponse)
async def login_submit(request: Request, username: str = Form(...), password: str = Form(...), next: str = Form("/")):
    if USERS.get(username) == password:
        response = RedirectResponse(next or "/", status_code=303)
        token = signer.sign(username.encode()).decode()
        response.set_cookie("session", token, httponly=True, max_age=3600)
        return response
    return templates.TemplateResponse(request, "login.html", {
        "error": "Invalid username or password.", "next": next,
    }, status_code=401)


@app.get("/logout")
async def logout():
    response = RedirectResponse("/", status_code=303)
    response.delete_cookie("session")
    return response


# ---- Security operations dashboard --------------------------------------

@app.get("/admin/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):
    return templates.TemplateResponse(request, "dashboard.html", {})


@app.get("/admin/stats.json")
async def stats():
    return JSONResponse({
        "totals": store.totals(),
        "top_clients": store.top_clients(12),
        "requests_per_second": store.requests_per_second_series(60),
        "recent_design_theft": store.recent_design_theft(8),
        "recent_blocks": store.recent_blocks(8),
        "server_time": time.time(),
    })
