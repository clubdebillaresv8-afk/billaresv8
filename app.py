# -*- coding: utf-8 -*-
"""
clubdebillaresV8 – POS simple con:
- Login y gestión de usuarios
- Factura de compra por empresa (varios productos) + PDF con 'precio de venta'
- Historial de facturas (persistente) con descarga de PDF por lote
- Ventas + recibo PDF (una sola fila con totales)
- Reposición (inventario)
- Inventario a fecha
Compatible con SQLite (local) y PostgreSQL (Render).
"""

from __future__ import annotations
import os, sqlite3, hashlib, secrets, datetime as dt
from io import BytesIO
from typing import List, Optional, Tuple

import streamlit as st

try:
    import psycopg2
    import psycopg2.extras
except ImportError:
    psycopg2 = None

# =============================================================================
# CONFIGURACIÓN
# =============================================================================
APP_TITLE = "clubdebillaresV8"
DB_PATH = os.path.join(os.path.dirname(__file__), "data_pos.db")
CURRENCY = ""
BUSINESS_NAME = ""
PBKDF2_ITERATIONS = 260_000
RESTOCK_STEP = 100.0

FIXED_USER = "condeomar"
FIXED_PASS = "122130@"

st.set_page_config(page_title=APP_TITLE, layout="wide")
st.markdown("""
<style>
#MainMenu, footer, header {visibility:hidden;}
.small-note{font-size:.9rem;opacity:.7}
:root {--azul:#2563eb;--azul-hover:#1d4ed8;}
section[data-testid="stSidebar"] button{
 background:var(--azul)!important;color:white!important;border:none!important}
section[data-testid="stSidebar"] button:hover{
 background:var(--azul-hover)!important}
</style>
""", unsafe_allow_html=True)

# =============================================================================
# UTILIDADES / CONEXIÓN HÍBRIDA
# =============================================================================
def money_dot_thousands(v: float) -> str:
    try:
        return f"{int(round(v)):,.0f}".replace(",", ".")
    except Exception:
        return "0"

def use_postgres() -> bool:
    return bool(os.environ.get("DATABASE_URL")) and psycopg2 is not None

def get_conn():
    """Devuelve conexión SQLite o PostgreSQL según entorno"""
    if use_postgres():
        url = os.environ["DATABASE_URL"]
        conn = psycopg2.connect(url, cursor_factory=psycopg2.extras.DictCursor)
        return conn
    else:
        conn = sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES)
        conn.row_factory = sqlite3.Row
        return conn

def show_msg(ok: bool, msg: str):
    (st.success if ok else st.error)(str(msg))

def reportlab_ok():
    try:
        import reportlab
        return True
    except Exception:
        return False

# =============================================================================
# CREACIÓN BASE DE DATOS
# =============================================================================
def init_db():
    """Inicializa las tablas básicas."""
    if use_postgres():
        conn = get_conn(); cur = conn.cursor()
        cur.execute("""
        CREATE TABLE IF NOT EXISTS users(
            id SERIAL PRIMARY KEY,
            username TEXT UNIQUE,
            password_hash TEXT, password_salt TEXT,
            iterations INTEGER DEFAULT 260000,
            is_admin BOOLEAN DEFAULT FALSE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);
        """)
        cur.execute("""
        CREATE TABLE IF NOT EXISTS products(
            id SERIAL PRIMARY KEY,
            code TEXT UNIQUE, name TEXT,
            price REAL DEFAULT 0, cost REAL DEFAULT 0,
            iva REAL DEFAULT 0, stock INTEGER DEFAULT 0,
            company TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);
        """)
        cur.execute("""
        CREATE TABLE IF NOT EXISTS sales(
            id SERIAL PRIMARY KEY,
            product_id INTEGER REFERENCES products(id),
            qty INTEGER, total REAL,
            sold_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);
        """)
        cur.execute("""
        CREATE TABLE IF NOT EXISTS invoices(
            id SERIAL PRIMARY KEY,
            product_id INTEGER REFERENCES products(id),
            qty INTEGER, invoice_total REAL,
            unit_cost REAL, new_price REAL,
            created_by TEXT, batch_id TEXT, company TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);
        """)
        conn.commit(); conn.close()
    else:
        with get_conn() as conn:
            c = conn.cursor()
            c.execute("""CREATE TABLE IF NOT EXISTS users(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE, password_hash TEXT,
                password_salt TEXT, iterations INTEGER,
                is_admin INTEGER, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);""")
            c.execute("""CREATE TABLE IF NOT EXISTS products(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                code TEXT UNIQUE, name TEXT, price REAL, cost REAL,
                iva REAL, stock INTEGER, company TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);""")
            c.execute("""CREATE TABLE IF NOT EXISTS sales(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                product_id INTEGER, qty INTEGER, total REAL,
                sold_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(product_id) REFERENCES products(id));""")
            c.execute("""CREATE TABLE IF NOT EXISTS invoices(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                product_id INTEGER, qty INTEGER, invoice_total REAL,
                unit_cost REAL, new_price REAL, created_by TEXT,
                batch_id TEXT, company TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(product_id) REFERENCES products(id));""")
            conn.commit()

# =============================================================================
# SEGURIDAD / HASH
# =============================================================================
def hash_password(password, salt_hex=None, iterations=PBKDF2_ITERATIONS):
    if not salt_hex:
        salt = secrets.token_bytes(16)
        salt_hex = salt.hex()
    else:
        salt = bytes.fromhex(salt_hex)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
    return dk.hex(), salt_hex, iterations

def verify_password(password, stored_hash_hex, salt_hex, iterations):
    h, _, _ = hash_password(password, salt_hex, iterations)
    return secrets.compare_digest(h, stored_hash_hex)

def create_user(username, password, is_admin=False):
    username = username.strip().lower()
    if not username or not password:
        return False, "Usuario y contraseña requeridos."
    h, s, it = hash_password(password)
    try:
        with get_conn() as conn:
            cur = conn.cursor()
            if use_postgres():
                cur.execute("INSERT INTO users(username,password_hash,password_salt,iterations,is_admin) VALUES(%s,%s,%s,%s,%s)",
                            (username, h, s, it, is_admin))
            else:
                cur.execute("INSERT INTO users(username,password_hash,password_salt,iterations,is_admin) VALUES(?,?,?,?,?)",
                            (username, h, s, it, 1 if is_admin else 0))
            conn.commit()
        return True, f"Usuario {username} creado."
    except Exception as e:
        return False, str(e)

def verify_user(username, password):
    u = username.strip().lower()
    if u == FIXED_USER and password == FIXED_PASS:
        return True, {"username": u, "is_admin": True}
    try:
        conn = get_conn(); cur = conn.cursor()
        if use_postgres():
            cur.execute("SELECT * FROM users WHERE username=%s", (u,))
        else:
            cur.execute("SELECT * FROM users WHERE username=?", (u,))
        row = cur.fetchone()
        if not row: return False, {}
        data = dict(row)
        if verify_password(password, data["password_hash"], data["password_salt"], int(data["iterations"])):
            return True, {"username": data["username"], "is_admin": bool(data["is_admin"])}
        return False, {}
    except Exception:
        return False, {}
# =============================================================================
# CRUD – PRODUCTOS / FACTURAS / VENTAS
# =============================================================================
def get_product_by_code(code: str):
    with get_conn() as conn:
        cur = conn.cursor()
        if use_postgres():
            cur.execute("SELECT * FROM products WHERE code=%s", (code,))
        else:
            cur.execute("SELECT * FROM products WHERE code=?", (code,))
        row = cur.fetchone()
        return dict(row) if row else None

def add_product(code, name, price, stock, cost, iva, company):
    try:
        with get_conn() as conn:
            cur = conn.cursor()
            if use_postgres():
                cur.execute("""INSERT INTO products(code,name,price,stock,cost,iva,company)
                               VALUES(%s,%s,%s,%s,%s,%s,%s)
                               ON CONFLICT (code) DO UPDATE SET
                               name=EXCLUDED.name,price=EXCLUDED.price,
                               stock=EXCLUDED.stock,cost=EXCLUDED.cost,iva=EXCLUDED.iva,company=EXCLUDED.company""",
                            (code, name, price, stock, cost, iva, company))
            else:
                cur.execute("""INSERT OR REPLACE INTO products(code,name,price,stock,cost,iva,company)
                               VALUES(?,?,?,?,?,?,?)""",
                            (code, name, price, stock, cost, iva, company))
            conn.commit()
        return True, "Producto guardado."
    except Exception as e:
        return False, f"Error: {e}"

def list_products_db():
    with get_conn() as conn:
        cur = conn.cursor()
        q = "SELECT * FROM products ORDER BY name ASC"
        cur.execute(q)
        return [dict(x) for x in cur.fetchall()]

def insert_invoice(product_id, qty, total, unit_cost, new_price, created_by, batch_id, company):
    with get_conn() as conn:
        cur = conn.cursor()
        if use_postgres():
            cur.execute("""INSERT INTO invoices(product_id,qty,invoice_total,unit_cost,new_price,created_by,batch_id,company)
                           VALUES(%s,%s,%s,%s,%s,%s,%s,%s)""",
                        (product_id, qty, total, unit_cost, new_price, created_by, batch_id, company))
        else:
            cur.execute("""INSERT INTO invoices(product_id,qty,invoice_total,unit_cost,new_price,created_by,batch_id,company)
                           VALUES(?,?,?,?,?,?,?,?)""",
                        (product_id, qty, total, unit_cost, new_price, created_by, batch_id, company))
        conn.commit()

def delete_invoice_batch(batch_id: str, adjust_stock=True):
    try:
        with get_conn() as conn:
            cur = conn.cursor()
            if use_postgres():
                cur.execute("SELECT product_id, qty FROM invoices WHERE batch_id=%s", (batch_id,))
            else:
                cur.execute("SELECT product_id, qty FROM invoices WHERE batch_id=?", (batch_id,))
            rows = cur.fetchall()
            if not rows:
                return False, "Lote no encontrado."
            if adjust_stock:
                for r in rows:
                    pid, q = int(r["product_id"]), int(r["qty"])
                    if use_postgres():
                        cur.execute("UPDATE products SET stock=GREATEST(stock - %s,0) WHERE id=%s", (q, pid))
                    else:
                        cur.execute("UPDATE products SET stock=max(stock - ?,0) WHERE id=?", (q, pid))
            if use_postgres():
                cur.execute("DELETE FROM invoices WHERE batch_id=%s", (batch_id,))
            else:
                cur.execute("DELETE FROM invoices WHERE batch_id=?", (batch_id,))
            conn.commit()
        return True, f"Lote {batch_id} eliminado."
    except Exception as e:
        return False, f"Error al borrar lote: {e}"

def register_sale(product_id: int, qty: int):
    if qty <= 0:
        return False, "Cantidad inválida", 0.0
    with get_conn() as conn:
        cur = conn.cursor()
        if use_postgres():
            cur.execute("SELECT price,stock,name,cost FROM products WHERE id=%s", (product_id,))
        else:
            cur.execute("SELECT price,stock,name,cost FROM products WHERE id=?", (product_id,))
        r = cur.fetchone()
        if not r:
            return False, "Producto no encontrado.", 0.0
        price, stock = float(r["price"]), int(r["stock"])
        if stock < qty:
            return False, f"Stock insuficiente ({stock})", 0.0
        total = round(price * qty, 2)
        try:
            if use_postgres():
                cur.execute("UPDATE products SET stock=stock-%s WHERE id=%s", (qty, product_id))
                cur.execute("INSERT INTO sales(product_id,qty,total) VALUES(%s,%s,%s)", (product_id, qty, total))
            else:
                cur.execute("UPDATE products SET stock=stock-? WHERE id=?", (qty, product_id))
                cur.execute("INSERT INTO sales(product_id,qty,total) VALUES(?,?,?)", (product_id, qty, total))
            conn.commit()
            return True, f"Venta de {qty} x {r['name']} registrada.", total
        except Exception as e:
            conn.rollback()
            return False, str(e), 0.0

# =============================================================================
# PDF
# =============================================================================
def build_company_invoice_pdf_with_sale(rows: List[dict], company: str, business_name: str = "", nit: str = ""):
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.enums import TA_CENTER
    from reportlab.lib import colors

    buf = BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=letter, leftMargin=24, rightMargin=24, topMargin=28, bottomMargin=28)
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("TitleStrong", parent=styles["Title"], fontName="Helvetica-Bold", alignment=TA_CENTER)
    title = Paragraph(f"<b>{(business_name or 'Factura por empresa')}</b>", title_style)
    subtitle = Paragraph(f"Empresa: <b>{company}</b> — Fecha: {dt.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles["Normal"])
    header = ["Código", "Unidades", "Nombre", "IVA", "Valor unitario", "Valor de venta", "Total"]
    data = [header]
    total_general = 0.0
    for r in rows:
        qty = int(r.get("qty", 0))
        iva = float(r.get("iva", 0.0))
        unit = float(r.get("unit_cost", 0.0))
        sale = float(r.get("sale_price", 0.0))
        total = qty * unit * (1 + iva/100)
        total_general += total
        data.append([r.get("code",""), qty, r.get("name",""), f"{iva:.2f}%", money_dot_thousands(unit),
                     money_dot_thousands(sale), money_dot_thousands(total)])
    data.append(["", "", "", "", "", "TOTAL", money_dot_thousands(total_general)])
    table = Table(data, colWidths=[65, 60, 220, 60, 80, 80, 80])
    table.setStyle(TableStyle([
        ("GRID", (0,0), (-1,-1), 1.2, colors.black),
        ("BACKGROUND",(0,0),(-1,0),colors.whitesmoke),
        ("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),
        ("ALIGN",(1,1),(-1,-1),"CENTER"),
        ("ALIGN",(2,1),(2,-1),"LEFT"),
        ("ALIGN",(4,1),(-1,-1),"RIGHT"),
        ("SPAN",(0,-1),(5,-1)),
        ("BACKGROUND",(0,-1),(-1,-1),colors.whitesmoke),
        ("FONTNAME",(5,-1),(6,-1),"Helvetica-Bold")
    ]))
    doc.build([title, Spacer(1,6), subtitle, Spacer(1,8), table])
    pdf = buf.getvalue(); buf.close()
    return pdf, None

# =============================================================================
# FOOTER
# =============================================================================
def render_footer():
    st.markdown("""
    <style>.custom-footer{position:fixed;bottom:0;width:100%;text-align:center;
    font-size:12px;color:#6b7280;}</style>
    <div class="custom-footer">© 2025 Creado por Omar Conde</div>
    """, unsafe_allow_html=True)
# =============================================================================
# INTERFAZ STREAMLIT
# =============================================================================
def ui_login():
    st.title("🔐 Iniciar sesión")
    with st.form("login_form"):
        u = st.text_input("Usuario")
        p = st.text_input("Contraseña", type="password")
        if st.form_submit_button("Entrar"):
            ok, data = verify_user(u, p)
            if ok:
                st.session_state["user"] = data
                st.success(f"Bienvenido, {data['username']}")
                st.rerun()
            else:
                st.error("Credenciales incorrectas")

def ui_factura_compra():
    st.header("📦 Ingreso de factura de compra por empresa")
    company = st.text_input("Nombre de la empresa")
    fecha_factura = st.date_input("Fecha de la factura", dt.date.today())
    batch_id = f"{company}_{dt.datetime.now().strftime('%Y%m%d%H%M%S')}"
    st.markdown("---")
    code = st.text_input("Código del producto")
    name = st.text_input("Nombre del producto")
    qty = st.number_input("Cantidad", min_value=1, step=1)
    unit_cost = st.number_input("Costo unitario", min_value=0.0)
    sale_price = st.number_input("Valor de venta sugerido", min_value=0.0)
    iva = st.number_input("IVA (%)", min_value=0.0, value=0.0)
    btn_add = st.button("Agregar producto")

    if "factura_items" not in st.session_state:
        st.session_state.factura_items = []

    if btn_add:
        total = qty * unit_cost
        add_product(code, name, sale_price, qty, unit_cost, iva, company)
        product = get_product_by_code(code)
        if product:
            insert_invoice(product["id"], qty, total, unit_cost, sale_price,
                           st.session_state["user"]["username"], batch_id, company)
            st.session_state.factura_items.append({
                "code": code, "name": name, "qty": qty, "iva": iva,
                "unit_cost": unit_cost, "sale_price": sale_price
            })
            st.success(f"Producto {name} agregado a la factura.")
    st.markdown("---")

    if st.session_state.factura_items:
        st.subheader("Detalle de factura actual")
        st.table(st.session_state.factura_items)
        if st.button("Generar PDF de esta factura"):
            pdf, _ = build_company_invoice_pdf_with_sale(
                st.session_state.factura_items, company)
            st.download_button("Descargar factura PDF", pdf,
                               f"Factura_{company}.pdf", "application/pdf")

def ui_historial_facturas():
    st.header("🧾 Historial de facturas de compra")
    with get_conn() as conn:
        cur = conn.cursor()
        if use_postgres():
            cur.execute("""SELECT DISTINCT batch_id, company, MIN(created_at) as fecha, COUNT(*) as productos
                           FROM invoices GROUP BY batch_id, company ORDER BY fecha DESC""")
        else:
            cur.execute("""SELECT DISTINCT batch_id, company, MIN(created_at) as fecha, COUNT(*) as productos
                           FROM invoices GROUP BY batch_id, company ORDER BY fecha DESC""")
        rows = [dict(r) for r in cur.fetchall()]
    st.dataframe(rows)
    if rows:
        sel = st.selectbox("Selecciona un lote", [r["batch_id"] for r in rows])
        if st.button("Ver factura en PDF"):
            with get_conn() as conn:
                cur = conn.cursor()
                if use_postgres():
                    cur.execute("""SELECT p.code,p.name,i.qty,p.iva,i.unit_cost,i.new_price as sale_price
                                   FROM invoices i JOIN products p ON i.product_id=p.id WHERE i.batch_id=%s""", (sel,))
                else:
                    cur.execute("""SELECT p.code,p.name,i.qty,p.iva,i.unit_cost,i.new_price as sale_price
                                   FROM invoices i JOIN products p ON i.product_id=p.id WHERE i.batch_id=?""", (sel,))
                rows2 = [dict(r) for r in cur.fetchall()]
            if rows2:
                pdf, _ = build_company_invoice_pdf_with_sale(rows2, rows[0]["company"])
                st.download_button("Descargar PDF", pdf, f"{sel}.pdf", "application/pdf")

def ui_inventario():
    st.header("📋 Inventario actual")
    data = list_products_db()
    st.dataframe(data)
    st.download_button("Descargar inventario CSV",
                       "\n".join([",".join(map(str, x.values())) for x in data]),
                       "inventario.csv", "text/csv")

# =============================================================================
# MAIN
# =============================================================================
def main():
    init_db()
    render_footer()

    user = st.session_state.get("user")
    if not user:
        ui_login()
        return

    menu = st.sidebar.radio("Navegación", ["Factura de compra", "Historial", "Inventario", "Salir"])

    if menu == "Factura de compra":
        ui_factura_compra()
    elif menu == "Historial":
        ui_historial_facturas()
    elif menu == "Inventario":
        ui_inventario()
    elif menu == "Salir":
        st.session_state.clear()
        st.rerun()

if __name__ == "__main__":
    main()
integralo pormi y melo imprimes # -*- coding: utf-8 -*-
"""
clubdebillaresV8 – POS simple con:
- Login y gestión de usuarios
- Factura de compra por empresa (varios productos) + PDF con 'precio de venta'
- Historial de facturas (persistente) con descarga de PDF por lote
- Ventas + recibo PDF (una sola fila con totales)
- Reposición (inventario)
- Inventario a fecha

Requisitos:
    pip install streamlit==1.38.0 reportlab

Ejecutar:
    streamlit run app.py
"""
from __future__ import annotations

import os
import sqlite3
import hashlib
import secrets
import datetime as dt
from io import BytesIO
from typing import List, Optional, Tuple

import streamlit as st

# =============================================================================
# CONFIGURACIÓN
# =============================================================================
APP_TITLE = "clubdebillaresV8"
DB_PATH = os.environ.get("POS_DB_PATH") or os.path.join(os.path.dirname(__file__), "data_pos.db")
CURRENCY = ""              # Moneda visible (ej. "$")
BUSINESS_NAME = ""         # Nombre por defecto para PDFs
PBKDF2_ITERATIONS = 260_000

# Usuario fijo opcional (para entrar sin crear usuario)
FIXED_USER = "condeomar"
FIXED_PASS = "122130@"

# Paso para +/- en REPOSICIÓN
RESTOCK_STEP = 100.0


# =============================================================================
# ESTILOS / LAYOUT
# =============================================================================
st.set_page_config(page_title=APP_TITLE, page_icon=None, layout="wide")
st.markdown(
    """
<style>
div[data-testid="stElementToolbar"],
div[data-testid="stDecoration"],
header [data-testid="baseButton-headerNoPadding"],
div[data-testid="stToolbar"],
#MainMenu { display:none !important; }
.small-note { font-size:.9rem; opacity:.7; }

/* ====== COLOR AZUL EN EL SIDEBAR ====== */
:root { --azul-primario: #2563eb; --azul-primario-hover:#1d4ed8; }
section[data-testid="stSidebar"] input[type="radio"],
section[data-testid="stSidebar"] input[type="checkbox"] {
  accent-color: var(--azul-primario);
}
section[data-testid="stSidebar"] .stButton > button {
  background: var(--azul-primario) !important;
  border: 1px solid var(--azul-primario) !important;
  color: #fff !important;
  box-shadow: none !important;
}
section[data-testid="stSidebar"] .stButton > button:hover {
  background: var(--azul-primario-hover) !important;
  border-color: var(--azul-primario-hover) !important;
}
section[data-testid="stSidebar"] .stButton > button:focus,
section[data-testid="stSidebar"] .stButton > button:active {
  outline: none !important;
  box-shadow: 0 0 0 2px rgba(37, 99, 235, .25) !important;
}
</style>
""",
    unsafe_allow_html=True,
)


# =============================================================================
# UTILIDADES
# =============================================================================
def money_dot_thousands(v: float) -> str:
    return f"{int(round(v)):,.0f}".replace(",", ".")


def reportlab_ok() -> bool:
    try:
        import reportlab  # noqa: F401
        return True
    except Exception:
        return False


def show_msg(ok: bool, msg: str) -> None:
    safe = str(msg)
    try:
        (st.success if ok else st.error)(safe)
    except Exception:
        st.write(("OK: " if ok else "ERROR: ") + safe)


# =============================================================================
# BASE DE DATOS
# =============================================================================
def get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES | sqlite3.PARSE_COLNAMES)
    conn.row_factory = sqlite3.Row
    return conn


def _col_exists(conn: sqlite3.Connection, table: str, col: str) -> bool:
    r = conn.execute(f"PRAGMA table_info({table})").fetchall()
    return any(c[1] == col for c in r)

# ---- NUEVO: utilitario para dejar la base "en blanco" (conserva usuarios por defecto)
def wipe_business_data(keep_users: bool = True) -> None:
    with get_conn() as conn:
        conn.execute("DELETE FROM invoices;")
        conn.execute("DELETE FROM sales;")
        conn.execute("DELETE FROM products;")
        if not keep_users:
            conn.execute("DELETE FROM users;")
        conn.commit()

# ---- NUEVO: eliminar un lote de facturas (opción para revertir stock)
def delete_invoice_batch(batch_id: str, adjust_stock: bool = True) -> Tuple[bool, str]:
    if not batch_id:
        return False, "Batch ID inválido."
    try:
        with get_conn() as conn:
            lines = conn.execute(
                "SELECT product_id, qty FROM invoices WHERE batch_id=?",
                (batch_id,),
            ).fetchall()

            if not lines:
                return False, "No se encontraron líneas para ese lote."

            if adjust_stock:
                # Revertir stock por cada línea
                for ln in lines:
                    pid = int(ln["product_id"])
                    q = int(ln["qty"])
                    cur = conn.execute("SELECT stock FROM products WHERE id=?", (pid,)).fetchone()
                    if cur:
                        new_stock = max(int(cur["stock"] or 0) - q, 0)
                        conn.execute("UPDATE products SET stock=? WHERE id=?", (new_stock, pid))

            # Borrar las líneas del lote
            conn.execute("DELETE FROM invoices WHERE batch_id=?", (batch_id,))
            conn.commit()

        return True, f"Lote {batch_id} eliminado correctamente" + (" y stock revertido." if adjust_stock else ".")
    except Exception as e:
        return False, f"No se pudo borrar el lote: {e}"


def init_db() -> None:
    with get_conn() as conn:
        cur = conn.cursor()

        # -- Usuarios
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS users(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                password_salt TEXT NOT NULL,
                iterations INTEGER NOT NULL DEFAULT 260000,
                is_admin INTEGER NOT NULL DEFAULT 0,
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            """
        )

        # -- Products SIN UNIQUE EN name
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS products(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                price REAL NOT NULL CHECK(price>=0),
                stock INTEGER NOT NULL DEFAULT 0 CHECK(stock>=0),
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            """
        )

        # -- Ventas
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS sales(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                product_id INTEGER NOT NULL,
                qty INTEGER NOT NULL CHECK(qty>0),
                total REAL NOT NULL CHECK(total>=0),
                sold_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(product_id) REFERENCES products(id)
            );
            """
        )

        # -- Migraciones de columnas en products
        cur.execute("PRAGMA table_info(products)")
        cols = [r[1] for r in cur.fetchall()]
        if "code" not in cols:
            cur.execute("ALTER TABLE products ADD COLUMN code TEXT")
            cur.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_products_code_unique ON products(code)")
        if "cost" not in cols:
            cur.execute("ALTER TABLE products ADD COLUMN cost REAL NOT NULL DEFAULT 0")
        if "iva" not in cols:
            cur.execute("ALTER TABLE products ADD COLUMN iva REAL NOT NULL DEFAULT 0")
        if "company" not in cols:
            cur.execute("ALTER TABLE products ADD COLUMN company TEXT")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_products_company ON products(company)")

        # -- Facturas (reabastecimientos por línea) + migraciones
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS invoices(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                product_id INTEGER NOT NULL,
                qty INTEGER NOT NULL CHECK(qty>0),
                invoice_total REAL NOT NULL CHECK(invoice_total>=0),
                unit_cost REAL NOT NULL CHECK(unit_cost>=0),
                new_price REAL,
                created_by TEXT,
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            """
        )
        # Migraciones nuevas para historial por lote
        if not _col_exists(conn, "invoices", "batch_id"):
            cur.execute("ALTER TABLE invoices ADD COLUMN batch_id TEXT")
        if not _col_exists(conn, "invoices", "company"):
            cur.execute("ALTER TABLE invoices ADD COLUMN company TEXT")

        # ====== MIGRACIÓN: si la tabla products tenía UNIQUE en name, reconstruir ======
        row = conn.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='products'").fetchone()
        sql_products = (row["sql"] if row and "sql" in row.keys() else (row[0] if row else "")) or ""
        if "name TEXT NOT NULL UNIQUE" in sql_products:
            conn.execute("PRAGMA foreign_keys=off")
            conn.execute("ALTER TABLE products RENAME TO _products_old")
            conn.execute(
                """
                CREATE TABLE products(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    price REAL NOT NULL CHECK(price>=0),
                    stock INTEGER NOT NULL DEFAULT 0 CHECK(stock>=0),
                    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    code TEXT,
                    cost REAL NOT NULL DEFAULT 0,
                    iva REAL NOT NULL DEFAULT 0,
                    company TEXT
                );
                """
            )
            conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_products_code_unique ON products(code)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_products_company ON products(company)")
            conn.execute(
                """
                INSERT INTO products(id, name, price, stock, created_at, code, cost, iva, company)
                SELECT id, name, price, stock, created_at, code, COALESCE(cost,0), COALESCE(iva,0), company
                FROM _products_old
                """
            )
            conn.execute("DROP TABLE _products_old")
            conn.execute("PRAGMA foreign_keys=on")

        conn.commit()

    # ---- Mantener app en blanco si POS_EMPTY_DB=1 (conservando usuarios)
    if os.environ.get("POS_EMPTY_DB") == "1":
        wipe_business_data(keep_users=True)


# =============================================================================
# SEGURIDAD – HASH DE CONTRASEÑAS
# =============================================================================
def hash_password(password: str, salt_hex: Optional[str] = None, iterations: int = PBKDF2_ITERATIONS):
    if not salt_hex:
        salt = secrets.token_bytes(16)
        salt_hex = salt.hex()
    else:
        salt = bytes.fromhex(salt_hex)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return dk.hex(), salt_hex, iterations


def verify_password(password: str, stored_hash_hex: str, salt_hex: str, iterations: int) -> bool:
    new_hash_hex, _, _ = hash_password(password, salt_hex, iterations)
    return secrets.compare_digest(new_hash_hex, stored_hash_hex)


# =============================================================================
# CRUD – USUARIOS
# =============================================================================
def create_user(username: str, password: str, is_admin: bool = False) -> Tuple[bool, str]:
    username = (username or "").strip().lower()
    if not username:
        return False, "El usuario no puede estar vacío."
    if not password or len(password) < 4:
        return False, "La contraseña debe tener al menos 4 caracteres."

    hash_hex, salt_hex, iters = hash_password(password)
    try:
        with get_conn() as conn:
            conn.execute(
                "INSERT INTO users(username,password_hash,password_salt,iterations,is_admin) VALUES (?,?,?,?,?)",
                (username, hash_hex, salt_hex, iters, 1 if is_admin else 0),
            )
            conn.commit()
        return True, f"Usuario '{username}' creado."
    except sqlite3.IntegrityError:
        return False, "Ese usuario ya existe."


def list_users() -> List[sqlite3.Row]:
    with get_conn() as conn:
        return conn.execute(
            "SELECT id, username, is_admin, created_at FROM users ORDER BY username ASC"
        ).fetchall()


def delete_user(user_id: int) -> Tuple[bool, str]:
    try:
        with get_conn() as conn:
            conn.execute("DELETE FROM users WHERE id=?", (user_id,))
            conn.commit()
        return True, "Usuario eliminado."
    except Exception as e:
        return False, f"No se pudo eliminar: {e}"


def verify_user(username: str, password: str) -> Tuple[bool, dict]:
    u = (username or "").strip().lower()
    if u == FIXED_USER and password == FIXED_PASS:
        return True, {"username": FIXED_USER, "is_admin": True}

    with get_conn() as conn:
        row = conn.execute("SELECT * FROM users WHERE username=?", (u,)).fetchone()
        if not row:
            return False, {}
        if verify_password(password, row["password_hash"], row["password_salt"], int(row["iterations"])):  # type: ignore
            return True, {"username": row["username"], "is_admin": bool(row["is_admin"]) }
        return False, {}


# =============================================================================
# CRUD – PRODUCTOS / VENTAS / FACTURAS
# =============================================================================
def add_product(code: str, name: str, price: float, stock: int, cost: float, iva: float, company: str) -> Tuple[bool, str]:
    code = (code or "").strip()
    name = (name or "").strip()
    company = (company or "").strip()
    if not code:
        return False, "El código no puede estar vacío."
    if not name:
        return False, "El nombre no puede estar vacío."
    if price < 0:
        return False, "El precio no puede ser negativo."
    if stock < 0:
        return False, "El stock no puede ser negativo."
    if cost < 0:
        return False, "El costo unitario no puede ser negativo."
    if iva < 0:
        return False, "El IVA no puede ser negativo."

    existing = get_product_by_code(code)
    if existing:
        ok, msg = update_product_by_code(code, name, float(price), int(stock), float(cost), float(iva), company)
        if ok:
            return True, f"Producto actualizado (código '{code}' ya existía)."
        return False, msg

    try:
        with get_conn() as conn:
            conn.execute(
                "INSERT INTO products(code,name,price,stock,cost,iva,company) VALUES (?,?,?,?,?,?,?)",
                (code, name, price, stock, cost, iva, company),
            )
            conn.commit()
        return True, f"Producto '{name}' agregado."
    except sqlite3.IntegrityError as e:
        m = str(e).lower()
        if "unique" in m and ("products.code" in m or ".code" in m or "idx_products_code_unique" in m):
            return False, "Ya existe un producto con ese CÓDIGO."
        return False, "No se pudo guardar el producto."


def update_product_by_code(code: str, name: str, price: float, stock: int, cost: float, iva: float, company: str) -> Tuple[bool, str]:
    code = (code or "").strip()
    if not code:
        return False, "Código requerido."
    with get_conn() as conn:
        cur = conn.execute("SELECT id FROM products WHERE code=?", (code,)).fetchone()
        if not cur:
            return False, "No existe un producto con ese código."
        try:
            conn.execute(
                "UPDATE products SET name=?, price=?, stock=?, cost=?, iva=?, company=? WHERE code=?",
                (name.strip(), float(price), int(stock), float(cost), float(iva), (company or None), code),
            )
            conn.commit()
            return True, "Producto actualizado."
        except sqlite3.IntegrityError as e:
            return False, f"No se pudo actualizar: {e}"


def delete_product(product_id: int) -> Tuple[bool, str]:
    try:
        with get_conn() as conn:
            conn.execute("DELETE FROM products WHERE id=?", (product_id,))
            conn.commit()
        return True, "Producto eliminado permanentemente."
    except Exception as e:
        return False, f"No se pudo eliminar el producto: {e}"


def get_product_by_code(code: str) -> Optional[sqlite3.Row]:
    with get_conn() as conn:
        return conn.execute(
            "SELECT id, code, name, price, stock, cost, iva, company FROM products WHERE code=?", (code.strip(),)
        ).fetchone()


def get_product_by_name(name: str) -> Optional[sqlite3.Row]:
    with get_conn() as conn:
        return conn.execute(
            "SELECT id, code, name, price, stock, cost, iva, company "
            "FROM products WHERE LOWER(name)=LOWER(?) LIMIT 1",
            (name.strip(),),
        ).fetchone()


def list_products_db() -> List[sqlite3.Row]:
    with get_conn() as conn:
        return conn.execute(
            "SELECT id, code, name, price, stock, cost, iva, company FROM products ORDER BY name ASC"
        ).fetchall()


def insert_invoice(
    product_id: int,
    qty: int,
    invoice_total: float,
    unit_cost: float,
    new_price: Optional[float],
    created_by: Optional[str],
    *,
    batch_id: Optional[str],
    company: Optional[str],
) -> None:
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO invoices(product_id, qty, invoice_total, unit_cost, new_price, created_by, batch_id, company) "
            "VALUES (?,?,?,?,?,?,?,?)",
            (product_id, qty, invoice_total, unit_cost, new_price, created_by, batch_id, company),
        )
        conn.commit()


def list_invoices(limit: Optional[int] = 15) -> List[sqlite3.Row]:
    sql = """
        SELECT
            i.id,
            i.created_at,
            i.qty,
            i.invoice_total,
            i.unit_cost,
            i.new_price,
            i.created_by,
            i.batch_id,
            i.company,
            p.name AS product,
            p.code
        FROM invoices i
        JOIN products p ON p.id = i.product_id
        ORDER BY i.created_at DESC
    """
    if limit:
        sql += f" LIMIT {int(limit)}"
    with get_conn() as conn:
        return conn.execute(sql).fetchall()


def restock_with_invoice(
    product_id: int, qty: int, invoice_total: Optional[float], new_price: Optional[float]
) -> Tuple[bool, str]:
    if qty <= 0:
        return False, "La cantidad debe ser mayor a 0."
    if invoice_total is not None and invoice_total < 0:
        return False, "El valor de la factura no puede ser negativo."
    if new_price is not None and new_price < 0:
        return False, "El precio de venta no puede ser negativo."

    with get_conn() as conn:
        row = conn.execute("SELECT name, stock FROM products WHERE id=?", (product_id,)).fetchone()
        if not row:
            return False, "Producto no encontrado."

        new_stock = int(row["stock"]) + int(qty)
        sets, params = ["stock=?"], [new_stock]
        unit_cost: Optional[float] = None

        if invoice_total is not None and qty > 0:
            unit_cost = round(float(invoice_total) / int(qty), 4)
            sets.append("cost=?"); params.append(unit_cost)

        if new_price is not None:
            sets.append("price=?"); params.append(float(new_price))

        params.append(product_id)
        conn.execute(f"UPDATE products SET {', '.join(sets)} WHERE id=?", params)
        conn.commit()

    creator = (st.session_state.get("auth_user") or {}).get("username")
    if invoice_total is not None and unit_cost is not None:
        insert_invoice(
            product_id, int(qty), float(invoice_total), float(unit_cost),
            float(new_price) if new_price is not None else None, creator,
            batch_id=None, company=None
        )

    extras = []
    if invoice_total is not None and unit_cost is not None:
        extras.append(
            f"factura {CURRENCY}{money_dot_thousands(invoice_total)} "
            f"(costo unit. {CURRENCY}{money_dot_thousands(unit_cost)})"
        )
    extra_msg = " — " + ", ".join(extras) if extras else ""
    return True, f"Stock actualizado a {new_stock}.{extra_msg}"


def register_sale(product_id: int, qty: int) -> Tuple[bool, str, float]:
    if qty <= 0:
        return False, "La cantidad debe ser mayor a 0.", 0.0

    with get_conn() as conn:
        row = conn.execute(
            "SELECT price, stock, name, cost FROM products WHERE id=?", (product_id,)
        ).fetchone()
        if not row:
            return False, "Producto no encontrado.", 0.0
        if row["stock"] < qty:
            return False, f"Stock insuficiente. Disponible: {row['stock']}", 0.0

        total = round(float(row["price"]) * int(qty), 2)

        try:
            conn.execute("BEGIN")
            conn.execute("UPDATE products SET stock=stock-? WHERE id=?", (int(qty), product_id))
            conn.execute("INSERT INTO sales(product_id, qty, total) VALUES (?,?,?)", (product_id, int(qty), total))
            conn.commit()
            return True, f"Venta registrada de {qty} x {row['name']}.", total
        except Exception as e:
            conn.rollback()
            return False, f"Error al registrar venta: {e}", 0.0


# =============================================================================
# PDFs
# =============================================================================
def build_sale_pdf_like_screenshot(
    *, business_name: str, product: str, qty: int, cost_unit: float, price_unit: float,
    when: Optional[dt.datetime] = None
):
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib import colors

    when = when or dt.datetime.now()

    unidades = int(qty)
    costo_u = float(cost_unit)
    precio_u = float(price_unit)
    valor = precio_u * unidades
    ganancia = (precio_u - costo_u) * unidades

    buf = BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=letter, leftMargin=24, rightMargin=24, topMargin=28, bottomMargin=28)
    styles = getSampleStyleSheet()

    titulo = f"<b>{business_name}</b>" if business_name else "<b>Recibo de venta</b>"
    title = Paragraph(titulo, styles["Title"])
    when_p = Paragraph(f"Fecha/Hora: {when.strftime('%Y-%m-%d %H:%M:%S')}", styles["Normal"])

    header = ["Producto", "Unidades", "Costo unit.", "Precio venta", "Valor", "Ganancia"]
    fila = [
        str(product),
        f"{unidades}",
        money_dot_thousands(costo_u),
        money_dot_thousands(precio_u),
        money_dot_thousands(valor),
        money_dot_thousands(ganancia),
    ]
    data = [header, fila]

    table = Table(data, colWidths=[220, 60, 90, 90, 90, 90])
    table.setStyle(
        TableStyle(
            [
                ("GRID", (0, 0), (-1, -1), 0.8, colors.black),
                ("BACKGROUND", (0, 0), (-1, 0), colors.whitesmoke),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("ALIGN", (0, 1), (0, 1), "LEFT"),
                ("ALIGN", (1, 1), (-1, 1), "RIGHT"),
                ("FONTSIZE", (0, 0), (-1, -1), 9.5),
            ]
        )
    )

    doc.build([title, Spacer(1, 6), when_p, Spacer(1, 10), table])
    pdf = buf.getvalue()
    buf.close()
    return pdf, None


def build_company_invoice_pdf_with_sale(
    *, rows: List[dict], company: str, business_name: str = "", nit: str = ""
):
    """
    PDF multi-ítem por empresa con columna Valor de venta.
    rows: dicts con keys: code, qty, name, iva, unit_cost, sale_price
    """
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.enums import TA_CENTER
    from reportlab.lib import colors
    import datetime as dt

    buf = BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=letter,
        leftMargin=24, rightMargin=24, topMargin=28, bottomMargin=28
    )
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("TitleStrong", parent=styles["Title"], fontName="Helvetica-Bold", alignment=TA_CENTER)

    title = Paragraph(
        f"<b>{(business_name or 'Factura por empresa')}{(' – NIT ' + nit) if nit else ''}</b>",
        title_style
    )
    subtitle = Paragraph(
        f"Empresa: <b>{company}</b> — Fecha/Hora: {dt.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        styles["Normal"]
    )

    header = ["Código", "Unidades", "Nombre", "IVA", "Valor unitario", "Valor de venta", "Total"]
    data = [header]
    total_general = 0.0

    for r in rows:
        qty = int(r.get("qty", 0))
        iva = float(r.get("iva", 0.0))
        unit = float(r.get("unit_cost", 0.0))
        sale = float(r.get("sale_price", 0.0))
        total = qty * unit * (1.0 + iva/100.0)
        total_general += total
        data.append([
            str(r.get("code", "")),
            f"{qty}",
            str(r.get("name", "")),
            f"{iva:.2f} %",
            money_dot_thousands(unit),
            money_dot_thousands(sale),
            money_dot_thousands(total),
        ])

    data.append(["", "", "", "", "", "TOTAL", money_dot_thousands(total_general)])

    table = Table(data, colWidths=[65, 60, 230, 60, 85, 85, 85])
    table.setStyle(
        TableStyle(
            [
                ("GRID", (0, 0), (-1, -1), 1.2, colors.black),
                ("BACKGROUND", (0, 0), (-1, 0), colors.whitesmoke),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, 0), 11),
                ("ALIGN", (0, 1), (1, -2), "CENTER"),
                ("ALIGN", (2, 1), (2, -2), "LEFT"),
                ("ALIGN", (3, 1), (3, -2), "CENTER"),
                ("ALIGN", (4, 1), (6, -2), "RIGHT"),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("TOPPADDING", (0, 1), (-1, -2), 3),
                ("BOTTOMPADDING", (0, 1), (-1, -2), 3),
                ("LEFTPADDING", (0, 0), (-1, -1), 4),
                ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                ("SPAN", (0, -1), (5, -1)),
                ("BACKGROUND", (0, -1), (-1, -1), colors.whitesmoke),
                ("FONTNAME", (5, -1), (6, -1), "Helvetica-Bold"),
                ("ALIGN", (6, -1), (6, -1), "RIGHT"),
            ]
        )
    )

    doc.build([title, Spacer(1, 6), subtitle, Spacer(1, 8), table])
    pdf = buf.getvalue()
    buf.close()
    return pdf, None


# =============================================================================
# PIE DE PÁGINA
# =============================================================================
def render_footer() -> None:
    st.markdown(
        """
        <style>
        .custom-footer {
            position: fixed; left: 0; right: 0; bottom: 0;
            padding: 8px 12px; text-align: center;
            font-size: 12px; color: #6b7280; background: transparent;
            z-index: 9999; pointer-events: none;
        }
        </style>
        <div class="custom-footer">© 2025 CREADO POR OMAR CONDE</div>
        """,
        unsafe_allow_html=True,
    )


# =============================================================================
# AUTOCARGA (EN FACTURA) AL ESCRIBIR CÓDIGO
# =============================================================================
def _load_item_from_code():
    code = (st.session_state.get("inv_code") or "").strip()
    if not code:
        st.session_state["inv_loaded_ok"] = False
        st.session_state["inv_loaded_msg"] = ""
        return
    row = get_product_by_code(code)
    if row:
        st.session_state["inv_name"]  = row["name"] or ""
        st.session_state["inv_iva"]   = float(row["iva"] or 0.0)
        st.session_state["inv_cost"]  = float(row["cost"] or 0.0)
        st.session_state["inv_price"] = float(row["price"] or 0.0)
        if not (st.session_state.get("cur_company") or "").strip():
            st.session_state["cur_company"] = row["company"] or ""
        st.session_state["inv_loaded_ok"]  = True
        st.session_state["inv_loaded_msg"] = f"Producto cargado: [{row['code']}] {row['name']}. Puedes editarlo y agregar."
    else:
        st.session_state["inv_loaded_ok"]  = False
        st.session_state["inv_loaded_msg"] = "No existe un producto con ese código."


# =============================================================================
# PÁGINAS (VIEWS)
# =============================================================================
def login_screen() -> None:
    st.title(APP_TITLE)
    u = st.text_input("Usuario", value="")
    p = st.text_input("Contraseña", type="password", value="")
    if st.button("Entrar", use_container_width=True):
        ok, user = verify_user(u, p)
        if ok:
            st.session_state["auth_user"] = user
            st.session_state["page"] = "Vender producto"
            st.rerun()
        else:
            st.error("Usuario o contraseña incorrectos.")


def page_sell() -> None:
    if not reportlab_ok():
        st.warning("Para exportar a PDF instala: pip install reportlab")

    products = list_products_db()
    if not products:
        st.info("No hay productos. Agrega uno en la sección 'factura de compra'.")
        return

    names = [f"[{p['code'] or p['id']}] {p['name']}" for p in products]
    idx = st.selectbox("Producto", options=list(range(len(products))), format_func=lambda i: names[i])
    qty = st.number_input("Cantidad", min_value=1, step=1, value=1)

    if st.button("Registrar venta", use_container_width=True):
        ok, msg, total = register_sale(products[idx]["id"], int(qty))
        if ok:
            st.success(f"{msg} Total: {CURRENCY}{total:.2f}")
            if reportlab_ok():
                pdf_bytes, _ = build_sale_pdf_like_screenshot(
                    business_name=BUSINESS_NAME,
                    product=products[idx]["name"],
                    qty=int(qty),
                    cost_unit=float(products[idx]["cost"] or 0.0),
                    price_unit=float(products[idx]["price"] or 0.0),
                    when=dt.datetime.now(),
                )
                st.download_button(
                    "Generar PDF (recibo)",
                    data=pdf_bytes,
                    file_name=f"venta_{dt.datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf",
                    mime="application/pdf",
                    use_container_width=True,
                    key=f"dl_sell_{dt.datetime.now().timestamp()}",
                )
        else:
            st.error(msg)


def page_products() -> None:
    # ======= Estado para factura en construcción =======
    st.session_state.setdefault("cur_company", "")
    st.session_state.setdefault("cur_nit", "")
    st.session_state.setdefault("cur_items", [])  # lista de dicts (code,name,qty,cost,iva,price)

    ctop1, ctop2 = st.columns([2, 1])
    with ctop1:
        st.session_state["cur_company"] = st.text_input("Empresa/Nombre", value=st.session_state["cur_company"])
    with ctop2:
        st.session_state["cur_nit"] = st.text_input("NIT", value=st.session_state["cur_nit"])

    with st.expander("Agregar ítem a la factura de compra", expanded=True):
        # estados de los inputs (default en cero)
        st.session_state.setdefault("inv_code", "")
        st.session_state.setdefault("inv_name", "")
        st.session_state.setdefault("inv_qty", 0)
        st.session_state.setdefault("inv_cost", 0.0)
        st.session_state.setdefault("inv_iva", 0.0)
        st.session_state.setdefault("inv_price", 0.0)

        col1, col2, col3 = st.columns([1.2, 2.2, 1])
        with col1:
            code = st.text_input("Código", key="inv_code", on_change=_load_item_from_code)
        with col2:
            name = st.text_input("Nombre", key="inv_name")
        with col3:
            qty = st.number_input("Unidades", min_value=0, step=1, value=st.session_state.get("inv_qty", 0), key="inv_qty")

        STEP = 100.0
        col4, col5, col6 = st.columns([1.1, 1.1, 1.1])
        with col4:
            st.number_input("Valor unitario (compra)", min_value=0.0, step=STEP, format="%.2f", key="inv_cost")
        with col5:
            st.number_input("IVA %", min_value=0.0, max_value=100.0, step=1.0,
                            value=st.session_state.get("inv_iva", 0.0), key="inv_iva")
        with col6:
            st.number_input("precio de venta", min_value=0.0, step=STEP, format="%.2f", key="inv_price")

        # mensaje de autocarga por código (si aplica)
        msg = st.session_state.get("inv_loaded_msg", "")
        if msg:
            (st.success if st.session_state.get("inv_loaded_ok", False) else st.warning)(msg)

        add_col, _ = st.columns([1, 3])
        with add_col:
            if st.button("Agregar ítem", type="primary", use_container_width=True):
                if not code.strip() or not name.strip() or qty <= 0:
                    st.error("Código, Nombre y Unidades (>0) son obligatorios.")
                else:
                    st.session_state["cur_items"].append(
                        {"code": code.strip(), "name": name.strip(), "qty": int(qty),
                         "unit_cost": float(st.session_state.get("inv_cost", 0.0)),
                         "iva": float(st.session_state.get("inv_iva", 0.0)),
                         "sale_price": float(st.session_state.get("inv_price", 0.0))}
                    )
                    # limpiar inputs
                    for k in ["inv_code", "inv_name", "inv_qty", "inv_cost", "inv_iva", "inv_price",
                              "inv_loaded_ok", "inv_loaded_msg"]:
                        st.session_state.pop(k, None)
                    st.rerun()

    # Tabla temporal de ítems de la factura
    items = st.session_state["cur_items"]
    if items:
        st.dataframe(
            [
                {
                    "Código": it["code"],
                    "Nombre": it["name"],
                    "Unidades": it["qty"],
                    "IVA %": it["iva"],
                    "Valor unit. (compra)": it["unit_cost"],
                    "Valor de venta": it["sale_price"],
                } for it in items
            ],
            hide_index=True, use_container_width=True
        )

    # Guardar/cancelar factura
    cbtn1, cbtn2 = st.columns([1.2, 1])
    with cbtn1:
        if st.button("Guardar factura y generar PDF", type="primary", use_container_width=True, disabled=not items):
            company = st.session_state.get("cur_company", "").strip()
            nit = st.session_state.get("cur_nit", "").strip()
            if not company:
                st.error("Escribe el nombre de la empresa.")
            else:
                batch_id = dt.datetime.now().strftime("%Y%m%d%H%M%S")
                creator = (st.session_state.get("auth_user") or {}).get("username")

                for it in items:
                    existing = get_product_by_code(it["code"])
                    if existing:
                        update_product_by_code(
                            it["code"], it["name"],
                            float(it["sale_price"]),
                            int(existing["stock"]),
                            float(it["unit_cost"]),
                            float(it["iva"]),
                            company
                        )
                        product_id = int(existing["id"])
                    else:
                        add_product(
                            it["code"], it["name"],
                            float(it["sale_price"]),
                            0,
                            float(it["unit_cost"]), float(it["iva"]), company
                        )
                        product_id = int(get_product_by_code(it["code"])["id"])

                    with get_conn() as conn:
                        conn.execute("UPDATE products SET stock = stock + ? WHERE id=?", (int(it["qty"]), product_id))
                        conn.commit()

                    invoice_total = float(it["qty"]) * float(it["unit_cost"]) * (1.0 + float(it["iva"])/100.0)
                    insert_invoice(
                        product_id=product_id,
                        qty=int(it["qty"]),
                        invoice_total=invoice_total,
                        unit_cost=float(it["unit_cost"]),
                        new_price=float(it["sale_price"]),
                        created_by=creator,
                        batch_id=batch_id,
                        company=company
                    )

                if reportlab_ok():
                    pdf_bytes, _ = build_company_invoice_pdf_with_sale(
                        rows=items, company=company,
                        business_name=company or st.session_state.get("pdf_empresa", ""),
                        nit=nit
                    )
                    st.download_button(
                        "Descargar PDF de la factura",
                        data=pdf_bytes,
                        file_name=f"factura_{company}_{batch_id}.pdf",
                        mime="application/pdf",
                        use_container_width=True,
                        key=f"dl_batch_{batch_id}",
                    )
                st.success(f"Factura guardada: {company} ({len(items)} ítems).")
                st.session_state["cur_items"] = []
                st.session_state["cur_company"] = company
                st.session_state["cur_nit"] = nit

    with cbtn2:
        if st.button("Cancelar factura", use_container_width=True, disabled=not items):
            st.session_state["cur_items"] = []
            st.info("Factura en construcción cancelada.")

    st.divider()

    # ====== Historial de facturas (por lote / empresa) ======
    st.markdown("### Historial de facturas de compra")

    # ---- Calendario / Filtro por día ----
    filt_col1, filt_col2 = st.columns([1.2, 1])
    with filt_col1:
        sel_date = st.date_input(
            "Calendario de facturas (día)",
            value=dt.date.today(),
            help="Selecciona un día para ver los lotes guardados ese día."
        )
    with filt_col2:
        ver_todas = st.checkbox("Ver todas las facturas", value=False, help="Ignora el calendario y lista todo.")

    start_dt = dt.datetime.combine(sel_date, dt.time.min)
    end_dt   = dt.datetime.combine(sel_date, dt.time.max)

    with get_conn() as conn:
        if ver_todas:
            query = """
                SELECT
                    batch_id,
                    COALESCE(company,'') AS company,
                    MIN(created_at) AS fecha,
                    COUNT(*) AS lineas,
                    SUM(qty) AS total_unidades,
                    SUM(invoice_total) AS total_facturado
                FROM invoices
                WHERE batch_id IS NOT NULL
                GROUP BY batch_id, company
                ORDER BY fecha DESC
            """
            rows = conn.execute(query).fetchall()
        else:
            query = """
                SELECT
                    batch_id,
                    COALESCE(company,'') AS company,
                    MIN(created_at) AS fecha,
                    COUNT(*) AS lineas,
                    SUM(qty) AS total_unidades,
                    SUM(invoice_total) AS total_facturado
                FROM invoices
                WHERE batch_id IS NOT NULL
                  AND created_at BETWEEN ? AND ?
                GROUP BY batch_id, company
                ORDER BY fecha DESC
            """
            rows = conn.execute(query, (start_dt, end_dt)).fetchall()

    subtitle = f"Mostrando: {sel_date.strftime('%Y-%m-%d')}" if not ver_todas else "Mostrando: todas las fechas"
    st.caption(subtitle)

    if rows:
        for r in rows:
            c1, c2, c3, c4, c5 = st.columns([2, 1.5, 1, 1, 1.5])
            with c1: st.write(f"**{r['company']}**")
            with c2: st.write(f"Fecha: {r['fecha']}")
            with c3: st.write(f"Ítems: {r['lineas']}")
            with c4: st.write(f"Unidades: {int(r['total_unidades'] or 0)}")
            with c5: st.write(f"Total: {money_dot_thousands(float(r['total_facturado'] or 0))}")

            # Reconstruir y descargar PDF del lote
            with get_conn() as conn:
                lines = conn.execute(
                    """
                    SELECT p.code, p.name, i.qty, p.iva AS iva, i.unit_cost, COALESCE(i.new_price, p.price) AS sale_price
                    FROM invoices i
                    JOIN products p ON p.id = i.product_id
                    WHERE i.batch_id = ?
                    ORDER BY p.name ASC
                    """,
                    (r["batch_id"],)
                ).fetchall()
            items_lote = [
                {"code": x["code"], "name": x["name"], "qty": int(x["qty"]),
                 "iva": float(x["iva"] or 0.0), "unit_cost": float(x["unit_cost"] or 0.0),
                 "sale_price": float(x["sale_price"] or 0.0)}
                for x in lines
            ]
            if reportlab_ok() and items_lote:
                pdf_bytes, _ = build_company_invoice_pdf_with_sale(
                    rows=items_lote, company=r["company"], business_name=r["company"], nit=""
                )
                st.download_button(
                    f"Descargar PDF ({r['batch_id']})",
                    data=pdf_bytes,
                    file_name=f"factura_{r['company']}_{r['batch_id']}.pdf",
                    mime="application/pdf",
                    use_container_width=True,
                    key=f"dl_hist_{r['batch_id']}",
                )

            # ---- NUEVO: borrar lote (con confirmación y opción de revertir stock)
            del_col1, del_col2, del_col3 = st.columns([1.2, 1, 1.8])
            with del_col1:
                revert = st.checkbox("Revertir stock", value=True, key=f"rev_{r['batch_id']}")
            with del_col2:
                confirm = st.checkbox("Confirmar", key=f"cfm_{r['batch_id']}")
            with del_col3:
                if st.button("Borrar lote", key=f"del_{r['batch_id']}", use_container_width=True, disabled=not confirm):
                    ok, msg = delete_invoice_batch(r["batch_id"], adjust_stock=revert)
                    show_msg(ok, msg)
                    if ok:
                        st.rerun()

        st.caption(f"Total de facturas mostradas: **{len(rows)}**")
    else:
        mensaje = "Sin facturas en la fecha seleccionada." if not ver_todas else "Sin facturas registradas aún."
        st.info(mensaje)

    st.divider()

    # ====== Gestión de productos (tabla) ======
    data = list_products_db()
    if data:
        st.dataframe(
            [
                {
                    "Código": p["code"],
                    "Nombre": p["name"],
                    "Empresa": p["company"] or "",
                    "Costo unit.": p["cost"],
                    "Precio (venta)": p["price"],
                    "IVA %": p["iva"],
                    "Unidades": p["stock"],
                }
                for p in data
            ],
            hide_index=True,
            use_container_width=True,
        )
    else:
        st.info("Aún no hay productos.")
    # (El bloque de borrar producto por nombre está en Reponer)


def page_restock() -> None:
    products = list_products_db()
    if not products:
        st.info("No hay productos para reponer.")
        st.markdown("### Crear producto rápido")
        ncode = st.text_input("Código nuevo", key="restock_create_code_empty")
        nname = st.text_input("Nombre nuevo", key="restock_create_name_empty")
        if st.button("Crear producto", use_container_width=True, key="restock_create_btn_empty"):
            ok, msg = add_product(ncode, nname, 0.0, 0, 0.0, 0.0, "")
            show_msg(ok, msg)
            if ok:
                st.rerun()
        return

    with st.expander("Crear o cargar producto por código/nombre", expanded=True):
        colx1, colx2, colx3 = st.columns([2, 2, 1])
        with colx1:
            quick_code = st.text_input("Código del producto", key="restock_quick_code")
        with colx2:
            quick_name = st.text_input("Nombre del producto", key="restock_quick_name")
        with colx3:
            st.markdown("<div style='height:7px'></div>", unsafe_allow_html=True)
            if st.button("Cargar (si existe)", key="restock_quick_load", use_container_width=True):
                row = None
                if quick_code.strip():
                    row = get_product_by_code(quick_code.strip())
                if (row is None) and quick_name.strip():
                    row = get_product_by_name(quick_name.strip())
                if row:
                    ids = [p["id"] for p in products]
                    try:
                        st.session_state["restock_idx"] = ids.index(row["id"])
                        st.success(f"Producto cargado: [{row['code']}] {row['name']}")
                        st.rerun()
                    except ValueError:
                        st.warning("Encontrado, pero no visible en la lista.")
                else:
                    st.warning("No se encontró. Puedes crearlo abajo.")

        coly1, coly2 = st.columns([1, 1])
        with coly1:
            if st.button("Crear producto (solo con código y nombre)", key="restock_quick_create", use_container_width=True):
                if not quick_code.strip() or not quick_name.strip():
                    st.error("Escribe CÓDIGO y NOMBRE para crear.")
                else:
                    ok, msg = add_product(quick_code.strip(), quick_name.strip(), 0.0, 0, 0.0, 0.0, "")
                    show_msg(ok, msg)
                    if ok:
                        st.rerun()
        with coly2:
            st.caption("Se crean con precio, costo, IVA y unidades = 0 (puedes ajustarlos al reponer).")

    names = [f"[{p['code'] or p['id']}] {p['name']}" for p in products]
    idx = st.selectbox("Producto", options=list(range(len(products))), format_func=lambda i: names[i], key="restock_idx")

    # Reinicia SIEMPRE costo y precio a 0 cuando cambie el producto
    cur_id = products[idx]["id"]
    if st.session_state.get("restock_current_id") != cur_id:
        st.session_state["restock_current_id"] = cur_id
        st.session_state["restock_cost"] = 0.0
        st.session_state["restock_price"] = 0.0

    # Borrar producto seleccionado
    col_del_sel, _ = st.columns([1, 3])
    with col_del_sel:
        if st.button("Borrar producto seleccionado", use_container_width=True, key="restock_delete_selected"):
            ok, msg = delete_product(int(products[idx]["id"]))
            show_msg(ok, msg)
            if ok:
                st.rerun()

    # ====== (1) Cantidad en CERO por defecto ======
    st.session_state.setdefault("restock_qty", 0)  # ← ahora inicia en 0
    qty = st.number_input("Cantidad a agregar", min_value=0, step=1, key="restock_qty")

    # === SOLO los inputs (sin botones extra ni checkbox) ===
    st.markdown("### Precio y costo del producto seleccionado")
    c1, c2 = st.columns([1.1, 1.1])
    with c1:
        st.number_input("Valor unitario (compra)", min_value=0.0, step=RESTOCK_STEP, format="%.2f",
                        key="restock_cost")
    with c2:
        st.number_input("precio de venta", min_value=0.0, step=RESTOCK_STEP, format="%.2f",
                        key="restock_price")

    # Mensajes
    colA, colB = st.columns(2)
    with colA:
        st.info(f"Agregarás {int(qty)} unidades al inventario del producto seleccionado.")
    with colB:
        st.info("Reposición: mueve inventario. No crea factura.")

    # Acciones
    col1, col2 = st.columns(2)
    with col1:
        if st.button("Reponer", use_container_width=True):
            ok, msg = restock_with_invoice(products[idx]["id"], int(qty), None, None)
            if ok:
                st.success(msg)
                # dejamos qty en 0 otra vez si quieres que quede "en cero" tras reponer
                st.session_state["restock_qty"] = 0
                st.rerun()
            else:
                st.error(msg)

    with col2:
        with st.expander("Eliminar producto por nombre (acción irreversible)"):
            rows_del = list_products_db()
            if not rows_del:
                st.info("No hay productos para eliminar.")
            else:
                etiquetas = [
                    f"[{r['code'] or r['id']}] {r['name']} — stock {r['stock']}"
                    for r in rows_del
                ]
                idx_del = st.selectbox(
                    "Producto a eliminar",
                    options=list(range(len(rows_del))),
                    format_func=lambda i: etiquetas[i],
                    key="delete_idx_restock"
                )
                confirm = st.checkbox("Entiendo los riesgos y deseo eliminarlo.", key="delete_confirm_restock")

                if st.button("Eliminar producto", type="primary", use_container_width=True, disabled=not confirm, key="delete_btn_restock"):
                    ok, msg = delete_product(int(rows_del[idx_del]["id"]))
                    if ok:
                        st.success(msg)
                        st.rerun()
                    else:
                        st.error(msg)

    # ====== (2) Inventario actual visible aquí mismo ======
    st.divider()
    st.markdown("### Inventario actual")
    data = list_products_db()
    if data:
        st.dataframe(
            [
                {
                    "Código": p["code"],
                    "Nombre": p["name"],
                    "Empresa": p["company"] or "",
                    "Costo unit.": p["cost"],
                    "Precio (venta)": p["price"],
                    "IVA %": p["iva"],
                    "Unidades": p["stock"],
                }
                for p in data
            ],
            hide_index=True,
            use_container_width=True,
        )
    else:
        st.info("Aún no hay productos.")


def page_inventory() -> None:
    cut_date = st.date_input("Fecha de corte (inventario a la fecha)", value=dt.date.today(), key="inv_cut_date")
    cutoff_dt = dt.datetime.combine(cut_date, dt.time.max)

    rows = list_products_db()
    if not rows:
        st.info("No hay productos.")
        return

    with get_conn() as conn:
        sales_after = dict(
            conn.execute(
                """
                SELECT product_id, COALESCE(SUM(qty),0) AS s
                FROM sales
                WHERE sold_at > ?
                GROUP BY product_id
                """,
                (cutoff_dt,),
            ).fetchall()
        )

        invoices_after = dict(
            conn.execute(
                """
                SELECT product_id, COALESCE(SUM(qty),0) AS q
                FROM invoices
                WHERE created_at > ?
                GROUP BY product_id
                """,
                (cutoff_dt,),
            ).fetchall()
        )

    items = []
    total_costo = total_venta = total_costo_cut = total_venta_cut = 0.0

    for p in rows:
        cur_stock = int(p["stock"] or 0)
        sold_after = int(sales_after.get(p["id"], 0) if isinstance(sales_after, dict) else 0)
        restock_after = int(invoices_after.get(p["id"], 0) if isinstance(invoices_after, dict) else 0)
        stock_at_cut = max(cur_stock + sold_after - restock_after, 0)

        costo_total = float(p["cost"] or 0) * cur_stock
        venta_total = float(p["price"] or 0) * cur_stock
        costo_total_cut = float(p["cost"] or 0) * stock_at_cut
        venta_total_cut = float(p["price"] or 0) * stock_at_cut

        total_costo += costo_total
        total_venta += venta_total
        total_costo_cut += costo_total_cut
        total_venta_cut += venta_total_cut

        items.append(
            {
                "Código": p["code"],
                "Nombre": p["name"],
                "Empresa": p["company"] or "",
                "Stock": cur_stock,
                "Costo unit.": money_dot_thousands(float(p["cost"] or 0)),
                "Precio de venta": money_dot_thousands(float(p["price"] or 0)),
            }
        )

    st.dataframe(items, hide_index=True, use_container_width=True)
    st.success(
        f"Costo total inventario (actual): {CURRENCY}{money_dot_thousands(total_costo)}  |  "
        f"Valor potencial de venta (actual): {CURRENCY}{money_dot_thousands(total_venta)}"
    )
    st.success(
        f"Inventario a {cutoff_dt.strftime('%Y-%m-%d')} — "
        f"Costo total: {CURRENCY}{money_dot_thousands(total_costo_cut)}  |  "
        f"Valor potencial: {CURRENCY}{money_dot_thousands(total_venta_cut)}"
    )
    st.caption(" ")


def page_users() -> None:
    st.header("Gestor de usuarios")
    c1, c2, c3, c4 = st.columns([2, 2, 2, 1])
    with c1:
        u = st.text_input("Usuario nuevo")
    with c2:
        p = st.text_input("Contraseña", type="password")
    with c3:
        is_admin = st.checkbox("Administrador", value=False)
    with c4:
        st.markdown("<div style='height:26px'></div>", unsafe_allow_html=True)
    if st.button("Crear", use_container_width=True):
        ok, msg = create_user(u, p, is_admin)
        show_msg(ok, msg)

    st.divider()
    rows = list_users()
    if rows:
        for r in rows:
            a, b, c = st.columns([4, 2, 1])
            with a:
                st.write(f"{r['username']} {'(admin)' if r['is_admin'] else ''}")
            with b:
                st.write(f"Creado: {r['created_at']}")
            with c:
                cur = st.session_state.get("auth_user", {}).get("username")
                disabled = cur == r["username"]
                if st.button("Borrar", key=f"del_{r['id']}", disabled=disabled):
                    ok, msg = delete_user(int(r['id']))
                    show_msg(ok, msg)
                    st.rerun()
    else:
        st.info("No hay usuarios.")


# =============================================================================
# MAIN
# =============================================================================
def main() -> None:
    init_db()

    if not st.session_state.get("auth_user"):
        login_screen()
        render_footer()
        return

    st.session_state.setdefault("page", "Vender producto")

    def _on_nav_change():
        st.session_state["page"] = st.session_state.get("nav", "Vender producto")

    def _go_usuarios():
        st.session_state["page"] = "Usuarios"

    def _logout():
        st.session_state["auth_user"] = None
        st.session_state.pop("nav", None)
        st.session_state["page"] = "Vender producto"

    options = ["Vender producto", "factura de compra", "Reponer", "Inventario"]
    current_page = st.session_state.get("page", "Vender producto")
    current_index = options.index(current_page) if current_page in options else 0

    with st.sidebar:
        st.radio("", options, key="nav", index=current_index, on_change=_on_nav_change)
        st.divider()
        st.button("Usuarios", use_container_width=True, on_click=_go_usuarios)
        st.button("Cerrar sesión", use_container_width=True, on_click=_logout)
        st.caption(": " + CURRENCY)

    page = st.session_state.get("page", "Vender producto")
    if page == "Vender producto":
        page_sell()
    elif page == "factura de compra":
        page_products()
    elif page == "Reponer":
        page_restock()
    elif page == "Inventario":
        page_inventory()
    elif page == "Usuarios":
        page_users()
    else:
        st.session_state["page"] = "Vender producto"
        page_sell()

    render_footer()


if __name__ == "__main__":
    main()
