# -*- coding: utf-8 -*-
"""
clubdebillaresV8 – POS simple con:
- Login y gestión de usuarios
- Productos
- Reposición + registro de facturas de compra
- Ventas + recibo PDF
- Informe de ventas + PDF
- Inventario a fecha
- Pie de página con créditos

Requisitos:
    pip install streamlit==1.38.0 reportlab

Ejecutar:
    streamlit run app.py
"""
# =============================================================================
# IMPORTS
# =============================================================================
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
# CONFIGURACIÓN GLOBAL
# =============================================================================
APP_TITLE = "clubdebillaresV8"
DB_PATH = os.environ.get("POS_DB_PATH") or os.path.join(os.path.dirname(__file__), "data_pos.db")
CURRENCY = ""              # Moneda visible en la UI (puedes poner "$")
BUSINESS_NAME = ""         # Nombre para los PDFs (vacío = título genérico)
PBKDF2_ITERATIONS = 260_000

# Usuario fijo adicional (opcional)
FIXED_USER = "condeomar"
FIXED_PASS = "122130@"


# -----------------------------------------------------------------------------
# Streamlit – página + estilos
# -----------------------------------------------------------------------------
st.set_page_config(page_title=APP_TITLE, page_icon=None, layout="wide")
st.markdown(
    """
<style>
/* Ocultar toolbars y 3 puntos */
div[data-testid="stElementToolbar"],
div[data-testid="stDecoration"],
header [data-testid="baseButton-headerNoPadding"],
div[data-testid="stToolbar"],
#MainMenu { display:none !important; }
.small-note { font-size:.9rem; opacity:.7; }

/* ====== COLOR AZUL EN EL SIDEBAR ====== */
:root { --azul-primario: #2563eb; --azul-primario-hover:#1d4ed8; }
/* radios/checkbox */
section[data-testid="stSidebar"] input[type="radio"],
section[data-testid="stSidebar"] input[type="checkbox"] {
  accent-color: var(--azul-primario);
}
/* botones */
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
# UTILIDADES GENERALES
# =============================================================================
def money_dot_thousands(v: float) -> str:
    """Formatea un número con puntos de miles sin decimales."""
    return f"{int(round(v)):,.0f}".replace(",", ".")


def reportlab_ok() -> bool:
    try:
        import reportlab  # noqa: F401
        return True
    except Exception:
        return False


def show_msg(ok: bool, msg: str) -> None:
    """Mensaje seguro (evita errores de representación en algunas versiones)."""
    safe = str(msg)
    try:
        (st.success if ok else st.error)(safe)
    except Exception:
        st.write(("OK: " if ok else "ERROR: ") + safe)


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
# CONEXIÓN Y ESQUEMA DE BASE DE DATOS
# =============================================================================
def get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES | sqlite3.PARSE_COLNAMES)
    conn.row_factory = sqlite3.Row
    return conn


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

        # -- Productos
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS products(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
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

        # -- Facturas (reabastecimientos)
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
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(product_id) REFERENCES products(id)
            );
            """
        )

        conn.commit()


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
        if verify_password(password, row["password_hash"], row["password_salt"], int(row["iterations"])):
            return True, {"username": row["username"], "is_admin": bool(row["is_admin"])}
        return False, {}


# =============================================================================
# CRUD – PRODUCTOS / VENTAS / FACTURAS
# =============================================================================
def add_product(code: str, name: str, price: float, stock: int, cost: float) -> Tuple[bool, str]:
    code = (code or "").strip()
    name = (name or "").strip()
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

    try:
        with get_conn() as conn:
            conn.execute(
                "INSERT INTO products(code,name,price,stock,cost) VALUES (?,?,?,?,?)",
                (code, name, price, stock, cost),
            )
            conn.commit()
        return True, f"Producto '{name}' agregado."
    except sqlite3.IntegrityError as e:
        m = str(e).lower()
        if "code" in m:
            return False, "Ya existe un producto con ese código."
        if "name" in m:
            return False, "Ya existe un producto con ese nombre."
        return False, "No se pudo guardar el producto."


def list_products_db() -> List[sqlite3.Row]:
    with get_conn() as conn:
        return conn.execute(
            "SELECT id, code, name, price, stock, cost FROM products ORDER BY name ASC"
        ).fetchall()


def insert_invoice(
    product_id: int,
    qty: int,
    invoice_total: float,
    unit_cost: float,
    new_price: Optional[float],
    created_by: Optional[str],
) -> None:
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO invoices(product_id, qty, invoice_total, unit_cost, new_price, created_by) "
            "VALUES (?,?,?,?,?,?)",
            (product_id, qty, invoice_total, unit_cost, new_price, created_by),
        )
        conn.commit()


# >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
# FUNCIÓN AGREGADA: list_invoices (para evitar NameError en page_products)
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
# <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<


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
            sets.append("cost=?")
            params.append(unit_cost)

        if new_price is not None:
            sets.append("price=?")
            params.append(float(new_price))

        params.append(product_id)
        conn.execute(f"UPDATE products SET {', '.join(sets)} WHERE id=?", params)
        conn.commit()

    # Guardar factura si corresponde
    creator = (st.session_state.get("auth_user") or {}).get("username")
    if invoice_total is not None and unit_cost is not None:
        insert_invoice(
            product_id, int(qty), float(invoice_total), float(unit_cost),
            float(new_price) if new_price is not None else None, creator
        )

    extras = []
    if invoice_total is not None and unit_cost is not None:
        extras.append(
            f"factura {CURRENCY}{money_dot_thousands(invoice_total)} "
            f"(costo unit. {CURRENCY}{money_dot_thousands(unit_cost)})"
        )
    if new_price is not None:
        extras.append(f"precio {CURRENCY}{money_dot_thousands(new_price)}")

    extra_msg = " — " + ", ".join(extras) if extras else ""
    return True, f"Stock actualizado a {new_stock}.{extra_msg}"


def register_sale(product_id: int, qty: int) -> Tuple[bool, str, float]:
    if qty <= 0:
        return False, "La cantidad debe ser mayor a 0.", 0.0

    with get_conn() as conn:
        row = conn.execute(
            "SELECT price, stock, name FROM products WHERE id=?", (product_id,)
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


def sales_detail(start: dt.datetime, end: dt.datetime) -> List[sqlite3.Row]:
    with get_conn() as conn:
        return conn.execute(
            """
            SELECT
                p.name,
                s.qty AS unidades,
                s.total AS ingreso,
                p.cost AS costo_unit,
                p.price AS precio_unit,
                s.sold_at
            FROM sales s
            JOIN products p ON p.id = s.product_id
            WHERE s.sold_at >= ? AND s.sold_at < ?
            ORDER BY s.sold_at ASC
            """,
            (start, end),
        ).fetchall()


# =============================================================================
# PDFs
# =============================================================================
def build_sale_pdf(*, business_name: str, product: str, qty: int, total: float, when: dt.datetime):
    """Genera recibo de venta."""
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib import colors

    def _title_text(name: str) -> str:
        return f"<b>{name} - Recibo de venta</b>" if name else "<b>Recibo de venta</b>"

    buf = BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=letter, leftMargin=40, rightMargin=40, topMargin=40, bottomMargin=40)
    styles = getSampleStyleSheet()
    title = Paragraph(_title_text(business_name), styles["Title"])
    when_p = Paragraph(f"Fecha/Hora: {when.strftime('%Y-%m-%d %H:%M:%S')}", styles["Normal"])

    data = [
        ["Producto", str(product)],
        ["Unidades", f"{int(qty)}"],
        ["Valor", money_dot_thousands(float(total))],
    ]
    t = Table(data, colWidths=[120, 370])
    t.setStyle(
        TableStyle(
            [
                ("GRID", (0, 0), (-1, -1), 0.8, colors.black),
                ("BACKGROUND", (0, 0), (-1, 0), colors.whitesmoke),
                ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                ("ALIGN", (1, 0), (1, -1), "LEFT"),
            ]
        )
    )
    doc.build([title, Spacer(1, 6), when_p, Spacer(1, 12), t])

    pdf = buf.getvalue()
    buf.close()
    return pdf, None


def build_report_pdf_detailed(*, rows: List[sqlite3.Row]):
    """Genera informe de ventas detallado."""
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib import colors

    buf = BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=letter, leftMargin=24, rightMargin=24, topMargin=28, bottomMargin=28)
    styles = getSampleStyleSheet()
    title = Paragraph("<b>Informe de ventas (detalle)</b>", styles["Title"])

    data = [["Producto", "Unidades", "Costo unit.", "Precio", "Valor", "Ganancia"]]
    tu = tv = tg = 0
    for r in rows:
        u = int(r["unidades"] or 0)
        valor = float(r["ingreso"] or 0.0)
        cu = float(r["costo_unit"] or 0.0)
        pu = float(r["precio_unit"] or 0.0)
        g = (pu - cu) * u
        tu += u
        tv += valor
        tg += g
        data.append(
            [
                str(r["name"]),
                f"{u}",
                money_dot_thousands(cu),
                money_dot_thousands(pu),
                money_dot_thousands(valor),
                money_dot_thousands(g),
            ]
        )

    data.append(["Totales", f"{tu}", "", "", money_dot_thousands(tv), money_dot_thousands(tg)])

    table = Table(data, colWidths=[220, 60, 80, 80, 90, 90])
    table.setStyle(
        TableStyle(
            [
                ("GRID", (0, 0), (-1, -1), 0.8, colors.black),
                ("BACKGROUND", (0, 0), (-1, 0), colors.whitesmoke),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("ALIGN", (1, 1), (1, -2), "RIGHT"),
                ("ALIGN", (2, 1), (5, -2), "RIGHT"),
                ("ALIGN", (1, -1), (5, -1), "RIGHT"),
                ("FONTNAME", (0, -1), (-1, -1), "Helvetica-Bold"),
                ("BACKGROUND", (0, -1), (-1, -1), colors.whitesmoke),
                ("FONTSIZE", (0, 0), (-1, -1), 9.5),
            ]
        )
    )
    doc.build([title, Spacer(1, 8), table])

    pdf = buf.getvalue()
    buf.close()
    return pdf, None


# =============================================================================
# UI – PIE DE PÁGINA
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
            st.session_state["page"] = "Vendedor"
            st.rerun()
        else:
            st.error("Usuario o contraseña incorrectos.")


def page_sell() -> None:
    if not reportlab_ok():
        st.warning("Para exportar a PDF instala: pip install reportlab")

    products = list_products_db()
    if not products:
        st.info("No hay productos. Agrega uno en la sección 'Productos'.")
        return

    names = [
        f"[{p['code'] or p['id']}] {p['name']} (stock: {p['stock']}, precio: {CURRENCY}{p['price']:.2f})"
        for p in products
    ]
    idx = st.selectbox("Producto", options=list(range(len(products))), format_func=lambda i: names[i])
    qty = st.number_input("Cantidad", min_value=1, step=1, value=1)

    if st.button("Registrar venta", use_container_width=True):
        ok, msg, total = register_sale(products[idx]["id"], int(qty))
        if ok:
            st.success(f"{msg} Total: {CURRENCY}{total:.2f}")
            if reportlab_ok():
                pdf_bytes, _ = build_sale_pdf(
                    business_name=BUSINESS_NAME,
                    product=products[idx]["name"],
                    qty=int(qty),
                    total=float(total),
                    when=dt.datetime.now(),
                )
                st.download_button(
                    "Generar PDF (recibo)",
                    data=pdf_bytes,
                    file_name=f"venta_{dt.datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf",
                    mime="application/pdf",
                    use_container_width=True,
                )
        else:
            st.error(msg)


def page_products() -> None:
    with st.expander("Agregar nuevo producto", expanded=True):
        code = st.text_input("Código", placeholder="Ej. C-001")
        name = st.text_input("Nombre", placeholder="Ej. Cerveza")
        cost = st.number_input("Costo unitario (de factura)", min_value=0.0, step=100.0, format="%.2f", value=0.0)
        price = st.number_input("Precio de venta", min_value=0.0, step=100.0, format="%.2f")
        stock = st.number_input("Unidades", min_value=0, step=1, value=0)
        if st.button("Guardar producto", type="primary"):
            ok, msg = add_product(code, name, float(price), int(stock), float(cost))
            show_msg(ok, msg)

    data = list_products_db()
    if data:
        st.dataframe(
            [
                {
                    "Código": p["code"],
                    "Nombre": p["name"],
                    "Costo unit.": p["cost"],
                    "Precio": p["price"],
                    "Unidades": p["stock"],
                }
                for p in data
            ],
            hide_index=True,
            use_container_width=True,
        )
    else:
        st.info("Aún no hay productos.")

    # -------- Recibo rápido (sin registrar venta) ----------
    st.markdown("### Imprimir recibo rápido (sin registrar venta)")
    prod_list = list_products_db()
    if prod_list:
        names_print = [
            f"[{p['code'] or p['id']}] {p['name']} (precio: {CURRENCY}{p['price']:.2f})" for p in prod_list
        ]
        idx_print = st.selectbox(
            "Producto a imprimir",
            options=list(range(len(prod_list))),
            format_func=lambda i: names_print[i],
            key="print_idx",
        )
        qty_print = st.number_input("Cantidad a imprimir en recibo", min_value=1, step=1, value=1, key="print_qty")

        if st.button("Generar PDF de recibo", use_container_width=True, key="print_btn"):
            p = prod_list[idx_print]
            total_print = float(p["price"]) * int(qty_print)
            if reportlab_ok():
                pdf_bytes, _ = build_sale_pdf(
                    business_name=BUSINESS_NAME,
                    product=p["name"],
                    qty=int(qty_print),
                    total=float(total_print),
                    when=dt.datetime.now(),
                )
                st.download_button(
                    "Descargar PDF (recibo)",
                    data=pdf_bytes,
                    file_name=f"recibo_{p['code'] or p['id']}_{dt.datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf",
                    mime="application/pdf",
                    use_container_width=True,
                )
                st.info(f"Recibo generado: {int(qty_print)} x {p['name']} — Total: {CURRENCY}{total_print:.2f}")
            else:
                st.warning("Para exportar a PDF instala: pip install reportlab")
    else:
        st.info("No hay productos para imprimir.")

    # -------- Últimas facturas ----------
    st.markdown("### Últimas facturas de compra")
    inv = list_invoices(limit=20)
    if inv:
        st.dataframe(
            [
                {
                    "Fecha": r["created_at"],
                    "Código": r["code"],
                    "Producto": r["product"],
                    "Cant.": r["qty"],
                    "Valor factura": money_dot_thousands(float(r["invoice_total"])),
                    "Costo unit.": money_dot_thousands(float(r["unit_cost"])),
                    "Precio nuevo": (money_dot_thousands(float(r["new_price"])) if r["new_price"] is not None else ""),
                    "Creado por": r["created_by"] or "",
                }
                for r in inv
            ],
            hide_index=True,
            use_container_width=True,
        )
    else:
        st.info("Sin facturas registradas aún.")


def page_restock() -> None:
    products = list_products_db()
    if not products:
        st.info("No hay productos para reponer.")
        return

    names = [
        f"[{p['code'] or p['id']}] {p['name']}  (stock:{p['stock']}, "
        f"costo:{money_dot_thousands(p['cost'])}, precio:{money_dot_thousands(p['price'])})"
        for p in products
    ]
    idx = st.selectbox("Producto", options=list(range(len(products))), format_func=lambda i: names[i], key="restock_idx")

    # Estado de campos
    def _reset_restock_fields():
        st.session_state["restock_qty"] = 1
        st.session_state["restock_invoice"] = 0.0
        st.session_state["restock_use_invoice"] = False
        st.session_state["restock_new_price"] = 0.0
        st.session_state["restock_apply_new_price"] = False

    if "restock_qty" not in st.session_state:
        _reset_restock_fields()

    qty = st.number_input("Cantidad a agregar", min_value=1, step=1, value=st.session_state.get("restock_qty", 1), key="restock_qty")
    invoice_total = st.number_input(
        "Valor total de la factura (opcional)", min_value=0.0, step=100.0, format="%.2f",
        value=st.session_state.get("restock_invoice", 0.0), key="restock_invoice"
    )
    use_invoice = st.checkbox(
        "Usar valor de la factura para actualizar costo unitario",
        value=st.session_state.get("restock_use_invoice", False),
        key="restock_use_invoice",
    )
    new_price = st.number_input(
        "Nuevo precio de venta (opcional)", min_value=0.0, step=100.0, format="%.2f",
        value=st.session_state.get("restock_new_price", 0.0), key="restock_new_price"
    )
    apply_new_price = st.checkbox(
        "Actualizar precio de venta con el valor anterior",
        value=st.session_state.get("restock_apply_new_price", False),
        key="restock_apply_new_price",
    )

    colA, colB = st.columns(2)
    with colA:
        st.caption("Resumen de la factura ingresada:")
        if use_invoice and qty > 0 and invoice_total > 0:
            unit = invoice_total / qty
            st.info(
                f"Cantidad: {int(qty)}  |  Valor factura: {CURRENCY}{money_dot_thousands(invoice_total)}\n\n"
                f"Costo unitario calculado: {CURRENCY}{money_dot_thousands(unit)}"
            )
        else:
            st.info("Ingresa cantidad y valor de factura y marca la casilla para ver el costo unitario.")
    with colB:
        if apply_new_price and new_price > 0:
            st.info(f"Nuevo precio de venta a aplicar: {CURRENCY}{money_dot_thousands(new_price)}")
        else:
            st.info("Puedes indicar un nuevo precio y marcar la casilla para aplicarlo.")

    if st.button("Reponer", use_container_width=True):
        inv_val = float(invoice_total) if use_invoice else None
        price_val = float(new_price) if apply_new_price else None
        ok, msg = restock_with_invoice(products[idx]["id"], int(qty), inv_val, price_val)
        if ok:
            extra = []
            if inv_val is not None and qty > 0:
                extra.append(
                    f"Factura: {CURRENCY}{money_dot_thousands(invoice_total)}  |  "
                    f"Costo unit.: {CURRENCY}{money_dot_thousands(invoice_total/qty)}"
                )
            if price_val is not None:
                extra.append(f"Nuevo precio: {CURRENCY}{money_dot_thousands(new_price)}")
            detalle = " — " + " — ".join(extra) if extra else ""
            st.success(f"Reposición guardada para {products[idx]['name']} — Cantidad: {int(qty)}{detalle}")

            _reset_restock_fields()
            st.rerun()
        else:
            st.error(msg)


def page_report() -> None:
    today = dt.date.today()
    c1, c2 = st.columns(2)
    with c1:
        d1 = st.date_input("Desde", value=today)
    with c2:
        d2 = st.date_input("Hasta (incl.)", value=today)

    start_dt = dt.datetime.combine(d1, dt.time.min)
    end_dt = dt.datetime.combine(d2, dt.time.max)
    rows = sales_detail(start_dt, end_dt + dt.timedelta(seconds=1))

    if rows:
        tabla = [
            {
                "Producto": r["name"],
                "Unidades": int(r["unidades"] or 0),
                "Costo unit.": money_dot_thousands(float(r["costo_unit"] or 0.0)),
                "Precio": money_dot_thousands(float(r["precio_unit"] or 0.0)),
                "Valor": money_dot_thousands(float(r["ingreso"] or 0.0)),
                "Ganancia": money_dot_thousands(
                    (float(r["precio_unit"] or 0.0) - float(r["costo_unit"] or 0.0)) * int(r["unidades"] or 0)
                ),
            }
            for r in rows
        ]
        st.dataframe(tabla, hide_index=True, use_container_width=True)
        if reportlab_ok():
            pdf_bytes, _ = build_report_pdf_detailed(rows=rows)
            st.download_button(
                "Generar PDF ",
                data=pdf_bytes,
                file_name=f"informe_{dt.datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf",
                mime="application/pdf",
                use_container_width=True,
            )
    else:
        st.info("Sin ventas para el rango seleccionado.")


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
        stock_at_cut = cur_stock + sold_after - restock_after
        stock_at_cut = max(stock_at_cut, 0)

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
                "Stock": cur_stock,
                "Stock (a fecha)": stock_at_cut,
                "Costo unit.": money_dot_thousands(float(p["cost"] or 0)),
                "Costo total": money_dot_thousands(costo_total),
                "Costo total (a fecha)": money_dot_thousands(costo_total_cut),
                "Precio": money_dot_thousands(float(p["price"] or 0)),
                "Valor potencial": money_dot_thousands(venta_total),
                "Valor potencial (a fecha)": money_dot_thousands(venta_total_cut),
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
    st.caption(
        "Nota: el cálculo a fecha usa ventas y facturas posteriores. "
        "Si repones sin registrar factura, ese movimiento no se puede reflejar aquí."
    )


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
                    ok, msg = delete_user(int(r["id"]))
                    show_msg(ok, msg)
                    st.rerun()
    else:
        st.info("No hay usuarios.")


# =============================================================================
# MAIN
# =============================================================================
def main() -> None:
    init_db()

    # --- LOGIN ---
    if not st.session_state.get("auth_user"):
        login_screen()
        render_footer()  # pie también en el login
        return

    # Página inicial por defecto
    st.session_state.setdefault("page", "Vendedor")

    # --- Navegación (sidebar) ---
    def _on_nav_change():
        st.session_state["page"] = st.session_state.get("nav", "Vendedor")

    def _go_usuarios():
        st.session_state["page"] = "Usuarios"

    def _logout():
        st.session_state["auth_user"] = None
        st.session_state.pop("nav", None)
        st.session_state["page"] = "Vendedor"

    options = ["Vendedor", "Productos", "Reponer", "Informe", "Inventario"]
    current_page = st.session_state.get("page", "Vendedor")
    default_nav_value = current_page if current_page in options else options[0]
    default_index = options.index(default_nav_value)

    with st.sidebar:
        st.radio("", options, key="nav", index=default_index, on_change=_on_nav_change)
        st.divider()
        st.button("Usuarios", use_container_width=True, on_click=_go_usuarios)
        st.button("Cerrar sesión", use_container_width=True, on_click=_logout)
        st.caption(": " + CURRENCY)

    # --- Router de páginas ---
    page = st.session_state.get("page", "Vendedor")
    if page == "Vendedor":
        page_sell()
    elif page == "Productos":
        page_products()
    elif page == "Reponer":
        page_restock()
    elif page == "Informe":
        page_report()
    elif page == "Inventario":
        page_inventory()
    elif page == "Usuarios":
        page_users()
    else:
        st.session_state["page"] = "Vendedor"
        page_sell()

    # Pie fijo
    render_footer()


if __name__ == "__main__":
    main()
