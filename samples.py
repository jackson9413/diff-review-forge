"""Built-in sample diffs for Diff Review Forge.

Six scenarios, each one exercising a different part of the rule set.
They double as calibration cases: the clean one should score near 100 and
the dangerous one should be clearly blocked.
"""

from __future__ import annotations

from typing import Dict, List, Optional

SAMPLES: List[dict] = [
    {
        "id": "clean_pull_request",
        "title": "Clean feature with a test",
        "blurb": "A small helper plus a unit test. Nothing to fix - this is the control case.",
        "profile": "general",
        "diff": r'''diff --git a/app/utils/formatting.py b/app/utils/formatting.py
index 1a2b3c4..5d6e7f8 100644
--- a/app/utils/formatting.py
+++ b/app/utils/formatting.py
@@ -10,6 +10,13 @@ def _split_name(raw: str) -> list:
     return [part for part in raw.split() if part]
 
 
+def format_currency(amount: float, currency: str = "USD") -> str:
+    """Return a currency string with thousands separators."""
+    symbol = {"USD": "$"}.get(currency, "")
+    formatted = f"{amount:,.2f}"
+    return symbol + formatted if symbol else formatted
+
+
 def format_name(raw: str) -> str:
     first, _, last = raw.partition(" ")
     return f"{first.title()} {last.title()}".strip()
diff --git a/tests/test_formatting.py b/tests/test_formatting.py
index 2b3c4d5..6e7f8a9 100644
--- a/tests/test_formatting.py
+++ b/tests/test_formatting.py
@@ -1,5 +1,9 @@
 from app.utils.formatting import format_currency, format_name
 
 
+def test_format_currency_with_symbol():
+    assert format_currency(1234.5) == "$1,234.50"
+
+
 def test_format_name():
     assert format_name("ada lovelace") == "Ada Lovelace"
''',
    },
    {
        "id": "secret_leak",
        "title": "Credentials committed to the repository",
        "blurb": "A database password, a live-looking API key and a session secret, all in source.",
        "profile": "security_audit",
        "diff": r'''diff --git a/app/settings/production.py b/app/settings/production.py
index 1f2e3d4..5a6b7c8 100644
--- a/app/settings/production.py
+++ b/app/settings/production.py
@@ -1,8 +1,16 @@
 import os
 
-DATABASE_URL = "postgres://localhost/app"
+DB_PASSWORD = "Sup3rS3cretPassw0rd"
+STRIPE_SECRET_KEY = "sk-live-51H8xQm2LkR9wTm4pQ7vZ0xBd"
+SESSION_SECRET = "b7f3c1a9d4e6f8a2c5b9e3d1f7a4c8e6"
+DATABASE_URL = "postgres://admin:" + DB_PASSWORD + "@db.internal:5432/prod"
 
 APP_DEBUG = False
 
+
+def debug_dump(request):
+    """Return a debug view of the request."""
+    return {"path": request.path, "headers": dict(request.headers)}
+
+
 class Settings:
     timeout = 30
''',
    },
    {
        "id": "n_plus_one_regression",
        "title": "Report endpoint queries per row",
        "blurb": "One product lookup per order, a sleep in the loop and a list membership test.",
        "profile": "performance",
        "diff": r'''diff --git a/app/api/reports.py b/app/api/reports.py
index 2c3d4e5..6b7c8d9 100644
--- a/app/api/reports.py
+++ b/app/api/reports.py
@@ -20,4 +20,14 @@ from app.db import session
 def build_report(customer_id: int) -> dict:
     customer = session.query(Customer).get(customer_id)
     orders = session.query(Order).filter(Order.customer_id == customer_id).all()
+    known_skus = []
+    total = 0
+    for order in orders:
+        product = session.query(Product).get(order.product_id)
+        if product.sku in known_skus:
+            continue
+        known_skus.append(product.sku)
+        time.sleep(0.01)
+        total += product.price * order.quantity
     return {"customer": customer.name, "orders": len(orders), "total": total}
''',
    },
    {
        "id": "bugfix_without_tests",
        "title": "Bug fix with no test and a swallowed error",
        "blurb": "A pricing fix that swallows a TypeError and adds a function with a mutable default.",
        "profile": "bug_hunt",
        "diff": r'''diff --git a/app/services/pricing.py b/app/services/pricing.py
index 3d4e5f6..7c8d9e0 100644
--- a/app/services/pricing.py
+++ b/app/services/pricing.py
@@ -40,10 +40,21 @@ def _base_price(item):
 def apply_discount(item, user, code=None):
     price = _base_price(item)
-    if code == None:
+    if code is None:
         return price
     discount = 0.0
     for rule in user.discount_rules:
         if rule.code == code:
             discount = rule.percent
-    if discount > 0:
-        price = price - (price * discount / 100)
-    return price
+    try:
+        price = price - (price * discount / 100)
+    except TypeError:
+        pass
+    return round(price, 2)
+
+
+def apply_discount_with_log(item, user, code=None, history=[]):
+    if history == None:
+        history = []
+    history.append(apply_discount(item, user, code))
+    return apply_discount(item, user, code), history
''',
    },
    {
        "id": "breaking_api_rename",
        "title": "Public endpoint renamed and a module deleted",
        "blurb": "A route loses its methods, a public function is renamed and a file is deleted.",
        "profile": "api_stability",
        "diff": r'''diff --git a/app/api/users.py b/app/api/users.py
index 4e5f6a7..8d9e0f1 100644
--- a/app/api/users.py
+++ b/app/api/users.py
@@ -12,11 +12,10 @@ from flask import Blueprint
 users_bp = Blueprint("users", __name__)
 
 
-@users_bp.route("/api/users/<int:user_id>", methods=["GET"])
-def get_user(user_id):
-    user = User.query.get(user_id)
-    return serialize(user)
+@users_bp.route("/api/users/<int:user_id>")
+def fetch_user(user_id):
+    return serialize(User.query.get(user_id))
 
 
 def list_users():
     return [u.to_dict() for u in User.query.all()]
diff --git a/app/api/legacy.py b/app/api/legacy.py
deleted file mode 100644
index 5f6a7b8..0000000
--- a/app/api/legacy.py
+++ /dev/null
@@ -1,6 +0,0 @@
-def legacy_export():
-    return build_csv(User.query.all())
-
-
-def legacy_import(rows):
-    return insert_rows(rows)
''',
    },
    {
        "id": "refactor_sweep",
        "title": "Mixed quality refactor",
        "blurb": "TODO markers, commented-out code, a debug log and a second renderer with no test.",
        "profile": "general",
        "diff": r'''diff --git a/web/src/legacy.js b/web/src/legacy.js
index 6a7b8c9..9e0f1a2 100644
--- a/web/src/legacy.js
+++ b/web/src/legacy.js
@@ -1,11 +1,31 @@
 import { format } from "./util";
 
-export function renderAll(items) {
-  for (const item of items) {
-    render(item);
-  }
+export function renderAll(items) {
+  // TODO: rewrite this in the new renderer
+  const seen = [];
+  for (const item of items) {
+    // const item = item;
+    if (seen.includes(item.id)) {
+      continue;
+    }
+    seen.push(item.id);
+    console.log("rendering", item.id);
+    render(item);
+  }
 }
 
 export function render(item) {
   return format(item);
 }
+
+export function renderLegacy(items) {
+  var out = [];
+  for (const item of items) {
+    out = out.concat(format(item));
+  }
+  return out;
+}
''',
    },
]

_BY_ID: Dict[str, dict] = {s["id"]: s for s in SAMPLES}


def list_samples() -> List[dict]:
    return [
        {
            "id": s["id"],
            "title": s["title"],
            "blurb": s["blurb"],
            "profile": s["profile"],
            "lines": s["diff"].count("\n"),
        }
        for s in SAMPLES
    ]


def get_sample(sample_id: str) -> Optional[dict]:
    return _BY_ID.get(sample_id)
