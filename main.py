"""
FraudDetection-01 — phi47 SIDAD Agent
Railway deployable service

Author: Walter Calmels — TUCH Systems Research Laboratory
"""
import os, sys, json, time
from pathlib import Path

# ── Config ────────────────────────────────────────
PORT           = int(os.environ.get("PORT", 8080))
AGENT_ID       = os.environ.get("AGENT_ID",   "fraud_001")
AGENT_NAME     = os.environ.get("AGENT_NAME", "FraudDetection-01")
META_URL       = os.environ.get("META_URL",
    "https://web-production-1f5bf0.up.railway.app")
HUB_URL        = os.environ.get("HUB_URL",
    "https://phi47-federated-hub-production.up.railway.app")

os.environ.setdefault("NEMOSINE_DB", f"/tmp/fraud_001.db")

print(f"""
  FraudDetection-01
  SIDAD phi47 v1.0
  ID:   fraud_001
  Meta: {META_URL}
  Hub:  {HUB_URL}
""")

# ── Import agent ──────────────────────────────────
from specialized_agents import FraudDetectionAgent
from federated_phi import FederatedHub

hub   = FederatedHub(db_path=f"/tmp/fraud_001_hub.db", remote_url=HUB_URL)
agent = FraudDetectionAgent(
    agent_id = AGENT_ID,
    hub      = hub,
    **{"currency":"CLP"}
)
agent.start_learning()

# ── Flask API ─────────────────────────────────────
app = agent.create_api()

from flask import jsonify, request
from flask_cors import CORS
CORS(app)

# ── Auto-register with Meta-Orchestrator ─────────
def _register():
    import urllib.request
    time.sleep(5)  # wait for server to start
    try:
        # FIX: RAILWAY_PUBLIC_DOMAIN no siempre esta seteada por default --
        # probar varias variables que Railway puede exponer segun el plan/
        # configuracion, antes de caer a localhost (inutil fuera del propio
        # contenedor, y es lo que estaba pasando: el agente se registraba
        # con url=localhost:8080 y el Meta-Orquestador nunca podia
        # consultar su /health real).
        my_url = ""
        for _env_var in ("RAILWAY_PUBLIC_DOMAIN", "RAILWAY_STATIC_URL",
                         "RENDER_EXTERNAL_URL", "PUBLIC_URL"):
            val = os.environ.get(_env_var, "")
            if val:
                my_url = val
                break
        if my_url and not my_url.startswith("http"):
            my_url = f"https://{my_url}"
        if not my_url:
            my_url = f"http://localhost:{PORT}"
            print(f"  [!] No se detecto URL publica de Railway -- "
                  f"registrando con {my_url} (Meta-Orquestador no podra "
                  f"consultar este agente). Configurar manualmente la "
                  f"variable AGENT_PUBLIC_URL en Railway si esto persiste.")
        # Override manual explicito, por si ninguna de las anteriores aplica
        my_url = os.environ.get("AGENT_PUBLIC_URL", my_url)

        payload = json.dumps({
            "agent_id":    AGENT_ID,
            "name":        AGENT_NAME,
            "url":         my_url,
            "domain":      agent.domain,
            "tier":        agent.tier,
            "capabilities":getattr(agent,"capabilities",[]),
        }).encode()
        req = urllib.request.Request(
            META_URL + "/agents",
            data=payload,
            headers={"Content-Type":"application/json"},
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=10) as r:
            d = json.loads(r.read())
            print(f"  ✓ Registrado en Meta: n_agents={d.get('n_agents')} "
                  f"onl_active={d.get('onl_active')}")
    except Exception as e:
        print(f"  ✗ Auto-registro fallido: {e}")

import threading
threading.Thread(target=_register, daemon=True).start()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=PORT, debug=False, threaded=True)
