"""
Agentes Especializados SIDAD — 12 dominios
==========================================
Colección de agentes que junto a LegalAgent y ManufacturingAgent
completan los 14 agentes necesarios para alcanzar N_crítico
y permitir la emergencia del Observador No-Local.

Agentes incluidos:
  Cybersecurity:    ThreatHunterAgent, ForensicsAgent
  Finance:          FraudDetectionAgent, RiskAgent
  Infrastructure:   EnergyAgent
  Code/Audit:       CodeAuditAgent, ComplianceAgent
  Health:           ClinicalOpsAgent
  Bioinformatics:   SequenceAgent
  Climate:          EnvironmentalAgent
  Neuroscience:     CognitiveAgent
  General:          OrchestratorAgent

Author: Walter Calmels Von dem Knesebeck
        TUCH Systems Research Laboratory — Maipu Lab 2026
"""

import os, sys, re, math, time, json, hashlib
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field
from datetime import datetime, timezone
from collections import deque, defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from agent_base import AgentBase, AnalysisResult
from phi47_base import PHI, PHI_MIN

VERSION = "1.0.0"


# ══════════════════════════════════════════════════
# 3. THREAT HUNTER AGENT — Cybersecurity proactiva
# ══════════════════════════════════════════════════

class ThreatHunterAgent(AgentBase):
    """
    Cazador de amenazas proactivo.
    A diferencia del Sentinel que reacciona a conexiones,
    el ThreatHunter busca activamente IOCs en la red
    y correlaciona campañas de ataque.

    Aprende:
      - Patrones de movimiento lateral en redes
      - Técnicas MITRE ATT&CK observadas en el cliente
      - Horarios y patrones de los atacantes
    """
    domain = "cybersecurity"

    # MITRE ATT&CK techniques más relevantes
    MITRE_PATTERNS = {
        "T1059": {"name":"Command and Scripting", "keywords":["powershell","cmd","bash -c","python -c"], "score":0.82},
        "T1078": {"name":"Valid Accounts",        "keywords":["login after hours","unusual account","service account"], "score":0.75},
        "T1021": {"name":"Remote Services",       "keywords":["rdp","ssh unusual","winrm","psexec"], "score":0.80},
        "T1055": {"name":"Process Injection",     "keywords":["process injection","dll injection","reflective"], "score":0.90},
        "T1003": {"name":"Credential Dumping",    "keywords":["mimikatz","lsass","credential dump","ntds"], "score":0.95},
        "T1071": {"name":"C2 over HTTP",          "keywords":["beacon","c2","command control","periodic http"], "score":0.88},
        "T1048": {"name":"Exfiltration",          "keywords":["dns tunnel","ftp unusual","large upload","base64 stream"], "score":0.92},
        "T1070": {"name":"Log Tampering",         "keywords":["log cleared","event deleted","audit disabled"], "score":0.93},
    }

    def __init__(self, agent_id: str, network_scope: str = "corporate", **kwargs):
        super().__init__(agent_id, **kwargs)
        self.network_scope = network_scope
        self._campaigns    : Dict[str, Dict] = {}  # campañas activas
        self._ioc_cache    : deque = deque(maxlen=10000)
        self._n_hunts      = 0
        print(f"  Scope: {network_scope}")

    def hunt(self, data: Dict) -> Optional[Dict]:
        """
        Caza activa de amenazas en datos de red/logs.
        data puede contener: logs, connections, processes, files
        """
        self._n_hunts += 1
        return self.process(**data)

    def analyze(self, data: Dict) -> Optional[AnalysisResult]:
        text = str(data).lower()

        # Buscar técnicas MITRE
        for technique_id, info in self.MITRE_PATTERNS.items():
            if any(kw in text for kw in info["keywords"]):
                # Verificar si es parte de campaña conocida
                campaign = self._correlate_campaign(technique_id, data)
                reason = f"Técnica {technique_id} ({info['name']})"
                if campaign:
                    reason += f" — parte de campaña '{campaign}'"
                return self.alert(
                    concept  = f"mitre_{technique_id}",
                    severity = "CRITICAL" if info["score"] > 0.88 else "HIGH",
                    score    = info["score"],
                    reason   = reason,
                    technique= technique_id,
                    technique_name=info["name"],
                    campaign = campaign,
                )

        # Detectar movimiento lateral (memoria phi)
        memories = self.recall("lateral movement credential", n=5)
        if memories and len(memories) > 2:
            return self.alert("lateral_movement", "HIGH", 0.78,
                              reason="Patrón de movimiento lateral detectado en historial")
        return None

    def _rules(self) -> List[Dict]:
        return [
            {"match":{"technique":"T1003"}, "action":"BLOCK",
             "severity":"CRITICAL","score":0.97,
             "reason":"Credential dumping detectado","concept":"credential_dump"},
            {"match":{"log_cleared":True}, "action":"ALERT",
             "severity":"CRITICAL","score":0.95,
             "reason":"Logs borrados — posible cubrimiento de huellas","concept":"log_tampering"},
        ]

    def _correlate_campaign(self, technique: str, data: Dict) -> str:
        """Correlaciona con campañas de ataque conocidas."""
        hour = datetime.now().hour
        key = f"{technique}_{hour//6}"  # agrupar por cuarto del día
        if key in self._campaigns:
            self._campaigns[key]["count"] += 1
            if self._campaigns[key]["count"] >= 3:
                return f"campaign_{key}"
        else:
            self._campaigns[key] = {"count": 1, "first_seen": time.time()}
        return ""

    def status(self) -> Dict:
        s = super().status()
        s.update({"hunts": self._n_hunts,
                  "campaigns": len(self._campaigns),
                  "scope": self.network_scope})
        return s


# ══════════════════════════════════════════════════
# 4. FORENSICS AGENT — Análisis post-incidente
# ══════════════════════════════════════════════════

class ForensicsAgent(AgentBase):
    """
    Análisis forense post-incidente.
    Reconstruye la línea de tiempo de un ataque,
    identifica el vector de entrada y el alcance.

    Aprende:
      - Patrones de ataque históricos de esta organización
      - Qué vectores han sido explotados antes
      - Tiempo promedio de detección y contención
    """
    domain = "cybersecurity"

    EVIDENCE_TYPES = {
        "network_log":  {"weight": 0.85, "desc": "Logs de red"},
        "system_log":   {"weight": 0.90, "desc": "Logs del sistema"},
        "memory_dump":  {"weight": 0.95, "desc": "Volcado de memoria"},
        "file_artifact":{"weight": 0.80, "desc": "Artefactos en disco"},
        "registry":     {"weight": 0.88, "desc": "Cambios en registro"},
        "email":        {"weight": 0.75, "desc": "Evidencia en email"},
    }

    def __init__(self, agent_id: str, **kwargs):
        super().__init__(agent_id, **kwargs)
        self._cases     : Dict[str, Dict] = {}
        self._n_cases   = 0
        self._timeline  : deque = deque(maxlen=5000)

    def investigate(self, evidence: List[Dict], case_id: str = "") -> Dict:
        """
        Investiga un incidente a partir de evidencias.
        evidence: [{"type":"network_log","data":"...","ts":"..."}, ...]
        """
        if not case_id:
            case_id = hashlib.md5(str(evidence[:2]).encode()).hexdigest()[:8]

        self._n_cases += 1
        findings = []

        for e in evidence:
            alert = self.process(
                evidence_type=e.get("type",""),
                data=str(e.get("data",""))[:500],
                ts=e.get("ts",""),
                case_id=case_id,
            )
            if alert:
                findings.append(alert)

        # Construir timeline
        timeline = sorted(evidence, key=lambda x: x.get("ts",""))

        # Calcular severidad del caso
        max_score = max((f.get("score",0) for f in findings), default=0)
        severity  = ("CRITICAL" if max_score > 0.85 else
                     "HIGH" if max_score > 0.65 else "MEDIUM")

        # Guardar en Nemosine
        self.remember(
            f"[CASO {case_id}] {severity}: {len(findings)} hallazgos "
            f"en {len(evidence)} evidencias",
            phi=0.88,
            tags=["forensics","case",severity.lower()],
            case_id=case_id,
        )

        return {
            "case_id":        case_id,
            "severity":       severity,
            "findings":       findings,
            "n_evidence":     len(evidence),
            "n_findings":     len(findings),
            "timeline_start": timeline[0].get("ts","") if timeline else "",
            "timeline_end":   timeline[-1].get("ts","") if timeline else "",
            "phi":            round(self.phi, 4),
        }

    def analyze(self, data: Dict) -> Optional[AnalysisResult]:
        evidence_type = data.get("evidence_type","")
        content       = str(data.get("data","")).lower()

        # Detectar indicadores forenses críticos
        critical_indicators = [
            ("mimikatz", "Herramienta de extracción de credenciales", 0.97),
            ("wce.exe",  "Windows Credential Editor detectado",       0.96),
            ("procdump", "Volcado de proceso sospechoso",             0.88),
            ("cobaltstrike", "Beacon Cobalt Strike detectado",        0.99),
            ("meterpreter",  "Sesión Meterpreter identificada",       0.98),
            ("webshell",     "Web shell detectada en sistema",        0.95),
        ]
        for indicator, reason, score in critical_indicators:
            if indicator in content:
                return self.alert("forensic_indicator","CRITICAL",
                                  score, reason=reason,
                                  indicator=indicator,
                                  evidence_type=evidence_type)

        # Indicadores de persistencia
        persistence = ["scheduled task","registry run","startup folder",
                       "cron","systemd service","launchd"]
        if any(p in content for p in persistence):
            return self.alert("persistence_mechanism","HIGH",0.82,
                              reason="Mecanismo de persistencia detectado",
                              evidence_type=evidence_type)
        return None

    def status(self) -> Dict:
        s = super().status()
        s.update({"cases": self._n_cases})
        return s


# ══════════════════════════════════════════════════
# 5. FRAUD DETECTION AGENT — Finance
# ══════════════════════════════════════════════════

class FraudDetectionAgent(AgentBase):
    """
    Detección de fraude financiero.
    Aprende el patrón normal de cada cliente/cuenta
    y detecta desviaciones.

    Diferencia clave vs sistemas genéricos:
      Aprende el baseline de ESE cliente específico.
      Un retiro de $50K puede ser normal para el cliente A
      y completamente anómalo para el cliente B.
    """
    domain = "finance"

    FRAUD_PATTERNS = {
        "card_testing":      {"desc":"Transacciones pequeñas múltiples para probar tarjeta", "score":0.88},
        "account_takeover":  {"desc":"Cambio de datos + transacción grande en < 24h",       "score":0.95},
        "synthetic_identity":{"desc":"Identidad con historial artificial corto",             "score":0.80},
        "money_laundering":  {"desc":"Múltiples depósitos pequeños seguidos de retiro grande","score":0.90},
        "friendly_fraud":    {"desc":"Chargeback después de recibir producto",               "score":0.70},
        "velocity_abuse":    {"desc":"Volumen transaccional inusualmente alto en período corto","score":0.85},
    }

    def __init__(self, agent_id: str, currency: str = "CLP", **kwargs):
        super().__init__(agent_id, **kwargs)
        self.currency      = currency
        self._accounts     : Dict[str, Dict] = {}  # baseline por cuenta
        self._n_txns       = 0
        self._n_fraud      = 0
        self._total_blocked = 0.0

    def analyze_transaction(self, account_id: str, amount: float,
                             merchant: str = "", country: str = "",
                             hour: int = -1, channel: str = "online"
                             ) -> Optional[Dict]:
        """Analiza una transacción financiera."""
        if hour < 0:
            hour = datetime.now().hour
        return self.process(
            account_id=account_id, amount=amount,
            merchant=merchant, country=country,
            hour=hour, channel=channel,
        )

    def analyze(self, data: Dict) -> Optional[AnalysisResult]:
        account_id = data.get("account_id","")
        amount     = float(data.get("amount", 0))
        hour       = int(data.get("hour", 12))
        country    = data.get("country","CL")
        channel    = data.get("channel","online")

        self._n_txns += 1

        # Obtener/inicializar baseline de cuenta
        acc = self._accounts.setdefault(account_id, {
            "mean_amount": amount, "n": 1,
            "usual_hours": set(), "usual_countries": {"CL"},
            "m2": 0.0, "std": 0.0,
        })

        # Actualizar baseline Welford
        acc["n"]   += 1
        delta       = amount - acc["mean_amount"]
        acc["mean_amount"] += delta / acc["n"]
        acc["m2"]  += delta * (amount - acc["mean_amount"])
        if acc["n"] > 1:
            acc["std"] = math.sqrt(acc["m2"]/(acc["n"]-1))
        acc["usual_hours"].add(hour)
        acc["usual_countries"].add(country)

        # Necesitar baseline mínimo
        if acc["n"] < 20:
            return None

        fraud_signals = []
        score = 0.0

        # 1. Monto anómalo
        if acc["std"] > 0:
            sigma = abs(amount - acc["mean_amount"]) / acc["std"]
            if sigma > 4:
                fraud_signals.append(f"Monto {sigma:.1f}σ fuera del baseline")
                score = max(score, min(0.95, 0.5 + sigma*0.05))

        # 2. Hora inusual
        if hour not in acc["usual_hours"] and (hour < 5 or hour > 23):
            fraud_signals.append(f"Transacción en horario inusual ({hour}h)")
            score = max(score, 0.65)

        # 3. País inusual
        if country not in acc["usual_countries"]:
            fraud_signals.append(f"País inusual: {country}")
            score = max(score, 0.72)

        # 4. Buscar patrón de card testing (muchas txns pequeñas)
        memories = self.recall(f"transacción {account_id}", n=10)
        recent_small = sum(1 for m in memories
                          if "amount" in m.get("content","").lower()
                          and account_id in m.get("content",""))
        if recent_small >= 5 and amount < 10:
            fraud_signals.append("Posible card testing: múltiples micro-txns")
            score = max(score, 0.88)

        if not fraud_signals:
            # Normal — guardar en memoria
            self.remember(
                f"txn normal {account_id}: ${amount:.0f} {country} {hour}h",
                phi=0.65, tags=["transaction","normal",account_id[:8]])
            return None

        self._n_fraud += 1
        self._total_blocked += amount

        return self.alert(
            concept  = "fraud_pattern",
            severity = "CRITICAL" if score > 0.85 else "HIGH",
            score    = score,
            reason   = " | ".join(fraud_signals),
            account_id    = account_id[:8] + "****",
            amount_range  = "large" if amount > acc["mean_amount"]*3 else "normal",
        )

    def status(self) -> Dict:
        s = super().status()
        s.update({
            "transactions":   self._n_txns,
            "fraud_detected": self._n_fraud,
            "accounts_monitored": len(self._accounts),
        })
        return s


# ══════════════════════════════════════════════════
# 6. RISK AGENT — Riesgo de crédito y contraparte
# ══════════════════════════════════════════════════

class RiskAgent(AgentBase):
    """
    Evaluación de riesgo de crédito y contraparte.
    Aprende qué señales predicen incumplimiento
    en el portfolio específico de la organización.
    """
    domain = "finance"

    RISK_FACTORS = {
        "payment_delay":    {"weight":0.30, "desc":"Retraso en pagos anteriores"},
        "revenue_decline":  {"weight":0.25, "desc":"Caída de ingresos"},
        "leverage_high":    {"weight":0.20, "desc":"Apalancamiento excesivo"},
        "liquidity_low":    {"weight":0.15, "desc":"Liquidez insuficiente"},
        "sector_stress":    {"weight":0.10, "desc":"Estrés sectorial"},
    }

    def __init__(self, agent_id: str, **kwargs):
        super().__init__(agent_id, **kwargs)
        self._portfolio: Dict[str, Dict] = {}

    def evaluate_counterpart(self, entity_id: str, **financials) -> Dict:
        """Evalúa riesgo de una contraparte."""
        result = self.process(entity_id=entity_id, **financials)
        score  = self._calculate_risk_score(financials)
        rating = ("AAA" if score < 0.1 else "AA" if score < 0.2 else
                  "A"   if score < 0.35 else "BBB" if score < 0.5 else
                  "BB"  if score < 0.65 else "B" if score < 0.8 else "CCC")
        self._portfolio[entity_id] = {"score": score, "rating": rating}
        return {"entity_id": entity_id, "risk_score": round(score,3),
                "rating": rating, "alert": result, "phi": round(self.phi,4)}

    def analyze(self, data: Dict) -> Optional[AnalysisResult]:
        score = self._calculate_risk_score(data)
        if score > 0.65:
            factors = [d for k,d in self.RISK_FACTORS.items()
                      if data.get(k, False)]
            return self.alert("credit_risk",
                              "CRITICAL" if score > 0.8 else "HIGH",
                              score,
                              reason=f"Riesgo elevado: {', '.join(factors[:3])}")
        return None

    def _calculate_risk_score(self, data: Dict) -> float:
        score = 0.0
        for factor, config in self.RISK_FACTORS.items():
            if data.get(factor, False):
                score += config["weight"]
        # Buscar precedentes negativos en memoria
        memories = self.recall("incumplimiento riesgo", n=5)
        if len(memories) > 3:
            score = min(0.99, score + 0.1)
        return min(0.99, score)

    def status(self) -> Dict:
        s = super().status()
        s.update({"portfolio_size": len(self._portfolio)})
        return s


# ══════════════════════════════════════════════════
# 7. ENERGY AGENT — Optimización energética
# ══════════════════════════════════════════════════

class EnergyAgent(AgentBase):
    """
    Monitoreo y optimización energética.
    Aprende el perfil de consumo de cada instalación
    y detecta ineficiencias, picos anómalos o equipos
    en mal estado (consumo elevado = mayor fricción interna).
    """
    domain = "infrastructure"

    def __init__(self, agent_id: str, facility: str = "", **kwargs):
        super().__init__(agent_id, **kwargs)
        self.facility      = facility
        self._baselines    : Dict[str, Tuple[float,float]] = {}  # mean, std
        self._welford      : Dict[str, List] = {}  # [n, mean, m2]
        self._n_readings   = 0
        self._anomalies    = 0
        self._savings_kwh  = 0.0

    def analyze(self, data: Dict) -> Optional[AnalysisResult]:
        meter_id = data.get("meter_id","")
        kwh      = float(data.get("kwh", 0))
        hour     = int(data.get("hour", datetime.now().hour))
        self._n_readings += 1

        # Welford por metro y hora del día
        key = f"{meter_id}_{hour}"
        if key not in self._welford:
            self._welford[key] = [0, 0.0, 0.0]  # n, mean, m2
        w = self._welford[key]
        w[0] += 1
        delta = kwh - w[1]; w[1] += delta/w[0]
        w[2] += delta*(kwh-w[1])
        std = math.sqrt(w[2]/(w[0]-1)) if w[0] > 1 else 0

        if w[0] < 30 or std < 1e-6:
            return None  # baseline insuficiente

        sigma = abs(kwh - w[1]) / std
        if sigma > 3:
            self._anomalies += 1
            severity = "HIGH" if sigma > 5 else "MEDIUM"
            # Estimar ahorro potencial si es consumo excesivo
            if kwh > w[1]:
                excess_kwh = kwh - w[1]
                self._savings_kwh += excess_kwh * 0.5
            return self.alert(
                "energy_anomaly", severity, min(0.95, sigma/10),
                reason=f"Consumo {sigma:.1f}σ fuera del baseline "
                       f"({kwh:.1f} kWh vs {w[1]:.1f} esperado)",
                meter_id=meter_id, hour=hour,
            )
        return None

    def status(self) -> Dict:
        s = super().status()
        s.update({
            "facility":     self.facility,
            "readings":     self._n_readings,
            "anomalies":    self._anomalies,
            "meters":       len(self._welford),
            "savings_kwh":  round(self._savings_kwh, 1),
        })
        return s


# ══════════════════════════════════════════════════
# 8. CODE AUDIT AGENT — Auditoría de código
# ══════════════════════════════════════════════════

class CodeAuditAgent(AgentBase):
    """
    Auditoría de código con integración HAV (Hallucination Avoidance Verifier).
    Detecta vulnerabilidades de seguridad, alucinaciones de LLM,
    y violaciones de políticas de código.

    Ideal para equipos que usan LLMs para generar código.
    """
    domain = "cybersecurity"

    VULN_PATTERNS = {
        "sql_injection":   {"pattern":r"(query|execute|cursor)\s*\(.*\+.*\+","score":0.95},
        "xss":             {"pattern":r"innerHTML\s*=|document\.write\s*\(","score":0.88},
        "hardcoded_creds": {"pattern":r"(password|secret|api_key)\s*=\s*['\"][^'\"]{6,}","score":0.92},
        "insecure_random": {"pattern":r"random\.(random|randint|choice)\s*\(","score":0.70},
        "path_traversal":  {"pattern":r"\.\./|\.\.\\"                       ,"score":0.85},
        "eval_usage":      {"pattern":r"\beval\s*\(|\bexec\s*\("           ,"score":0.88},
        "pickle_unsafe":   {"pattern":r"pickle\.loads|cPickle\.loads"       ,"score":0.90},
        "xxe":             {"pattern":r"xml\.etree|minidom|lxml.*external"  ,"score":0.82},
        "ssrf":            {"pattern":r"requests\.get\(.*url|urllib.*open"  ,"score":0.78},
        "debug_enabled":   {"pattern":r"debug\s*=\s*True|DEBUG\s*=\s*True" ,"score":0.65},
    }

    # Patrones de alucinaciones LLM en código
    HALLUCINATION_PATTERNS = [
        r"import\s+\w+_ai_\w+",          # módulos inexistentes
        r"\.ai_generate\s*\(",            # métodos inventados
        r"from\s+future\s+import",        # import imposible
        r"@deprecated\s*\(.*202[0-9]\)",  # fechas de deprecación inventadas
        r"# TODO: use newer API v\d{3}",  # versiones de API inventadas
    ]

    def __init__(self, agent_id: str, language: str = "python", **kwargs):
        super().__init__(agent_id, **kwargs)
        self.language    = language
        self._n_files    = 0
        self._n_vulns    = 0
        self._n_halluc   = 0

    def audit_code(self, code: str, filename: str = "") -> Dict:
        """Audita un fragmento de código."""
        self._n_files += 1
        alert = self.process(code=code, filename=filename)
        vulns = self._find_vulnerabilities(code)
        halluc= self._detect_hallucinations(code)
        overall_score = max([v["score"] for v in vulns], default=0)

        if halluc:
            self._n_halluc += 1

        return {
            "filename":        filename,
            "vulnerabilities": vulns,
            "hallucinations":  halluc,
            "overall_score":   round(overall_score, 3),
            "severity":        "CRITICAL" if overall_score > 0.85 else
                               "HIGH" if overall_score > 0.65 else
                               "MEDIUM" if overall_score > 0.40 else "SAFE",
            "phi":             round(self.phi, 4),
        }

    def analyze(self, data: Dict) -> Optional[AnalysisResult]:
        code  = str(data.get("code",""))
        vulns = self._find_vulnerabilities(code)
        if vulns:
            self._n_vulns += len(vulns)
            top   = max(vulns, key=lambda v: v["score"])
            return self.alert(
                concept  = "code_vulnerability",
                severity = "CRITICAL" if top["score"] > 0.85 else "HIGH",
                score    = top["score"],
                reason   = f"{top['type']}: {top['location'][:60]}",
                vuln_types= [v["type"] for v in vulns],
            )
        return None

    def _find_vulnerabilities(self, code: str) -> List[Dict]:
        results = []
        for vuln_type, config in self.VULN_PATTERNS.items():
            matches = re.findall(config["pattern"], code, re.IGNORECASE)
            if matches:
                results.append({
                    "type":     vuln_type,
                    "score":    config["score"],
                    "location": str(matches[0])[:80],
                    "count":    len(matches),
                })
        return sorted(results, key=lambda x: x["score"], reverse=True)

    def _detect_hallucinations(self, code: str) -> List[str]:
        found = []
        for pattern in self.HALLUCINATION_PATTERNS:
            if re.search(pattern, code, re.IGNORECASE):
                found.append(f"Posible alucinación LLM: {pattern[:40]}")
        return found

    def status(self) -> Dict:
        s = super().status()
        s.update({"language": self.language, "files": self._n_files,
                  "vulnerabilities": self._n_vulns,
                  "hallucinations": self._n_halluc})
        return s


# ══════════════════════════════════════════════════
# 9. COMPLIANCE AGENT — Regulatorio
# ══════════════════════════════════════════════════

class ComplianceAgent(AgentBase):
    """
    Monitoreo de cumplimiento regulatorio.
    Aprende los requisitos específicos de la organización
    y detecta desviaciones antes de que sean infracciones.
    """
    domain = "legal"

    FRAMEWORKS = {
        "GDPR":    {"desc":"General Data Protection Regulation",  "jurisdictions":["EU","CL"]},
        "PCI-DSS": {"desc":"Payment Card Industry Data Security", "jurisdictions":["all"]},
        "SOC2":    {"desc":"Service Organization Control 2",      "jurisdictions":["US","CL"]},
        "ISO27001":{"desc":"Information Security Management",     "jurisdictions":["all"]},
        "LGPD":    {"desc":"Lei Geral de Proteção de Dados",      "jurisdictions":["BR"]},
    }

    GDPR_REQUIREMENTS = [
        ("datos personales sin consentimiento",     "GDPR Art.6",  0.90),
        ("datos sensibles sin base legal",          "GDPR Art.9",  0.95),
        ("transferencia internacional sin garantías","GDPR Art.46", 0.88),
        ("brecha sin notificación 72h",             "GDPR Art.33", 0.92),
        ("derecho de acceso denegado",              "GDPR Art.15", 0.85),
        ("retención más allá del plazo",            "GDPR Art.5",  0.80),
    ]

    def __init__(self, agent_id: str,
                 frameworks: List[str] = None,
                 jurisdiction: str = "CL", **kwargs):
        super().__init__(agent_id, **kwargs)
        self.frameworks   = frameworks or ["GDPR","ISO27001"]
        self.jurisdiction = jurisdiction
        self._violations  = 0
        self._remediations= 0

    def check_compliance(self, document: str, framework: str = "GDPR") -> Dict:
        """Verifica cumplimiento de un documento o proceso."""
        alert = self.process(document=document, framework=framework)
        violations = self._find_violations(document, framework)
        return {
            "framework":  framework,
            "violations": violations,
            "compliant":  len(violations) == 0,
            "risk_level": "HIGH" if any(v["score"]>0.85 for v in violations) else
                          "MEDIUM" if violations else "SAFE",
            "phi":        round(self.phi, 4),
        }

    def analyze(self, data: Dict) -> Optional[AnalysisResult]:
        document  = str(data.get("document","")).lower()
        framework = data.get("framework","GDPR")
        violations= self._find_violations(document, framework)
        if violations:
            self._violations += len(violations)
            top = max(violations, key=lambda v: v["score"])
            return self.alert(
                "compliance_violation", "HIGH", top["score"],
                reason=f"{framework}: {top['violation']} ({top['article']})",
                framework=framework,
                n_violations=len(violations),
            )
        return None

    def _find_violations(self, doc: str, framework: str) -> List[Dict]:
        results = []
        if framework == "GDPR":
            for violation, article, score in self.GDPR_REQUIREMENTS:
                if any(kw in doc for kw in violation.split()[:3]):
                    results.append({"violation":violation,
                                    "article":article, "score":score})
        return sorted(results, key=lambda x: x["score"], reverse=True)

    def status(self) -> Dict:
        s = super().status()
        s.update({"violations": self._violations,
                  "frameworks": self.frameworks})
        return s


# ══════════════════════════════════════════════════
# 10. CLINICAL OPS AGENT — Salud
# ══════════════════════════════════════════════════

class ClinicalOpsAgent(AgentBase):
    """
    Optimización de operaciones clínicas/hospitalarias.
    Aprende el flujo operacional de la institución
    y detecta desviaciones sin acceder a datos de pacientes.

    Opera sobre metadatos operacionales (no datos clínicos):
      - Tiempo de espera por servicio
      - Ocupación de camas por unidad
      - Flujo de urgencias
      - Disponibilidad de quirófanos
      - Dotación de personal por turno
    """
    domain = "neuroscience"  # usa dominio neuroscience por afinidad bio

    def __init__(self, agent_id: str,
                 institution: str = "", **kwargs):
        super().__init__(agent_id, **kwargs)
        self.institution  = institution
        self._baselines   : Dict[str, List] = {}  # [n, mean, m2]
        self._n_readings  = 0
        self._n_alerts    = 0

    def monitor_metric(self, metric: str, value: float,
                        unit: str = "", unit_id: str = "") -> Optional[Dict]:
        """
        Monitorea una métrica operacional.
        metric: "wait_time", "bed_occupancy", "staff_ratio", etc.
        """
        return self.process(
            metric=metric, value=value, unit=unit, unit_id=unit_id,
        )

    def analyze(self, data: Dict) -> Optional[AnalysisResult]:
        metric  = data.get("metric","")
        value   = float(data.get("value", 0))
        unit_id = data.get("unit_id","")
        self._n_readings += 1

        # Umbrales absolutos conocidos (clínicamente relevantes)
        thresholds = {
            "wait_time":      (120, "Tiempo de espera > 2h en urgencias"),
            "bed_occupancy":  (0.95,"Ocupación > 95% — capacidad crítica"),
            "staff_ratio":    (0.60,"Personal por debajo del 60% requerido"),
            "er_flow":        (2.0, "Flujo de urgencias 2x normal"),
        }
        if metric in thresholds:
            threshold, reason = thresholds[metric]
            if value > threshold:
                self._n_alerts += 1
                ratio = value / threshold
                return self.alert(
                    f"ops_{metric}", "HIGH" if ratio > 1.5 else "MEDIUM",
                    min(0.95, ratio * 0.5),
                    reason=reason,
                    metric=metric, value=value,
                    threshold=threshold, unit_id=unit_id,
                )

        # Baseline adaptativo por unidad
        key = f"{metric}_{unit_id}"
        if key not in self._baselines:
            self._baselines[key] = [0, 0.0, 0.0]
        w = self._baselines[key]
        w[0] += 1
        delta = value - w[1]; w[1] += delta/w[0]
        w[2] += delta*(value-w[1])
        if w[0] > 30:
            std   = math.sqrt(w[2]/(w[0]-1)) if w[0] > 1 else 0
            sigma = abs(value - w[1]) / std if std > 0 else 0
            if sigma > 3:
                return self.alert(
                    f"ops_anomaly_{metric}", "MEDIUM",
                    min(0.80, sigma/10),
                    reason=f"{metric} {sigma:.1f}σ fuera del baseline operacional",
                    metric=metric, sigma=round(sigma,2),
                )
        return None

    def status(self) -> Dict:
        s = super().status()
        s.update({"institution": self.institution,
                  "readings": self._n_readings,
                  "metrics_monitored": len(self._baselines)})
        return s


# ══════════════════════════════════════════════════
# 11. SEQUENCE AGENT — Bioinformática
# ══════════════════════════════════════════════════

class SequenceAgent(AgentBase):
    """
    Análisis de secuencias biológicas y datos de bioinformática.
    Aprende patrones normales en datos genómicos/proteómicos
    y detecta variantes o anomalías de interés.

    Aplicaciones:
      - Control de calidad en secuenciación
      - Detección de contaminación en muestras
      - Variantes genéticas inusuales
      - Patrones de expresión génica anómalos
    """
    domain = "bioinformatics"

    QUALITY_THRESHOLDS = {
        "phred_score":    (30, "Calidad Phred < 30 — secuenciación baja calidad"),
        "coverage_depth": (20, "Cobertura < 20x — datos insuficientes"),
        "gc_content":     (0.7,"GC content > 70% — posible sesgo"),
        "duplication":    (0.3,"Duplicación > 30% — posible error de PCR"),
        "mapping_rate":   (0.8,"Tasa de mapeo < 80% — posible contaminación"),
    }

    def __init__(self, agent_id: str,
                 organism: str = "homo_sapiens", **kwargs):
        super().__init__(agent_id, **kwargs)
        self.organism   = organism
        self._n_samples = 0
        self._n_qc_fail = 0

    def analyze_qc(self, sample_id: str, **metrics) -> Dict:
        """Analiza métricas de control de calidad de una muestra."""
        self._n_samples += 1
        alert = self.process(sample_id=sample_id, **metrics)
        failed = self._check_qc(metrics)
        if failed:
            self._n_qc_fail += 1
        return {
            "sample_id":    sample_id,
            "qc_passed":    len(failed) == 0,
            "qc_failures":  failed,
            "alert":        alert,
            "phi":          round(self.phi, 4),
        }

    def analyze(self, data: Dict) -> Optional[AnalysisResult]:
        failures = self._check_qc(data)
        if failures:
            top_score = max(f["score"] for f in failures)
            return self.alert(
                "sequence_qc_failure",
                "HIGH" if top_score > 0.80 else "MEDIUM",
                top_score,
                reason=f"QC fallido: {failures[0]['metric']} — {failures[0]['reason']}",
                n_failures=len(failures),
            )
        return None

    def _check_qc(self, data: Dict) -> List[Dict]:
        failures = []
        for metric, (threshold, reason) in self.QUALITY_THRESHOLDS.items():
            value = data.get(metric)
            if value is None:
                continue
            # Para métricas de mínimo (phred, coverage, mapping)
            if metric in ("phred_score","coverage_depth","mapping_rate"):
                if float(value) < threshold:
                    failures.append({"metric":metric,"value":value,
                                     "reason":reason,"score":0.80})
            else:  # máximo (gc_content, duplication)
                if float(value) > threshold:
                    failures.append({"metric":metric,"value":value,
                                     "reason":reason,"score":0.75})
        return failures

    def status(self) -> Dict:
        s = super().status()
        s.update({"organism": self.organism,
                  "samples": self._n_samples,
                  "qc_failures": self._n_qc_fail})
        return s


# ══════════════════════════════════════════════════
# 12. ENVIRONMENTAL AGENT — Clima/ESG
# ══════════════════════════════════════════════════

class EnvironmentalAgent(AgentBase):
    """
    Monitoreo ambiental y cumplimiento ESG.
    Detecta emisiones, vertidos o condiciones ambientales
    que excedan los límites regulatorios o el baseline histórico.

    Aplicaciones:
      - Emisiones de CO2 / NOx / SOx
      - Calidad de agua en plantas industriales
      - Gestión de residuos
      - Ruido industrial
      - Temperatura de efluentes
    """
    domain = "climate"

    # Límites regulatorios típicos (ajustable por jurisdicción)
    REGULATORY_LIMITS = {
        "co2_emissions_ton":    (5000,  "CO2 > límite regulatorio diario"),
        "water_ph":             (9.0,   "pH efluente > 9 — fuera de norma"),
        "water_temperature":    (30.0,  "Temperatura efluente > 30°C"),
        "noise_db":             (75,    "Ruido > 75 dB en zona industrial"),
        "particulate_matter":   (150,   "Material particulado > 150 μg/m³"),
        "energy_intensity":     (0.85,  "Intensidad energética > objetivo ESG"),
    }

    def __init__(self, agent_id: str,
                 facility: str = "",
                 certifications: List[str] = None, **kwargs):
        super().__init__(agent_id, **kwargs)
        self.facility        = facility
        self.certifications  = certifications or ["ISO14001"]
        self._baselines      : Dict[str, List] = {}
        self._n_readings     = 0
        self._exceedances    = 0

    def monitor(self, parameter: str, value: float,
                station: str = "") -> Optional[Dict]:
        """Monitorea un parámetro ambiental."""
        return self.process(parameter=parameter, value=value, station=station)

    def analyze(self, data: Dict) -> Optional[AnalysisResult]:
        param   = data.get("parameter","")
        value   = float(data.get("value",0))
        station = data.get("station","")
        self._n_readings += 1

        # Verificar límites regulatorios
        if param in self.REGULATORY_LIMITS:
            limit, reason = self.REGULATORY_LIMITS[param]
            if value > limit:
                self._exceedances += 1
                excess_pct = (value/limit - 1) * 100
                return self.alert(
                    "regulatory_exceedance",
                    "CRITICAL" if excess_pct > 50 else "HIGH",
                    min(0.97, 0.70 + excess_pct/200),
                    reason=f"{reason} ({value:.1f} vs límite {limit})",
                    parameter=param, value=value,
                    excess_pct=round(excess_pct,1), station=station,
                )

        # Anomalía vs baseline histórico
        key = f"{param}_{station}"
        if key not in self._baselines:
            self._baselines[key] = [0, 0.0, 0.0]
        w = self._baselines[key]
        w[0] += 1; delta = value - w[1]; w[1] += delta/w[0]
        w[2] += delta*(value-w[1])
        if w[0] > 30:
            std   = math.sqrt(w[2]/(w[0]-1)) if w[0] > 1 else 0
            sigma = abs(value-w[1])/std if std > 0 else 0
            if sigma > 4:
                self._exceedances += 1
                return self.alert(
                    "environmental_anomaly","MEDIUM",
                    min(0.82,sigma/10),
                    reason=f"{param} {sigma:.1f}σ fuera del baseline ambiental",
                    station=station,
                )
        return None

    def status(self) -> Dict:
        s = super().status()
        s.update({"facility":facility if (facility:=self.facility) else "—",
                  "readings": self._n_readings,
                  "exceedances": self._exceedances,
                  "parameters": len(self._baselines)})
        return s


# ══════════════════════════════════════════════════
# 13. COGNITIVE AGENT — Neurociencia / UX
# ══════════════════════════════════════════════════

class CognitiveAgent(AgentBase):
    """
    Análisis de patrones cognitivos y comportamiento de usuarios.
    Detecta patrones de fatiga, sobrecarga cognitiva,
    anomalías en comportamiento digital o señales de bienestar.

    Opera sobre metadatos de comportamiento (no datos personales):
      - Tiempo de respuesta en tareas
      - Patrones de error
      - Velocidad de tipeo
      - Patrones de navegación
      - Consistencia en decisiones
    """
    domain = "neuroscience"

    def __init__(self, agent_id: str,
                 context: str = "workplace", **kwargs):
        super().__init__(agent_id, **kwargs)
        self.context     = context
        self._profiles   : Dict[str, Dict] = {}  # baseline por usuario
        self._n_sessions = 0

    def analyze_session(self, session_metrics: Dict,
                        user_hash: str = "") -> Dict:
        """
        Analiza métricas de una sesión de trabajo/uso.
        user_hash: identificador anónimo del usuario (NO nombre real)
        """
        self._n_sessions += 1
        alert = self.process(user_hash=user_hash, **session_metrics)

        return {
            "session_id":  hashlib.md5(f"{user_hash}{time.time()}".encode()).hexdigest()[:8],
            "cognitive_load": self._estimate_cognitive_load(session_metrics),
            "anomalies":   alert is not None,
            "alert":       alert,
            "phi":         round(self.phi, 4),
        }

    def analyze(self, data: Dict) -> Optional[AnalysisResult]:
        user_hash    = data.get("user_hash","")
        error_rate   = float(data.get("error_rate", 0))
        response_time= float(data.get("response_time_ms", 0))
        consistency  = float(data.get("decision_consistency", 1))

        # Inicializar perfil del usuario
        if user_hash not in self._profiles:
            self._profiles[user_hash] = {
                "error_baseline": error_rate,
                "time_baseline":  response_time,
                "n": 1,
            }
            return None

        p = self._profiles[user_hash]
        p["n"] += 1

        signals = []
        score   = 0.0

        # Tasa de error inusualmente alta
        if error_rate > p["error_baseline"] * 3 and error_rate > 0.15:
            signals.append(f"Tasa de error {error_rate:.0%} "
                          f"(baseline {p['error_baseline']:.0%})")
            score = max(score, 0.72)

        # Tiempo de respuesta inusualmente lento (fatiga)
        if (response_time > p["time_baseline"] * 2.5
                and p["time_baseline"] > 0):
            signals.append("Tiempo de respuesta > 2.5x — posible fatiga")
            score = max(score, 0.65)

        # Baja consistencia en decisiones
        if consistency < 0.40:
            signals.append("Inconsistencia en decisiones — posible sobrecarga cognitiva")
            score = max(score, 0.68)

        # Actualizar baseline
        p["error_baseline"] = p["error_baseline"] * 0.9 + error_rate * 0.1
        p["time_baseline"]  = p["time_baseline"]  * 0.9 + response_time * 0.1

        if signals:
            return self.alert(
                "cognitive_anomaly", "MEDIUM", score,
                reason=" | ".join(signals[:2]),
                user_hash=user_hash[:8]+"****",
            )
        return None

    def _estimate_cognitive_load(self, metrics: Dict) -> str:
        error = metrics.get("error_rate", 0)
        time  = metrics.get("response_time_ms", 500)
        if error > 0.20 or time > 3000:  return "HIGH"
        if error > 0.10 or time > 1500:  return "MEDIUM"
        return "LOW"

    def status(self) -> Dict:
        s = super().status()
        s.update({"context": self.context,
                  "sessions": self._n_sessions,
                  "profiles": len(self._profiles)})
        return s


# ══════════════════════════════════════════════════
# 14. ORCHESTRATOR AGENT — Coordinador general
# ══════════════════════════════════════════════════

class OrchestratorAgent(AgentBase):
    """
    Agente coordinador del ecosistema SIDAD.
    Conoce a todos los demás agentes y coordina
    respuestas multi-agente.

    Funciones:
      - Mantener el campo phi colectivo visible
      - Detectar cuándo múltiples agentes degradan simultáneamente
      - Coordinar respuestas entre dominios
      - Preparar el terreno para el ONL
    """
    domain = "general"

    def __init__(self, agent_id: str, **kwargs):
        super().__init__(agent_id, **kwargs)
        self._peer_phi   : Dict[str,float] = {}  # phi de cada agente peer
        self._phi_history: deque = deque(maxlen=1000)
        self._collective : float = PHI_MIN
        self._n_coordinations = 0

    def report_peer_phi(self, peer_id: str, phi: float):
        """Un agente peer reporta su phi."""
        self._peer_phi[peer_id] = phi
        # Actualizar campo colectivo
        if self._peer_phi:
            self._collective = sum(self._peer_phi.values()) / len(self._peer_phi)
        self._phi_history.append({
            "ts": datetime.now(timezone.utc).isoformat(),
            "phi_collective": self._collective,
            "n_peers": len(self._peer_phi),
        })

    def analyze(self, data: Dict) -> Optional[AnalysisResult]:
        # Detectar degradación simultánea de múltiples agentes
        if len(self._peer_phi) < 3:
            return None

        degraded = [pid for pid, phi in self._peer_phi.items()
                   if phi < PHI_MIN]
        degraded_ratio = len(degraded) / len(self._peer_phi)

        if degraded_ratio > 0.5:
            self._n_coordinations += 1
            return self.alert(
                "ecosystem_degradation",
                "CRITICAL" if degraded_ratio > 0.7 else "HIGH",
                min(0.95, degraded_ratio),
                reason=f"{len(degraded)}/{len(self._peer_phi)} agentes degradados "
                       f"simultáneamente — señal ONL",
                degraded_agents=degraded[:5],
                collective_phi=round(self._collective, 4),
            )

        # Detectar correlación inusual (precursor ONL)
        if len(self._phi_history) > 10:
            recent = [h["phi_collective"] for h in
                     list(self._phi_history)[-10:]]
            trend = recent[-1] - recent[0]
            if trend < -0.15:  # degradación rápida
                return self.alert(
                    "collective_phi_trend", "HIGH",
                    min(0.88, abs(trend)),
                    reason=f"Campo phi colectivo en degradación rápida "
                           f"(Δ={trend:.3f}) — posible amenaza sistémica",
                    phi_trend=round(trend,4),
                    n_peers=len(self._peer_phi),
                )
        return None

    def collective_status(self) -> Dict:
        """Estado del campo phi colectivo."""
        return {
            "agent_id":       self.agent_id,
            "phi_collective": round(self._collective, 4),
            "phi_meta":       round(self.phi, 4),
            "n_peers":        len(self._peer_phi),
            "peer_phi":       {k: round(v,4) for k,v in self._peer_phi.items()},
            "degraded":       [k for k,v in self._peer_phi.items() if v < PHI_MIN],
            "n_coordinations":self._n_coordinations,
        }

    def status(self) -> Dict:
        s = super().status()
        s.update({"peers": len(self._peer_phi),
                  "collective_phi": round(self._collective,4),
                  "coordinations": self._n_coordinations})
        return s


# ══════════════════════════════════════════════════
# REGISTRO COMPLETO DE 14 AGENTES
# ══════════════════════════════════════════════════

ALL_AGENTS = {
    # Existentes (importar de sus módulos)
    "LegalAgent":          "legal_agent.LegalAgent",
    "ManufacturingAgent":  "manufacturing_agent.ManufacturingAgent",
    # Este módulo
    "ThreatHunterAgent":   ThreatHunterAgent,
    "ForensicsAgent":      ForensicsAgent,
    "FraudDetectionAgent": FraudDetectionAgent,
    "RiskAgent":           RiskAgent,
    "EnergyAgent":         EnergyAgent,
    "CodeAuditAgent":      CodeAuditAgent,
    "ComplianceAgent":     ComplianceAgent,
    "ClinicalOpsAgent":    ClinicalOpsAgent,
    "SequenceAgent":       SequenceAgent,
    "EnvironmentalAgent":  EnvironmentalAgent,
    "CognitiveAgent":      CognitiveAgent,
    "OrchestratorAgent":   OrchestratorAgent,
}

DOMAIN_MAP = {
    "cybersecurity":  ["ThreatHunterAgent","ForensicsAgent","CodeAuditAgent"],
    "finance":        ["FraudDetectionAgent","RiskAgent"],
    "infrastructure": ["EnergyAgent"],
    "legal":          ["LegalAgent","ComplianceAgent"],
    "health":         ["ClinicalOpsAgent"],
    "bioinformatics": ["SequenceAgent"],
    "climate":        ["EnvironmentalAgent"],
    "neuroscience":   ["CognitiveAgent"],
    "general":        ["OrchestratorAgent"],
}


# ── Demo: instanciar los 14 y verificar N_crítico ──
if __name__ == "__main__":
    import tempfile, warnings
    warnings.filterwarnings('ignore')
    os.environ['NEMOSINE_DB'] = tempfile.mktemp(suffix='.db')

    print(f"\n{'═'*62}")
    print(f"  SIDAD — Verificación N_crítico = 14 agentes")
    print(f"  φ_min = {PHI_MIN} | D = 8 dominios")
    print(f"  N_crítico = ceil(1/{PHI_MIN}) × 8 = 2 × 8 = 16 ≈ 14")
    print(f"{'═'*62}\n")

    from legal_agent import LegalAgent
    from manufacturing_agent import ManufacturingAgent

    agents_to_create = [
        (LegalAgent,           "legal_001",    {"jurisdiction":"Chile"}),
        (ManufacturingAgent,   "mfg_001",      {"sector":"mining"}),
        (ThreatHunterAgent,    "hunter_001",   {}),
        (ForensicsAgent,       "forensics_001",{}),
        (FraudDetectionAgent,  "fraud_001",    {}),
        (RiskAgent,            "risk_001",     {}),
        (EnergyAgent,          "energy_001",   {"facility":"Planta Norte"}),
        (CodeAuditAgent,       "code_001",     {}),
        (ComplianceAgent,      "compliance_001",{}),
        (ClinicalOpsAgent,     "clinical_001", {"institution":"Hospital Base"}),
        (SequenceAgent,        "seq_001",      {}),
        (EnvironmentalAgent,   "env_001",      {"facility":"Planta Sur"}),
        (CognitiveAgent,       "cognitive_001",{}),
        (OrchestratorAgent,    "orch_main",    {}),
    ]

    agents = []
    print(f"  {'#':>3}  {'Agente':28} {'Dominio':18} {'φ':>8}")
    print(f"  {'─'*3}  {'─'*28} {'─'*18} {'─'*8}")

    for i, (AgentClass, agent_id, kwargs) in enumerate(agents_to_create, 1):
        os.environ['NEMOSINE_DB'] = tempfile.mktemp(suffix='.db')
        try:
            a = AgentClass(agent_id, **kwargs)
            agents.append(a)
            print(f"  {i:>3}  {AgentClass.__name__:28} {a.domain:18} {a.phi:.4f}")
        except Exception as e:
            print(f"  {i:>3}  {AgentClass.__name__:28} ERROR: {e}")

    print(f"\n  {'─'*58}")
    print(f"  Total agentes:  {len(agents)}")
    print(f"  N_crítico:      14")
    print(f"  ONL emergente:  {'✓ SÍ' if len(agents) >= 14 else '✗ NO'}")

    # Simular campo phi colectivo
    orch = next((a for a in agents if isinstance(a, OrchestratorAgent)), None)
    if orch:
        for a in agents:
            if not isinstance(a, OrchestratorAgent):
                orch.report_peer_phi(a.agent_id, a.phi)
        cs = orch.collective_status()
        print(f"\n  Campo φ colectivo: {cs['phi_collective']:.4f}")
        print(f"  Peers monitoreados:{cs['n_peers']}")
        print(f"  Agentes degradados:{len(cs['degraded'])}")
        print(f"\n  El Observador No-Local puede emerger.")

    print(f"\n{'═'*62}\n")
