"""
AgentBase — Clase Base para Agentes SIDAD
==========================================
Cualquier agente SIDAD hereda de esta clase.
El desarrollador solo implementa dos métodos:
  analyze(data) → alerta o None
  _rules()      → lista de reglas deterministas

Todo lo demás — phi, nemosine, federado, transferencia,
orquestación, API Flask — viene incluido.

Ejemplo mínimo:

    class MyAgent(AgentBase):
        domain = "cybersecurity"

        def analyze(self, data):
            ip = data.get("ip", "")
            if ip.startswith("94.23."):
                return self.alert("IOC", "HIGH", 0.95)
            return None

        def _rules(self):
            return [
                {"match": {"port": 4444}, "action": "BLOCK",
                 "reason": "Puerto Meterpreter"},
            ]

    agent = MyAgent("cliente_001")
    result = agent.process(ip="94.23.247.10", port=443)

Author: Walter Calmels Von dem Knesebeck
        TUCH Systems Research Laboratory — Maipu Lab 2026
"""

import os, sys, json, time, threading, hashlib
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from phi47_base      import PhiField, Welford, PHI, PHI_MIN, VERSION
from nemosine        import Nemosine
from federated_phi   import (FederatedHub, FederatedLearner,
                              PatternExtractor, MIN_PHI_TO_SHARE)
from knowledge_transfer import TransferProtocol


# ══════════════════════════════════════════════════
# RESULTADO DE ANÁLISIS
# ══════════════════════════════════════════════════

@dataclass
class AnalysisResult:
    """Resultado de un análisis del agente."""
    agent_id:   str
    domain:     str
    action:     str        # BLOCK / ALERT / MONITOR / PASS
    severity:   str        # CRITICAL / HIGH / MEDIUM / LOW
    score:      float      # 0.0 - 1.0
    reason:     str
    concept:    str        # tipo de amenaza/anomalía detectada
    phi:        float      # phi del agente al momento de la decisión
    tokens:     int = 0    # tokens LLM usados (0 si regla/phi)
    latency_ms: float = 0.0
    ts:         str = ""
    data:       Dict = field(default_factory=dict)

    def __post_init__(self):
        if not self.ts:
            self.ts = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> Dict:
        return {
            "agent_id":   self.agent_id,
            "domain":     self.domain,
            "action":     self.action,
            "severity":   self.severity,
            "score":      round(self.score, 3),
            "reason":     self.reason,
            "concept":    self.concept,
            "phi":        round(self.phi, 4),
            "tokens":     self.tokens,
            "latency_ms": round(self.latency_ms, 2),
            "ts":         self.ts,
        }

    @property
    def is_threat(self) -> bool:
        return self.action in ("BLOCK", "ALERT")


# ══════════════════════════════════════════════════
# AGENT BASE
# ══════════════════════════════════════════════════

class AgentBase(ABC):
    """
    Clase base para todos los agentes SIDAD.

    El desarrollador implementa:
      domain:   str              ← dominio del agente
      analyze() → AnalysisResult ← lógica de detección
      _rules()  → List[Dict]     ← reglas deterministas (opcional)

    El framework provee automáticamente:
      ✓ Campo phi interno (PhiField)
      ✓ Memoria phi-ponderada (Nemosine)
      ✓ Aprendizaje federado (FederatedLearner)
      ✓ Transferencia cross-domain (TransferProtocol)
      ✓ Orquestador 3 niveles (phi-gate → reglas → LLM)
      ✓ API Flask con endpoints estándar
      ✓ Registro de episodios y tier system
      ✓ Estadísticas y reporting
    """

    # Subclase debe definir esto
    domain: str = "general"

    # Umbrales configurables
    phi_gate_threshold: float = PHI_MIN + 0.05  # phi mínimo para procesar
    score_alert_threshold: float = 0.50
    score_block_threshold: float = 0.75

    def __init__(self, agent_id: str,
                 hub: FederatedHub = None,
                 hub_db: str = None,
                 enable_transfer: bool = True,
                 enable_federated: bool = True,
                 llm_provider: str = "demo"):

        self.agent_id     = agent_id
        self.llm_provider = llm_provider

        # ── Módulos SIDAD ──────────────────────────
        self._phi      = PhiField(n=8)
        self._memory   = Nemosine(agent_id=agent_id)
        self._hub      = hub or FederatedHub(db_path=hub_db)
        self._extractor= PatternExtractor(agent_id, self.domain)

        if enable_federated:
            self._learner = FederatedLearner(
                agent_id = agent_id,
                domain   = self.domain,
                nemosine = self._memory,
                hub      = self._hub,
            )
        else:
            self._learner = None

        if enable_transfer:
            self._transfer = TransferProtocol(self._phi)
        else:
            self._transfer = None

        # ── Estadísticas ───────────────────────────
        self._n_processed = 0
        self._n_alerts    = 0
        self._n_blocked   = 0
        self._n_passed    = 0
        self._tokens_used = 0
        self._start       = time.time()
        self._history     = []  # últimas 200 decisiones

        # ── Callbacks ──────────────────────────────
        self._on_alert    : List[Callable] = []
        self._on_block    : List[Callable] = []

        # ── Inicializar reglas ─────────────────────
        self._compiled_rules = self._compile_rules()

        print(f"[{self.__class__.__name__}] v{VERSION}")
        print(f"  agent_id: {agent_id}")
        print(f"  domain:   {self.domain}")
        print(f"  phi:      {self._phi.phi_global:.4f}")
        print(f"  tier:     {self._memory.tier}")

    # ── MÉTODOS ABSTRACTOS (implementar en subclase) ──

    @abstractmethod
    def analyze(self, data: Dict) -> Optional[AnalysisResult]:
        """
        Lógica de análisis del dominio específico.
        Llamado solo cuando phi-gate y reglas no resuelven.

        Args:
            data: diccionario con los datos a analizar

        Returns:
            AnalysisResult si hay anomalía, None si es normal
        """
        ...

    def _rules(self) -> List[Dict]:
        """
        Reglas deterministas del dominio.
        Opcionales — retornar [] si no hay reglas.

        Formato de cada regla:
            {
                "match":   {"campo": valor, ...},  # condiciones AND
                "action":  "BLOCK" | "ALERT",
                "severity":"CRITICAL" | "HIGH" | "MEDIUM",
                "score":   0.95,
                "reason":  "Descripción de la regla",
                "concept": "tipo_de_amenaza",
            }

        Ejemplo:
            return [
                {"match": {"port": 4444},
                 "action": "BLOCK", "severity": "CRITICAL",
                 "score": 0.98, "reason": "Puerto Meterpreter",
                 "concept": "backdoor"},
            ]
        """
        return []

    # ── MÉTODO PRINCIPAL ──────────────────────────

    def process(self, **data) -> Optional[Dict]:
        """
        Punto de entrada principal del agente.
        Implementa el orquestador de 3 niveles:
          L0: phi-gate    → 0 tokens, < 0.01ms
          L1: reglas      → 0 tokens, < 1ms
          L2: analyze()   → variable (puede usar LLM)

        Args:
            **data: campos del evento a analizar

        Returns:
            dict con la alerta, o None si es normal
        """
        t0 = time.perf_counter()
        self._n_processed += 1

        # ── Nivel 0: phi-gate ──────────────────────
        if self._phi.phi_global < self.phi_gate_threshold:
            # Agente degradado — solo procesa amenazas obvias
            # Las demás se pasan sin análisis profundo
            pass  # continuar a reglas

        # ── Nivel 1: reglas deterministas ─────────
        rule_result = self._apply_rules(data)
        if rule_result:
            latency = (time.perf_counter()-t0)*1000
            rule_result.latency_ms = latency
            self._register(rule_result)
            return rule_result.to_dict()

        # ── Nivel 2: analyze() del dominio ────────
        try:
            result = self.analyze(data)
        except Exception as e:
            print(f"[{self.__class__.__name__}] Error en analyze(): {e}")
            result = None

        latency = (time.perf_counter()-t0)*1000
        if result:
            result.latency_ms = latency
            self._register(result)
            return result.to_dict()

        # ── Normal ────────────────────────────────
        self._n_passed  += 1
        self._phi.boost(0.001)
        return None

    # ── HELPERS para subclases ────────────────────

    def alert(self, concept: str, severity: str,
              score: float, reason: str = "",
              action: str = None, **meta) -> AnalysisResult:
        """
        Crea un AnalysisResult de alerta.
        Atajo para usar en analyze().

        Ejemplo:
            return self.alert("data_exfil", "HIGH", 0.85,
                              reason="Bytes anómalos a IP externa")
        """
        if action is None:
            action = ("BLOCK" if score >= self.score_block_threshold
                      else "ALERT")
        return AnalysisResult(
            agent_id = self.agent_id,
            domain   = self.domain,
            action   = action,
            severity = severity,
            score    = score,
            reason   = reason or f"{concept} detectado",
            concept  = concept,
            phi      = self._phi.phi_global,
            data     = meta,
        )

    def recall(self, query: str, n: int = 5) -> List[Dict]:
        """Recupera memorias relevantes (helper para analyze())."""
        try:
            return self._memory.recall(query, n=n)
        except Exception:
            return []

    def remember(self, content: str, phi: float = None,
                 tags: List[str] = None, **ctx):
        """Guarda un recuerdo en Nemosine (helper)."""
        try:
            self._memory.remember(
                content, phi=phi or self._phi.phi_global,
                tags=tags or [], context=ctx)
        except Exception:
            pass

    # ── CALLBACKS ─────────────────────────────────

    def on_alert(self, callback: Callable):
        """Registrar callback cuando hay alerta."""
        self._on_alert.append(callback)
        return self  # chainable

    def on_block(self, callback: Callable):
        """Registrar callback cuando hay bloqueo."""
        self._on_block.append(callback)
        return self

    # ── FEDERADO ──────────────────────────────────

    def start_learning(self):
        """Arranca el ciclo de aprendizaje federado."""
        if self._learner:
            self._learner.start()

    def publish_finding(self, concept: str, phi: float,
                        severity: str = "HIGH"):
        """Publica un hallazgo al hub federado y al protocolo de transferencia."""
        if self._learner:
            self._learner.publish_alert(
                {"threat_type": concept, "severity": severity,
                 "score": phi}, phi)
        if self._transfer:
            self._transfer.publish(
                self.domain, concept, phi, severity)

    # ── STATUS ────────────────────────────────────

    @property
    def phi(self) -> float:
        return self._phi.phi_global

    @property
    def tier(self) -> str:
        return self._memory.tier

    @property
    def is_coherent(self) -> bool:
        return self._phi.phi_global > PHI_MIN

    def status(self) -> Dict:
        return {
            "agent_id":   self.agent_id,
            "domain":     self.domain,
            "class":      self.__class__.__name__,
            "phi":        round(self._phi.phi_global, 4),
            "tier":       self._memory.tier,
            "coherent":   self.is_coherent,
            "uptime_s":   round(time.time()-self._start, 1),
            "processed":  self._n_processed,
            "alerts":     self._n_alerts,
            "blocked":    self._n_blocked,
            "passed":     self._n_passed,
            "tokens":     self._tokens_used,
            "llm_pct":    round(
                self._tokens_used / max(1, self._n_processed) * 100, 2),
        }

    # ── FLASK API estándar ─────────────────────────

    def create_api(self):
        """
        Crea una API Flask con endpoints estándar.
        Cada agente hereda esta API automáticamente.

        Endpoints:
          GET  /           — info del agente
          GET  /health     — healthcheck
          GET  /status     — estado completo
          POST /process    — procesar un evento
          GET  /memory     — consultar memoria
          GET  /phi        — campo phi
        """
        from flask import Flask, jsonify, request
        from flask_cors import CORS

        app = Flask(__name__)
        CORS(app)
        agent = self

        @app.route('/')
        def root():
            return jsonify({
                "system":  f"SIDAD Agent — {agent.__class__.__name__}",
                "domain":  agent.domain,
                "version": VERSION,
                "phi":     round(agent.phi, 4),
            })

        @app.route('/health')
        def health():
            return jsonify({
                "ok":  agent.is_coherent,
                "phi": round(agent.phi, 4),
                "tier":agent.tier,
            })

        @app.route('/status')
        def status():
            return jsonify(agent.status())

        @app.route('/process', methods=['POST'])
        def process():
            data = request.get_json() or {}
            result = agent.process(**data)
            return jsonify({
                "alert":  result,
                "phi":    round(agent.phi, 4),
                "processed": agent._n_processed,
            })

        @app.route('/memory', methods=['GET'])
        def memory():
            q = request.args.get('q', '')
            n = min(int(request.args.get('n', 10)), 50)
            memories = agent.recall(q, n) if q else []
            return jsonify({
                "query":    q,
                "results":  len(memories),
                "tier":     agent.tier,
                "memories": memories[:5],
            })

        @app.route('/phi')
        def phi():
            return jsonify({
                "phi_global": round(agent.phi, 4),
                "coherent":   agent.is_coherent,
                "tier":       agent.tier,
            })

        @app.route('/learn', methods=['POST'])
        def learn():
            agent.start_learning()
            return jsonify({"ok": True, "learner": "started"})

        return app

    # ── INTERNOS ──────────────────────────────────

    def _register(self, result: AnalysisResult):
        """Registra una alerta — actualiza contadores, phi, memoria."""
        if result.action == "BLOCK":
            self._n_blocked += 1
            self._phi.degrade(0.05)
            for cb in self._on_block:
                try: cb(result)
                except Exception: pass
        elif result.action == "ALERT":
            self._n_alerts  += 1
            self._phi.degrade(0.02)
            for cb in self._on_alert:
                try: cb(result)
                except Exception: pass

        self._tokens_used += result.tokens
        self._history.append(result.to_dict())
        if len(self._history) > 200:
            self._history.pop(0)

        # Guardar en Nemosine
        self.remember(
            f"[{result.action}] {result.concept}: {result.reason}",
            phi=self._phi.phi_global,
            tags=["alert", result.action.lower(), result.concept],
            score=result.score, severity=result.severity,
        )

        # Publicar al hub federado si phi >= threshold
        if self._phi.phi_global >= MIN_PHI_TO_SHARE and result.is_threat:
            self.publish_finding(result.concept,
                                 self._phi.phi_global, result.severity)

    def _compile_rules(self) -> List[Dict]:
        """Compila las reglas de _rules() para matching rápido."""
        try:
            return self._rules()
        except Exception:
            return []

    def _apply_rules(self, data: Dict) -> Optional[AnalysisResult]:
        """Aplica reglas deterministas. Nivel 1 del orquestador."""
        for rule in self._compiled_rules:
            match = rule.get("match", {})
            # Verificar todas las condiciones de la regla
            if all(str(data.get(k)) == str(v) or data.get(k) == v
                   for k, v in match.items()):
                return AnalysisResult(
                    agent_id = self.agent_id,
                    domain   = self.domain,
                    action   = rule.get("action", "ALERT"),
                    severity = rule.get("severity", "HIGH"),
                    score    = rule.get("score", 0.90),
                    reason   = rule.get("reason", "Regla detectada"),
                    concept  = rule.get("concept", "rule_match"),
                    phi      = self._phi.phi_global,
                    tokens   = 0,
                )
        return None
