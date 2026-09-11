"""
Protocolo de Transferencia de Conocimiento entre Dominios (PTKD)
================================================================
Permite que lo que aprende un agente en un dominio
informe a agentes de otros dominios.

El problema que resuelve:
  Un C2 beacon en red + transacciones anómalas simultáneas
  = ataque coordinado de alta sofisticación
  
  Sin PTKD: Cyber ve el beacon, Finance ve las transacciones.
            Ninguno sabe que son parte del mismo ataque.
  
  Con PTKD: El protocolo detecta correlación temporal
            entre señales de distintos dominios.
            El Meta-Orquestador sintetiza el patrón completo.
            Ambos agentes se alertan mutuamente.

Componentes:
  DomainBridge      → mapea conceptos entre dominios
  TemporalCorrelator → detecta eventos correlacionados en el tiempo
  KnowledgeTranslator → traduce conocimiento de un dominio a otro
  CrossDomainSynth   → sintetiza patrones multi-dominio
  TransferProtocol   → orquesta el flujo completo

Principio de privacidad (igual que AFC):
  Solo viajan patrones abstractos entre dominios
  Los datos del cliente nunca se comparten
  La correlación se hace sobre metadata temporal, no datos

Author: Walter Calmels Von dem Knesebeck
        TUCH Systems Research Laboratory — Maipu Lab 2026
"""

import os, sys, json, time, math, hashlib, threading
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Tuple, Set, Any
from dataclasses import dataclass, field
from collections import deque, defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from phi47_base import PhiField, PHI, PHI_MIN, VERSION

# ── Ventana temporal para correlación ────────────
CORRELATION_WINDOW_S = 300   # 5 minutos
MIN_PHI_TO_TRANSFER  = 0.72
TRANSFER_WEIGHT      = 0.55  # peso al transferir cross-domain


# ══════════════════════════════════════════════════
# MAPA DE DOMINIOS
# Qué conceptos son equivalentes entre dominios
# ══════════════════════════════════════════════════

DOMAIN_BRIDGE = {
    # cybersecurity → finance
    ("cybersecurity", "finance"): {
        "c2_beacon":     "automated_micro_transactions",
        "data_exfil":    "large_transfer_anomaly",
        "port_scan":     "account_enumeration",
        "IOC":           "known_fraud_indicator",
        "anomaly":       "behavioral_anomaly",
        "phi_degraded":  "risk_elevated",
    },
    # finance → cybersecurity
    ("finance", "cybersecurity"): {
        "fraud_pattern":         "behavioral_anomaly",
        "account_takeover":      "credential_compromise",
        "large_transfer_anomaly":"data_exfil",
        "micro_transaction":     "c2_beacon",
        "behavioral_anomaly":    "anomaly",
    },
    # cybersecurity → infrastructure
    ("cybersecurity", "infrastructure"): {
        "c2_beacon":    "periodic_signal_anomaly",
        "data_exfil":   "bandwidth_anomaly",
        "port_scan":    "service_enumeration",
        "IOC":          "known_bad_endpoint",
        "phi_degraded": "system_health_critical",
    },
    # infrastructure → cybersecurity
    ("infrastructure", "cybersecurity"): {
        "system_failure":       "potential_attack_impact",
        "bandwidth_anomaly":    "data_exfil",
        "service_down":         "dos_attack",
        "periodic_anomaly":     "c2_beacon",
    },
    # cybersecurity → legal/compliance
    ("cybersecurity", "legal"): {
        "data_exfil":   "data_breach_indicator",
        "IOC":          "compliance_risk",
        "anomaly":      "audit_trigger",
        "phi_degraded": "regulatory_risk_elevated",
    },
    # bioinformatics → neuroscience (dominios afines)
    ("bioinformatics", "neuroscience"): {
        "sequence_anomaly": "pattern_deviation",
        "mutation":         "signal_variance",
        "threshold_breach": "activation_anomaly",
    },
}

# Dominios que tienen alta compatibilidad natural
DOMAIN_AFFINITY = {
    "cybersecurity":   {"infrastructure": 0.85, "finance": 0.70, "legal": 0.65},
    "finance":         {"cybersecurity": 0.70, "legal": 0.80},
    "infrastructure":  {"cybersecurity": 0.85, "materials": 0.60, "climate": 0.55},
    "bioinformatics":  {"neuroscience": 0.80, "materials": 0.50},
    "neuroscience":    {"bioinformatics": 0.80},
    "materials":       {"infrastructure": 0.60, "bioinformatics": 0.50},
    "climate":         {"infrastructure": 0.55},
    "legal":           {"finance": 0.80, "cybersecurity": 0.65},
}


# ══════════════════════════════════════════════════
# SEÑAL DE CONOCIMIENTO
# Unidad que viaja entre dominios
# ══════════════════════════════════════════════════

@dataclass
class KnowledgeSignal:
    """
    Señal de conocimiento abstracto entre dominios.
    
    Contiene el patrón detectado, cuándo ocurrió (relativo,
    no timestamp real), y la severidad phi.
    """
    signal_id:       str
    source_domain:   str
    source_concept:  str     # concepto en el dominio origen
    phi_value:       float   # phi cuando se detectó
    severity:        str     # CRITICAL/HIGH/MEDIUM/LOW
    # Tiempo relativo — NO el timestamp real del cliente
    # Solo indica "cuántos segundos hace que ocurrió"
    relative_age_s:  float
    # Metadata abstracta (sin datos del cliente)
    abstract_meta:   Dict = field(default_factory=dict)
    ts_published:    str  = ""

    def __post_init__(self):
        if not self.ts_published:
            self.ts_published = datetime.now(timezone.utc).isoformat()
        if not self.signal_id:
            self.signal_id = hashlib.md5(
                f"{self.source_domain}{self.source_concept}{self.phi_value}".encode()
            ).hexdigest()[:12]

    def age_s(self) -> float:
        """Segundos desde que se publicó la señal."""
        pub = datetime.fromisoformat(self.ts_published)
        now = datetime.now(timezone.utc)
        return (now - pub.replace(tzinfo=timezone.utc)).total_seconds()


# ══════════════════════════════════════════════════
# DOMAIN BRIDGE
# Traduce conceptos entre dominios
# ══════════════════════════════════════════════════

class DomainBridge:
    """
    Mapea conceptos de un dominio a otro.
    Permite que agentes de distintos dominios
    entiendan señales de otros.
    """

    def translate(self, concept: str,
                  from_domain: str,
                  to_domain: str) -> Optional[str]:
        """
        Traduce un concepto de un dominio a otro.
        Returns None si no hay traducción conocida.
        """
        if from_domain == to_domain:
            return concept

        bridge = DOMAIN_BRIDGE.get((from_domain, to_domain))
        if bridge:
            return bridge.get(concept)

        # Traducción inversa
        bridge_inv = DOMAIN_BRIDGE.get((to_domain, from_domain))
        if bridge_inv:
            for k, v in bridge_inv.items():
                if v == concept:
                    return k

        return None

    def affinity(self, domain_a: str, domain_b: str) -> float:
        """
        Nivel de afinidad entre dos dominios (0-1).
        Mayor afinidad = transferencia más valiosa.
        """
        return DOMAIN_AFFINITY.get(domain_a, {}).get(domain_b, 0.2)

    def compatible_domains(self, domain: str,
                           min_affinity: float = 0.5) -> List[str]:
        """Lista de dominios compatibles con afinidad mínima."""
        return [
            d for d, aff in DOMAIN_AFFINITY.get(domain, {}).items()
            if aff >= min_affinity
        ]


# ══════════════════════════════════════════════════
# TEMPORAL CORRELATOR
# Detecta eventos correlacionados en el tiempo
# ══════════════════════════════════════════════════

class TemporalCorrelator:
    """
    Detecta cuando múltiples agentes de distintos dominios
    reportan anomalías en la misma ventana temporal.
    
    Si Cyber detecta C2 beacon y Finance detecta micro-transacciones
    en los mismos 5 minutos → probable ataque coordinado.
    """

    def __init__(self, window_s: float = CORRELATION_WINDOW_S):
        self.window_s = window_s
        self._signals : deque = deque(maxlen=1000)
        self._lock    = threading.Lock()

    def add_signal(self, signal: KnowledgeSignal):
        """Registra una señal entrante."""
        with self._lock:
            self._signals.appendleft(signal)

    def find_correlations(self) -> List[Dict]:
        """
        Encuentra señales correlacionadas en la ventana temporal.
        Returns lista de correlaciones detectadas.
        """
        with self._lock:
            signals = list(self._signals)

        now = time.time()
        # Filtrar señales dentro de la ventana temporal
        recent = [
            s for s in signals
            if s.age_s() <= self.window_s
        ]

        if len(recent) < 2:
            return []

        correlations = []
        # Buscar pares de señales de dominios distintos
        for i, sig_a in enumerate(recent):
            for sig_b in recent[i+1:]:
                if sig_a.source_domain == sig_b.source_domain:
                    continue

                # Verificar ventana temporal (relativa)
                age_diff = abs(sig_a.age_s() - sig_b.age_s())
                if age_diff > self.window_s:
                    continue

                # Calcular fuerza de correlación
                bridge = DomainBridge()
                affinity = bridge.affinity(
                    sig_a.source_domain, sig_b.source_domain)

                if affinity < 0.3:
                    continue

                # Fuerza = phi promedio * afinidad * (1 - age_diff/window)
                phi_avg    = (sig_a.phi_value + sig_b.phi_value) / 2
                time_score = 1 - (age_diff / self.window_s)
                strength   = round(phi_avg * affinity * time_score, 3)

                if strength >= 0.35:
                    correlations.append({
                        "correlation_id": hashlib.md5(
                            f"{sig_a.signal_id}{sig_b.signal_id}".encode()
                        ).hexdigest()[:10],
                        "signal_a":    sig_a.signal_id,
                        "signal_b":    sig_b.signal_id,
                        "domain_a":    sig_a.source_domain,
                        "domain_b":    sig_b.source_domain,
                        "concept_a":   sig_a.source_concept,
                        "concept_b":   sig_b.source_concept,
                        "strength":    strength,
                        "phi_avg":     round(phi_avg, 4),
                        "age_diff_s":  round(age_diff, 1),
                        "interpretation": self._interpret(sig_a, sig_b, strength),
                    })

        # Ordenar por fuerza descendente
        return sorted(correlations, key=lambda x: x["strength"], reverse=True)

    def _interpret(self, sig_a: KnowledgeSignal,
                   sig_b: KnowledgeSignal,
                   strength: float) -> str:
        """Genera interpretación legible de la correlación."""
        severity = (
            "CRÍTICA" if strength > 0.75 else
            "ALTA"    if strength > 0.55 else
            "MEDIA"
        )
        return (
            f"Correlación {severity} entre "
            f"{sig_a.source_concept} ({sig_a.source_domain}) "
            f"y {sig_b.source_concept} ({sig_b.source_domain}) — "
            f"posible evento coordinado (fuerza={strength:.2f})"
        )


# ══════════════════════════════════════════════════
# KNOWLEDGE TRANSLATOR
# Traduce conocimiento para que otro dominio lo entienda
# ══════════════════════════════════════════════════

class KnowledgeTranslator:
    """
    Traduce conocimiento de un dominio para que
    un agente de otro dominio pueda usarlo.
    
    No solo traduce el concepto — genera una
    explicación en el lenguaje del dominio receptor.
    """

    def __init__(self):
        self._bridge = DomainBridge()

    def translate_signal(self, signal: KnowledgeSignal,
                         target_domain: str
                         ) -> Optional[Dict]:
        """
        Traduce una señal al lenguaje del dominio receptor.
        Returns None si la traducción no aplica.
        """
        if signal.source_domain == target_domain:
            return None

        affinity = self._bridge.affinity(
            signal.source_domain, target_domain)
        if affinity < 0.3:
            return None

        translated_concept = self._bridge.translate(
            signal.source_concept,
            signal.source_domain,
            target_domain,
        )

        if not translated_concept:
            return None

        # Peso de transferencia ajustado por afinidad
        transfer_weight = TRANSFER_WEIGHT * affinity
        phi_transferred = signal.phi_value * transfer_weight

        return {
            "signal_id":         signal.signal_id,
            "original_domain":   signal.source_domain,
            "original_concept":  signal.source_concept,
            "target_domain":     target_domain,
            "translated_concept":translated_concept,
            "phi_transferred":   round(phi_transferred, 4),
            "phi_original":      signal.phi_value,
            "affinity":          affinity,
            "transfer_weight":   round(transfer_weight, 3),
            "severity":          signal.severity,
            "recommendation":    self._recommend(
                translated_concept, target_domain, signal.severity),
            "ts":                datetime.now(timezone.utc).isoformat(),
        }

    def _recommend(self, concept: str,
                   domain: str, severity: str) -> str:
        """Genera recomendación de acción para el dominio receptor."""
        recommendations = {
            ("automated_micro_transactions", "finance"):
                "Monitorear transacciones pequeñas periódicas — posible automatización maliciosa",
            ("large_transfer_anomaly", "finance"):
                "Revisar transferencias grandes a cuentas nuevas — posible exfiltración financiera",
            ("account_enumeration", "finance"):
                "Verificar intentos de acceso a múltiples cuentas — posible credential stuffing",
            ("known_fraud_indicator", "finance"):
                "IP/entidad en lista negra de seguridad — riesgo de fraude elevado",
            ("behavioral_anomaly", "finance"):
                "Comportamiento inusual detectado por agente de seguridad — revisión manual recomendada",
            ("periodic_signal_anomaly", "infrastructure"):
                "Señal periódica detectada — verificar integridad de procesos automáticos",
            ("bandwidth_anomaly", "infrastructure"):
                "Uso inusual de ancho de banda — posible transferencia no autorizada",
            ("system_health_critical", "infrastructure"):
                "Sistema en estado crítico según agente de seguridad — verificar operaciones",
            ("data_breach_indicator", "legal"):
                "Posible brecha de datos detectada — evaluar obligaciones regulatorias",
            ("compliance_risk", "legal"):
                "Indicador de riesgo de compliance detectado — revisión de controles recomendada",
        }
        key = (concept, domain)
        return recommendations.get(
            key,
            f"Anomalía de tipo '{concept}' detectada — revisar según protocolos de {domain}"
        )


# ══════════════════════════════════════════════════
# CROSS-DOMAIN SYNTHESIZER
# Sintetiza patrones que cruzan múltiples dominios
# ══════════════════════════════════════════════════

class CrossDomainSynth:
    """
    Sintetiza patrones que ningún agente individual puede ver.
    
    Cuando múltiples dominios reportan anomalías correlacionadas,
    el sintetizador genera un patrón de orden superior que
    representa el evento completo.
    
    Ejemplo:
      Cyber:   C2 beacon detectado (phi=0.92)
      Finance: micro-transacciones anómalas (phi=0.88)
      → Synth: Ataque APT con componente financiero
               Probabilidad: alta
               Acción recomendada: LOCKDOWN multi-dominio
    """

    # Patrones compuestos conocidos
    COMPOUND_PATTERNS = {
        frozenset([("cybersecurity","c2_beacon"),
                   ("finance","automated_micro_transactions")]): {
            "name":    "APT con exfiltración financiera",
            "severity":"CRITICAL",
            "desc":    "Beacon C2 simultáneo con transacciones automatizadas "
                       "— patrón consistente con APT de motivación financiera",
            "action":  "LOCKDOWN_MULTI_DOMAIN",
        },
        frozenset([("cybersecurity","data_exfil"),
                   ("finance","large_transfer_anomaly")]): {
            "name":    "Exfiltración coordinada datos + dinero",
            "severity":"CRITICAL",
            "desc":    "Exfiltración de datos y transferencia financiera simultáneas "
                       "— ataque coordinado de alta sofisticación",
            "action":  "EMERGENCY_RESPONSE",
        },
        frozenset([("cybersecurity","IOC"),
                   ("infrastructure","bandwidth_anomaly")]): {
            "name":    "Compromiso de infraestructura",
            "severity":"HIGH",
            "desc":    "IOC conocido con anomalía de red en infraestructura "
                       "— posible pivoting en infraestructura crítica",
            "action":  "ISOLATE_AND_INVESTIGATE",
        },
        frozenset([("cybersecurity","port_scan"),
                   ("infrastructure","service_enumeration")]): {
            "name":    "Reconocimiento avanzado multi-vector",
            "severity":"HIGH",
            "desc":    "Escaneo de puertos con enumeración de servicios "
                       "— fase de reconocimiento de ataque planificado",
            "action":  "HEIGHTENED_MONITORING",
        },
        frozenset([("finance","account_takeover"),
                   ("cybersecurity","credential_compromise")]): {
            "name":    "Compromiso de credenciales multi-sistema",
            "severity":"CRITICAL",
            "desc":    "Compromiso de cuentas financieras y credenciales de red "
                       "— brecha sistémica en curso",
            "action":  "EMERGENCY_RESPONSE",
        },
    }

    def __init__(self):
        self._bridge     = DomainBridge()
        self._correlator = TemporalCorrelator()
        self._synth_log  = deque(maxlen=200)

    def add_signal(self, signal: KnowledgeSignal):
        self._correlator.add_signal(signal)

    def synthesize(self) -> List[Dict]:
        """
        Busca patrones compuestos en las correlaciones activas.
        Returns lista de patrones sintetizados.
        """
        correlations = self._correlator.find_correlations()
        if not correlations:
            return []

        results = []
        for corr in correlations:
            # Buscar patrón compuesto conocido
            pattern_key = frozenset([
                (corr["domain_a"], corr["concept_a"]),
                (corr["domain_b"], corr["concept_b"]),
            ])

            compound = self.COMPOUND_PATTERNS.get(pattern_key)

            if compound:
                synth = {
                    "synth_id":       corr["correlation_id"],
                    "pattern_name":   compound["name"],
                    "severity":       compound["severity"],
                    "description":    compound["desc"],
                    "action":         compound["action"],
                    "domains":        [corr["domain_a"], corr["domain_b"]],
                    "phi_avg":        corr["phi_avg"],
                    "strength":       corr["strength"],
                    "correlation":    corr,
                    "ts":             datetime.now(timezone.utc).isoformat(),
                    "known_pattern":  True,
                }
            else:
                # Patrón no catalogado — reportar como correlación anómala
                synth = {
                    "synth_id":       corr["correlation_id"],
                    "pattern_name":   f"Correlación {corr['domain_a']}/{corr['domain_b']}",
                    "severity":       "HIGH" if corr["strength"] > 0.6 else "MEDIUM",
                    "description":    corr["interpretation"],
                    "action":         "INVESTIGATE_MULTI_DOMAIN",
                    "domains":        [corr["domain_a"], corr["domain_b"]],
                    "phi_avg":        corr["phi_avg"],
                    "strength":       corr["strength"],
                    "correlation":    corr,
                    "ts":             datetime.now(timezone.utc).isoformat(),
                    "known_pattern":  False,
                }

            self._synth_log.appendleft(synth)
            results.append(synth)

        return results

    def recent(self, n=10) -> List[Dict]:
        return list(self._synth_log)[:n]


# ══════════════════════════════════════════════════
# TRANSFER PROTOCOL — Motor principal
# ══════════════════════════════════════════════════

class TransferProtocol:
    """
    Protocolo completo de transferencia de conocimiento
    entre dominios.

    Integra:
      DomainBridge       → mapeo de conceptos
      TemporalCorrelator → correlación temporal
      KnowledgeTranslator → traducción de señales
      CrossDomainSynth   → síntesis de patrones compuestos

    Flujo:
      1. Un agente publica una señal (detect_and_publish)
      2. El protocolo la traduce para dominios compatibles
      3. Busca correlaciones con señales recientes
      4. Sintetiza patrones compuestos si los hay
      5. Notifica a los agentes relevantes
    """

    def __init__(self, phi_field: PhiField = None):
        self._phi        = phi_field or PhiField(n=6)
        self._bridge     = DomainBridge()
        self._translator = KnowledgeTranslator()
        self._synth      = CrossDomainSynth()
        self._signals    = deque(maxlen=500)
        self._transfers  = deque(maxlen=500)
        self._lock       = threading.Lock()

        # Callbacks: cuando se detecta patrón cross-domain
        self._callbacks  : List = []

        print(f"[TransferProtocol] v{VERSION}")
        print(f"  Dominios soportados: {list(DOMAIN_AFFINITY.keys())}")
        print(f"  Patrones compuestos: {len(CrossDomainSynth.COMPOUND_PATTERNS)}")

    def publish(self, domain: str, concept: str,
                phi: float, severity: str = "HIGH",
                meta: Dict = None) -> Dict:
        """
        Un agente publica una señal de conocimiento.
        El protocolo la procesa y busca correlaciones.
        """
        if phi < MIN_PHI_TO_TRANSFER:
            return {"published": False, "reason": "phi insuficiente"}

        signal = KnowledgeSignal(
            signal_id      = hashlib.md5(f"{domain}{concept}{phi}{time.time()}".encode()).hexdigest()[:12],
            source_domain  = domain,
            source_concept = concept,
            phi_value      = phi,
            severity       = severity,
            relative_age_s = 0,
            abstract_meta  = meta or {},
        )

        with self._lock:
            self._signals.appendleft(signal)

        # Degradar phi del ecosistema si es severo
        if severity in ("CRITICAL","HIGH"):
            self._phi.degrade(0.05)

        # Añadir al sintetizador
        self._synth.add_signal(signal)

        # Traducir para dominios compatibles
        transfers = []
        compatible = self._bridge.compatible_domains(domain, min_affinity=0.5)
        for target_domain in compatible:
            translation = self._translator.translate_signal(signal, target_domain)
            if translation:
                transfers.append(translation)
                with self._lock:
                    self._transfers.appendleft(translation)

        # Buscar patrones compuestos
        compounds = self._synth.synthesize()
        if compounds:
            # Boost phi si detectamos un patrón conocido
            # (el sistema es más coherente cuando entiende lo que pasa)
            self._phi.boost(0.03)
            # Notificar callbacks
            for cb in self._callbacks:
                try: cb(compounds)
                except Exception: pass

        result = {
            "published":      True,
            "signal_id":      signal.signal_id,
            "domain":         domain,
            "concept":        concept,
            "phi":            round(phi, 4),
            "transfers":      len(transfers),
            "compounds":      len(compounds),
            "translations":   transfers[:3],
            "compound_alerts": compounds[:2],
            "ecosystem_phi":  round(self._phi.phi_global, 4),
        }

        self._print_publish(domain, concept, phi, transfers, compounds)
        return result

    def on_compound_pattern(self, callback):
        """Registrar callback para cuando se detecta un patrón compuesto."""
        self._callbacks.append(callback)

    def query_translations(self, domain: str,
                           concept: str) -> List[Dict]:
        """¿Cómo se ve este concepto en otros dominios?"""
        results = []
        for target in DOMAIN_AFFINITY.get(domain, {}).keys():
            translated = self._bridge.translate(concept, domain, target)
            if translated:
                affinity = self._bridge.affinity(domain, target)
                results.append({
                    "target_domain":     target,
                    "translated_concept":translated,
                    "affinity":          affinity,
                    "recommendation":    self._translator._recommend(
                        translated, target, "HIGH"),
                })
        return results

    def active_correlations(self) -> List[Dict]:
        """Correlaciones activas en la ventana temporal."""
        return self._synth._correlator.find_correlations()

    def recent_compounds(self, n=5) -> List[Dict]:
        """Patrones compuestos detectados recientemente."""
        return self._synth.recent(n)

    def _print_publish(self, domain, concept, phi,
                       transfers, compounds):
        ts = datetime.now().strftime('%H:%M:%S')
        print(f"  [{ts}] 📡 {domain}:{concept} phi={phi:.3f} "
              f"→ {len(transfers)} dominios "
              + (f"⚠ {len(compounds)} COMPUESTOS" if compounds else ""))
        for c in compounds:
            print(f"    🚨 {c['severity']}: {c['pattern_name']}")

    def status(self) -> Dict:
        phi = self._phi.phi_global
        with self._lock:
            n_signals   = len(self._signals)
            n_transfers = len(self._transfers)
        return {
            "version":         VERSION,
            "phi_global":      round(phi, 4),
            "coherent":        phi > PHI_MIN,
            "signals":         n_signals,
            "transfers":       n_transfers,
            "active_correlations": len(self.active_correlations()),
            "compound_patterns":   len(CrossDomainSynth.COMPOUND_PATTERNS),
            "supported_domains":   list(DOMAIN_AFFINITY.keys()),
            "recent_compounds":    self.recent_compounds(3),
        }


# ══════════════════════════════════════════════════
# FLASK API
# ══════════════════════════════════════════════════

def create_protocol_api(protocol: TransferProtocol):
    from flask import Flask, jsonify, request
    from flask_cors import CORS

    app = Flask(__name__)
    CORS(app)

    @app.route('/')
    def root():
        return jsonify({
            "system":  "phi47 Transfer Protocol",
            "version": VERSION,
            "phi":     round(protocol._phi.phi_global, 4),
        })

    @app.route('/health')
    def health():
        return jsonify({
            "ok":  True,
            "phi": round(protocol._phi.phi_global, 4),
        })

    @app.route('/publish', methods=['POST'])
    def publish():
        """Un agente publica una señal de conocimiento."""
        d = request.get_json() or {}
        result = protocol.publish(
            domain   = d.get("domain", "cybersecurity"),
            concept  = d.get("concept", "anomaly"),
            phi      = float(d.get("phi", PHI_MIN + 0.1)),
            severity = d.get("severity", "HIGH"),
            meta     = d.get("meta", {}),
        )
        return jsonify(result)

    @app.route('/translate', methods=['POST'])
    def translate():
        """¿Cómo se ve este concepto en otros dominios?"""
        d = request.get_json() or {}
        translations = protocol.query_translations(
            domain  = d.get("domain", "cybersecurity"),
            concept = d.get("concept", "anomaly"),
        )
        return jsonify({
            "domain":        d.get("domain"),
            "concept":       d.get("concept"),
            "translations":  translations,
            "count":         len(translations),
        })

    @app.route('/correlations')
    def correlations():
        return jsonify({
            "correlations": protocol.active_correlations(),
            "phi":          round(protocol._phi.phi_global, 4),
        })

    @app.route('/compounds')
    def compounds():
        n = min(int(request.args.get('n', 10)), 50)
        return jsonify({
            "compounds": protocol.recent_compounds(n),
            "known_patterns": len(CrossDomainSynth.COMPOUND_PATTERNS),
        })

    @app.route('/status')
    def status():
        return jsonify(protocol.status())

    @app.route('/domains')
    def domains():
        return jsonify({
            "domains":  list(DOMAIN_AFFINITY.keys()),
            "bridges":  len(DOMAIN_BRIDGE),
            "affinities": {
                d: dict(affs)
                for d, affs in DOMAIN_AFFINITY.items()
            },
        })

    return app


# ── Main / Demo ───────────────────────────────────
if __name__ == "__main__":
    print(f"\n{'═'*62}")
    print(f"  phi47 Protocolo de Transferencia de Conocimiento (PTKD)")
    print(f"  v{VERSION}")
    print(f"{'═'*62}\n")

    protocol = TransferProtocol()

    # Callback cuando se detecta un patrón compuesto
    def on_compound(compounds):
        for c in compounds:
            print(f"\n  {'🚨'*3} PATRÓN COMPUESTO DETECTADO {'🚨'*3}")
            print(f"  Nombre:   {c['pattern_name']}")
            print(f"  Severidad:{c['severity']}")
            print(f"  Desc:     {c['description']}")
            print(f"  Acción:   {c['action']}")
            print(f"  Fuerza:   {c['strength']:.3f}")
            print()

    protocol.on_compound_pattern(on_compound)

    # ── Escenario 1: APT con componente financiero ──
    print("── Escenario 1: APT con componente financiero ──\n")

    print("  [Cyber] Detecta C2 beacon...")
    r1 = protocol.publish(
        domain="cybersecurity", concept="c2_beacon",
        phi=0.92, severity="HIGH",
        meta={"interval_cat":"medium","bytes_cat":"tiny"}
    )
    print(f"  → {r1['transfers']} dominios informados")
    if r1['translations']:
        t = r1['translations'][0]
        print(f"  → Finance recibe: '{t['translated_concept']}' (peso={t['transfer_weight']})")
        print(f"     Recomendación: {t['recommendation'][:70]}")

    time.sleep(0.1)

    print("\n  [Finance] Detecta micro-transacciones automáticas...")
    r2 = protocol.publish(
        domain="finance", concept="automated_micro_transactions",
        phi=0.88, severity="HIGH",
        meta={"interval_cat":"fast","bytes_cat":"tiny"}
    )

    # ── Escenario 2: Exfiltración coordinada ──
    print("\n── Escenario 2: Exfiltración coordinada ──\n")

    print("  [Cyber] Detecta exfiltración de datos...")
    r3 = protocol.publish(
        domain="cybersecurity", concept="data_exfil",
        phi=0.95, severity="CRITICAL",
        meta={"bytes_cat":"large","hour_cat":"night"}
    )

    time.sleep(0.1)

    print("\n  [Finance] Detecta transferencia grande anómala...")
    r4 = protocol.publish(
        domain="finance", concept="large_transfer_anomaly",
        phi=0.91, severity="CRITICAL",
    )

    # ── Traducción manual ──
    print("\n── Traducción de conceptos ──\n")
    translations = protocol.query_translations("cybersecurity", "c2_beacon")
    for t in translations:
        print(f"  cybersecurity:c2_beacon → {t['target_domain']}:{t['translated_concept']}")
        print(f"     afinidad={t['affinity']} | {t['recommendation'][:60]}")

    # ── Status final ──
    print(f"\n{'─'*62}")
    s = protocol.status()
    print(f"  phi_global:          {s['phi_global']}")
    print(f"  Señales procesadas:  {s['signals']}")
    print(f"  Transferencias:      {s['transfers']}")
    print(f"  Patrones compuestos: {len(s['recent_compounds'])} detectados")
    print(f"  Catálogo compuestos: {s['compound_patterns']}")
    print(f"{'═'*62}\n")
