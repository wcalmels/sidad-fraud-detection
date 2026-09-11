"""
Aprendizaje Federado phi-Coherente (AFC)
=========================================
Módulo que permite que múltiples agentes phi47 compartan
conocimiento sin compartir datos privados de sus clientes.

Principio fundamental:
  Lo que viaja entre agentes no son datos — son PATRONES.
  Un patrón es conocimiento abstracto destilado por phi.
  Los datos del cliente nunca salen de su agente.

Flujo completo:

  Agente A (minería) detecta patrón C2 beacon
  → phi_global = 0.92 (alta coherencia)
  → Nemosine guarda episodio con phi=0.92
  → AFC extrae patrón abstracto:
      {tipo: "behavioral", patron: "c2_beacon",
       phi: 0.92, tier: "CONSCIOUS", dominio: "cybersecurity"}
  → Publica al Hub AFC (sin datos del cliente)

  Agente B (finanzas) recibe el patrón
  → Verifica: tier CONSCIOUS ✓, phi 0.92 > 0.75 ✓
  → Integra en su Nemosine con peso reducido:
      phi_efectivo = 0.92 * 0.7 (factor confianza) = 0.644
  → La próxima vez que B vea un C2 beacon → ya sabe qué es
  → Si B confirma el patrón → peso sube a 0.92
  → Si B nunca lo ve → decae y se olvida

Componentes:
  PatternExtractor   → extrae patrones abstractos de Nemosine
  PhiTrustProtocol   → protocolo de confianza entre agentes
  FederatedHub       → central de intercambio de patrones
  FederatedLearner   → integra patrones de otros agentes

Privacidad garantizada:
  ✓ IPs reales → nunca salen
  ✓ Timestamps reales → nunca salen
  ✓ Datos del cliente → nunca salen
  ✓ Solo patrones abstractos con phi ≥ threshold

Author: Walter Calmels Von dem Knesebeck
        TUCH Systems Research Laboratory — Maipu Lab 2026
"""

import os, json, time, math, hashlib, threading, sqlite3
import urllib.request, urllib.error
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Tuple, Set
from dataclasses import dataclass, asdict, field
from collections import defaultdict, deque
from pathlib import Path

VERSION  = "1.0.0"
PHI      = 1.6180339887498948
PHI_MIN  = 0.618

# ── Threshold mínimo para compartir un patrón ──
MIN_PHI_TO_SHARE  = 0.75   # solo patrones de alta coherencia
MIN_TIER_TO_SHARE = 1      # mínimo Awakening (>= 100 episodios)
TRUST_FACTOR      = 0.70   # peso inicial al recibir patrón externo
CONFIRMATION_BOOST= 0.15   # boost cuando el receptor confirma el patrón
DECAY_UNCONFIRMED = 0.05   # decay por ciclo si no se confirma

TIER_LEVELS = {
    "Nascent":    0,
    "Awakening":  1,
    "Conscious":  2,
    "Elder":      3,
}


# ══════════════════════════════════════════════════
# PATRÓN ABSTRACTO
# La unidad de conocimiento que viaja entre agentes
# ══════════════════════════════════════════════════

@dataclass
class AbstractPattern:
    """
    Patrón de conocimiento abstracto — sin datos del cliente.

    Es el resultado de destilar un episodio de alta coherencia
    en algo genérico y transferible.

    Ejemplo:
      Episodio real: "IP 94.23.247.10 conectó a puerto 4444
                      cada 60 segundos con 512 bytes"
      Patrón abstracto: "conexión periódica (interval=60s, bytes<1KB)
                         a puerto no estándar → probable C2 beacon"
    """
    pattern_id:    str
    pattern_type:  str    # behavioral / ioc_range / anomaly / port / temporal
    domain:        str    # cybersecurity / finance / infrastructure / etc.
    description:   str    # descripción abstracta del patrón
    phi_source:    float  # phi del episodio que generó este patrón
    tier_source:   str    # tier del agente emisor
    agent_id:      str    # ID del agente (hasheado, anónimo)
    timestamp:     str    # cuándo se publicó
    confirmations: int    = 0  # cuántos agentes confirmaron este patrón
    rejections:    int    = 0  # cuántos agentes lo rechazaron
    # Metadata técnica (sin datos del cliente)
    meta: Dict = field(default_factory=dict)

    @property
    def phi_effective(self) -> float:
        """phi ajustado por confirmaciones de otros agentes."""
        if self.confirmations + self.rejections == 0:
            return self.phi_source
        conf_rate = self.confirmations / (self.confirmations + self.rejections)
        boost = conf_rate * 0.2
        return min(PHI, self.phi_source + boost)

    @property
    def trust_score(self) -> float:
        """Score de confianza 0-1 basado en tier y phi."""
        tier_score = TIER_LEVELS.get(self.tier_source, 0) / 3.0
        phi_score  = (self.phi_source - PHI_MIN) / (PHI - PHI_MIN)
        return round((tier_score * 0.4 + phi_score * 0.6), 3)

    def to_dict(self) -> Dict:
        d = asdict(self)
        d['phi_effective'] = self.phi_effective
        d['trust_score']   = self.trust_score
        return d


# ══════════════════════════════════════════════════
# EXTRACTOR DE PATRONES
# Convierte episodios de Nemosine en patrones abstractos
# ══════════════════════════════════════════════════

class PatternExtractor:
    """
    Extrae patrones abstractos de la memoria Nemosine
    sin incluir datos identificables del cliente.
    """

    # Templates de abstracción por tipo de amenaza
    ABSTRACTIONS = {
        "c2_beacon": {
            "type":   "behavioral",
            "desc":   "Conexión periódica con bytes pequeños — probable C2 beacon",
            "meta":   ["interval_range", "bytes_range", "port_category"],
        },
        "data_exfil": {
            "type":   "behavioral",
            "desc":   "Transferencia masiva a IP externa — probable exfiltración",
            "meta":   ["bytes_range", "duration_range", "port_category"],
        },
        "port_scan": {
            "type":   "behavioral",
            "desc":   "Múltiples puertos contactados en ventana corta — port scan",
            "meta":   ["n_ports_range", "window_s"],
        },
        "IOC": {
            "type":   "ioc_range",
            "desc":   "Conexión a rango IP malicioso conocido",
            "meta":   ["ip_prefix", "port_category"],
        },
        "ANOMALY": {
            "type":   "anomaly",
            "desc":   "Anomalía vs baseline del cliente",
            "meta":   ["score_range", "hour_category", "bytes_category"],
        },
    }

    def __init__(self, agent_id: str, domain: str = "cybersecurity"):
        self.agent_id = agent_id
        self.domain   = domain
        # ID anónimo del agente para publicar
        self._anon_id = hashlib.sha256(agent_id.encode()).hexdigest()[:16]

    def extract(self, memories: List[Dict],
                tier: str, min_phi: float = MIN_PHI_TO_SHARE
                ) -> List[AbstractPattern]:
        """
        Extrae patrones abstractos de una lista de memorias.
        Solo procesa memorias con phi >= min_phi.
        Nunca incluye datos identificables.
        """
        if TIER_LEVELS.get(tier, 0) < MIN_TIER_TO_SHARE:
            return []  # agente muy nuevo — no comparte todavía

        patterns = []
        seen     = set()  # evitar duplicados

        for mem in memories:
            phi = float(mem.get("phi", 0))
            if phi < min_phi:
                continue

            content   = mem.get("content", "")
            tags      = mem.get("tags", [])
            context   = mem.get("context", {})

            pattern = self._abstract(content, tags, context, phi, tier)
            if pattern and pattern.description not in seen:
                seen.add(pattern.description)
                patterns.append(pattern)

        return patterns

    def _abstract(self, content: str, tags: List[str],
                  context: Dict, phi: float,
                  tier: str) -> Optional[AbstractPattern]:
        """Convierte un episodio concreto en patrón abstracto."""

        # Detectar tipo de patrón
        pattern_key = None
        for key in self.ABSTRACTIONS:
            if key.lower() in content.lower() or key in tags:
                pattern_key = key
                break

        if not pattern_key:
            # Patrón genérico si no matchea
            if phi < 0.85:
                return None  # no es suficientemente relevante
            pattern_key = "ANOMALY"

        tmpl = self.ABSTRACTIONS[pattern_key]

        # Extraer metadata sin datos identificables
        meta = self._extract_meta(context, tmpl["meta"])

        pid = hashlib.md5(
            f"{pattern_key}{self.domain}{meta}".encode()
        ).hexdigest()[:12]

        return AbstractPattern(
            pattern_id  = pid,
            pattern_type= tmpl["type"],
            domain      = self.domain,
            description = tmpl["desc"],
            phi_source  = round(phi, 4),
            tier_source = tier,
            agent_id    = self._anon_id,
            timestamp   = datetime.now(timezone.utc).isoformat(),
            meta        = meta,
        )

    def _extract_meta(self, context: Dict,
                      fields: List[str]) -> Dict:
        """
        Extrae metadata técnica sin datos identificables.
        Convierte valores exactos en rangos/categorías.
        """
        meta = {}
        for field in fields:
            if field == "ip_prefix":
                # Solo el prefijo /8 o /16, nunca la IP completa
                ip = context.get("ip", "")
                if ip:
                    parts = ip.split(".")
                    meta["ip_prefix"] = f"{parts[0]}.{parts[1]}.*.*" if len(parts) >= 2 else ""
            elif field == "port_category":
                port = int(context.get("port", 0))
                meta["port_cat"] = (
                    "well_known" if port < 1024 else
                    "registered" if port < 49152 else
                    "dynamic"
                )
            elif field == "bytes_range":
                b = int(context.get("bytes", 0))
                meta["bytes_cat"] = (
                    "tiny"   if b < 1024 else
                    "small"  if b < 10240 else
                    "medium" if b < 102400 else
                    "large"
                )
            elif field == "interval_range":
                iv = float(context.get("interval", 0))
                meta["interval_cat"] = (
                    "fast"   if iv < 10 else
                    "medium" if iv < 60 else
                    "slow"
                )
            elif field == "score_range":
                sc = float(context.get("score", 0))
                meta["score_cat"] = (
                    "low"    if sc < 0.4 else
                    "medium" if sc < 0.7 else
                    "high"
                )
            elif field == "hour_category":
                h = int(context.get("hour", 12))
                meta["hour_cat"] = (
                    "business"  if 8 <= h <= 18 else
                    "evening"   if 18 <= h <= 23 else
                    "night"
                )

        return meta

    def from_threat_alert(self, alert: Dict,
                          phi: float, tier: str
                          ) -> Optional[AbstractPattern]:
        """
        Crea un patrón directamente desde una alerta del Sentinel-Agent.
        Más simple que extraer de Nemosine — útil para tiempo real.
        """
        if phi < MIN_PHI_TO_SHARE:
            return None

        threat_type = alert.get("threat_type", "ANOMALY")
        pattern_key = alert.get("pattern", threat_type)
        tmpl        = self.ABSTRACTIONS.get(pattern_key,
                      self.ABSTRACTIONS["ANOMALY"])

        context = {
            "ip":    alert.get("ip", ""),
            "port":  alert.get("port", 0),
            "bytes": alert.get("score", 0) * 10000,
            "score": alert.get("score", 0),
        }
        meta = self._extract_meta(context, tmpl["meta"])

        pid = hashlib.md5(
            f"{pattern_key}{phi}{self.domain}".encode()
        ).hexdigest()[:12]

        return AbstractPattern(
            pattern_id  = pid,
            pattern_type= tmpl["type"],
            domain      = self.domain,
            description = tmpl["desc"],
            phi_source  = round(phi, 4),
            tier_source = tier,
            agent_id    = self._anon_id,
            timestamp   = datetime.now(timezone.utc).isoformat(),
            meta        = meta,
        )


# ══════════════════════════════════════════════════
# PROTOCOLO DE CONFIANZA phi
# Decide si aceptar un patrón de otro agente
# ══════════════════════════════════════════════════

class PhiTrustProtocol:
    """
    Protocolo de confianza entre agentes.

    Un agente no acepta ciegamente el conocimiento de otro.
    Evalúa:
      1. Madurez del emisor (tier)
      2. Calidad del patrón (phi)
      3. Relevancia del dominio
      4. Historial del emisor (¿ha enviado falsos positivos antes?)
    """

    def __init__(self, my_domain: str, my_tier: str):
        self.domain     = my_domain
        self.tier       = my_tier
        self._history   : Dict[str, Dict] = {}  # agent_id → historial
        self._lock      = threading.Lock()

    def evaluate(self, pattern: AbstractPattern
                 ) -> Tuple[bool, float, str]:
        """
        Evalúa si aceptar un patrón.
        Returns (accept, weight, reason)
        weight: cuánto peso darle en Nemosine (0-1)
        """
        # 1. Tier mínimo del emisor
        tier_level = TIER_LEVELS.get(pattern.tier_source, 0)
        if tier_level < MIN_TIER_TO_SHARE:
            return False, 0.0, f"Tier insuficiente: {pattern.tier_source}"

        # 2. phi mínimo del patrón
        if pattern.phi_source < MIN_PHI_TO_SHARE:
            return False, 0.0, f"phi insuficiente: {pattern.phi_source:.3f}"

        # 3. Dominio compatible
        domain_weight = self._domain_compatibility(pattern.domain)
        if domain_weight < 0.3:
            return False, 0.0, f"Dominio incompatible: {pattern.domain}"

        # 4. Historial del emisor
        trust_history = self._get_agent_trust(pattern.agent_id)

        # Calcular peso final
        phi_norm    = (pattern.phi_source - PHI_MIN) / (PHI - PHI_MIN)
        tier_norm   = tier_level / 3.0
        weight      = (
            phi_norm      * 0.40 +
            tier_norm     * 0.25 +
            domain_weight * 0.20 +
            trust_history * 0.15
        ) * TRUST_FACTOR

        weight = round(min(0.95, max(0.1, weight)), 3)

        reason = (f"Aceptado: phi={pattern.phi_source:.3f} "
                  f"tier={pattern.tier_source} "
                  f"domain_match={domain_weight:.2f} "
                  f"weight={weight:.3f}")

        return True, weight, reason

    def confirm_pattern(self, pattern_id: str, agent_id: str):
        """El receptor confirmó que el patrón es válido."""
        with self._lock:
            h = self._history.setdefault(agent_id, {
                "confirmed": 0, "rejected": 0, "total": 0
            })
            h["confirmed"] += 1
            h["total"]     += 1

    def reject_pattern(self, pattern_id: str, agent_id: str,
                       reason: str = ""):
        """El receptor rechazó el patrón (falso positivo)."""
        with self._lock:
            h = self._history.setdefault(agent_id, {
                "confirmed": 0, "rejected": 0, "total": 0
            })
            h["rejected"] += 1
            h["total"]    += 1

    def _domain_compatibility(self, pattern_domain: str) -> float:
        """Compatibilidad entre dominios 0-1."""
        if pattern_domain == self.domain:
            return 1.0
        # Dominios que comparten patrones útiles
        compatible = {
            "cybersecurity":   ["infrastructure", "finance"],
            "finance":         ["cybersecurity"],
            "infrastructure":  ["cybersecurity", "materials"],
            "bioinformatics":  ["neuroscience"],
            "neuroscience":    ["bioinformatics"],
            "materials":       ["infrastructure"],
            "climate":         ["infrastructure"],
        }
        if pattern_domain in compatible.get(self.domain, []):
            return 0.65
        return 0.15  # distinto dominio — baja relevancia

    def _get_agent_trust(self, agent_id: str) -> float:
        """Historial de confianza de un agente específico 0-1."""
        with self._lock:
            h = self._history.get(agent_id)
            if not h or h["total"] == 0:
                return 0.5  # desconocido — confianza neutral
            conf_rate = h["confirmed"] / h["total"]
            return round(conf_rate, 3)


# ══════════════════════════════════════════════════
# FEDERATED HUB
# Central de intercambio de patrones (puede ser local o remota)
# ══════════════════════════════════════════════════

class FederatedHub:
    """
    Hub central de patrones federados.

    En producción: un servidor Railway compartido por todos los agentes.
    En desarrollo: base de datos local SQLite.

    El Hub solo guarda patrones abstractos — nunca datos del cliente.
    """

    def __init__(self, db_path: str = None, remote_url: str = None):
        self.db_path    = db_path or str(Path.home() / "phi47_federated_hub.db")
        self.remote_url = remote_url
        self._lock      = threading.Lock()
        self._cache     : Dict[str, AbstractPattern] = {}
        self._init_db()
        print(f"[FederatedHub] v{VERSION}")
        print(f"  DB:     {self.db_path}")
        print(f"  Remote: {remote_url or 'local only'}")

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
            CREATE TABLE IF NOT EXISTS patterns (
                pattern_id    TEXT PRIMARY KEY,
                pattern_type  TEXT,
                domain        TEXT,
                description   TEXT,
                phi_source    REAL,
                tier_source   TEXT,
                agent_id      TEXT,
                timestamp     TEXT,
                confirmations INTEGER DEFAULT 0,
                rejections    INTEGER DEFAULT 0,
                meta          TEXT,
                last_seen     TEXT
            )""")
            conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_domain
            ON patterns(domain, phi_source DESC)
            """)

    def publish(self, pattern: AbstractPattern) -> bool:
        """Publica un patrón al hub."""
        with self._lock:
            try:
                with sqlite3.connect(self.db_path) as conn:
                    conn.execute("""
                    INSERT OR REPLACE INTO patterns
                    (pattern_id, pattern_type, domain, description,
                     phi_source, tier_source, agent_id, timestamp,
                     confirmations, rejections, meta, last_seen)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
                    """, (
                        pattern.pattern_id,
                        pattern.pattern_type,
                        pattern.domain,
                        pattern.description,
                        pattern.phi_source,
                        pattern.tier_source,
                        pattern.agent_id,
                        pattern.timestamp,
                        pattern.confirmations,
                        pattern.rejections,
                        json.dumps(pattern.meta),
                        datetime.now(timezone.utc).isoformat(),
                    ))
                self._cache[pattern.pattern_id] = pattern
                return True
            except Exception as e:
                print(f"[FederatedHub] Error publish: {e}")
                return False

    def get_patterns(self, domain: str = None,
                     min_phi: float = MIN_PHI_TO_SHARE,
                     min_confirmations: int = 0,
                     limit: int = 50
                     ) -> List[AbstractPattern]:
        """Obtiene patrones del hub — incluye todos los dominios para evaluación."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            if domain:
                # Incluir todos los dominios — PhiTrustProtocol filtra por relevancia
                rows = conn.execute("""
                SELECT * FROM patterns
                WHERE phi_source >= ?
                  AND confirmations >= ?
                ORDER BY phi_source DESC, confirmations DESC
                LIMIT ?
                """, (min_phi, min_confirmations, limit)).fetchall()
            else:
                rows = conn.execute("""
                SELECT * FROM patterns
                WHERE phi_source >= ?
                  AND confirmations >= ?
                ORDER BY phi_source DESC
                LIMIT ?
                """, (min_phi, min_confirmations, limit)).fetchall()

        return [self._row_to_pattern(r) for r in rows]

    def confirm(self, pattern_id: str, agent_id: str):
        """Un agente confirmó el patrón."""
        with self._lock:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                UPDATE patterns SET confirmations = confirmations + 1
                WHERE pattern_id = ?
                """, (pattern_id,))

    def reject(self, pattern_id: str, agent_id: str):
        """Un agente rechazó el patrón (falso positivo)."""
        with self._lock:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                UPDATE patterns SET rejections = rejections + 1
                WHERE pattern_id = ?
                """, (pattern_id,))

    def stats(self) -> Dict:
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            total = conn.execute("SELECT COUNT(*) FROM patterns").fetchone()[0]
            by_domain = conn.execute("""
            SELECT domain, COUNT(*) as n, AVG(phi_source) as avg_phi
            FROM patterns GROUP BY domain ORDER BY n DESC
            """).fetchall()
            top = conn.execute("""
            SELECT description, phi_source, confirmations, domain
            FROM patterns ORDER BY confirmations DESC, phi_source DESC
            LIMIT 5
            """).fetchall()

        return {
            "total_patterns":  total,
            "by_domain":       [dict(r) for r in by_domain],
            "top_patterns":    [dict(r) for r in top],
        }

    def _row_to_pattern(self, row) -> AbstractPattern:
        return AbstractPattern(
            pattern_id   = row["pattern_id"],
            pattern_type = row["pattern_type"],
            domain       = row["domain"],
            description  = row["description"],
            phi_source   = row["phi_source"],
            tier_source  = row["tier_source"],
            agent_id     = row["agent_id"],
            timestamp    = row["timestamp"],
            confirmations= row["confirmations"],
            rejections   = row["rejections"],
            meta         = json.loads(row["meta"] or "{}"),
        )


# ══════════════════════════════════════════════════
# FEDERATED LEARNER
# El módulo que cada agente usa para aprender de otros
# ══════════════════════════════════════════════════

class FederatedLearner:
    """
    Módulo de aprendizaje federado para un agente phi47.

    Integra:
      - PatternExtractor: extrae conocimiento de la memoria del agente
      - PhiTrustProtocol: evalúa patrones de otros agentes
      - FederatedHub: intercambio de patrones

    Ciclo cada N horas:
      1. Extrae patrones de Nemosine propios (phi >= 0.75)
      2. Publica al Hub (sin datos del cliente)
      3. Descarga patrones del Hub para su dominio
      4. Evalúa con PhiTrustProtocol
      5. Integra en su Nemosine los aceptados
    """

    SYNC_INTERVAL = 3600  # 1 hora

    def __init__(self, agent_id: str, domain: str,
                 nemosine=None, hub: FederatedHub = None,
                 hub_path: str = None):
        self.agent_id  = agent_id
        self.domain    = domain
        self._nemosine = nemosine
        self._hub      = hub or FederatedHub(db_path=hub_path)
        self._extractor= PatternExtractor(agent_id, domain)
        self._trust    = PhiTrustProtocol(domain, "Nascent")
        self._running  = False
        self._synced   = 0
        self._shared   = 0
        self._learned  = 0
        self._confirmed= 0
        self._log      = deque(maxlen=100)
        # Patrones que recibimos y están pendientes de confirmación
        self._pending  : Dict[str, Tuple[AbstractPattern, float]] = {}

    def start(self):
        """Arranca el ciclo de sincronización en background."""
        self._running = True
        t = threading.Thread(target=self._loop, daemon=True)
        t.start()
        print(f"[FederatedLearner] Iniciado — agente={self.agent_id[:12]}")
        print(f"  Dominio: {self.domain} | Hub: {self._hub.db_path}")

    def stop(self):
        self._running = False

    def _loop(self):
        while self._running:
            try:
                self._sync_cycle()
            except Exception as e:
                print(f"[FederatedLearner] Error en sync: {e}")
            time.sleep(self.SYNC_INTERVAL)

    def _sync_cycle(self):
        """Un ciclo completo de sincronización."""
        self._synced += 1
        print(f"[FederatedLearner] Sync #{self._synced}")

        tier = self._get_tier()
        self._trust.tier = tier

        # 1. Extraer y publicar patrones propios
        if self._nemosine:
            try:
                memories = self._nemosine.recall(
                    "threat anomaly block detect",
                    n=50, min_phi=MIN_PHI_TO_SHARE
                )
                patterns = self._extractor.extract(memories, tier)
                for p in patterns:
                    if self._hub.publish(p):
                        self._shared += 1
                if patterns:
                    print(f"  Publicados: {len(patterns)} patrones")
            except Exception as e:
                print(f"  Error extrayendo: {e}")

        # 2. Descargar patrones del hub
        hub_patterns = self._hub.get_patterns(
            domain=self.domain,
            min_phi=MIN_PHI_TO_SHARE,
            limit=20,
        )
        print(f"  Hub: {len(hub_patterns)} patrones disponibles")

        # 3. Evaluar y aprender
        learned_this = 0
        for pattern in hub_patterns:
            # No aprender patrones propios
            if pattern.agent_id == hashlib.sha256(
                self.agent_id.encode()).hexdigest()[:16]:
                continue

            accept, weight, reason = self._trust.evaluate(pattern)
            if accept:
                self._integrate(pattern, weight)
                self._pending[pattern.pattern_id] = (pattern, weight)
                learned_this += 1

        if learned_this:
            self._learned += learned_this
            print(f"  Aprendidos: {learned_this} patrones nuevos")

        self._log.appendleft({
            "ts":      datetime.now(timezone.utc).isoformat(),
            "synced":  self._synced,
            "shared":  self._shared,
            "learned": self._learned,
            "tier":    tier,
        })

    def _integrate(self, pattern: AbstractPattern, weight: float):
        """Integra un patrón en la memoria del agente."""
        if not self._nemosine:
            return
        # El peso phi del patrón en Nemosine es reducido por TRUST_FACTOR
        phi_to_store = pattern.phi_source * weight
        content = (
            f"[FEDERADO] {pattern.description} "
            f"[dominio={pattern.domain}, tipo={pattern.pattern_type}, "
            f"tier_origen={pattern.tier_source}]"
        )
        try:
            self._nemosine.remember(
                content,
                phi=phi_to_store,
                mem_type="semantic",
                tags=["federated", pattern.pattern_type, pattern.domain],
                context={
                    "pattern_id":  pattern.pattern_id,
                    "source_tier": pattern.tier_source,
                    "weight":      weight,
                    "federated":   True,
                },
            )
        except Exception:
            pass

    def confirm_pattern(self, pattern_id: str, reason: str = ""):
        """
        El agente confirmó que un patrón federado es válido.
        (El agente vio el mismo patrón con sus propios datos)
        """
        if pattern_id in self._pending:
            pattern, _ = self._pending[pattern_id]
            self._hub.confirm(pattern_id, self.agent_id)
            self._trust.confirm_pattern(pattern_id, pattern.agent_id)
            self._confirmed += 1
            # Boost en Nemosine — aumentar el peso del patrón
            if self._nemosine:
                try:
                    self._nemosine.remember(
                        f"[CONFIRMADO] {pattern.description}",
                        phi=pattern.phi_source,  # phi completo al confirmar
                        mem_type="semantic",
                        tags=["federated", "confirmed"],
                    )
                except Exception:
                    pass
            print(f"[FederatedLearner] Patrón confirmado: {pattern_id}")

    def reject_pattern(self, pattern_id: str, reason: str = ""):
        """El agente rechazó un patrón federado (falso positivo)."""
        if pattern_id in self._pending:
            pattern, _ = self._pending[pattern_id]
            self._hub.reject(pattern_id, self.agent_id)
            self._trust.reject_pattern(pattern_id, pattern.agent_id, reason)
            del self._pending[pattern_id]

    def sync_now(self) -> Dict:
        """Fuerza un ciclo de sync inmediato."""
        self._sync_cycle()
        return self.status()

    def publish_alert(self, alert: Dict, phi: float) -> bool:
        """
        Publica un patrón directamente desde una alerta.
        Más rápido que esperar el ciclo de sync.
        """
        tier    = self._get_tier()
        pattern = self._extractor.from_threat_alert(alert, phi, tier)
        if pattern:
            return self._hub.publish(pattern)
        return False

    def _get_tier(self) -> str:
        """Obtiene el tier actual del agente."""
        if not self._nemosine:
            return "Nascent"
        try:
            return self._nemosine.tier
        except Exception:
            return "Nascent"

    def status(self) -> Dict:
        hub_stats = self._hub.stats()
        return {
            "agent_id":     self.agent_id[:12] + "...",
            "domain":       self.domain,
            "tier":         self._get_tier(),
            "syncs":        self._synced,
            "shared":       self._shared,
            "learned":      self._learned,
            "confirmed":    self._confirmed,
            "pending":      len(self._pending),
            "hub":          hub_stats,
            "recent_log":   list(self._log)[:5],
        }


# ══════════════════════════════════════════════════
# FLASK API para el Hub federado
# ══════════════════════════════════════════════════

def create_hub_api(hub: FederatedHub):
    """API REST para el Hub federado — deployable en Railway."""
    from flask import Flask, jsonify, request
    from flask_cors import CORS

    app = Flask(__name__)
    CORS(app)

    @app.route('/')
    def root():
        return jsonify({
            "system":  "phi47 Federated Hub",
            "version": VERSION,
            "stats":   hub.stats(),
        })

    @app.route('/health')
    def health():
        s = hub.stats()
        return jsonify({"ok": True, "patterns": s["total_patterns"]})

    @app.route('/patterns', methods=['GET'])
    def get_patterns():
        domain = request.args.get('domain')
        min_phi= float(request.args.get('min_phi', MIN_PHI_TO_SHARE))
        limit  = min(int(request.args.get('limit', 50)), 200)
        patterns = hub.get_patterns(domain=domain, min_phi=min_phi, limit=limit)
        return jsonify({
            "patterns": [p.to_dict() for p in patterns],
            "count":    len(patterns),
        })

    @app.route('/publish', methods=['POST'])
    def publish():
        d = request.get_json() or {}
        try:
            p = AbstractPattern(
                pattern_id   = d.get("pattern_id", ""),
                pattern_type = d.get("pattern_type", ""),
                domain       = d.get("domain", ""),
                description  = d.get("description", ""),
                phi_source   = float(d.get("phi_source", 0)),
                tier_source  = d.get("tier_source", "Nascent"),
                agent_id     = d.get("agent_id", ""),
                timestamp    = d.get("timestamp",
                               datetime.now(timezone.utc).isoformat()),
                meta         = d.get("meta", {}),
            )
            ok = hub.publish(p)
            return jsonify({"ok": ok, "pattern_id": p.pattern_id})
        except Exception as e:
            return jsonify({"error": str(e)}), 400

    @app.route('/confirm/<pattern_id>', methods=['POST'])
    def confirm(pattern_id):
        d = request.get_json() or {}
        hub.confirm(pattern_id, d.get("agent_id", ""))
        return jsonify({"ok": True})

    @app.route('/reject/<pattern_id>', methods=['POST'])
    def reject(pattern_id):
        d = request.get_json() or {}
        hub.reject(pattern_id, d.get("agent_id", ""))
        return jsonify({"ok": True})

    @app.route('/stats')
    def stats():
        return jsonify(hub.stats())

    return app


# ══════════════════════════════════════════════════
# MAIN — Demo
# ══════════════════════════════════════════════════

if __name__ == "__main__":
    import tempfile

    print(f"\n{'═'*60}")
    print(f"  phi47 Aprendizaje Federado phi-Coherente (AFC)")
    print(f"  v{VERSION}")
    print(f"{'═'*60}\n")

    # Hub compartido en memoria para demo
    db = tempfile.mktemp(suffix='.db')
    hub = FederatedHub(db_path=db)

    # ── Agente A: empresa minera (cybersecurity) ──
    print("── Agente A: Empresa Minera ──")
    extA = PatternExtractor("agente_minera_001", "cybersecurity")

    # Simular memorias de alta coherencia del Agente A
    memories_A = [
        {"content": "c2_beacon detectado IP externa BLOCK",
         "phi": 0.92, "tags": ["threat","c2_beacon"],
         "context": {"ip":"94.23.247.10","port":443,"interval":60,"bytes":512}},
        {"content": "IOC Pegasus bloqueado CRITICAL",
         "phi": 0.95, "tags": ["threat","IOC"],
         "context": {"ip":"5.199.174.88","port":443}},
        {"content": "port_scan detectado desde IP externa",
         "phi": 0.78, "tags": ["threat","port_scan"],
         "context": {"ip":"185.1.2.3","port":80,"score":0.7}},
    ]

    patterns_A = extA.extract(memories_A, tier="Conscious")
    print(f"  Patrones extraídos: {len(patterns_A)}")
    for p in patterns_A:
        ok = hub.publish(p)
        print(f"  {'✓' if ok else '✗'} {p.description[:50]} (phi={p.phi_source})")

    # ── Agente B: empresa financiera ──
    print("\n── Agente B: Empresa Financiera ──")
    trustB = PhiTrustProtocol("finance", "Awakening")

    hub_patterns = hub.get_patterns(domain="finance")
    print(f"  Patrones disponibles en hub: {len(hub_patterns)}")

    accepted = 0
    for p in hub_patterns:
        accept, weight, reason = trustB.evaluate(p)
        status = "✓ ACEPTA" if accept else "✗ RECHAZA"
        print(f"  {status} [{p.domain}] {p.description[:40]}")
        print(f"           phi={p.phi_source} tier={p.tier_source} weight={weight:.3f}")
        if accept:
            accepted += 1
            # Simular confirmación después de verlo en producción
            hub.confirm(p.pattern_id, "agente_financiero_001")

    print(f"\n  Patrones aceptados: {accepted}/{len(hub_patterns)}")

    # ── Stats del Hub ──
    print("\n── Estado del Hub ──")
    stats = hub.stats()
    print(f"  Total patrones: {stats['total_patterns']}")
    print(f"  Por dominio:")
    for d in stats['by_domain']:
        print(f"    {d['domain']:20} {d['n']} patrones  phi_avg={d['avg_phi']:.3f}")

    if stats['top_patterns']:
        print(f"\n  Top patrón más confirmado:")
        t = stats['top_patterns'][0]
        print(f"    {t['description']}")
        print(f"    confirmaciones={t['confirmations']} phi={t['phi_source']}")

    print(f"\n{'═'*60}")
    print(f"  El Agente B aprendió sin recibir datos del Agente A")
    print(f"  Solo recibió patrones abstractos con phi garantizado")
    print(f"{'═'*60}\n")

    import os
    os.unlink(db)
