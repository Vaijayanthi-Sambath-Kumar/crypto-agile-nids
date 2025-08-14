from __future__ import annotations

import base64
import json
import logging
import os
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Optional, Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, padding, ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# ----------------------------------------------------------------------------
# Utilities
# ----------------------------------------------------------------------------

def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")

def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))

def now_ms() -> int:
    return int(time.time() * 1000)

# ----------------------------------------------------------------------------
# Key material and rotation
# ----------------------------------------------------------------------------

@dataclass
class AESKey:
    key: bytes
    created_ms: int = field(default_factory=now_ms)
    version: int = 1

@dataclass
class RSAKeypair:
    private_key_pem: bytes
    public_key_pem: bytes
    created_ms: int = field(default_factory=now_ms)
    version: int = 1

@dataclass
class ECCKeypair:
    private_key_pem: bytes
    public_key_pem: bytes
    created_ms: int = field(default_factory=now_ms)
    version: int = 1

class KeyManager:
    """
    Minimal in-memory key manager.
    Swap out with HSM/KMS or disk-backed keystore for production.
    Provides time-based AND usage-count-based rotation options.
    """
    def __init__(self,
                 aes_key: Optional[AESKey] = None,
                 rsa_keys: Optional[RSAKeypair] = None,
                 ecc_keys: Optional[ECCKeypair] = None,
                 rotate_minutes: int = 60,
                 max_uses_per_key: int = 10000) -> None:
        self.logger = logging.getLogger(self.__class__.__name__)
        self.rotate_minutes = rotate_minutes
        self.max_uses_per_key = max_uses_per_key

        self.aes_key = aes_key or self._generate_aes_key()
        self.rsa_keys = rsa_keys or self._generate_rsa_keypair()
        self.ecc_keys = ecc_keys or self._generate_ecc_keypair()

        self.uses_aes = 0
        self.uses_rsa = 0
        self.uses_ecc = 0

    # --- generation helpers ---

    def _generate_aes_key(self) -> AESKey:
        key = os.urandom(32)  # 256-bit
        return AESKey(key=key, version=int(time.time()))

    def _generate_rsa_keypair(self) -> RSAKeypair:
        prv = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        priv_pem = prv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        pub_pem = prv.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return RSAKeypair(private_key_pem=priv_pem, public_key_pem=pub_pem,
                          version=int(time.time()))

    def _generate_ecc_keypair(self) -> ECCKeypair:
        prv = ec.generate_private_key(ec.SECP256R1())
        priv_pem = prv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        pub_pem = prv.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return ECCKeypair(private_key_pem=priv_pem, public_key_pem=pub_pem,
                          version=int(time.time()))

    # --- getters ---

    def get_aes_key(self) -> AESKey:
        self._maybe_rotate('AES')
        self.uses_aes += 1
        return self.aes_key

    def get_rsa_keys(self) -> RSAKeypair:
        self._maybe_rotate('RSA')
        self.uses_rsa += 1
        return self.rsa_keys

    def get_ecc_keys(self) -> ECCKeypair:
        self._maybe_rotate('ECC')
        self.uses_ecc += 1
        return self.ecc_keys

    # --- rotation policy ---

    def _maybe_rotate(self, alg: str) -> None:
        age_minutes = (time.time() * 1000 - {
            'AES': self.aes_key.created_ms,
            'RSA': self.rsa_keys.created_ms,
            'ECC': self.ecc_keys.created_ms
        }[alg]) / 60000.0

        uses = {
            'AES': self.uses_aes,
            'RSA': self.uses_rsa,
            'ECC': self.uses_ecc
        }[alg]

        if age_minutes >= self.rotate_minutes or uses >= self.max_uses_per_key:
            self.logger.info("Rotating %s keys (age=%.1f min, uses=%d)", alg, age_minutes, uses)
            if alg == 'AES':
                self.aes_key = self._generate_aes_key()
                self.uses_aes = 0
            elif alg == 'RSA':
                self.rsa_keys = self._generate_rsa_keypair()
                self.uses_rsa = 0
            elif alg == 'ECC':
                self.ecc_keys = self._generate_ecc_keypair()
                self.uses_ecc = 0

def default_key_manager() -> KeyManager:
    """Helper to create a KeyManager with fresh keys."""
    logging.basicConfig(level=logging.INFO)
    return KeyManager()

# ----------------------------------------------------------------------------
# Encryptor strategies
# ----------------------------------------------------------------------------

class Encryptor:
    name: str
    def encrypt(self, plaintext: bytes, meta: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        raise NotImplementedError
    def decrypt(self, payload: Dict[str, Any]) -> bytes:
        raise NotImplementedError

class AESGCMEncryptor(Encryptor):
    name = "AES-GCM"

    def __init__(self, km: KeyManager) -> None:
        self.km = km

    def encrypt(self, plaintext: bytes, meta: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        k = self.km.get_aes_key()
        aead = AESGCM(k.key)
        nonce = os.urandom(12)  # 96-bit recommended for GCM
        ct = aead.encrypt(nonce, plaintext, None)
        return {
            "alg": "AES-GCM",
            "k_ver": k.version,
            "nonce": b64e(nonce),
            "ciphertext": b64e(ct),
            "meta": meta or {},
            "ts": now_ms()
        }

    def decrypt(self, payload: Dict[str, Any]) -> bytes:
        assert payload["alg"] == "AES-GCM"
        k = self.km.get_aes_key()  # assumes same active AES key version; adapt if multiple versions stored
        if k.version != payload.get("k_ver"):
            # In a real KMS, retrieve by version; here we just warn.
            logging.warning("AES key version mismatch (have=%s, need=%s). Decryption may fail.",
                            k.version, payload.get("k_ver"))
        aead = AESGCM(k.key)
        nonce = b64d(payload["nonce"])
        ct = b64d(payload["ciphertext"])
        return aead.decrypt(nonce, ct, None)

class RSAHybridEncryptor(Encryptor):
    """
    RSA-OAEP wraps a fresh content key (AES-GCM) which encrypts the payload.
    """
    name = "RSA-HYBRID"

    def __init__(self, km: KeyManager) -> None:
        self.km = km

    def _load_pub(self, pem: bytes):
        return serialization.load_pem_public_key(pem)

    def _load_prv(self, pem: bytes):
        return serialization.load_pem_private_key(pem, password=None)

    def encrypt(self, plaintext: bytes, meta: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        rsa_keys = self.km.get_rsa_keys()
        pub = self._load_pub(rsa_keys.public_key_pem)

        # Generate ephemeral content key
        cek = os.urandom(32)
        aes = AESGCM(cek)
        nonce = os.urandom(12)
        ct = aes.encrypt(nonce, plaintext, None)

        # Wrap CEK with RSA-OAEP(SHA256)
        wrapped = pub.encrypt(
            cek,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                         algorithm=hashes.SHA256(),
                         label=None)
        )

        return {
            "alg": "RSA-HYBRID",
            "k_ver": rsa_keys.version,
            "nonce": b64e(nonce),
            "ciphertext": b64e(ct),
            "wrapped_cek": b64e(wrapped),
            "meta": meta or {},
            "ts": now_ms(),
            "pub_key_fpr": b64e(rsa_keys.public_key_pem[:24])  # light fingerprint for routing
        }

    def decrypt(self, payload: Dict[str, Any]) -> bytes:
        assert payload["alg"] == "RSA-HYBRID"
        rsa_keys = self.km.get_rsa_keys()
        prv = self._load_prv(rsa_keys.private_key_pem)

        wrapped = b64d(payload["wrapped_cek"])
        cek = prv.decrypt(
            wrapped,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                         algorithm=hashes.SHA256(),
                         label=None)
        )
        nonce = b64d(payload["nonce"])
        ct = b64d(payload["ciphertext"])
        aes = AESGCM(cek)
        return aes.decrypt(nonce, ct, None)

class ECCHybridEncryptor(Encryptor):
    """
    ECIES-like: ephemeral ECDH (secp256r1) + HKDF-SHA256 → AES-GCM.
    """
    name = "ECC-HYBRID"

    def __init__(self, km: KeyManager) -> None:
        self.km = km

    def _load_pub(self, pem: bytes):
        return serialization.load_pem_public_key(pem)

    def _load_prv(self, pem: bytes):
        return serialization.load_pem_private_key(pem, password=None)

    def encrypt(self, plaintext: bytes, meta: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        ecc_keys = self.km.get_ecc_keys()
        recipient_pub = self._load_pub(ecc_keys.public_key_pem)

        # Ephemeral key for sender
        eph_private = ec.generate_private_key(ec.SECP256R1())
        shared = eph_private.exchange(ec.ECDH(), recipient_pub)

        # Derive CEK via HKDF
        cek = HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                   info=b"ECIES-CEK").derive(shared)

        aes = AESGCM(cek)
        nonce = os.urandom(12)
        ct = aes.encrypt(nonce, plaintext, None)

        # Ship ephemeral public key
        eph_pub_bytes = eph_private.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        return {
            "alg": "ECC-HYBRID",
            "k_ver": ecc_keys.version,
            "nonce": b64e(nonce),
            "ciphertext": b64e(ct),
            "eph_pub": b64e(eph_pub_bytes),
            "meta": meta or {},
            "ts": now_ms(),
            "pub_key_fpr": b64e(ecc_keys.public_key_pem[:24])
        }

    def decrypt(self, payload: Dict[str, Any]) -> bytes:
        assert payload["alg"] == "ECC-HYBRID"
        ecc_keys = self.km.get_ecc_keys()
        prv = self._load_prv(ecc_keys.private_key_pem)

        eph_pub = serialization.load_pem_public_key(b64d(payload["eph_pub"]))
        shared = prv.exchange(ec.ECDH(), eph_pub)
        cek = HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                   info=b"ECIES-CEK").derive(shared)

        nonce = b64d(payload["nonce"])
        ct = b64d(payload["ciphertext"])
        aes = AESGCM(cek)
        return aes.decrypt(nonce, ct, None)

# ----------------------------------------------------------------------------
# Threat-driven selection policy
# ----------------------------------------------------------------------------

@dataclass
class ThreatState:
    score: int = 0           # 0..100
    last_update_ms: int = field(default_factory=now_ms)

class SelectionPolicy:
    """
    Map a threat score to an encryptor choice. Override for custom logic.
    Default buckets:
      0-39   : AES-GCM
      40-74  : ECC-HYBRID
      75-100 : RSA-HYBRID
    """
    def choose(self, state: ThreatState) -> str:
        s = max(0, min(100, int(state.score)))
        if s <= 39:
            return "AES-GCM"
        if s <= 74:
            return "ECC-HYBRID"
        return "RSA-HYBRID"

# ----------------------------------------------------------------------------
# Crypto-agility engine
# ----------------------------------------------------------------------------

class CryptoAgilityEngine:
    def __init__(self,
                 key_manager: KeyManager,
                 policy: Optional[SelectionPolicy] = None) -> None:
        self.logger = logging.getLogger(self.__class__.__name__)
        self.km = key_manager
        self.policy = policy or SelectionPolicy()

        # Strategy instances
        self._enc_map: Dict[str, Encryptor] = {
            "AES-GCM": AESGCMEncryptor(self.km),
            "RSA-HYBRID": RSAHybridEncryptor(self.km),
            "ECC-HYBRID": ECCHybridEncryptor(self.km),
        }

        self.threat = ThreatState()
        self._active_alg = self.policy.choose(self.threat)
        self.logger.info("Initial algorithm: %s", self._active_alg)

    # --- NIDS integration ---

    def update_threat(self, score: int) -> None:
        """Call this whenever your ML NIDS emits a new score (0..100)."""
        self.threat.score = max(0, min(100, int(score)))
        self.threat.last_update_ms = now_ms()
        chosen = self.policy.choose(self.threat)
        if chosen != self._active_alg:
            self.logger.info("Threat score %d → switching %s → %s",
                             self.threat.score, self._active_alg, chosen)
            self._active_alg = chosen

    def get_active_algorithm(self) -> str:
        return self._active_alg

    # --- API surface ---

    def encrypt(self, plaintext: bytes, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Encrypt with the currently selected algorithm.
        `context` is an optional dict (flow ids, user ids, etc.) stored under 'meta'.
        """
        enc = self._enc_map[self._active_alg]
        return enc.encrypt(plaintext, meta=context)

    def decrypt(self, payload: Dict[str, Any]) -> bytes:
        """
        Auto-route decryption based on 'alg' field in the payload.
        """
        alg = payload.get("alg")
        if alg not in self._enc_map:
            raise ValueError(f"Unsupported alg: {alg}")
        return self._enc_map[alg].decrypt(payload)
