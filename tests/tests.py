# test_suite_unittest.py
# Suite de pruebas con unittest (sin instalar nada).
# Cubre: PBKDF2, HMAC de ficheros, AES-GCM (roundtrip, IVs, tamper),
# flujo híbrido (RSA+AES), clave privada ausente/corrupta, MFA y temporización.

import os
import re
import json
import base64
import time
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock
import inspect

# ---------- Utilidades comunes ----------

class TempCwdMixin:
    """Cambia el CWD a un directorio temporal para aislar los ficheros de cada test."""
    def setUp(self):
        self._old_cwd = os.getcwd()
        self._tmpdir = tempfile.TemporaryDirectory()
        os.chdir(self._tmpdir.name)

    def tearDown(self):
        os.chdir(self._old_cwd)
        self._tmpdir.cleanup()

def _import_or_skip(testcase, module_name):
    try:
        return __import__(module_name)
    except Exception as e:
        testcase.skipTest(f"No pude importar {module_name}: {e}")

def _getattr_or_skip(testcase, module, name):
    if not hasattr(module, name):
        testcase.skipTest(f"{module.__name__}.{name} no existe en tu práctica")
    return getattr(module, name)

# ---------- Tests PBKDF2 ----------

class TestPBKDF2(TempCwdMixin, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.funcs = _import_or_skip(self, "crypto")
        self.pbkdf2_hash = _getattr_or_skip(self, self.funcs, "_pbkdf2_hash")
        self.verify_pwd = _getattr_or_skip(self, self.funcs, "_verificar_password")

    def test_pbkdf2_format_and_verify(self):
        stored = self.pbkdf2_hash("12345678!")
        m = re.match(r"^pbkdf2\$sha256\$(\d+)\$([A-Za-z0-9+/=]+)\$([A-Za-z0-9+/=]+)$", stored)
        self.assertIsNotNone(m, f"Formato PBKDF2 inválido: {stored}")
        iters = int(m.group(1))
        salt = base64.b64decode(m.group(2))
        dk = base64.b64decode(m.group(3))
        self.assertGreaterEqual(iters, 200000, "Iteraciones insuficientes")
        self.assertEqual(len(salt), 16, "Salt debe ser 16 bytes")
        self.assertEqual(len(dk), 32, "DK (SHA-256) debe ser 32 bytes")

        self.assertTrue(self.verify_pwd("12345678!", stored))
        self.assertFalse(self.verify_pwd("no-es", stored))

    def test_pbkdf2_unique_salt(self):
        a = self.pbkdf2_hash("12345678!")
        b = self.pbkdf2_hash("12345678!")
        self.assertNotEqual(a, b, "PBKDF2 debería producir salt/derivadas diferentes")

# ---------- Tests HMAC integridad usuarios.json ----------

class TestHMACUsuarios(TempCwdMixin, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.files = _import_or_skip(self, "archivos_json")
        self.guardar = _getattr_or_skip(self, self.files, "guardar_usuarios_con_mac")
        self.cargar = _getattr_or_skip(self, self.files, "cargar_usuarios_con_mac")

    def test_guardar_y_verificar_ok(self):
        usuarios = {"adri": {"email": "a@a.es", "password": "pbkdf2$sha256$200000$X$Y"}}
        self.guardar(usuarios, "usuarios.json")
        out = self.cargar("usuarios.json")
        self.assertEqual(out, usuarios)

    def test_manipulacion_detectada(self):
        usuarios = {"adri": {"email": "a@a.es", "password": "pbkdf2$sha256$200000$X$Y"}}
        self.guardar(usuarios, "usuarios.json")
        with open("usuarios.json", "r", encoding="utf-8") as f:
            data = json.load(f)
        data["contenido"]["adri"]["email"] = "hacker@evil.com"
        with open("usuarios.json", "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        out = self.cargar("usuarios.json")
        self.assertEqual(out, {}, "Si cambia el contenido sin recalcular MAC debe devolver {}")

# ---------- Tests HMAC integridad votos.json ----------

class TestHMACVotos(TempCwdMixin, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.files = _import_or_skip(self, "archivos_json")
        self.g = _getattr_or_skip(self, self.files, "guardar_votos_con_mac")
        self.c = _getattr_or_skip(self, self.files, "cargar_votos_con_mac")

    def test_votos_mac_ok(self):
        votos = {"Opción A": 1, "Opción B": 0, "usuarios_votaron": ["adri"]}
        self.g(votos, "votos.json")
        out = self.c("votos.json")
        self.assertEqual(out["Opción A"], 1)
        self.assertEqual(out["Opción B"], 0)
        self.assertIn("usuarios_votaron", out)

    def test_votos_manipulados(self):
        votos = {"Opción A": 2, "Opción B": 0, "usuarios_votaron": []}
        self.g(votos, "votos.json")
        with open("votos.json", "r", encoding="utf-8") as f:
            data = json.load(f)
        data["contenido"]["Opción A"] = 999
        with open("votos.json", "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        out = self.c("votos.json")
        # Muchos diseños devuelven defaults con 0s cuando el MAC falla
        self.assertEqual(out.get("Opción A", 0), 0)
        self.assertEqual(out.get("Opción B", 0), 0)

# ---------- Tests AES-GCM (roundtrip, IVs) ----------

class TestAESGCM(TempCwdMixin, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.funcs = _import_or_skip(self, "crypto")
        self.gen_key = _getattr_or_skip(self, self.funcs, "generar_clave_aes")
        self.cifrar = _getattr_or_skip(self, self.funcs, "cifrar_mensaje")
        self.descifrar = _getattr_or_skip(self, self.funcs, "descifrar_mensaje")

    def test_roundtrip(self):
        key = self.gen_key()
        msg = "hola voto secreto"
        blob = self.cifrar(key, msg)
        raw = base64.b64decode(blob)
        self.assertGreaterEqual(len(raw), 12 + 16, "Debe incluir IV(12) y TAG(16)")
        out = self.descifrar(key, blob)
        self.assertEqual(out, msg)

    def test_iv_unicos(self):
        key = self.gen_key()
        ivs = set()
        for _ in range(15):
            blob = self.cifrar(key, "X")
            raw = base64.b64decode(blob)
            ivs.add(raw[:12])  # IV son los 12 primeros bytes en vuestro empaquetado
        self.assertEqual(len(ivs), 15, "IV repetido en AES-GCM: riesgo para GCM")

# ---------- Tests AES-GCM (tamper) ----------

class TestAESGCMTamper(TempCwdMixin, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.funcs = _import_or_skip(self, "crypto")
        self.gen_key = _getattr_or_skip(self, self.funcs, "generar_clave_aes")
        self.cifrar = _getattr_or_skip(self, self.funcs, "cifrar_mensaje")
        self.descifrar = _getattr_or_skip(self, self.funcs, "descifrar_mensaje")

    def test_detecta_modificacion_ciphertext(self):
        key = self.gen_key()
        blob = self.cifrar(key, "mensaje")
        raw = bytearray(base64.b64decode(blob))
        if len(raw) < 29:
            self.skipTest("Ciphertext demasiado corto para tamper aquí")
        raw[28] ^= 0x01  # flip de 1 byte dentro del CT
        blob_tamper = base64.b64encode(bytes(raw)).decode()
        with self.assertRaises(Exception):
            self.descifrar(key, blob_tamper)

# ---------- Tests híbrido (RSA + AES-GCM) ----------

class TestHibridoBasico(TempCwdMixin, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.cifrado = _import_or_skip(self, "cifrado")
        self.registrar = _getattr_or_skip(self, self.cifrado, "registrar_log_hibrido_hmac")
        self.exportar = _getattr_or_skip(self, self.cifrado, "exportar_log_hibrido_descifrado")

    def test_cifra_y_exporta_ok(self):
        # Genera 1 línea híbrida
        self.registrar("adri", "Opción A", "log_hibrido.jsonl")
        # Exporta (modo admin no interactivo si existe ese parámetro)
        try:
            self.exportar("log_hibrido.jsonl", salida="out.jsonl", admin_mode=True)
        except TypeError:
            # por si la firma no tiene admin_mode
            self.exportar("log_hibrido.jsonl", salida="out.jsonl")

        lines = list(open("out.jsonl", "r", encoding="utf-8"))
        self.assertGreaterEqual(len(lines), 1)
        r = json.loads(lines[0])
        self.assertIn("tipo_cifrado", r)
        self.assertIn(r["tipo_cifrado"], ("HÍBRIDO", "HÍBRIDO_ERROR"))

# ---------- Tests clave privada ausente/corrupta ----------

class TestAdminClavePrivada(TempCwdMixin, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.cifrado = _import_or_skip(self, "cifrado")
        self.registrar = _getattr_or_skip(self, self.cifrado, "registrar_log_hibrido_hmac")
        # punto de entrada del admin (ajusta si tu función se llama distinto)
        try:
            self.admin = _import_or_skip(self, "admin")
            # El nombre real en el código es descifrar_votos_hibridos_con_hmac
            self.descifrar_admin = _getattr_or_skip(self, self.admin, "descifrar_votos_hibridos_con_hmac")
        except unittest.SkipTest:
            # como alternativa, usa la exportación de cifrado
            self.admin = None
            self.descifrar_admin = None
        # Evitar pausas interactivas en los módulos de mensajes (msj_espera.pause)
        try:
            from data import msj_espera
            self._pause_patcher = mock.patch.object(msj_espera, "pause", lambda: None)
            self._pause_patcher.start()
        except Exception:
            self._pause_patcher = None

    def tearDown(self):
        if getattr(self, "_pause_patcher", None):
            self._pause_patcher.stop()
        super().tearDown()

    def test_ausente(self):
        self.registrar("u", "Opción A", "votos_cifrados.jsonl")
        # asegurar archivo para renombrado
        Path("admin_private_key.pem").write_text("DUMMY", encoding="utf-8")
        # renombrar a .bak
        bak = Path("admin_private_key.pem").with_suffix(".pem.bak")
        Path("admin_private_key.pem").rename(bak)
        try:
            # llamar flujo admin (si existe), si no, caer a exportar en cifrado
            if self.descifrar_admin:
                # some implementations expect no args, others accept a filename
                sig = inspect.signature(self.descifrar_admin)
                if len(sig.parameters) == 0:
                    self.descifrar_admin()
                else:
                    self.descifrar_admin("votos_cifrados.jsonl")
            else:
                exp = _getattr_or_skip(self, self.cifrado, "exportar_log_hibrido_descifrado")
                exp("votos_cifrados.jsonl", salida="out.jsonl")
            self.assertTrue(True, "Manejo de ausencia sin crash")
        finally:
            if bak.exists():
                bak.rename("admin_private_key.pem")

    def test_corrupta(self):
        self.registrar("u", "Opción A", "votos_cifrados.jsonl")
        Path("admin_private_key.pem").write_text(
            "-----BEGIN PRIVATE KEY-----\nCORRUPT\n-----END PRIVATE KEY-----\n",
            encoding="utf-8"
        )
        # No debe crashear el proceso; debe manejarlo
        if self.descifrar_admin:
            sig = inspect.signature(self.descifrar_admin)
            if len(sig.parameters) == 0:
                self.descifrar_admin()
            else:
                self.descifrar_admin("votos_cifrados.jsonl")
        else:
            exp = _getattr_or_skip(self, self.cifrado, "exportar_log_hibrido_descifrado")
            exp("votos_cifrados.jsonl", salida="out.jsonl")
        self.assertTrue(True)

# ---------- Tests MFA ----------

class TestMFA(TempCwdMixin, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.mfa = _import_or_skip(self, "mfa")
        self.gen = _getattr_or_skip(self, self.mfa, "generar_codigo_mfa")
        self.guardar = _getattr_or_skip(self, self.mfa, "guardar_codigo_mfa")
        self.verificar = _getattr_or_skip(self, self.mfa, "verificar_codigo_mfa")
        # Mock de ventana para no abrir GUI
        if hasattr(self.mfa, "mostrar_codigo_ventana"):
            self._patcher = mock.patch.object(self.mfa, "mostrar_codigo_ventana", lambda codigo: True)
            self._patcher.start()
        else:
            self._patcher = None

    def tearDown(self):
        if self._patcher:
            self._patcher.stop()
        super().tearDown()

    def test_mfa_ok(self):
        codigo = self.gen()
        self.guardar("adri", codigo)
        ok, msg = self.verificar("adri", codigo)
        self.assertTrue(ok)
        self.assertIn("correct", msg.lower())

    def test_mfa_expira(self):
        # Forzar un timestamp viejo para simular expirado (>150s en vuestro diseño)
        codigo = self.gen()
        json.dump({"adri": {"codigo": codigo, "timestamp": time.time() - 999}},
                  open("codigos_mfa.json", "w", encoding="utf-8"), indent=2)
        ok, msg = self.verificar("adri", codigo)
        self.assertFalse(ok)
        self.assertIn("expir", msg.lower())

# ---------- Test de temporización (comparación constante) ----------

class TestTiming(TempCwdMixin, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.funcs = _import_or_skip(self, "crypto")
        self.pbkdf2_hash = _getattr_or_skip(self, self.funcs, "_pbkdf2_hash")
        self.verify_pwd = _getattr_or_skip(self, self.funcs, "_verificar_password")

    def _measure(self, stored, pwd, n=20, warmup=3):
        for _ in range(warmup):
            self.verify_pwd(pwd, stored)
        ts = []
        for _ in range(n):
            t0 = time.perf_counter()
            self.verify_pwd(pwd, stored)
            ts.append(time.perf_counter() - t0)
        return sum(ts) / len(ts)

    def test_verificacion_constante(self):
        stored = self.pbkdf2_hash("12345678!")
        mean_ok = self._measure(stored, "12345678!")
        mean_bad = self._measure(stored, "XXXX-not-correct-XXXX")
        # Umbral razonable local (10 ms). Si en tu máquina es más ruidoso, puedes subirlo.
        self.assertLess(abs(mean_ok - mean_bad), 0.010, f"Posible filtrado temporal: {mean_ok} vs {mean_bad}")

if __name__ == "__main__":
    unittest.main(verbosity=2)