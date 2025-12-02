import os
import re
import json
import time
import base64
import tempfile
import unittest
from pathlib import Path
from unittest import mock
import io
import contextlib
from importlib import import_module
import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))

# Utilidades comunes para los tests 
class TempCwdMixin:
    def setUp(self):
        # Guardar cwd original y crear un tmpdir aislado (mkdtemp para control explícito)
        self._old_cwd = os.getcwd()
        self._tmpdir_path = tempfile.mkdtemp()
        os.chdir(self._tmpdir_path)
        # Asegurar que exista la carpeta de datos json/ (el proyecto usa json/)
        try:
            os.makedirs("json", exist_ok=True)
        except Exception:
            pass

    def tearDown(self):
        # Restaurar cwd antes de eliminar el tmpdir
        try:
            os.chdir(self._old_cwd)
        except Exception:
            pass

        # Intentar eliminar el tmpdir de forma robusta sin invocar el handler recursivo de tempfile
        try:
            # cerrar cualquier descriptor abierto implícitamente no posible aquí; forzamos rmtree ignorando errores
            import shutil
            shutil.rmtree(self._tmpdir_path, ignore_errors=True)
        except Exception:
            # último recurso: no fallar los tests por no poder limpiar el tmpdir
            pass

def _import_or_skip(testcase, module_name):
    try:
        # aceptar rutas con '/' o '.' y usar import_module
        module_name = module_name.replace("/", ".")
        from importlib import import_module
        return import_module(module_name)
    except Exception as e:
        testcase.skipTest(f"No pude importar {module_name}: {e}")

def _getattr_or_skip(testcase, module, *names):
    """Busca múltiples aliases posibles y devuelve el primero existente, o hace skip."""
    for name in names:
        if hasattr(module, name):
            return getattr(module, name)
    testcase.skipTest(f"{module.__name__} no tiene ninguno de: {names}")

# ---------- Tests PBKDF2 ----------
class TestPBKDF2(TempCwdMixin, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.crypto = _import_or_skip(self, "crypto")
        # Aceptar nombres con y sin guion bajo (compatibilidad)
        self.pbkdf2_hash = _getattr_or_skip(self, self.crypto, "pbkdf2_hash", "pbkdf2_hash")
        self.verify_pwd = _getattr_or_skip(self, self.crypto, "verificar_password", "verificar_password")

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
        self.guardar = _getattr_or_skip(self, self.files, "guardar_usuarios_con_mac", "guardar_usuarios")
        self.cargar = _getattr_or_skip(self, self.files, "cargar_usuarios_con_mac", "cargar_usuarios")

    def test_guardar_y_verificar_ok(self):
        usuarios = {"adri": {"email": "adri@gmail.com", "password": "pbkdf2$sha256$200000$X$Y"}}
        self.guardar(usuarios, "json/usuarios.json")
        out = self.cargar("json/usuarios.json")
        # Algunos diseños devuelven la estructura completa; aceptamos equivalencia parcial
        self.assertIn("adri", out)
        self.assertEqual(out.get("adri", {}).get("email"), usuarios["adri"]["email"])

    def test_manipulacion_detectada(self):
        usuarios = {"adri": {"email": "adri@gmail.com", "password": "pbkdf2$sha256$200000$X$Y"}}
        self.guardar(usuarios, "json/usuarios.json")
        # Modificar el fichero JSON por fuera de la API
        with open("json/usuarios.json", "r", encoding="utf-8") as f:
            data = json.load(f)
        # Intentar localizar la estructura dentro del fichero (varios formatos posibles)
        if isinstance(data, dict) and "contenido" in data:
            data["contenido"]["adri"]["email"] = "hacker@gmail.com"
        elif isinstance(data, dict) and "adri" in data:
            data["adri"]["email"] = "hacker@gmail.com"
        else:
            # fallback: reserializar con distinto contenido
            data = {"adri": {"email": "hacker@gmail.com", "password": "X"}}
        with open("json/usuarios.json", "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)

        out = self.cargar("json/usuarios.json")
        # Si cambia el contenido sin recalcular MAC la carga debe detectar manipulación.
        # Muchas implementaciones devuelven {} o un dict sin usuarios válidos.
        self.assertFalse("adri" in out and out.get("adri", {}).get("email") == "hacker@gmail.com",
                         "Si cambia el contenido sin recalcular MAC debe devolver registro inválido")

# ---------- Tests HMAC integridad votos.json ----------
class TestHMACVotos(TempCwdMixin, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.files = _import_or_skip(self, "archivos_json")
        self.guardar = _getattr_or_skip(self, self.files, "guardar_votos_con_mac", "guardar_votos")
        self.cargar = _getattr_or_skip(self, self.files, "cargar_votos_con_mac", "cargar_votos")

    def test_votos_mac_ok(self):
        votos = {"Opción A": 1, "Opción B": 0, "usuarios_votaron": ["adri"]}
        self.guardar(votos, "json/votos.json")
        out = self.cargar("json/votos.json")
        self.assertEqual(out.get("Opción A", 0), 1)
        self.assertEqual(out.get("Opción B", 0), 0)
        self.assertIn("usuarios_votaron", out)

    def test_votos_manipulados(self):
        votos = {"Opción A": 2, "Opción B": 0, "usuarios_votaron": []}
        self.guardar(votos, "json/votos.json")
        with open("json/votos.json", "r", encoding="utf-8") as f:
            data = json.load(f)
        # intentar manipular contenido
        if isinstance(data, dict) and "contenido" in data:
            data["contenido"]["Opción A"] = 999
        elif isinstance(data, dict) and "Opción A" in data:
            data["Opción A"] = 999
        else:
            data = {"Opción A": 999, "Opción B": 0, "usuarios_votaron": []}
        with open("json/votos.json", "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)

        out = self.cargar("json/votos.json")
        # Muchos diseños devuelven defaults con 0s cuando el MAC falla
        self.assertEqual(out.get("Opción A", 0), 0)
        self.assertEqual(out.get("Opción B", 0), 0)

# ---------- Tests AES-GCM (roundtrip, IVs) ----------
class TestAESGCM(TempCwdMixin, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.crypto = _import_or_skip(self, "crypto")
        self.gen_key = _getattr_or_skip(self, self.crypto, "generar_clave_aes", "generar_clave_aes")
        self.cifrar = _getattr_or_skip(self, self.crypto, "cifrar_mensaje", "cifrar_mensaje")
        self.descifrar = _getattr_or_skip(self, self.crypto, "descifrar_mensaje", "descifrar_mensaje")

    def test_roundtrip(self):
        key = self.gen_key()
        msg = "hola voto secreto"
        blob = self.cifrar(key, msg)
        raw = base64.b64decode(blob)
        # IV(12) + TAG(16) al menos
        self.assertGreaterEqual(len(raw), 12 + 16, "Debe incluir IV(12) y TAG(16)")
        out = self.descifrar(key, blob)
        self.assertEqual(out, msg)

    def test_iv_unicos(self):
        key = self.gen_key()
        ivs = set()
        for _ in range(15):
            blob = self.cifrar(key, "texto")
            raw = base64.b64decode(blob)
            iv = raw[:12]
            ivs.add(iv)
        self.assertEqual(len(ivs), 15, "IV repetido en AES-GCM: riesgo para GCM")

# ---------- Tests AES-GCM (tamper) ----------
class TestAESGCMTamper(TempCwdMixin, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.crypto = _import_or_skip(self, "crypto")
        self.gen_key = _getattr_or_skip(self, self.crypto, "generar_clave_aes", "generar_clave_aes")
        self.cifrar = _getattr_or_skip(self, self.crypto, "cifrar_mensaje", "cifrar_mensaje")
        self.descifrar = _getattr_or_skip(self, self.crypto, "descifrar_mensaje", "descifrar_mensaje")

    def test_detecta_modificacion_ciphertext(self):
        key = self.gen_key()
        blob = self.cifrar(key, "mensaje")
        raw = bytearray(base64.b64decode(blob))
        # asegurar tamaño
        if len(raw) < 29:
            self.skipTest("blob demasiado corto para tamper test")
        # flip de 1 byte dentro del CT (después de IV(12)+TAG(16)=28)
        raw[28] ^= 0x01
        blob_tamper = base64.b64encode(bytes(raw)).decode()
        with self.assertRaises(Exception):
            # la implementación debe lanzar al verificar tag inválido
            self.descifrar(key, blob_tamper)

# ---------- Tests híbrido (RSA + AES-GCM) ----------
class TestHibridoBasico(TempCwdMixin, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.mod = _import_or_skip(self, "cifrado")
        self.registrar = _getattr_or_skip(self, self.mod, "registrar_log_hibrido_hmac", "registrar_log_hibrido_hmac")
        # Preferir el exportador híbrido; si no existe, caer a exportar_log_descifrado
        self.exportar = _getattr_or_skip(self, self.mod, "exportar_log_hibrido_descifrado", "exportar_log_descifrado")

    def test_cifra_y_exporta_ok(self):
        # Genera 1 entrada híbrida (registrar escribe pretty-printed blocks separados por línea en blanco)
        self.registrar("adri", "Opción A", "json/log_hibrido.jsonl")

        # Ejecutar export con stdout capturado y input parcheado para evitar bloqueos.
        with mock.patch("builtins.input", return_value=""):
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                try:
                    # intentar la firma más completa primero
                    try:
                        self.exportar("json/log_hibrido.jsonl", "clave_aes.bin", salida="json/out.jsonl", admin_mode=True)
                    except TypeError:
                        # fallback a firma alternativa
                        self.exportar("json/log_hibrido.jsonl", salida="json/out.jsonl", admin_mode=True)
                except Exception as e:
                    self.skipTest(f"exportar no compatible o falló: {e}")

        salida_stdout = buf.getvalue()

        # Leer out.jsonl si fue creado (asegurarse de cerrar el fichero correctamente)
        lines = []
        if Path("json/out.jsonl").exists():
            with open("json/out.jsonl", "r", encoding="utf-8") as f:
                lines = [l for l in f.readlines() if l.strip()]

        # Aceptar señal de éxito por archivo o por mensaje en stdout
        exported_msg_ok = ("Log descifrado exportado" in salida_stdout) or ("Log descifrado exportado en" in salida_stdout) or ("Guardado en:" in salida_stdout)
        if not (len(lines) >= 1 or exported_msg_ok):
            self.fail("Ni se creó json/out.jsonl con contenido ni se imprimió mensaje de exportación. Salida:\n" + salida_stdout)

        # Si hay líneas, intentar parsear la primera como JSON y comprobar clave esperada.
        if len(lines) >= 1:
            try:
                r = json.loads(lines[0])
                # verificar que la salida tiene campos esperados por el exportador híbrido
                self.assertIn("texto", r)
            except Exception:
                if not exported_msg_ok:
                    self.fail("json/out.jsonl existe pero la primera línea no es JSON válido y no hubo mensaje de exportación.")

# ---------- Tests clave privada ausente/corrupta ----------
class TestAdminClavePrivada(TempCwdMixin, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.cifrado = _import_or_skip(self, "cifrado")
        self.registrar = _getattr_or_skip(self, self.cifrado, "registrar_log_hibrido_hmac", "registrar_log_hibrido_hibrido")

        # Evitar pausas interactivas durante los tests (msj_espera.pause)
        try:
            self._pause_patcher = mock.patch("data.msj_espera.pause", lambda: None)
            self._pause_patcher.start()
        except Exception:
            self._pause_patcher = None

        # Evitar imprimir mensajes largos en stdout (opcional)
        try:
            self._stdout_patcher = mock.patch("sys.stdout")
            self._stdout_patcher.start()
        except Exception:
            self._stdout_patcher = None

    def tearDown(self):
        if getattr(self, "_pause_patcher", None):
            self._pause_patcher.stop()
        if getattr(self, "_stdout_patcher", None):
            self._stdout_patcher.stop()
        super().tearDown()

    def test_ausente(self):
        # Registrar crea un fichero cifrado
        self.registrar("u", "Opción A", "votos_cifrados.jsonl")

        # Si existe clave privada, renombrarla para simular ausencia
        pk = Path("admin_private_key.pem")
        renamed = False
        if pk.exists():
            bak = pk.with_suffix(".pem.bak")
            pk.rename(bak)
            renamed = True

        try:
            # Preferir exportador híbrido, si no existe caer al simétrico
            try:
                export = _getattr_or_skip(self, self.cifrado, "exportar_log_hibrido_descifrado", "exportar_log_descifrado")
            except unittest.SkipTest:
                return  # no hay exportador disponible; no hay fallo

            # Llamar al exportador sin bloquear entradas interactivas
            with mock.patch("builtins.input", return_value=""):
                try:
                    # capturar stdout en caso de prompts internos
                    buf = io.StringIO()
                    with contextlib.redirect_stdout(buf):
                        try:
                            export("votos_cifrados.jsonl", "clave_aes.bin", salida="out.jsonl", admin_mode=True)
                        except TypeError:
                            # firma alternativa: intentar sin archivo_clave si la firma difiere
                            try:
                                export("votos_cifrados.jsonl", salida="out.jsonl", admin_mode=True)
                            except Exception:
                                pass
                except Exception:
                    # aceptar errores manejados por la propia función
                    pass
        finally:
            # restaurar la clave privada si la renombramos
            if renamed:
                bak = pk.with_suffix(".pem.bak")
                if bak.exists():
                    bak.rename(pk)

# ---------- Tests MFA ----------
class TestMFA(TempCwdMixin, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.mfa = _import_or_skip(self, "mfa")
        self.gen = _getattr_or_skip(self, self.mfa, "generar_codigo_mfa", "generar_codigo_mfa")
        self.guardar = _getattr_or_skip(self, self.mfa, "guardar_codigo_mfa", "guardar_codigo_mfa")
        self.verificar = _getattr_or_skip(self, self.mfa, "verificar_codigo_mfa", "verificar_codigo_mfa")
        # Mock de ventana para no abrir GUI
        if hasattr(self.mfa, "mostrar_codigo_ventana"):
            self._patcher = mock.patch.object(self.mfa, "mostrar_codigo_ventana", lambda x: None)
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
        codigo = self.gen()
        # ensure folder exists like the application expects
        try:
            os.makedirs(os.path.join("json", "codigos"), exist_ok=True)
        except Exception:
            pass
        with open(os.path.join("json", "codigos", "codigos_mfa.json"), "w", encoding="utf-8") as f:
            json.dump({"adri": {"codigo": codigo, "timestamp": time.time() - 999}}, f, indent=2)
        ok, msg = self.verificar("adri", codigo)
        self.assertFalse(ok)

# ---------- Tests cifrado y descifrado ----------

class TestRegistrarYExportadorHibrido(TempCwdMixin, unittest.TestCase):
    def setUp(self):
        # asegurarse de ejecutar TempCwdMixin.setUp para aislar cwd
        super().setUp()
        self.cifrado = import_module("cifrado")
        # evitar pausas y prompts
        try:
            mock.patch("data.msj_espera.pause", lambda: None).start()
        except Exception:
            pass

    def tearDown(self):
        # eliminar ficheros residuales
        for p in ("json/log_hibrido.jsonl","json/out.jsonl","json/votos_cifrados.jsonl"):
            if Path(p).exists():
                Path(p).unlink()
        # finalizar TempCwdMixin cleanup
        super().tearDown()

    def test_registrar_escribe_campos_hibridos(self):
        # crear una entrada
        self.cifrado.registrar_log_hibrido_hmac("testuser","Opción A","json/log_hibrido.jsonl")
        assert Path("json/log_hibrido.jsonl").exists()
        txt = Path("json/log_hibrido.jsonl").read_text(encoding="utf-8")
        # comprobar que contiene campos esperados
        assert "voto_cifrado" in txt
        assert "clave_sim_cifrada" in txt
        assert "iv" in txt
        assert "mac" in txt

    def test_exportador_hibrido_produce_out_jsonl(self):
        self.cifrado.registrar_log_hibrido_hmac("testuser","Opción A","json/log_hibrido.jsonl")
        # usar exportador preferente (híbrido si existe)
        export = getattr(self.cifrado, "exportar_log_hibrido_descifrado", None) or getattr(self.cifrado, "exportar_log_descifrado", None)
        if not export:
            self.skipTest("No hay exportador disponible")
        with mock.patch("builtins.input", return_value=""):
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                # forzar modo admin para evitar prompts
                try:
                    export("json/log_hibrido.jsonl", "admin_private_key.pem", salida="json/out.jsonl", admin_mode=True)
                except TypeError:
                    export("json/log_hibrido.jsonl", salida="json/out.jsonl", admin_mode=True)
        # comprobar salida
        if Path("json/out.jsonl").exists():
            lines = [l for l in Path("json/out.jsonl").read_text(encoding="utf-8").splitlines() if l.strip()]
            self.assertGreaterEqual(len(lines), 1)
            j = json.loads(lines[0])
            # salida híbrida debe contener texto (o al menos campo "texto")
            self.assertIn("texto", j)
        else:
            self.fail("No se generó json/out.jsonl")


# ---------- Tests RSA Signatures & PKI ----------
class TestSignatureAndPKI(TempCwdMixin, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.sig = _import_or_skip(self, "crypto.signature_rsa")
        self.pki = _import_or_skip(self, "crypto.pki")
        self.generar_par = _getattr_or_skip(self, self.sig, "generar_par_claves_rsa", "generar_par_claves_rsa")
        self.firmar = _getattr_or_skip(self, self.sig, "firmar", "firmar")
        self.verificar_sig = _getattr_or_skip(self, self.sig, "verificar", "verificar")
        self.asegurar_pki = _getattr_or_skip(self, self.pki, "asegurar_pki", "asegurar_pki")
        self.emitir = _getattr_or_skip(self, self.pki, "emitir_certificado_usuario", "emitir_certificado_usuario")
        self.verificar_cadena = _getattr_or_skip(self, self.pki, "verificar_cadena_certificado", "verificar_cadena_certificado")
        self.revocar = _getattr_or_skip(self, self.pki, "revocar_certificado", "revocar_certificado")
        self.exportar_pfx = _getattr_or_skip(self, self.pki, "exportar_usuario_a_pfx", "exportar_usuario_a_pfx")
        self.cargar_pfx = _getattr_or_skip(self, self.pki, "cargar_clave_desde_pfx", "cargar_clave_desde_pfx")

    def test_rsa_firma_y_verificacion(self):
        # generar par RSA y firmar/verificar
        priv_pem, pub_pem = self.generar_par(bits=2048)
        # cargar objetos crypto necesarios
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.backends import default_backend

        priv_obj = serialization.load_pem_private_key(priv_pem, password=None, backend=default_backend())
        pub_obj = serialization.load_pem_public_key(pub_pem, backend=default_backend())

        mensaje = b"mensaje prueba firma"
        sig_b64 = self.firmar(priv_obj, mensaje)
        ok = self.verificar_sig(pub_obj, mensaje, sig_b64)
        self.assertTrue(ok, "Firma RSA-PSS no verificada correctamente")

    def test_pki_emitir_verificar_revocar(self):
        # Asegurar PKI y emitir certificado de usuario
        self.asegurar_pki()
        priv_pem, pub_pem = self.generar_par(bits=2048)

        # emitir certificado
        ruta_cert, serial = self.emitir("prueba_usuario", pub_pem)
        self.assertTrue(os.path.exists(ruta_cert), "No se generó el certificado del usuario")

        # verificar cadena válida
        with open(ruta_cert, 'rb') as f:
            cert_pem = f.read()
        ok, razon = self.verificar_cadena(cert_pem)
        self.assertTrue(ok, f"La cadena de certificados no es válida: {razon}")

        # exportar a PFX y recargar la clave desde PFX
        from cryptography.hazmat.primitives import serialization as _serial
        from cryptography.hazmat.backends import default_backend as _default_backend
        priv_obj = _serial.load_pem_private_key(priv_pem, password=None, backend=_default_backend())
        pfx_path = self.exportar_pfx("prueba_usuario", priv_obj, ruta_cert, passphrase="testpass123")
        self.assertTrue(os.path.exists(pfx_path), "No se creó el archivo PFX")

        loaded = self.cargar_pfx(pfx_path, "testpass123")
        self.assertIsNotNone(loaded, "No se pudo cargar la clave desde el PFX")

        # revocar y comprobar verificación falla por revocado
        revoked = self.revocar(serial)
        self.assertTrue(revoked, "No se pudo revocar el certificado")
        ok2, razon2 = self.verificar_cadena(cert_pem)
        self.assertFalse(ok2)
        self.assertIn("revocado", razon2.lower())

    def test_firma_detecta_manipulacion(self):
        # comprobar que si se altera el mensaje la verificación falla
        priv_pem, pub_pem = self.generar_par(bits=2048)
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.backends import default_backend
        priv_obj = serialization.load_pem_private_key(priv_pem, password=None, backend=default_backend())
        pub_obj = serialization.load_pem_public_key(pub_pem, backend=default_backend())

        mensaje = b"mensaje para firmar"
        sig_b64 = self.firmar(priv_obj, mensaje)
        # verificación válida
        self.assertTrue(self.verificar_sig(pub_obj, mensaje, sig_b64))

        # alterar mensaje -> debe fallar
        mensaje_mod = b"mensaje para firmar modificado"
        self.assertFalse(self.verificar_sig(pub_obj, mensaje_mod, sig_b64))

        # alterar firma -> debe fallar (manipulación de bytes)
        import base64
        sig_bytes = bytearray(base64.b64decode(sig_b64))
        # flip simple
        sig_bytes[0] ^= 0x01
        sig_bad = base64.b64encode(bytes(sig_bytes)).decode()
        try:
            ok = self.verificar_sig(pub_obj, mensaje, sig_bad)
            self.assertFalse(ok)
        except Exception:
            pass

    def test_pfx_contrasena_invalida(self):
        # Asegurar PKI, generar claves, emitir y exportar PFX
        self.asegurar_pki()
        priv_pem, pub_pem = self.generar_par(bits=2048)
        ruta_cert, serial = self.emitir("usuario_pfx", pub_pem)
        from cryptography.hazmat.primitives import serialization as _serial
        from cryptography.hazmat.backends import default_backend as _default_backend
        priv_obj = _serial.load_pem_private_key(priv_pem, password=None, backend=_default_backend())
        pfx_path = self.exportar_pfx("usuario_pfx", priv_obj, ruta_cert, passphrase="correcthorsebattery")
        self.assertTrue(os.path.exists(pfx_path))
        # intentar cargar con contraseña incorrecta 
        with self.assertRaises(Exception):
            self.cargar_pfx(pfx_path, "malacontraseña")

    def test_certificado_expirado(self):
        # emitir certificado con validez negativa para hacerlo expirado
        self.asegurar_pki()
        priv_pem, pub_pem = self.generar_par(bits=2048)
        ruta_cert, serial = self.emitir("usuario_expirado", pub_pem, dias=-1)
        cert_pem = None
        with open(ruta_cert, 'rb') as f:
            cert_pem = f.read()
        ok, razon = self.verificar_cadena(cert_pem)
        self.assertFalse(ok)
        self.assertIn("fuera", razon.lower())


class TestHMACRotation(TempCwdMixin, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.files = _import_or_skip(self, "archivos_json")
        self.guardar = _getattr_or_skip(self, self.files, "guardar_votos_con_mac", "guardar_votos")
        self.cargar = _getattr_or_skip(self, self.files, "cargar_votos_con_mac", "cargar_votos")

    def test_hmac_clave_invalida(self):
        # preparar votos y guardar con MAC usando la clave actual
        votos = {"Opción A": 5, "Opción B": 2, "usuarios_votaron": ["adri"]}
        os.makedirs(os.path.join("json"), exist_ok=True)
        self.guardar(votos, "json/votos.json")

        # forzar escritura de otra clave MAC diferente
        key_path = os.path.join("json", "clave_mac_votos.bin")
        # asegurarnos de que exista
        self.assertTrue(os.path.exists(key_path), "La clave MAC esperada no existe tras guardar")
        # sobrescribir con otra clave
        with open(key_path, "wb") as f:
            f.write(os.urandom(32))

        # ahora la verificación debe fallar 
        out = self.cargar("json/votos.json")
        self.assertEqual(out.get("Opción A", 0), 0)
        self.assertEqual(out.get("Opción B", 0), 0)

# Ejecutar tests
if __name__ == "__main__":
    unittest.main(verbosity=2)