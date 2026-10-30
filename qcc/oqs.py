"""ctypes-обёртка над liboqs (vendor/oqs-install), собранной локально."""

import ctypes
import os
import pathlib

_LIB_PATH = os.environ.get(
    "QCC_LIBOQS",
    str(pathlib.Path(__file__).resolve().parent.parent / "vendor" / "oqs-install" / "lib" / "liboqs.so"),
)

OQS_SUCCESS = 0

_u8p = ctypes.POINTER(ctypes.c_uint8)


class _OQS_SIG(ctypes.Structure):
    # Повторяет struct OQS_SIG из liboqs 0.14 (sig.h)
    _fields_ = [
        ("method_name", ctypes.c_char_p),
        ("alg_version", ctypes.c_char_p),
        ("claimed_nist_level", ctypes.c_uint8),
        ("euf_cma", ctypes.c_bool),
        ("suf_cma", ctypes.c_bool),
        ("sig_with_ctx_support", ctypes.c_bool),
        ("length_public_key", ctypes.c_size_t),
        ("length_secret_key", ctypes.c_size_t),
        ("length_signature", ctypes.c_size_t),
    ]


try:
    _lib = ctypes.CDLL(_LIB_PATH)
except OSError:
    _lib = None

if _lib is not None:
    _lib.OQS_SIG_new.restype = ctypes.POINTER(_OQS_SIG)
    _lib.OQS_SIG_new.argtypes = [ctypes.c_char_p]
    _lib.OQS_SIG_keypair.argtypes = [ctypes.c_void_p, _u8p, _u8p]
    _lib.OQS_SIG_sign.argtypes = [ctypes.c_void_p, _u8p, ctypes.POINTER(ctypes.c_size_t), _u8p, ctypes.c_size_t, _u8p]
    _lib.OQS_SIG_sign_with_ctx_str.argtypes = [
        ctypes.c_void_p, _u8p, ctypes.POINTER(ctypes.c_size_t), _u8p, ctypes.c_size_t, _u8p, ctypes.c_size_t, _u8p,
    ]
    _lib.OQS_SIG_verify.argtypes = [ctypes.c_void_p, _u8p, ctypes.c_size_t, _u8p, ctypes.c_size_t, _u8p]
    _lib.OQS_SIG_verify_with_ctx_str.argtypes = [
        ctypes.c_void_p, _u8p, ctypes.c_size_t, _u8p, ctypes.c_size_t, _u8p, ctypes.c_size_t, _u8p,
    ]
    _lib.OQS_SIG_alg_is_enabled.argtypes = [ctypes.c_char_p]


def available(name):
    return _lib is not None and bool(_lib.OQS_SIG_alg_is_enabled(name.encode()))


def _buf(data):
    return (ctypes.c_uint8 * max(1, len(data))).from_buffer_copy(data or b"\0")


class Sig:
    def __init__(self, name):
        if not available(name):
            raise RuntimeError(f"liboqs: алгоритм {name} недоступен ({_LIB_PATH})")
        self._ptr = _lib.OQS_SIG_new(name.encode())
        info = self._ptr.contents
        self.name = name
        self.pk_size = info.length_public_key
        self.sk_size = info.length_secret_key
        self.max_sig_size = info.length_signature
        self.ctx_support = info.sig_with_ctx_support

    def keypair(self):
        pk = (ctypes.c_uint8 * self.pk_size)()
        sk = (ctypes.c_uint8 * self.sk_size)()
        if _lib.OQS_SIG_keypair(self._ptr, pk, sk) != OQS_SUCCESS:
            raise RuntimeError("OQS_SIG_keypair")
        return bytes(pk), bytes(sk)

    def sign(self, sk, msg, ctx=None):
        sig = (ctypes.c_uint8 * self.max_sig_size)()
        n = ctypes.c_size_t(0)
        if ctx is None:
            rc = _lib.OQS_SIG_sign(self._ptr, sig, ctypes.byref(n), _buf(msg), len(msg), _buf(sk))
        else:
            rc = _lib.OQS_SIG_sign_with_ctx_str(
                self._ptr, sig, ctypes.byref(n), _buf(msg), len(msg), _buf(ctx), len(ctx), _buf(sk)
            )
        if rc != OQS_SUCCESS:
            raise RuntimeError("OQS_SIG_sign")
        return bytes(sig[: n.value])

    def verify(self, pk, msg, sig, ctx=None):
        if ctx is None:
            rc = _lib.OQS_SIG_verify(self._ptr, _buf(msg), len(msg), _buf(sig), len(sig), _buf(pk))
        else:
            rc = _lib.OQS_SIG_verify_with_ctx_str(
                self._ptr, _buf(msg), len(msg), _buf(sig), len(sig), _buf(ctx), len(ctx), _buf(pk)
            )
        return rc == OQS_SUCCESS
