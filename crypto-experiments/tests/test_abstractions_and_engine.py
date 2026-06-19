import pytest

from domain.cipher.CipherPrimitive import CipherPrimitive
from domain.engine import EncryptionEngine
from domain.mode.OperationMode import OperationMode


class DummyPrimitive(CipherPrimitive):
    @property
    def block_size(self) -> int:
        return 4

    @property
    def key_size(self) -> int:
        return 4

    def encrypt_block(self, block: bytes) -> bytes:
        if len(block) != self.block_size:
            raise ValueError("bad block")
        return bytes((b + 1) % 256 for b in block)

    def decrypt_block(self, block: bytes) -> bytes:
        if len(block) != self.block_size:
            raise ValueError("bad block")
        return bytes((b - 1) % 256 for b in block)


class DummyMode(OperationMode):
    def encrypt(self, plaintext: bytes, **kwargs) -> bytes:
        return self._primitive.encrypt_blocks(plaintext)

    def decrypt(self, ciphertext: bytes, **kwargs) -> bytes:
        return self._primitive.decrypt_blocks(ciphertext)



def test_cipherprimitive_default_batch_methods_and_repr():
    primitive = DummyPrimitive()
    plain = b"abcdefgh"  # 2 blocks of 4

    encrypted = primitive.encrypt_blocks(plain)
    assert primitive.decrypt_blocks(encrypted) == plain

    assert "DummyPrimitive" in repr(primitive)
    assert "block_size=4" in repr(primitive)

    with pytest.raises(ValueError):
        primitive.encrypt_blocks(b"abc")
    with pytest.raises(ValueError):
        primitive.decrypt_blocks(b"abc")


def test_operationmode_repr_and_primitive_property():
    primitive = DummyPrimitive()
    mode = DummyMode(primitive)

    assert mode.primitive is primitive
    assert "DummyMode" in repr(mode)
    assert "primitive=" in repr(mode)


def test_encryption_engine_success_paths_and_repr():
    primitive = DummyPrimitive()
    mode = DummyMode(primitive)
    engine = EncryptionEngine(primitive, mode)

    plaintext = b"abcdefgh"
    encrypted = engine.encrypt(plaintext)
    assert engine.decrypt(encrypted) == plaintext

    assert engine.primitive is primitive
    assert engine.mode is mode
    assert "EncryptionEngine" in repr(engine)
    assert "DummyPrimitive" in repr(engine)
    assert "DummyMode" in repr(engine)


def test_encryption_engine_rejects_mismatched_mode_primitive():
    primitive_a = DummyPrimitive()
    primitive_b = DummyPrimitive()
    mode_for_b = DummyMode(primitive_b)

    with pytest.raises(ValueError):
        EncryptionEngine(primitive_a, mode_for_b)
