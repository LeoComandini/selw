import wallycore as wally

from selw.key import *
from selw.constants import *


class ElementsOutput(object):
    """Base class for Elements outputs"""

    def __init__(self, key, blinding_key):
        _key = ECKey()
        _key.prv = key
        _blinding_key = ECKey()
        _blinding_key.prv = blinding_key
        self.key = _key
        self.blinding_key = _blinding_key


class P2wpkhElementsOutput(ElementsOutput):
    """P2WPKH output"""

    def __init__(self, key, blinding_key):
        super().__init__(key, blinding_key)

    @property
    def witness_script(self) -> bytes:
        return self.key.pub

    @property
    def witness_program(self) -> bytes:
        return wally.sha256(self.witness_script)

    @property
    def scriptcode(self) -> bytes:
        return wally.scriptpubkey_p2pkh_from_bytes(self.witness_script, wally.WALLY_SCRIPT_HASH160)

    @property
    def redeem_script(self) -> bytes:
        raise NotImplementedError

    @property
    def scriptpubkey(self) -> bytes:
        return wally.witness_program_from_bytes(self.witness_script, wally.WALLY_SCRIPT_HASH160)

    @property
    def unconf_address(self) -> str:
        return wally.addr_segwit_from_bytes(self.scriptpubkey, BECH32_FAMILY_TESTNET_LIQUID, 0)

    @property
    def conf_address(self) -> str:
        return wally.confidential_addr_from_addr_segwit(
            self.unconf_address(), BECH32_FAMILY_TESTNET_LIQUID, BLECH32_FAMILY_TESTNET_LIQUID, self.blinding_key.pub)

    def sign(self, h):
        """Produce a DER encoded signature using the user key"""
        return self.key.sign(h)

    @property
    def script_sig(self) -> bytes:
        return b''

    def get_signed_witness_stack(self, h, sighash):
        return [
            self.sign(h) + bytes([sighash]),
            self.witness_script]

    def get_signed_witness(self, h, sighash=wally.WALLY_SIGHASH_ALL):
        return wally.tx_witness_stack_create(self.get_signed_witness_stack(h, sighash))
