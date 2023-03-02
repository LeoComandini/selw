import wallycore as wally
import requests
import os

from selw.utils import *
from selw.output import *
from selw.utxo import *
from selw.constants import *


class Wallet(object):
    """A Simple wallet consisting in a single address/scriptpubkey"""
    def __init__(self, scriptpubkey, private_blinding_key):
        self.scriptpubkey = scriptpubkey
        self.private_blinding_key = private_blinding_key
        self.utxos = list()
        self.output = None

    def public_blinding_key(self):
        return wally.ec_public_key_from_private_key(self.private_blinding_key)

    def unconf_address(self):
        return wally.addr_segwit_from_bytes(self.scriptpubkey, BECH32_FAMILY_TESTNET_LIQUID, 0)

    def address(self):
        return wally.confidential_addr_from_addr_segwit(
            self.unconf_address(), BECH32_FAMILY_TESTNET_LIQUID, BLECH32_FAMILY_TESTNET_LIQUID, self.public_blinding_key())

    def sync(self, url):
        utxos = requests.get(f"{url}/api/address/{self.unconf_address()}/utxo").json()
        for utxo in utxos:
            txid = utxo.get("txid")
            vout = utxo.get("vout")
            tx = requests.get(f"{url}/api/tx/{txid}/hex").text
            unspent = {
                "txid": txid,
                "vout": vout,
                "scriptpubkey": b2h(self.scriptpubkey),
                "height": utxo.get("status", {}).get("block_height"),
                "asset": utxo.get("asset"),
                "value": utxo.get("value"),
                "valuecommitment": utxo.get("valuecommitment"),
                "assetcommitment": utxo.get("assetcommitment"),
                "noncecommitment": utxo.get("noncecommitment"),
                "tx": tx,
            }
            self.utxos.append(SpendableElementsUTXO(unspent, self.output, self.private_blinding_key))

    def balance(self):
        return _balance(self.utxos)

    @staticmethod
    def set_witness_script(psbt, idx, utxo):
        pass

    def create_psbt(self, utxos, address, asset_hex, value):
        psbt = wally.psbt_init(2, 0, 0, 0, wally.WALLY_PSBT_INIT_PSET)
        for utxo in utxos:
            # Input
            idx = wally.psbt_get_num_inputs(psbt)
            seq = 0xfffffffe
            inp = wally.tx_input_init(utxo.txid, utxo.vout, seq, None, None)
            wally.psbt_add_tx_input_at(psbt, idx, 0, inp)
            # Witness UTXO
            wally.psbt_set_input_witness_utxo_from_tx(psbt, idx, utxo.tx, utxo.vout)
            wally.psbt_set_input_utxo_rangeproof(psbt, idx, utxo.rangeproof)
            self.set_witness_script(psbt, idx, utxo)
            # Add explicit proofs
            wally.psbt_generate_input_explicit_proofs(psbt, idx, utxo.value, utxo.asset, utxo.abf, utxo.vbf, os.urandom(32))
            # Add key path
            self.set_keypaths(psbt, idx, utxo)
        # Add sent output
        # FIXME: handle asset not L-BTC
        asset_tag = bytes([1]) + h2b_rev(asset_hex)
        lbtc_tag = bytes([1]) + h2b_rev(LBTC_HEX)
        assert asset_tag == lbtc_tag
        fee = 500
        spk_send, bpub_send = parse_address(address)
        _value = wally.tx_confidential_value_from_satoshi(value)
        txout_send = wally.tx_elements_output_init(spk_send, asset_tag, _value, bpub_send)
        output_idx = wally.psbt_get_num_outputs(psbt)
        wally.psbt_add_tx_output_at(psbt, output_idx, 0, txout_send)
        wally.psbt_set_output_blinder_index(psbt, output_idx, 0)
        # Add change
        value_change = _balance(utxos)[asset_hex] - value - fee
        assert value_change > 0
        spk_change, bpub_change = parse_address(self.address())
        _value_change = wally.tx_confidential_value_from_satoshi(value_change)
        txout_change = wally.tx_elements_output_init(spk_change, asset_tag, _value_change, bpub_change)
        output_idx = wally.psbt_get_num_outputs(psbt)
        wally.psbt_add_tx_output_at(psbt, output_idx, 0, txout_change)
        wally.psbt_set_output_blinder_index(psbt, output_idx, 0)
        # Add fee output
        _fee = wally.tx_confidential_value_from_satoshi(fee)
        txout_fee = wally.tx_elements_output_init(None, lbtc_tag, _fee)
        output_idx = wally.psbt_get_num_outputs(psbt)
        wally.psbt_add_tx_output_at(psbt, output_idx, 0, txout_fee)
        return wally.psbt_to_base64(psbt, 0)

    @staticmethod
    def blind_psbt(psbt, used_utxos):
        psbt = wally.psbt_from_base64(psbt, 0)
        values = {i: wally.tx_confidential_value_from_satoshi(u.value) for i, u in enumerate(used_utxos)}
        assets = {i: u.asset for i, u in enumerate(used_utxos)}
        vbfs = {i: u.vbf for i, u in enumerate(used_utxos)}
        abfs = {i: u.abf for i, u in enumerate(used_utxos)}

        eph_keys = wally.psbt_blind(
            psbt,
            wally.map_from_dict(values),
            wally.map_from_dict(vbfs),
            wally.map_from_dict(assets),
            wally.map_from_dict(abfs),
            os.urandom(32*5*(wally.psbt_get_num_outputs(psbt)-1)),
            wally.WALLY_PSET_BLIND_ALL,
            0,
        )
        eph_keys = wally.map_to_dict(eph_keys)
        return wally.psbt_to_base64(psbt, 0)

    @staticmethod
    def send_psbt(psbt, url):
        psbt = wally.psbt_from_base64(psbt, 0)
        wally.psbt_finalize(psbt)
        tx = wally.psbt_extract(psbt, 0)
        flags = wally.WALLY_TX_FLAG_USE_WITNESS | wally.WALLY_TX_FLAG_USE_ELEMENTS
        txhex = wally.tx_to_hex(tx, flags)
        txid = requests.post(f"{url}/api/tx", data=txhex).text
        return txid


def _balance(utxos):
    ret = {}
    for utxo in utxos:
        asset_hex = b2h_rev(utxo.asset)
        if asset_hex in ret:
            ret[asset_hex] += utxo.value
        else:
            ret[asset_hex] = utxo.value
    return ret


def parse_address(address):
    # FIXME: add support for pre-segwit
    unconf_address = wally.confidential_addr_to_addr_segwit(address, BLECH32_FAMILY_TESTNET_LIQUID, BECH32_FAMILY_TESTNET_LIQUID)
    scriptpubkey = wally.addr_segwit_to_bytes(unconf_address, BECH32_FAMILY_TESTNET_LIQUID, 0)
    blinding_public_key = wally.confidential_addr_segwit_to_ec_public_key(address, BLECH32_FAMILY_TESTNET_LIQUID)
    return scriptpubkey, blinding_public_key


class WalletP2wpkh(Wallet):
    """A Simple wallet consisting in a single P2WPKH address/scriptpubkey"""
    def __init__(self, private_key, private_blinding_key):
        self.private_key = private_key
        output = P2wpkhElementsOutput(private_key, private_blinding_key)
        super().__init__(output.scriptpubkey, private_blinding_key)
        self.output = output

    @staticmethod
    def set_keypaths(psbt, idx, utxo):
        fingerprint = b'\x00' * 4
        keypaths = wally.map_keypath_public_key_init(1)
        wally.map_keypath_add(keypaths, utxo.output.key.pub, fingerprint, [0])
        wally.psbt_set_input_keypaths(psbt, idx, keypaths)

    @staticmethod
    def sign_psbt(psbt, used_utxos):
        psbt = wally.psbt_from_base64(psbt, 0)
        flags = 0
        for utxo in used_utxos:
            wally.psbt_sign(psbt, utxo.output.key.prv, flags)
        return wally.psbt_to_base64(psbt, 0)


class WalletP2wsh2of3(Wallet):
    """A Simple wallet consisting in a single P2WSH-2OF3 address/scriptpubkey"""
    def __init__(self, keys, private_blinding_key):
        self.keys = keys
        output = P2wsh2of3ElementsOutput(keys, private_blinding_key)
        super().__init__(output.scriptpubkey, private_blinding_key)
        self.output = output

    @staticmethod
    def set_witness_script(psbt, idx, utxo):
        wally.psbt_set_input_witness_script(psbt, idx, utxo.output.witness_script)

    @staticmethod
    def set_keypaths(psbt, idx, utxo):
        fingerprint = b'\x00' * 4
        keypaths = wally.map_keypath_public_key_init(len(utxo.output.keys))
        for key in utxo.output.keys:
            wally.map_keypath_add(keypaths, key.pub, fingerprint, [0])
        wally.psbt_set_input_keypaths(psbt, idx, keypaths)

    @staticmethod
    def sign_psbt(psbt, used_utxos):
        psbt = wally.psbt_from_base64(psbt, 0)
        flags = 0
        for utxo in used_utxos:
            for key in utxo.output.keys:
                if key.prv is not None:
                    wally.psbt_sign(psbt, key.prv, flags)
        return wally.psbt_to_base64(psbt, 0)
