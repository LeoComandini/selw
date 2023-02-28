import wallycore as wally

from selw.utils import b2h, h2b, h2b_rev


class ElementsUTXO(object):
    """Elements UTXO"""

    def __init__(self, unspent):
        """Create ElementsUTXO from scanutxoset (processed) output"""
        self.txid = h2b_rev(unspent.get('txid'))
        self.vout = unspent.get('vout')
        self.scriptpubkey = h2b(unspent.get('scriptpubkey'))
        self.height = unspent.get('height')

        # blinded data
        is_unblinded = unspent.get('asset') and unspent.get('value')
        self.asset = h2b_rev(unspent['asset']) if is_unblinded else None
        self.value = h2b_rev(unspent['value']) if is_unblinded else None
        self.abf = b'\x00' * 32 if self.asset else None
        self.vbf = b'\x00' * 32 if self.value else None

        self.asset_commitment = \
            b'\x01' + self.asset if is_unblinded else \
            h2b(unspent.get('assetcommitment'))
        self.value_commitment = \
            wally.tx_confidential_value_from_satoshi(self.value) if is_unblinded else \
            h2b(unspent.get('valuecommitment'))
        self.nonce_commitment = \
            b'' if is_unblinded else \
            h2b(unspent.get('noncecommitment'))

        flags = wally.WALLY_TX_FLAG_USE_WITNESS | wally.WALLY_TX_FLAG_USE_ELEMENTS
        self.tx = wally.tx_from_hex(unspent['tx'], flags)
        self.rangeproof = wally.tx_get_output_rangeproof(self.tx, self.vout)

    def unblind(self, private_blinding_key):
        if self.is_unblinded():
            return
        self.value, self.asset, self.abf, self.vbf = wally.asset_unblind(
            self.nonce_commitment, private_blinding_key, self.rangeproof, self.value_commitment,
            self.scriptpubkey, self.asset_commitment)

    def is_unblinded(self):
        return 1 == self.asset_commitment[0] == self.value_commitment[0]


class SpendableElementsUTXO(ElementsUTXO):
    """Elements unblinded UTXO able to spend itself"""

    def __init__(self, unspent, output, private_blinding_key):
        super().__init__(unspent)
        if output.scriptpubkey != self.scriptpubkey:
            raise ValueError('scriptpubkey must match: {}, {}'.format(
                b2h(output.scriptpubkey),
                b2h(self.scriptpubkey)))
        self.output = output
        self.unblind(output.blinding_key.prv)

    def _get_signature_hash(self, tx, index):
        return wally.tx_get_elements_signature_hash(
            tx,
            index,
            self.output.witness_script,
            self.value_commitment,
            wally.WALLY_SIGHASH_ALL,
            wally.WALLY_TX_FLAG_USE_WITNESS)

    def sign(self, tx, index):
        """Sign the index-th input of tx, fill its witness and scriptSig"""
        txhash = self._get_signature_hash(tx, index)
        wally.tx_set_input_witness(tx, index, self.output.get_signed_witness(txhash))
        wally.tx_set_input_script(tx, index, self.output.script_sig)
