import wallycore as wally

from selw.wallet import WalletP2wpkh
from selw.constants import LBTC_HEX

url = 'https://blockstream.info/liquidtestnet'

prv = b'REPLACE-THIS-WITH-A-PRIVATE-KEY'
cmd = 'python3 -c "import os; print(os.urandom(32))"'
assert len(prv) == 32, f'Replace the private key, you can generate one with this command:\n{cmd}'

# Using a dumb blinding private key, this can be replaced if you want to
bprv = b'\x01'*32

w = WalletP2wpkh(prv, bprv)
w.sync(url)
balance = w.balance()
assert balance.get(LBTC_HEX, 0) > 0, f'Balance is 0, send some funds to {w.address()} and run the script again'

psbt = w.create_psbt(w.utxos, w.address(), LBTC_HEX, 1000)
psbt = w.blind_psbt(psbt, w.utxos)
psbt = w.sign_psbt(psbt, w.utxos)
txid = w.send_psbt(psbt, url)
print(f'{url}/tx/{txid}')
