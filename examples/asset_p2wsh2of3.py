import wallycore as wally

from selw.wallet import WalletP2wsh2of3
from selw.constants import LBTC_HEX

url = 'https://blockstream.info/liquidtestnet'

prv_a = b'REPLACE-THIS-WITH-A-PRIVATE-KEY'
prv_b = b'REPLACE-THIS-WITH-A-PRIVATE-KEY'
prv_c = b'REPLACE-THIS-WITH-A-PRIVATE-KEY'
cmd = 'python3 -c "import os; print(os.urandom(32))"'
err_msg = f'Replace the private key, you can generate one with this command:\n{cmd}'
assert len(prv_a) == 32 or len(prv_b) == 32 or len(prv_c) == 32, err_msg

# Using a dumb blinding private key, this can be replaced if you want to
bprv = b'\x01'*32

w = WalletP2wsh2of3([prv_a, prv_b, prv_c], bprv)
w.sync(url)
balance = w.balance()
print(balance)
assert balance.get(LBTC_HEX, 0) > 0, f'tL-BTC balance is 0, send some tT-LBTC to {w.address()} and run the script again'
ASSET_HEX = "REPLACE-THIS-WITH-AN-ASSET-YOU-OWN"
assert len(ASSET_HEX) == 64, "Replace ASSET_HEX with an existing asset you own"
assert balance.get(ASSET_HEX, 0) > 0, f'Asset {ASSET_HEX} balance is 0, send some {ASSET_HEX} to {w.address()} and run the script again'

psbt = w.create_psbt(w.utxos, w.address(), ASSET_HEX, 1)
psbt = w.blind_psbt(psbt, w.utxos)
psbt = w.sign_psbt(psbt, w.utxos)
txid = w.send_psbt(psbt, url)
print(f'{url}/tx/{txid}')
