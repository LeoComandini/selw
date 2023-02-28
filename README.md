# Simple Elements Wallet

Simple Elements Wallet (`selw`) is Elements wallet written in Python
using [libwally](https://github.com/ElementsProject/libwally-core).
`selw` is not intended for production use, but rather to create
examples and PoCs.

**WARNING**: `selw` is in planning status, expect breaking changes and
bugs.

## Setup

Create and activate a virtualenv (optional):

    virtualenv -p python3 venv
    source venv/bin/activate

Then install `selw`:

    pip install .

## Tests

    pip install pycodestyle
    pycodestyle selw/ --max-line-length=140
    python3 -m unittest discover -v

## TODOs:

* [ ] Write TODO list

## LICENSE

[MIT](LICENSE)

Code is taken from:
* [garecovery](https://github.com/greenaddress/garecovery)
* [libwally-py](https://github.com/LeoComandini/libwally-py).
* [wally_swap_test](https://github.com/jgriffiths/wally_swap_test).
