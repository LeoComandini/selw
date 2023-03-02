class SewError(Exception):
    pass


class InvalidMultisig(SewError):
    pass


class InvalidPrivateKey(SewError):
    pass


class InvalidPublicKey(SewError):
    pass
