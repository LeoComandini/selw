class SewError(Exception):
    pass


class InvalidPrivateKey(SewError):
    pass


class InvalidPublicKey(SewError):
    pass
