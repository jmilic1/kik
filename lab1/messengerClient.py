#!/usr/bin/env python3

from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from typing import Dict


class State:
    def __init__(self, chain_key_send, chain_key_recv):
        self.chain_key_send = chain_key_send
        self.chain_key_recv = chain_key_recv
        self.Ns = 0
        self.Nr = 0


def kdf_ck(ck):
    h1 = hmac.HMAC(ck, hashes.SHA256())
    h1.update(b'x01')
    h2 = hmac.HMAC(ck, hashes.SHA256())
    h2.update(b'x02')

    return h1.finalize(), h2.finalize()


def my_hkdf(mk):
    hkdf = HKDF(
        algorithm=SHA256(),
        length=80,
        salt=b'\0' * 80,
        info=b'info',
    )
    key = hkdf.derive(mk)
    encryption_key = key[:32]
    iv = key[32:]
    return encryption_key, iv


def encrypt(ek, iv, plain_text):
    return AESGCM(ek).encrypt(iv, plain_text, None)


def decrypt(ek, cipher_text, iv):
    return AESGCM(ek).decrypt(iv, cipher_text, None)


def create_conns() -> Dict[str, State]:
    return {}


class MessengerClient:
    """ Messenger client class

        Feel free to modify the attributes and add new ones as you
        see fit.

    """

    def __init__(self, username, max_skip=10):
        """ Initializes a client

        Arguments:
        username (str) -- client name
        max_skip (int) -- Maximum number of message keys that can be skipped in
                          a single chain

        """
        self.username = username
        # Data regarding active connections.
        self.conn = create_conns()
        # Maximum number of message keys that can be skipped in a single chain
        self.max_skip = max_skip
        self.MKSKIPPED = {}

    def add_connection(self, username, chain_key_send, chain_key_recv):
        """ Add a new connection

        Arguments:
        username (str) -- user that we want to talk to
        chain_key_send -- sending chain key (CKs) of the username
        chain_key_recv -- receiving chain key (CKr) of the username

        """
        self.conn[username] = State(chain_key_send, chain_key_recv)

    def send_message(self, username, message):
        """ Send a message to a user

        Get the current sending key of the username, perform a symmetric-ratchet
        step, encrypt the message, update the sending key, return a header and
        a ciphertext.

        Arguments:
        username (str) -- user we want to send a message to
        message (str)  -- plaintext we want to send

        Returns a ciphertext and a header data (you can use a tuple object)

        """

        mk, ck = kdf_ck(self.conn[username].chain_key_send)
        self.conn[username].chain_key_send = ck

        ek, iv = my_hkdf(mk)
        cipher_text = encrypt(ek, iv, message.encode('utf-8'))

        Ns = self.conn[username].Ns
        self.conn[username].Ns += 1

        return cipher_text, Ns

    def receive_message(self, username, message):
        """ Receive a message from a user

        Get the username connection data, check if the message is out-of-order,
        perform necessary symmetric-ratchet steps, decrypt the message and
        return the plaintext.

        Arguments:
        username (str) -- user who sent the message
        message        -- a ciphertext and a header data

        Returns a plaintext (str)

        """

        cipher_text = message[0]
        n = message[1]

        plain_text = self.TrySkippedMessageKeys(n, username, cipher_text)
        if plain_text is not None:
            return plain_text

        self.SkipMessageKeys(n, username)

        mk, ck = kdf_ck(self.conn[username].chain_key_recv)
        self.conn[username].chain_key_recv = ck
        self.conn[username].Nr += 1

        ek, iv = my_hkdf(mk)
        return decrypt(ek, cipher_text, iv).decode('utf-8')

    def TrySkippedMessageKeys(self, n, username, cipher_text):
        if (username, n) in self.MKSKIPPED:
            mk = self.MKSKIPPED[username, n]
            del self.MKSKIPPED[username, n]

            ek, iv = my_hkdf(mk)
            plain_text = decrypt(ek, cipher_text, iv)
            if plain_text is not None:
                return plain_text.decode("utf-8")
        return None

    def SkipMessageKeys(self, until, username):
        if self.conn[username].Nr + self.max_skip < until:
            raise Error()

        CKr = self.conn[username].chain_key_recv
        if CKr is not None:
            while self.conn[username].Nr < until:
                mk, CKr = kdf_ck(CKr)
                self.conn[username].chain_key_recv = CKr
                self.setMKSkipped(username, mk)
                self.conn[username].Nr += 1

    def setMKSkipped(self, username, mk):
        self.MKSKIPPED[username, self.conn[username].Nr] = mk
