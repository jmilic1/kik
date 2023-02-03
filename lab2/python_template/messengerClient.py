#!/usr/bin/env python3

import pickle
from typing import Dict

from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import load_pem_public_key


class State:
    def __init__(self, dh_public):
        self.chain_key_send = None
        self.chain_key_recv = None
        self.root_key = None
        self.DHr = dh_public
        self.SK = None
        self.dh_key_pair = None


def GENERATE_DH():
    private_key = X25519PrivateKey.generate()
    public_key = private_key.public_key()

    return public_key, private_key


def DH(dh_pub, dh_private):
    private_key = dh_private
    if hasattr(dh_private, '__len__'):
        private_key = x25519.X25519PrivateKey.from_private_bytes(dh_private)

    public_key = dh_pub
    if hasattr(dh_pub, '__len__'):
        public_key = x25519.X25519PublicKey.from_public_bytes(dh_pub)

    return public_key, private_key


def kdf_ck(ck):
    h1 = hmac.HMAC(ck, hashes.SHA256())
    h1.update(b'x01')
    h2 = hmac.HMAC(ck, hashes.SHA256())
    h2.update(b'x02')

    return h1.finalize(), h2.finalize()


def kdf_rk(rk, dh_out):
    # out = smthElse(dh_out, 64, rk, SHA256, 1)
    hkdf = HKDF(
        algorithm=SHA256(),
        length=64,
        salt=rk,
        info=b'info',
    )
    key = hkdf.derive(dh_out[1].exchange(dh_out[0]))
    rk_input_material = key[:32]
    ck = key[32:]
    return rk_input_material, ck


def my_hkdf(mk):
    # out = smthElse(dh_out, 64, rk, SHA256, 1)

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
    """ Messenger client klasa

        Slobodno mijenjajte postojeće atribute i dodajte nove kako smatrate
        prikladnim.
    """

    def __init__(self, username, ca_pub_key: EllipticCurvePublicKey):
        """ Inicijalizacija klijenta

        Argumenti:
        username (str) -- ime klijenta
        ca_pub_key     -- javni ključ od CA (certificate authority)

        """
        self.username = username
        self.ca_pub_key = ca_pub_key
        # Aktivne konekcije s drugim klijentima
        self.conns = create_conns()
        self.dh_key_pair = None

        # [OLD]
        # self.username = username
        # # Data regarding active connections.
        # self.conn = {}
        # # Maximum number of message keys that can be skipped in a single chain
        # self.max_skip = 10
        # self.MKSKIPPED = {}

    def generate_certificate(self):
        """ Generira par Diffie-Hellman ključeva i vraća certifikacijski objekt

        Metoda generira inicijalni Diffie-Hellman par kljuceva; serijalizirani
        javni kljuc se zajedno s imenom klijenta postavlja u certifikacijski
        objekt kojeg metoda vraća. Certifikacijski objekt moze biti proizvoljan (npr.
        dict ili tuple). Za serijalizaciju kljuca mozete koristiti
        metodu `public_bytes`; format (PEM ili DER) je proizvoljan.

        Certifikacijski objekt koji metoda vrati bit će potpisan od strane CA te
        će tako dobiveni certifikat biti proslijeđen drugim klijentima.

        """
        self.dh_key_pair = GENERATE_DH()
        serialized = self.dh_key_pair[0].public_bytes(encoding=serialization.Encoding.PEM,
                                                      format=serialization.PublicFormat.SubjectPublicKeyInfo)
        return {"public-key": serialized, "username": self.username}

    def receive_certificate(self, cert, signature):
        """ Verificira certifikat klijenta i sprema informacije o klijentu (ime
            i javni ključ)

        Argumenti:
        cert      -- certifikacijski objekt
        signature -- digitalni potpis od `cert`

        Metoda prima certifikacijski objekt (koji sadrži inicijalni
        Diffie-Hellman javni ključ i ime klijenta) i njegov potpis kojeg
        verificira koristeći javni ključ od CA i, ako je verifikacija uspješna,
        sprema informacije o klijentu (ime i javni ključ). Javni ključ od CA je
        spremljen prilikom inicijalizacije objekta.

        """
        self.ca_pub_key.verify(signature, pickle.dumps(cert), ec.ECDSA(hashes.SHA256()))

        dh_public = cert["public-key"]
        username = cert["username"]

        foreign_public_key = load_pem_public_key(dh_public)
        self.conns[username] = State(foreign_public_key)
        self.conns[username].SK = self.dh_key_pair[1].exchange(foreign_public_key)
        self.conns[username].dh_key_pair = self.dh_key_pair

    def send_message(self, username, message):
        """ Slanje poruke klijentu

        Argumenti:
        message  -- poruka koju ćemo poslati
        username -- klijent kojem šaljemo poruku `message`

        Metoda šalje kriptiranu poruku sa zaglavljem klijentu s imenom `username`.
        Pretpostavite da već posjedujete certifikacijski objekt od klijenta
        (dobiven pomoću `receive_certificate`) i da klijent posjeduje vaš.
        Ako već prije niste komunicirali, uspostavite sesiju tako da generirate
        nužne `double ratchet` ključeve prema specifikaciji.

        Svaki put kada šaljete poruku napravite `ratchet` korak u `sending`
        lanacu (i `root` lanacu ako je potrebno prema specifikaciji).  S novim
        `sending` ključem kriptirajte poruku koristeći simetrični kriptosustav
        AES-GCM tako da zaglavlje poruke bude autentificirano.  Ovo znači da u
        zaglavlju poruke trebate proslijediti odgovarajući inicijalizacijski
        vektor.  Zaglavlje treba sadržavati podatke potrebne klijentu da
        derivira novi ključ i dekriptira poruku.  Svaka poruka mora biti
        kriptirana novim `sending` ključem.

        Metoda treba vratiti kriptiranu poruku zajedno sa zaglavljem.

        """

        if self.conns[username].chain_key_send is None:
            self.conns[username].dh_key_pair = GENERATE_DH()

            foreign_public_key = self.conns[username].DHr
            personal_private_key = self.conns[username].dh_key_pair[1]

            root_key, chain_key_send = kdf_rk(self.conns[username].SK, DH(foreign_public_key, personal_private_key))
            self.conns[username].root_key = root_key
            self.conns[username].chain_key_send = chain_key_send

        chain_key_send, mk = kdf_ck(self.conns[username].chain_key_send)
        self.conns[username].chain_key_send = chain_key_send

        ek, iv = my_hkdf(mk)
        cipher_text = encrypt(ek, iv, message.encode('utf-8'))

        return cipher_text, self.conns[username].dh_key_pair[0]

    def receive_message(self, username, message):
        """ Primanje poruke od korisnika

        Argumenti:
        message  -- poruka koju smo primili
        username -- klijent koji je poslao poruku

        Metoda prima kriptiranu poruku od klijenta s imenom `username`.
        Pretpostavite da već posjedujete certifikacijski objekt od klijenta
        (dobiven pomoću `receive_certificate`) i da je klijent izračunao
        inicijalni `root` ključ uz pomoć javnog Diffie-Hellman ključa iz vašeg
        certifikata.  Ako već prije niste komunicirali, uspostavite sesiju tako
        da generirate nužne `double ratchet` ključeve prema specifikaciji.

        Svaki put kada primite poruku napravite `ratchet` korak u `receiving`
        lanacu (i `root` lanacu ako je potrebno prema specifikaciji) koristeći
        informacije dostupne u zaglavlju i dekriptirajte poruku uz pomoć novog
        `receiving` ključa. Ako detektirate da je integritet poruke narušen,
        zaustavite izvršavanje programa i generirajte iznimku.

        Metoda treba vratiti dekriptiranu poruku.

        """
        cipher_text = message[0]
        foreign_public_key = message[1]

        if self.conns[username].chain_key_recv is None:
            personal_private_key = self.conns[username].dh_key_pair[1]
            self.conns[username].DHr = foreign_public_key

            root_key, chain_key_recv = kdf_rk(self.conns[username].SK, DH(foreign_public_key, personal_private_key))
            self.conns[username].root_key = root_key
            self.conns[username].chain_key_recv = chain_key_recv

        # plaintext = self.TrySkippedMessageKeys(foreign_public_key, username, cipher_text)
        # if plaintext != None:
        #     return plaintext

        if foreign_public_key != self.conns[username].DHr:
            self.DHRatchet(username, foreign_public_key)

        chain_key_recv = self.conns[username].chain_key_recv
        chain_key_recv, mk = kdf_ck(chain_key_recv)
        self.conns[username].chain_key_recv = chain_key_recv

        ek, iv = my_hkdf(mk)
        return decrypt(ek, cipher_text, iv).decode('utf-8')

    # def TrySkippedMessageKeys(self, n, username, cipher_text):
    #     if (username, n) in self.MKSKIPPED:
    #         mk = self.MKSKIPPED[username, n]
    #         del self.MKSKIPPED[username, n]
    #
    #         ek, iv = my_hkdf(mk)
    #         plain_text = decrypt(ek, cipher_text, iv)
    #         if plain_text is not None:
    #             return plain_text.decode("utf-8")
    #     return None

    def SkipMessageKeys(self, until, username):
        if self.conns[username].Nr + self.max_skip < until:
            raise Error()

        CKr = self.conns[username].chain_key_recv
        if CKr is not None:
            while self.conns[username].Nr < until:
                mk, CKr = kdf_ck(CKr)
                self.conns[username].chain_key_recv = CKr
                self.setMKSkipped(username, mk)
                self.conns[username].Nr += 1

    def setMKSkipped(self, username, mk):
        self.MKSKIPPED[username, self.conns[username].Nr] = mk

    def DHRatchet(self, username, foreign_public_key):
        # self.conns[username].Pn = self.conns[username].Ns
        # self.conns[username].Ns = 0
        # self.conns[username].Nr = 0
        self.conns[username].DHr = foreign_public_key

        personal_private_key = self.conns[username].dh_key_pair[1]
        root_key = self.conns[username].root_key

        root_key, chain_key_recv = kdf_rk(root_key, DH(foreign_public_key, personal_private_key))
        self.conns[username].root_key = root_key
        self.conns[username].chain_key_recv = chain_key_recv

        self.conns[username].dh_key_pair = GENERATE_DH()
        personal_private_key = self.conns[username].dh_key_pair[1]

        root_key, chain_key_send = kdf_rk(root_key, DH(foreign_public_key, personal_private_key))
        self.conns[username].root_key = root_key
        self.conns[username].chain_key_send = chain_key_send


def main():
    pass


if __name__ == "__main__":
    main()
