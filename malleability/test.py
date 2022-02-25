from cryptos.bitcoin import BITCOIN
from cryptos.transaction import Tx, TxIn, TxOut, Script
from cryptos.keys import PublicKey
from cryptos.ecdsa import sign
from cryptos.sha256 import sha256
from dataclasses import dataclass
from typing import List
import random
import logging
import requests

@dataclass
class UTXO:
    # amount: float
    tx_hash: str
    index: int = 0
    net: str = "test"


@dataclass
class Wallet:
    private_key: int
    public_key: PublicKey

    @staticmethod
    def gen_from_bytes(mnemonic_seed: bytes):
        secret_key = int.from_bytes(mnemonic_seed, 'big') # or just random.randrange(1, bitcoin_gen.n)
        assert 1 <= secret_key < BITCOIN.gen.n # check it's valid
        public_key =  PublicKey.from_point(secret_key * BITCOIN.gen.G)
        return Wallet(secret_key, public_key)

    def get_address(self, net='test', as_link=False):
        address = self.public_key.address(net='test', compressed=True)
        if as_link:
            address = f"https://www.blockchain.com/btc-{net}net/address/{address}"
        return address

    def get_pk_hash(self, compressed=True, hash160=True):
        return self.public_key.encode(compressed, hash160)

class TxBroadcaster:
    """ lazily fetches transactions using an api on demand """

    @staticmethod
    def broadcast(tx: Tx, net: str):
        assert isinstance(tx, Tx)
        assert net is not None, "can't fetch a transaction without knowing which net to look at, e.g. main|test"
        if net == 'main':
            url = 'https://blockstream.info/api/tx'
        elif net == 'test':
            url = 'https://blockstream.info/testnet/api/tx'
        else:
            raise ValueError("%s is not a valid net type, should be main|test" % (net, ))
        response = requests.post(url, tx.encode().hex())
        assert response.status_code == 200, "send transaction %s failed, response: %s" % (tx.id(), response)
        resp_text = response.text.strip()
        return resp_text


class MalleabilityTest:
    def __init__(self, 
        sender_wallet: Wallet, 
        receiver_wallet: Wallet,
        utxos: List[UTXO],
        send_amount: float = None,
        net: str = "test"):
        self.sender_wallet = sender_wallet
        self.receiver_wallet = receiver_wallet
        self.utxos = utxos
        self.send_amount = send_amount
        self.net = net

    def make_transaction(self, segwit: bool = False, fee_amount = 0.000003):
        tx_ins = []
        in_amount = 0
        for utxo in self.utxos:
            tx_in = TxIn(
                prev_tx = bytes.fromhex(utxo.tx_hash),
                prev_index = utxo.index,
                script_sig = None, # digital signature to be inserted later
                net = self.net
            )
            in_amount += tx_in.value()
            tx_ins.append(tx_in)
        fee_amount_satoshi = int(fee_amount * 100000000)
        if self.send_amount:
            send_amount_satoshi = int(self.send_amount * 100000000)
        else:
            send_amount_satoshi = in_amount - fee_amount_satoshi
        left_amount = in_amount - fee_amount_satoshi - send_amount_satoshi
        
        tx_outs = []
        # declare the owner as identity 3 above, by inserting the public key hash into the Script "padding"
        out_pkb_hash = self.receiver_wallet.public_key.encode(compressed=True, hash160=True)
        out_script_pubkey = Script([118, 169, out_pkb_hash, 136, 172]) # OP_DUP, OP_HASH160, <hash>, OP_EQUALVERIFY, OP_CHECKSIG

        tx_outs.append(
            TxOut(send_amount_satoshi, out_script_pubkey)
        )
        
        if left_amount > 0: 
            pkb_hash = self.sender_wallet.get_pk_hash()
            sender_script_pubkey = Script([118, 169, pkb_hash, 136, 172]) # OP_DUP, OP_HASH160, <hash>, OP_EQUALVERIFY, OP_CHECKSIG
            tx_outs.append(
                TxOut(left_amount, sender_script_pubkey)
            )

        tx = Tx(
            version = 1,
            tx_ins = tx_ins,
            tx_outs = tx_outs,
            segwit = segwit)
        for i in range(len(tx_ins)):
            message = tx.encode(sig_index=i)
            random.seed(int.from_bytes(sha256(message), 'big'))
            sig = sign(self.sender_wallet.private_key, message)
            sig_bytes_and_type = sig.encode() + b'\x01' # DER signature + SIGHASH_ALL
            pubkey_bytes = self.sender_wallet.public_key.encode(compressed=True, hash160=False)
            script_sig = Script([sig_bytes_and_type, pubkey_bytes])
            tx_ins[i].script_sig = script_sig
        return tx

    def modify_transation(self):
        pass

    def broadcast_transation(self, tx:Tx):
        return TxBroadcaster.broadcast(tx, net=self.net)

    def get_transation_status(self):
        pass



def main():
    logging.basicConfig(level=logging.INFO)

    sender_wallet = Wallet.gen_from_bytes(b"Kyle is cool :P")
    receiver_wallet = Wallet.gen_from_bytes(b"Kyle's Super Secret 2nd Wallet")

    # receiver_wallet = Wallet.gen_from_bytes(b"Kyle is cool :P")
    # sender_wallet = Wallet.gen_from_bytes(b"Kyle's Super Secret 2nd Wallet")
    logging.info(f"sender_wallet: {sender_wallet.get_address(as_link=True)}")
    logging.info(f"receiver_wallet: {receiver_wallet.get_address(as_link=True)}")

    utxos = [
        UTXO("87a42a746a45fe1729f60e8c2ea3a82721ca4ffd86cc1e3e2e106fddb50fcd76")
    ]
    
    test = MalleabilityTest(sender_wallet, receiver_wallet, utxos)
    tx = test.make_transaction()
    logging.info(f"tx: {tx}")
    logging.info(f"tx id: {tx.id()}")
    logging.info(f"tx encode: {tx.encode().hex()}")

    if tx.validate:
        resp = test.broadcast_transation(tx)
        logging.info(f"send transaction response: {resp}")

if __name__ == '__main__':
    main()