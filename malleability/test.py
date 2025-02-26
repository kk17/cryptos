from cryptos.bitcoin import BITCOIN
from cryptos.transaction import Tx, TxIn, TxOut, Script, TxFetcher
from cryptos.keys import PublicKey
from cryptos.ecdsa import sign, Signature
from cryptos.sha256 import sha256
from dataclasses import dataclass
from typing import List
import random
import logging
import requests
import string
import time
import logging
from io import BytesIO
from pprint import pprint

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
        resp_text = response.text.strip()
        assert response.status_code == 200, "send transaction %s failed, response: %s" % (tx.id(), resp_text)
        return resp_text


class TxStatusFetcher:
    """ lazily fetches transactions using an api on demand """

    @staticmethod
    def fetch(tx_id: str, net: str):
        assert isinstance(tx_id, str)
        assert all(c in string.hexdigits for c in tx_id)
        tx_id = tx_id.lower() # normalize just in case we get caps

        # fetch bytes from api
        # print("fetching transaction %s from API" % (tx_id, ))
        assert net is not None, "can't fetch a transaction without knowing which net to look at, e.g. main|test"
        if net == 'main':
            url = 'https://blockstream.info/api/tx/%s/status' % (tx_id, )
        elif net == 'test':
            url = 'https://blockstream.info/testnet/api/tx/%s/status' % (tx_id, )
        else:
            raise ValueError("%s is not a valid net type, should be main|test" % (net, ))
        response = requests.get(url)
        assert response.status_code == 200, "transaction id %s was not found on blockstream" % (tx_id, )
        status = response.json()
        return status

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

    def not_strictly_verify_transction(self, tx:Tx):
        return tx.validate()

    def modify_transation(self, tx_data: bytes, trick):
        tx = Tx.decode(BytesIO(tx_data))
        tx_in = tx.tx_ins[0]
        origin_cmds = tx_in.script_sig.cmds
        origin_sig = origin_cmds[0]

        # Decode the signature for modification
        # According to https://en.bitcoin.it/wiki/BIP_0062#DER_encoding DER has the following format:
        # 0x30 [total-length] 0x02 [R-length] [R] 0x02 [S-length] [S] [sighash-type]
        sig = Signature.decode(origin_sig[:-1])

        def dern(n:int):
            nb = n.to_bytes(34, byteorder='big')
            nb = nb.lstrip(b'\x00') # strip leading zeros
            nb = (b'\x00' if nb[0] >= 0x80 else b'') + nb # preprend 0x00 if first byte >= 0x80
            return nb

        if trick == "zero-padding-in-der":
            # Trick 1: padding 0x00 byte to the part of the DER signature bytes
            # However this trick is not working now, when we submit the transaction to blockstream we get error:
            # {"code":-26,"message":"non-mandatory-script-verify-flag (Non-canonical DER signature)"}
            rb = dern(sig.r)
            sb = dern(sig.s)
            new_rb = b'\x00' + rb
            content = b''.join([bytes([0x02, len(new_rb)]), new_rb, bytes([0x02, len(sb)]), sb])
            new_sig = b''.join([bytes([0x30, len(content)]), content]) + b'\x01' # DER signature + SIGHASH_ALL
        else:
            # Trick 2: using the complementary s for signature
            # However this trick is not working now, when we submit the transaction to blockstream we get error:
            # {"code":-26,"message":"non-mandatory-script-verify-flag (Non-canonical signature: S value is unnecessarily high)
            rb = dern(sig.r)
            new_s = BITCOIN.gen.n - sig.s
            sb = dern(new_s)
            content = b''.join([bytes([0x02, len(rb)]), rb, bytes([0x02, len(sb)]), sb])
            new_sig = b''.join([bytes([0x30, len(content)]), content]) + b'\x01' # DER signature + SIGHASH_ALL

        assert origin_sig != new_sig
        logging.debug(f"origin_sig: {origin_sig}")
        logging.debug(f"new_sig: {new_sig}")
        new_cmds = [new_sig, origin_cmds[1]]
        tx_in.script_sig = Script(new_cmds)
        return tx

    def broadcast_transation(self, tx:Tx):
        return TxBroadcaster.broadcast(tx, net=self.net)

    def fetch_transation(self, tx_id:str, retry_interval_seconds=1, max_tries=10):
        ex = None
        n = 0
        while n < max_tries:
            n += 1
            try:
                status = TxStatusFetcher.fetch(tx_id, self.net)
            except Exception as e:
                ex = e
                logging.info(f"get transaction {tx_id} status error: {e}, tried times: {n}")
            if status["confirmed"]:
                return TxFetcher.fetch(tx_id, self.net)
            time.sleep(retry_interval_seconds)
        raise ex


def print_tranction_info(tx:Tx):
    print(tx)
    print(f"      tx id: {tx.id()}")
    print(f"    tx link: https://www.blockchain.com/btc-testnet/tx/{tx.id()}")
    print(f"  tx encode: {tx.encode().hex()}")
    print(f"tx validate: {tx.validate()}")


def main():
    logging.basicConfig(level=logging.DEBUG)

    # sender_wallet = Wallet.gen_from_bytes(b"Kyle is cool :P")
    # receiver_wallet = Wallet.gen_from_bytes(b"Kyle's Super Secret 2nd Wallet")

    receiver_wallet = Wallet.gen_from_bytes(b"Kyle is cool :P")
    sender_wallet = Wallet.gen_from_bytes(b"Kyle's Super Secret 2nd Wallet")
    logging.info(f"sender_wallet: {sender_wallet.get_address(as_link=True)}")
    logging.info(f"receiver_wallet: {receiver_wallet.get_address(as_link=True)}")

    utxos = [
        UTXO("18f84576214e0ab89ea6a746afa0aafc65c87783dc2071ac75af9a538172b77f")
    ]
    
    test = MalleabilityTest(sender_wallet, receiver_wallet, utxos)

    print("-" * 80)
    tx = test.make_transaction()
    send_btc_amount = tx.tx_outs[0].amount / 100000000.0
    assert tx.validate()
    print("Original transaction info:")
    print_tranction_info(tx)
    print("-" * 80)
    print(f"Sending {send_btc_amount} btc from wallet {sender_wallet.get_address()} to wallet {receiver_wallet.get_address()}")


    tx_bytes = tx.encode()
    # Suppose the tx bytes data is send to a malicious node.
    # Remember we can't steal money or make any semantic changes to the transaction.
    # The node will modify the part of the signature of transation and the new transction
    # is valid but the transaction id is changed
    mod_tx1 = test.modify_transation(tx_bytes, trick="zero-padding-in-der")
    assert test.not_strictly_verify_transction(mod_tx1) == True
    assert mod_tx1.id() != tx.id()
    print("Modify transaction1 info:")
    print_tranction_info(mod_tx1)

    print("-" * 80)
    print(f"Original transaction id: {tx.id()}")
    print(f"  Modified transaction id: {mod_tx1.id()}")
    print(f"  Transaction ids equal: {mod_tx1.id() != tx.id()}")
    print(f"  Modified transaction vevild(not stritly verfify): {test.not_strictly_verify_transction(mod_tx1)}")
    print("-" * 80)

    # The malicious node will broadcast the modified transation to the network. Because is valid,
    # it will be confirmed and be part of one of the block in the blockchain.
    # The flaw related to DER-encoded ASN.1 data was fixed by the BIP66 soft fork.
    # Here we will get error: {"code":-26,"message":"non-mandatory-script-verify-flag (Non-canonical DER signature)"}
    try:
        test.broadcast_transation(mod_tx1)
    except Exception as e:
        print(e)


    mod_tx2 = test.modify_transation(tx_bytes, trick="high-s-in-ecdsa")
    assert test.not_strictly_verify_transction(mod_tx2) == True
    assert mod_tx2.id() != tx.id()
    print("Modify transaction1 info:")
    print_tranction_info(mod_tx2)

    print("-" * 80)
    print(f"Original transaction id: {tx.id()}")
    print(f"  Modified transaction id: {mod_tx2.id()}")
    print(f"  Transaction ids different: {mod_tx2.id() != tx.id()}")
    print(f"  Modified transaction vevild(not stritly verfify): {test.not_strictly_verify_transction(mod_tx2)}")
    print("-" * 80)

    # Bitcoin Core added a mechanism to enforce low S-values with PR #6769, which was merged in Bitcoin Core in October 2015. 
    # Here we will get error: {"code":-26,"message":"non-mandatory-script-verify-flag (Non-canonical signature: 
    # S value is unnecessarily high)"}
    try:
        test.broadcast_transation(mod_tx2)
    except Exception as e:
        print(e)

    # We will try to get the transaction from the network to verify it is confirmed
    # test.fetch_transation(mod_tx.id())

    # We also try to broadcast the original transaction to the network. But because the
    # modified transation was confirm, we cannot double spend the money. Thus it will no be 
    # confirmed.
    # test.broadcast_transation(tx)
    # test.fetch_transation(tx.id())

if __name__ == '__main__':
    main()