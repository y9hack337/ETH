import binascii, hashlib, hmac, struct
from ecdsa.curves import SECP256k1
from eth_utils import to_checksum_address, keccak as eth_utils_keccak
import requests
from mnemonic import Mnemonic
import ctypes
from threading import Thread
import time
from datetime import datetime

BIP39_PBKDF2_ROUNDS = 2048
BIP39_SALT_MODIFIER = "mnemonic"
BIP32_PRIVDEV = 0x80000000
BIP32_CURVE = SECP256k1
BIP32_SEED_MODIFIER = b'Bitcoin seed'
ETH_DERIVATION_PATH = "m/44'/60'/0'/0"

class PublicKey:
	def __init__(self, private_key):
		self.point = int.from_bytes(private_key, byteorder='big') * BIP32_CURVE.generator

	def __bytes__(self):
		xstr = self.point.x().to_bytes(32, byteorder='big')
		parity = self.point.y() & 1
		return (2 + parity).to_bytes(1, byteorder='big') + xstr

	def address(self):
		x = self.point.x()
		y = self.point.y()
		s = x.to_bytes(32, 'big') + y.to_bytes(32, 'big')
		return to_checksum_address(eth_utils_keccak(s)[12:])

def mnemonic_to_bip39seed(mnemonic, passphrase):
	mnemonic = bytes(mnemonic, 'utf8')
	salt = bytes(BIP39_SALT_MODIFIER + passphrase, 'utf8')
	return hashlib.pbkdf2_hmac('sha512', mnemonic, salt, BIP39_PBKDF2_ROUNDS)

def bip39seed_to_bip32masternode(seed):
	k = seed
	h = hmac.new(BIP32_SEED_MODIFIER, seed, hashlib.sha512).digest()
	key, chain_code = h[:32], h[32:]
	return key, chain_code

def derive_bip32childkey(parent_key, parent_chain_code, i):
	assert len(parent_key) == 32
	assert len(parent_chain_code) == 32
	k = parent_chain_code
	if (i & BIP32_PRIVDEV) != 0:
		key = b'\x00' + parent_key
	else:
		key = bytes(PublicKey(parent_key))
	d = key + struct.pack('>L', i)
	while True:
		h = hmac.new(k, d, hashlib.sha512).digest()
		key, chain_code = h[:32], h[32:]
		a = int.from_bytes(key, byteorder='big')
		b = int.from_bytes(parent_key, byteorder='big')
		key = (a + b) % BIP32_CURVE.order
		if a < BIP32_CURVE.order and key != 0:
			key = key.to_bytes(32, byteorder='big')
			break
		d = b'\x01' + h[32:] + struct.pack('>L', i)
	return key, chain_code

def parse_derivation_path(str_derivation_path):
	path = []
	if str_derivation_path[0:2] != 'm/':
		raise ValueError("Can't recognize derivation path. It should look like \"m/44'/60/0'/0\".")
	for i in str_derivation_path.lstrip('m/').split('/'):
		if "'" in i:
			path.append(BIP32_PRIVDEV + int(i[:-1]))
		else:
			path.append(int(i))
	return path

def mnemonic_to_private_key(mnemonic, str_derivation_path, passphrase=""):
	derivation_path = parse_derivation_path(str_derivation_path)
	bip39seed = mnemonic_to_bip39seed(mnemonic, passphrase)
	master_private_key, master_chain_code = bip39seed_to_bip32masternode(bip39seed)
	private_key, chain_code = master_private_key, master_chain_code
	for i in derivation_path:
		private_key, chain_code = derive_bip32childkey(private_key, chain_code, i)
	return private_key
totol = 0
i = 0
speed = 0
i_old = 0
start_time = datetime.now()
def sleepMe(key):
	global totol, i, speed,start_time
	mnemo = Mnemonic("english")
	while True:
		try:
			private_keys = []
			public_keys = []
			mnemonics = []
			for s in range(20):
				mnemonic = mnemo.generate(strength=128)
				private_key = mnemonic_to_private_key(mnemonic,
						str_derivation_path=f'{ETH_DERIVATION_PATH}/0')
				mnemonics.append(mnemonic)
				public_key = PublicKey(private_key)
				private_keys.append(binascii.hexlify(private_key).decode("utf-8"))
				public_keys.append(public_key.address())

			bb = requests.get(f'https://api.etherscan.io/api?module=account&action=balancemulti&address={",".join(public_keys)}&tag=latest&apikey={key}').json()
			if bb["result"] !="Max rate limit reached" and bb["result"] !="Invalid API Key":
				for result in bb["result"]:
					if result["balance"] !="0":
						print(key)
						print(f'privkey: {private_keys[public_keys.index(result["account"])]}')
						print(f'address: {result["account"]}')
						print(f'balance: {result["balance"]}')
						#ress = str(mnemonics[public_keys.index(result["account"])])+"\n"+str(result["balance"])
						#requests.get(f'https://api.telegram.org/bot<TOKEN>/sendMessage?chat_id=<ID>&text={ress}')
						totol+=int(result["balance"])/1000000000000000000
					i+=1
					strr = "Всего: "+str(i)+" Скорость: "+str(speed)+" h/s"+" Общий баланс: "+str(totol)+" Время работы: "+str((datetime.now() - start_time)).split(".")[0]
					ctypes.windll.kernel32.SetConsoleTitleA(strr.encode('utf-8'))
			elif bb["result"] == "Max rate limit reached":
				print(f"Max rate limit reached - {key}")
				time.sleep(10)
			elif bb["result"] == "Invalid API Key":
				print(f"Invalid API Key - {key}")
				break
		except Exception as e:
			print(e)
file1 = open("keys.txt", "r")
keys = file1.readlines()
n = 1
for key in keys:
	if requests.get(f'https://api.etherscan.io/api?module=account&action=balance&address=0xddbd2b932c763ba5b1b7ae3b362eac3e8d40121a&tag=latest&apikey={key.strip()}').json()["result"]!= "Invalid API Key":
		print(f"{n} - Good - {key.strip()}")
		th = Thread(target=sleepMe, args=(key.strip(), ))
		th.start()
	else:
		print(f"{n} - Invalid API Key - {key.strip()}")
	n+=1
while True:
	time.sleep(1)
	speed = i-i_old
	i_old = i