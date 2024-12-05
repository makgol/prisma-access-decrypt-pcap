import base64
import json
import argparse
from pathlib import Path
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256

def openFile(file):
    with open(file, "rb") as f:
        data = f.read()
    return data

def decrypt_pcap(json_path, pkey_path, pcap_path, out_path):
    json_data = openFile(json_path)
    private_key_data = openFile(pkey_path)
    pcap_data = openFile(pcap_path)

    pkey = RSA.importKey(private_key_data)

    cipher = PKCS1_OAEP.new(pkey, hashAlgo = SHA256)
    decrypted_json_data = cipher.decrypt(json_data).decode('utf-8')
    json_info = json.loads(decrypted_json_data)
    tag = base64.b64decode(json_info["tag"])
    key = base64.b64decode(json_info["key"])
    nonce = base64.b64decode(json_info["nonce"])

    aes_cipher = AES.new(key, AES.MODE_GCM, nonce)
    pcap = aes_cipher.decrypt_and_verify(pcap_data, tag)

    if out_path is None:
        out_path = "decrypted_" + Path(pcap_path).name.replace(".enc", "")
    with open(out_path, "wb") as f:
        f.write(pcap)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--pkey", help="private key path configured for traffic replication.")
    parser.add_argument("--json", help="pcapng.json file inside the zip file.")
    parser.add_argument("--pcap", help="pcapng.enc file inside the zip file.")
    parser.add_argument("--out", default=None, help="output path of decrypted pcap file.")
    args = parser.parse_args()
    decrypt_pcap(args.json, args.pkey, args.pcap, args.out)


if __name__ == '__main__':
    main()