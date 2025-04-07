# Decrypt pcap file for Prisma Access Traffic Replication

## How to use
1. Install Poetry if you need.  
https://python-poetry.org/docs/
```
curl -sSL https://install.python-poetry.org | python3 -
```
2. Unzip the downloaded file.
3. Decrypt pcap file  
- Poetry
```
poetry install
poetry run python decrypt_pcap.py --pkey <your_private_key_path> --json <pcapng.json_file_inside_zip> --pcap <pcapng.enc_file_inside_zip> --out <output_path_of_decrypted_pcap_file>
```
- Python
```
pip install -r requirements.txt
python decrypt_pcap.py --pkey <your_private_key_path> --json <pcapng.json_file_inside_zip> --pcap <pcapng.enc_file_inside_zip> --out <output_path_of_decrypted_pcap_file>
```