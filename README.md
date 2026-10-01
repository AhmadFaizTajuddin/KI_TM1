| Name           | NRP        | Kelas     |
| ---            | ---        | ----------|
| Ahmad Faiz Tajuddin | 5025231291 | Keamanan Informasi B |

# Bagian 1: Cara Penggunaan
## Persiapan
- Python 3 terpasang (tidak perlu pip install apa pun).
- chat.py dan aes_manual.py ada di folder yang sama.

## Skenario A: Dua terminal di satu komputer
## Terminal 1 (Receiver, dijalankan lebih dulu):
```
# Terminal 1 - Receiver (server)
python chat.py listen --key 0123456789abcdef --port 5000

# Terminal 2 - Sender (client); untuk 2 komputer/VM ganti --host dengan IP receiver
python chat.py connect --key 0123456789abcdef --host 127.0.0.1 --port 5000
```

