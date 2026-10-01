| Name           | NRP        | Kelas     |
| ---            | ---        | ----------|
| Ahmad Faiz Tajuddin | 5025231291 | Keamanan Informasi B |

# Bagian 1: Cara Penggunaan
## Persiapan
- Python 3 terpasang (tidak perlu `pip install` apa pun).
- `chat.py` dan `aes_manual.py` ada di folder yang sama.

## Skenario A: Dua terminal di satu komputer
## Terminal 1 (Receiver, dijalankan lebih dulu):
```
python chat.py listen --key 0123456789abcdef --port 5000
```
Muncul: `Menunggu koneksi di port 5000 ...`

## Terminal 2 (Sender):
```
python chat.py connect --key 0123456789abcdef --host 127.0.0.1 --port 5000
```

## Skenario B: Dua komputer atau dua VM
1. Pastikan keduanya satu jaringan.
2. Cari IP komputer Receiver (`ipconfig` di Windows, `ip a` di Linux), misalnya `192.168.1.10`.
3. Receiver menjalankan perintah `listen`. Sender menjalankan perintah `connect` dengan `--host 192.168.1.10`.
4. Jika gagal tersambung, buka port 5000 di firewall Receiver.

Saat berjalan
- Ketik pesan lalu Enter. Pesan dienkripsi dan dikirim.
- Kedua sisi bisa mengirim kapan saja (dua arah).
- Ketik `exit` untuk keluar.
