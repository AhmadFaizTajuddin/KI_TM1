"""Simulasi komunikasi ciphertext DUA ARAH (Sender <-> Receiver) lewat TCP socket.
Key sudah dibagi sebelumnya (pre-shared), TIDAK dikirim lewat jaringan.

Jalankan di dua terminal / dua VM / dua komputer:
  Terminal 1 (Receiver/server): python chat.py listen  --key KUNCI16KARAKTER --port 5000
  Terminal 2 (Sender/client)  : python chat.py connect --key KUNCI16KARAKTER --host 127.0.0.1 --port 5000
Setelah tersambung, KEDUA pihak bisa mengirim & menerima pesan. Ketik 'exit' untuk keluar.
"""
import argparse, socket, struct, threading, sys
import aes_manual as aes

def send_msg(sock, data: bytes):
    sock.sendall(struct.pack(">I", len(data)) + data)      # framing: 4 byte panjang

def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Koneksi ditutup")
        buf += chunk
    return buf

def recv_msg(sock):
    (n,) = struct.unpack(">I", recv_exact(sock, 4))
    return recv_exact(sock, n)

def receiver_loop(sock, key, name):
    try:
        while True:
            blob = recv_msg(sock)
            print(f"\n[{name}] <- Ciphertext diterima : {blob.hex()}")
            try:
                print(f"[{name}] <- Plaintext (dekripsi): {aes.decrypt(blob, key).decode()}")
            except Exception as e:
                print(f"[{name}] Gagal dekripsi: {e}")
    except (ConnectionError, OSError):
        print(f"\n[{name}] Koneksi terputus.")
        sock.close()

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", choices=["listen", "connect"])
    ap.add_argument("--key", required=True, help="pre-shared key, tepat 16 karakter")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=5000)
    a = ap.parse_args()

    key = a.key.encode()
    if len(key) != 16:
        sys.exit("Key harus tepat 16 karakter (128-bit).")

    if a.mode == "listen":
        name = "RECEIVER"
        srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("0.0.0.0", a.port)); srv.listen(1)
        print(f"[{name}] Menunggu koneksi di port {a.port} ...")
        sock, addr = srv.accept()
        print(f"[{name}] Tersambung dengan {addr}")
    else:
        name = "SENDER"
        sock = socket.create_connection((a.host, a.port))
        print(f"[{name}] Tersambung ke {a.host}:{a.port}")

    threading.Thread(target=receiver_loop, args=(sock, key, name), daemon=True).start()
    try:
        while True:
            text = input()
            if text.strip().lower() == "exit":
                break
            blob = aes.encrypt(text.encode(), key)
            print(f"[{name}] -> Plaintext            : {text}")
            print(f"[{name}] -> Ciphertext dikirim   : {blob.hex()}")
            send_msg(sock, blob)
    except (EOFError, KeyboardInterrupt, OSError):
        pass
    finally:
        sock.close()

if __name__ == "__main__":
    main()
