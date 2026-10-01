"""AES-128 (mode CBC + padding PKCS#7) - implementasi MANUAL tanpa library kripto.
Hanya memakai os.urandom untuk membuat IV acak (bukan fungsi enkripsi)."""
import os

# ---------- Tabel S-Box (dihitung dari GF(2^8)) ----------
def _rotl8(x, n):
    return ((x << n) | (x >> (8 - n))) & 0xFF

def _make_sbox():
    sbox = [0] * 256
    p = q = 1
    while True:
        p = p ^ ((p << 1) & 0xFF) ^ (0x1B if p & 0x80 else 0)
        q ^= q << 1; q ^= q << 2; q ^= q << 4; q &= 0xFF
        if q & 0x80:
            q ^= 0x09
        x = q ^ _rotl8(q, 1) ^ _rotl8(q, 2) ^ _rotl8(q, 3) ^ _rotl8(q, 4)
        sbox[p] = x ^ 0x63
        if p == 1:
            break
    sbox[0] = 0x63
    return sbox

SBOX = _make_sbox()
INV_SBOX = [0] * 256
for _i, _v in enumerate(SBOX):
    INV_SBOX[_v] = _i

def _gmul(a, b):
    r = 0
    while b:
        if b & 1:
            r ^= a
        a = ((a << 1) ^ 0x11B) & 0xFF if a & 0x80 else a << 1
        b >>= 1
    return r

# ---------- Key expansion ----------
def _expand_key(key):
    w = [list(key[4 * i:4 * i + 4]) for i in range(4)]
    rcon = 1
    for i in range(4, 44):
        t = w[i - 1][:]
        if i % 4 == 0:
            t = t[1:] + t[:1]
            t = [SBOX[b] for b in t]
            t[0] ^= rcon
            rcon = _gmul(rcon, 2)
        w.append([w[i - 4][j] ^ t[j] for j in range(4)])
    return [sum(w[4 * r:4 * r + 4], []) for r in range(11)]  # 11 round key @16 byte

# ---------- Transformasi ronde (state: 16 byte, urutan kolom) ----------
def _add_rk(s, rk):
    return [a ^ b for a, b in zip(s, rk)]

def _sub(s, box):
    return [box[b] for b in s]

def _shift_rows(s):
    return [s[r + 4 * ((c + r) % 4)] for c in range(4) for r in range(4)]

def _inv_shift_rows(s):
    return [s[r + 4 * ((c - r) % 4)] for c in range(4) for r in range(4)]

def _mix(s, m):
    out = []
    for c in range(4):
        col = s[4 * c:4 * c + 4]
        for r in range(4):
            out.append(_gmul(col[0], m[r][0]) ^ _gmul(col[1], m[r][1]) ^
                       _gmul(col[2], m[r][2]) ^ _gmul(col[3], m[r][3]))
    return out

_MIX = [[2, 3, 1, 1], [1, 2, 3, 1], [1, 1, 2, 3], [3, 1, 1, 2]]
_INV_MIX = [[14, 11, 13, 9], [9, 14, 11, 13], [13, 9, 14, 11], [11, 13, 9, 14]]

def encrypt_block(block, rks):
    s = _add_rk(list(block), rks[0])
    for r in range(1, 10):
        s = _add_rk(_mix(_shift_rows(_sub(s, SBOX)), _MIX), rks[r])
    s = _add_rk(_shift_rows(_sub(s, SBOX)), rks[10])
    return bytes(s)

def decrypt_block(block, rks):
    s = _add_rk(list(block), rks[10])
    for r in range(9, 0, -1):
        s = _sub(_inv_shift_rows(s), INV_SBOX)
        s = _mix(_add_rk(s, rks[r]), _INV_MIX)
    s = _add_rk(_sub(_inv_shift_rows(s), INV_SBOX), rks[0])
    return bytes(s)

# ---------- Padding & mode CBC ----------
def _pad(data):
    n = 16 - len(data) % 16
    return data + bytes([n]) * n

def _unpad(data):
    n = data[-1]
    if not 1 <= n <= 16 or data[-n:] != bytes([n]) * n:
        raise ValueError("Padding tidak valid (key salah / data rusak)")
    return data[:-n]

def _xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

def encrypt(plaintext: bytes, key: bytes) -> bytes:
    """Output: IV(16) || ciphertext"""
    rks = _expand_key(key)
    iv = os.urandom(16)
    prev, out = iv, [iv]
    data = _pad(plaintext)
    for i in range(0, len(data), 16):
        prev = encrypt_block(_xor(data[i:i + 16], prev), rks)
        out.append(prev)
    return b"".join(out)

def decrypt(blob: bytes, key: bytes) -> bytes:
    if len(blob) < 32 or len(blob) % 16:
        raise ValueError("Ciphertext tidak valid")
    rks = _expand_key(key)
    prev, out = blob[:16], []
    for i in range(16, len(blob), 16):
        c = blob[i:i + 16]
        out.append(_xor(decrypt_block(c, rks), prev))
        prev = c
    return _unpad(b"".join(out))
