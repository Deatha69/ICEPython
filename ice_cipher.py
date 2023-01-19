class IceKey(object):
    """
    ICE cipher class, ported from C implementation 
    Source: https://darkside.com.au/ice/
    """

    _sbox_init: bool = False
    _ice_sbox: list[list[int]] = list(list(0 for _ in range(1024)) for _ in range(4))
    _ice_smod: list[int] = [
        [333, 313, 505, 369],
        [379, 375, 319, 391],
        [361, 445, 451, 397],
        [397, 425, 395, 505]
    ]
    _ice_sxor: list[int] = [
        [0x83, 0x85, 0x9b, 0xcd],
        [0xcc, 0xa7, 0xad, 0x41],
        [0x4b, 0x2e, 0xd4, 0x33],
        [0xea, 0xcb, 0x2e, 0x04]
    ]
    _ice_keyrot: list[int] = [
        0, 1, 2, 3, 2, 1, 3, 0,
        1, 3, 2, 0, 3, 1, 0, 2
    ]
    _ice_pbox: list[int] = [
        0x00000001, 0x00000080, 0x00000400, 0x00002000,
        0x00080000, 0x00200000, 0x01000000, 0x40000000,
        0x00000008, 0x00000020, 0x00000100, 0x00004000,
        0x00010000, 0x00800000, 0x04000000, 0x20000000,
        0x00000004, 0x00000010, 0x00000200, 0x00008000,
        0x00020000, 0x00400000, 0x08000000, 0x10000000,
        0x00000002, 0x00000040, 0x00000800, 0x00001000,
        0x00040000, 0x00100000, 0x02000000, 0x80000000
    ]

    def __init__(self, n: int):
        if not self._sbox_init:
            self._init_sboxes()
            self._sbox_init = True

        if n < 1:
            self._size = 1
            self._rounds = 8
        else:
            self._size = n
            self._rounds = n * 16

        self._keysched: list[list[int]] = list(
            list(0 for _ in range(3)) for _ in range(self._rounds))

    @staticmethod
    def _gf_mult(a, b, m) -> int:
        res = 0
        while b:
            if b & 1:
                res ^= a
            a <<= 1
            b >>= 1
            if a >= 256:
                a ^= m
        return res

    def _gf_exp7(self, b, m) -> int:
        if not b:
            return 0
        x = self._gf_mult(b, b, m)
        x = self._gf_mult(b, x, m)
        x = self._gf_mult(x, x, m)
        return self._gf_mult(b, x, m)

    def _ice_perm32(self, x: int) -> int:
        res = 0
        box_index = 0
        while x:
            if x & 1:
                res |= self._ice_pbox[box_index]
            box_index += 1
            x >>= 1
        return res

    def _init_sboxes(self) -> None:
        for i in range(1024):
            col = (i >> 1) & 0xFF
            row = (i & 1) | ((i & 0x200) >> 8)

            x = self._gf_exp7(col ^ self._ice_sxor[0][row], self._ice_smod[0][row]) << 24
            self._ice_sbox[0][i] = self._ice_perm32(x)

            x = self._gf_exp7(col ^ self._ice_sxor[1][row], self._ice_smod[1][row]) << 16
            self._ice_sbox[1][i] = self._ice_perm32(x)

            x = self._gf_exp7(col ^ self._ice_sxor[2][row], self._ice_smod[2][row]) << 8
            self._ice_sbox[2][i] = self._ice_perm32(x)

            x = self._gf_exp7(col ^ self._ice_sxor[3][row], self._ice_smod[3][row])
            self._ice_sbox[3][i] = self._ice_perm32(x)

    def _schedulebuild(self, kb: list[int], n: int, keyrot: list[int]) -> None:
        for i in range(8):
            kr = keyrot[i]
            isk = self._keysched[n + i]

            for j in range(3):
                self._keysched[n + i][j] = 0

            for j in range(15):
                for k in range(4):
                    curr_kb = kb[(kr + k) & 3]
                    bit = curr_kb & 1

                    isk[j % 3] = (isk[j % 3] << 1) | bit
                    kb[(kr + k) & 3] = (curr_kb >> 1) | ((bit ^ 1) << 15)

    def _ice_f(self, p, sk):
        tl = (((p >> 16) & 0x3FF) | (((p >> 14) | (p << 18)) & 0xFFC00))
        tr = (p & 0x3FF) | ((p << 2) & 0xFFC00)

        al = sk[2] & (tl ^ tr)
        ar = al ^ tr
        al ^= tl

        al ^= sk[0]
        ar ^= sk[1]

        return (
            self._ice_sbox[0][al >> 10] |
            self._ice_sbox[1][al & 0x3FF] |
            self._ice_sbox[2][ar >> 10] |
            self._ice_sbox[3][ar & 0x3FF]
        )

    def set(self, key: bytes):
        if self._rounds == 8:
            kb = [0, 0, 0, 0]
            for i in range(len(kb)):
                kb[3 - i] = (key[i * 2] << 8) | key[i * 2 + 1]
            self._schedulebuild(kb, 0, self._ice_keyrot)
            return

        for i in range(self._size):
            kb = [0, 0, 0, 0]

            for j in range(len(kb)):
                kb[3 - j] = (key[i * 8 + j * 2] << 8) | key[i * 8 + j * 2 + 1]

            self._schedulebuild(kb, i * 8, self._ice_keyrot)
            self._schedulebuild(
                kb, self._rounds - 8 - i * 8, self._ice_keyrot[8:])

    def decrypt(self, ctext: bytes) -> bytes:
        left = (ctext[0] << 24) | (ctext[1] << 16) | (ctext[2] << 8) | ctext[3]
        right = (ctext[4] << 24) | (ctext[5] << 16) | (ctext[6] << 8) | ctext[7]

        for i in range(self._rounds - 1, 0, -2):
            left ^= self._ice_f(right, self._keysched[i])
            right ^= self._ice_f(left, self._keysched[i - 1])

        ptext = list(0 for _ in range(8))
        for i in range(4):
            ptext[3 - i] = right & 0xFF
            ptext[7 - i] = left & 0xFF
            right >>= 8
            left >>= 8
        return bytes(ptext)

    def encrypt(self, ptext: bytes) -> bytes:
        left = (ptext[0] << 24) | (ptext[1] << 16) | (ptext[2] << 8) | ptext[3]
        right = (ptext[4] << 24) | (ptext[5] << 16) | (ptext[6] << 8) | ptext[7]

        for i in range(0, self._rounds, 2):
            left ^= self._ice_f(right, self._keysched[i])
            right ^= self._ice_f(left, self._keysched[i + 1])

        ctext = list(0 for _ in range(8))
        for i in range(4):
            ctext[3 - i] = right & 0xFF
            ctext[7 - i] = left & 0xFF
            right >>= 8
            left >>= 8
        return bytes(ctext)

