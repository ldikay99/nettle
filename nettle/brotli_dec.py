"""Pure-Python Brotli DEcompressor (RFC 7932) — stdlib only, no C deps.

Scope: decompression only (the half a scraper needs when a CDN forces
``Content-Encoding: br``). Compression stays out — out of scope for a
fetch pipeline.

Everything here follows RFC 7932 (stream header, meta-block headers,
prefix codes, context modeling, ring-buffer distances and the static
dictionary with its 121 word transforms). The dictionary and transform
tables live in ``nettle._brotli_data`` (normative Appendix A/B data).

API:
    decompress(brotli_bytes) -> bytes          # whole stream
    BrotliError                                # invalid stream

Slow paths are acceptable: this is the correctness-first fallback used
by ``nettle.http`` when a server ignores our preferences and sends br.
If the C ``brotli`` module happens to be installed, ``decompress()``
still uses THIS decoder so production behavior is reproducible; callers
can compare both in tests (see tests/test_agentA3_brotli.py).
"""

from __future__ import annotations

from typing import Dict, List, Optional, Tuple

from ._brotli_data import DICT, OFFSETS, PREFIX_SUFFIX, SIZE_BITS, TRANSFORMS


class BrotliError(ValueError):
    """Invalid or truncated brotli stream."""


# --- insert / copy / block-count code tables (RFC 7932 Section 5/6) ---------

_INS_BASE = (
    0, 1, 2, 3, 4, 5, 6, 8, 10, 14, 18, 26, 34, 50, 66, 98,
    130, 194, 322, 578, 1090, 2114, 6210, 22594,
)
_INS_EXTRA = (
    0, 0, 0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5,
    6, 7, 8, 9, 10, 12, 14, 24,
)
_COPY_BASE = (
    2, 3, 4, 5, 6, 7, 8, 9, 10, 12, 14, 18, 22, 30, 38, 54,
    70, 102, 134, 198, 326, 582, 1094, 2118,
)
_COPY_EXTRA = (
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4,
    5, 5, 6, 7, 8, 9, 10, 24,
)
_BLC_BASE = (
    1, 5, 9, 13, 17, 25, 33, 41, 49, 65, 81, 97, 113, 145, 177, 209,
    241, 305, 369, 497, 753, 1265, 2289, 4337, 8433, 16625,
)
_BLC_EXTRA = (
    2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5,
    6, 6, 7, 8, 9, 10, 11, 12, 13, 24,
)

# --- context LUTs (RFC 7932 Section 7.1, transcribed) -----------------------

_LUT0 = (
    0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 4, 0, 0, 4, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    8, 12, 16, 12, 12, 20, 12, 16, 24, 28, 12, 12, 32, 12, 36, 12,
    44, 44, 44, 44, 44, 44, 44, 44, 44, 44, 32, 32, 24, 40, 28, 12,
    12, 48, 52, 52, 52, 48, 52, 52, 52, 48, 52, 52, 52, 52, 52, 48,
    52, 52, 52, 52, 52, 48, 52, 52, 52, 52, 52, 24, 12, 28, 12, 12,
    12, 56, 60, 60, 60, 56, 60, 60, 60, 56, 60, 60, 60, 60, 60, 56,
    60, 60, 60, 60, 60, 56, 60, 60, 60, 60, 60, 24, 12, 28, 12, 0,
    0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1,
    0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1,
    0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1,
    0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1,
    2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3,
    2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3,
    2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3,
    2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3,
)
_LUT1 = (
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1,
    1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1,
    1, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
    3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 1, 1, 1, 1, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
)
_LUT2 = (
    0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
    3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
    3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
    3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
    4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,
    4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,
    4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,
    4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,
    5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,
    5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,
    5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,
    6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 7,
)
assert len(_LUT0) == len(_LUT1) == len(_LUT2) == 256

# Transform type ids (google/brotli transform.h)
_T_IDENTITY, _T_OMIT_LAST, _T_UPPER_FIRST, _T_UPPER_ALL, _T_OMIT_FIRST = 0, 1, 10, 11, 12


# --- bit reader --------------------------------------------------------------

class _BitReader:
    """LSB-first bit reader over bytes (RFC 7932 packing)."""

    __slots__ = ("data", "pos", "bit", "len")

    def __init__(self, data: bytes) -> None:
        self.data = data
        self.len = len(data) * 8
        self.pos = 0  # bit position

    def read(self, n: int) -> int:
        if n == 0:
            return 0
        v = 0
        for i in range(n):
            p = self.pos
            if p >= self.len:
                # past EOF: zeros (RFC: last byte's unused bits are zero)
                self.pos += n - i
                return v
            v |= ((self.data[p >> 3] >> (p & 7)) & 1) << i
            self.pos = p + 1
        return v

    def read_bit(self) -> int:
        p = self.pos
        if p >= self.len:
            self.pos += 1
            return 0
        self.pos += 1
        return (self.data[p >> 3] >> (p & 7)) & 1

    def byte_align(self) -> None:
        self.pos = (self.pos + 7) & ~7

    def aligned_bytes(self, n: int) -> bytes:
        out = bytearray()
        for _ in range(n):
            v = 0
            for i in range(8):
                v |= self.read_bit() << i
            out.append(v)
        return bytes(out)


# --- prefix codes -------------------------------------------------------------

class _SingleCode:
    """Zero-length prefix code: one symbol, consumes no bits."""

    __slots__ = ("symbol",)

    def __init__(self, symbol: int) -> None:
        self.symbol = symbol

    def decode(self, r: "_BitReader") -> int:
        return self.symbol


class _PrefixCode:
    __slots__ = ("table", "maxlen")

    def __init__(self, table: Dict[Tuple[int, int], int], maxlen: int) -> None:
        self.table = table  # (nbits, canonical_code) -> symbol
        self.maxlen = maxlen

    def decode(self, r: "_BitReader") -> int:
        code = 0
        table = self.table
        p, data, ln = r.pos, r.data, r.len
        n = 0
        while n < 15:
            if p >= ln:
                r.pos = p + 1
                raise BrotliError("truncated prefix code")
            code = (code << 1) | ((data[p >> 3] >> (p & 7)) & 1)
            p += 1
            n += 1
            hit = table.get((n, code))
            if hit is not None:
                r.pos = p
                return hit
        raise BrotliError("invalid prefix code symbol")


def _canonical(lengths: List[int]) -> _PrefixCode:
    """Build canonical prefix code: shorter codes first; ties by symbol."""
    bl_count = [0] * 16
    for l in lengths:
        if l:
            bl_count[l] += 1
    next_code = [0] * 16
    code = 0
    for bits in range(1, 16):
        code = (code + bl_count[bits - 1]) << 1
        next_code[bits] = code
    table: Dict[Tuple[int, int], int] = {}
    maxlen = 0
    for sym, l in enumerate(lengths):
        if l:
            table[(l, next_code[l])] = sym
            next_code[l] += 1
            if l > maxlen:
                maxlen = l
    return _PrefixCode(table, maxlen)


_CLCL_CODE = {0: 0, 1: 4, 2: 3}  # 2-bit prefix of the var-length code


def _read_clcl(r: "_BitReader") -> int:
    """Read one code-length-code length (2..4 bit fixed code, RFC 3.5).

    Symbol: 0=`00` 1=`0111` 2=`011` 3=`10` 4=`01` 5=`1111` (MSB-left).
    """
    v = r.read(2)
    if v < 3:
        return _CLCL_CODE[v]
    if r.read(1) == 0:
        return 2
    return 1 if r.read(1) == 0 else 5


_CL_ORDER = (1, 2, 3, 4, 0, 5, 17, 6, 16, 7, 8, 9, 10, 11, 12, 13, 14, 15)


def read_prefix_code(r: "_BitReader", alphabet_size: int):
    """Read a prefix code definition (simple or complex), RFC 3.4/3.5."""
    hskip = r.read(2)
    if hskip == 1:  # simple
        nsym = r.read(2) + 1
        abits = max(1, (alphabet_size - 1).bit_length())
        syms = [r.read(abits) for _ in range(nsym)]
        for s in syms:
            if s >= alphabet_size:
                raise BrotliError("simple code symbol out of alphabet")
        if len(set(syms)) != nsym:
            raise BrotliError("simple code repeated symbol")
        if nsym == 1:
            return _SingleCode(syms[0])
        lengths = [0] * alphabet_size
        if nsym == 2:
            lengths[syms[0]] = 1
            lengths[syms[1]] = 1
        elif nsym == 3:
            lengths[syms[0]] = 1
            lengths[syms[1]] = 2
            lengths[syms[2]] = 2
        else:
            tsel = r.read(1)
            if tsel == 0:
                for s in syms:
                    lengths[s] = 2
            else:
                lengths[syms[0]] = 1
                lengths[syms[1]] = 2
                lengths[syms[2]] = 3
                lengths[syms[3]] = 3
        return _canonical(lengths)

    # complex
    cl_lengths = [0] * 18
    space = 32
    num_codes = 0
    for i in range(hskip, 18):
        ln = _read_clcl(r)
        cl_lengths[_CL_ORDER[i]] = ln
        if ln:
            num_codes += 1
            space -= 32 >> ln
        if space <= 0:
            if space < 0:
                raise BrotliError("overfull code-length code")
            break
    if num_codes == 0:
        raise BrotliError("empty code-length code")
    if num_codes == 1:
        # Single code-length symbol: its (zero-length) code returns it for
        # every entry — e.g. symbol 16 repeating implicit length 8.
        only = next(i for i, v in enumerate(cl_lengths) if v)
        cl_tree = _SingleCode(only)
    else:
        if space != 0:
            raise BrotliError("underfull code-length code")
        cl_tree = _canonical(cl_lengths)

    lengths = [0] * alphabet_size
    symbol = 0
    space = 32768
    prev_code_len = 8
    repeat = 0
    repeat_code_len = 0
    while symbol < alphabet_size and space > 0:
        code_len = cl_tree.decode(r)
        if code_len < 16:
            lengths[symbol] = code_len
            symbol += 1
            repeat = 0
            if code_len != 0:
                prev_code_len = code_len
                space -= 32768 >> code_len
        else:
            extra_bits = 2 if code_len == 16 else 3
            new_len = prev_code_len if code_len == 16 else 0
            if repeat_code_len != new_len:
                repeat = 0
                repeat_code_len = new_len
            old_repeat = repeat
            if repeat > 0:
                repeat = (repeat - 2) << extra_bits
            repeat += r.read(extra_bits) + 3
            repeat_delta = repeat - old_repeat
            if symbol + repeat_delta > alphabet_size:
                raise BrotliError("code length repeat exceeds alphabet")
            if repeat_code_len:
                space -= (32768 >> repeat_code_len) * repeat_delta
            lengths[symbol: symbol + repeat_delta] = [repeat_code_len] * repeat_delta
            symbol += repeat_delta
    if space < 0:
        raise BrotliError("overfull prefix code")
    if sum(1 for v in lengths[:symbol] if v) == 1:
        only = next(i for i in range(symbol) if lengths[i])
        return _SingleCode(only)
    if space != 0:
        raise BrotliError("underfull prefix code")
    return _canonical(lengths[:alphabet_size])


# --- static dictionary transforms ---------------------------------------------

def _to_upper(buf: bytearray, i: int) -> int:
    b = buf[i]
    if b < 0xC0:
        if 97 <= b <= 122:
            buf[i] = b ^ 32
        return 1
    if b < 0xE0:
        if i + 1 < len(buf):
            buf[i + 1] ^= 32
        return 2
    if i + 2 < len(buf):
        buf[i + 2] ^= 5
    return 3


def _transform_word(word: bytes, tid: int) -> bytes:
    prefix_len, prefix = PREFIX_SUFFIX[TRANSFORMS[tid][0]]
    ttype = TRANSFORMS[tid][1]
    suffix_len, suffix = PREFIX_SUFFIX[TRANSFORMS[tid][2]]
    out = bytearray(prefix)
    w = word
    if 1 <= ttype <= 9:  # OMIT_LAST_k
        w = w[: max(0, len(w) - ttype)]
    elif 12 <= ttype <= 20:  # OMIT_FIRST_k
        k = ttype - 11
        w = w[k:]
    out += w
    if ttype == _T_UPPER_FIRST and out[-len(w):]:
        _to_upper(out, len(out) - len(w))
    elif ttype == _T_UPPER_ALL:
        i = len(out) - len(w)
        end = len(out)
        while i < end:
            i += _to_upper(out, i)
    out += suffix
    return bytes(out)


# --- decoder -------------------------------------------------------------------

def _decode_varlen_count(r: "_BitReader") -> int:
    """NBLTYPESx / NTREESx variable-length code (RFC 9.2)."""
    if r.read(1) == 0:
        return 1
    n = r.read(3)
    if n == 0:
        return 2
    return (1 << n) + 1 + r.read(n)


def _read_context_map(r: "_BitReader", size: int, ntrees: int) -> List[int]:
    if ntrees <= 1:
        return [0] * size
    rlemax = 0
    if r.read(1):
        rlemax = r.read(4) + 1
    tree = read_prefix_code(r, ntrees + rlemax)
    cmap = []
    while len(cmap) < size:
        sym = tree.decode(r)
        if sym == 0:
            cmap.append(0)
        elif sym <= rlemax:
            reps = (1 << sym) + r.read(sym)
            if len(cmap) + reps > size:
                raise BrotliError("context map RLE overflow")
            cmap.extend([0] * reps)
        else:
            cmap.append(sym - rlemax)
    if len(cmap) != size:
        raise BrotliError("context map size mismatch")
    if r.read(1):  # IMTF
        mtf = list(range(256))
        for i, index in enumerate(cmap):
            value = mtf[index]
            cmap[i] = value
            j = index
            while j:
                mtf[j] = mtf[j - 1]
                j -= 1
            mtf[0] = value
    return cmap


class _BlockSwitcher:
    """Block type/count state for one category (RFC Section 6)."""

    def __init__(self, ntypes: int) -> None:
        self.ntypes = ntypes
        self.rb = [1, 0]
        self.left = 1 << 60  # effectively infinite

    def setup(self, r: "_BitReader", type_tree, count_tree) -> None:
        self.type_tree = type_tree
        self.count_tree = count_tree
        self.left = self._read_count(r)

    def _read_count(self, r: "_BitReader") -> int:
        code = self.count_tree.decode(r)
        return _BLC_BASE[code] + r.read(_BLC_EXTRA[code])

    def switch(self, r: "_BitReader") -> None:
        sym = self.type_tree.decode(r)
        if sym == 0:
            btype = self.rb[0]
        elif sym == 1:
            btype = self.rb[1] + 1
            if btype >= self.ntypes:
                btype = 0
        else:
            btype = sym - 2
        self.rb[0] = self.rb[1]
        self.rb[1] = btype
        self.left = self._read_count(r)

    @property
    def btype(self) -> int:
        return self.rb[1]


# (base_offset, insert_base, copy_base) per 64-code cell, RFC 7932 Section 5.
# cmd 0..63 and 64..127 reuse the last distance (no distance symbol).
_CMD_CELLS = (
    # (first_cmd, ins_base, copy_base, dist_zero)
    (0, 0, 0, True),
    (64, 0, 8, True),
    (128, 0, 0, False),
    (192, 0, 8, False),
    (256, 8, 0, False),
    (320, 8, 8, False),
    (384, 0, 16, False),
    (448, 16, 0, False),
    (512, 8, 16, False),
    (576, 16, 8, False),
    (640, 16, 16, False),
)


def _split_cmd(cmd: int) -> Tuple[int, int, bool]:
    """704-symbol insert&copy code -> (insert_code, copy_code, dist_zero)."""
    cell = None
    for first, ins_b, copy_b, dz in _CMD_CELLS:
        if cmd < first + 64:
            cell = (ins_b, copy_b, dz)
            break
    if cell is None:
        raise BrotliError(f"command code {cmd} out of range")
    ins_b, copy_b, dz = cell
    return ins_b + ((cmd >> 3) & 7), copy_b + (cmd & 7), dz


class _Decoder:
    def __init__(self, data: bytes) -> None:
        self.r = _BitReader(data)
        self.out = bytearray()

    def _ctx_literal(self, mode: int, p1: int, p2: int) -> int:
        if mode == 0:
            return p1 & 0x3F
        if mode == 1:
            return p1 >> 2
        if mode == 2:
            return _LUT0[p1] | _LUT1[p2]
        return (_LUT2[p1] << 3) | _LUT2[p2]

    def run(self) -> bytes:
        r = self.r
        # --- stream header: WBITS ---
        if r.read(1) == 0:
            wbits = 16
        else:
            n = r.read(3)
            if n:
                wbits = 17 + n
            else:
                n = r.read(3)
                wbits = 8 + n if n else 17
        if not 10 <= wbits <= 24:
            raise BrotliError(f"WBITS {wbits} out of range")
        window = (1 << wbits) - 16

        dist_rb = [4, 11, 15, 16]  # [last, 2nd-to-last, 3rd, 4th]

        while True:  # meta-blocks
            if r.pos >= r.len:
                # every valid stream ends with an ISLAST meta-block; hitting
                # the end without one means unterminated garbage (or padding
                # zeros, which can never encode ISLAST=1/ISLASTEMPTY=1)
                raise BrotliError("unterminated brotli stream (no ISLAST block)")
            islast = r.read(1)
            if islast and r.read(1):  # ISLASTEMPTY
                break
            mnibbles_code = r.read(2)
            mnibbles = {0: 4, 1: 5, 2: 6, 3: 0}[mnibbles_code]
            if mnibbles == 0:
                # metadata block
                if r.read(1):
                    raise BrotliError("metadata reserved bit set")
                mskipbytes = r.read(2)
                mskiplen = 0
                if mskipbytes:
                    mskiplen = 0
                    for i in range(mskipbytes * 8):
                        mskiplen |= r.read(1) << i
                    mskiplen += 1
                r.byte_align()
                # skip MSKIPLEN bytes
                self.r.pos += mskiplen * 8
                if islast:
                    break
                continue
            mlen = 0
            for i in range(mnibbles * 4):
                mlen |= r.read(1) << i
            mlen += 1
            if not islast and r.read(1):  # ISUNCOMPRESSED
                r.byte_align()
                end = len(r.data)
                start = r.pos >> 3
                if start + mlen > end:
                    raise BrotliError("uncompressed block truncated")
                self.out += r.data[start: start + mlen]
                r.pos += mlen * 8
                continue

            # --- meta-block header ---
            nbltypesl = _decode_varlen_count(r)
            lsw = _BlockSwitcher(nbltypesl)
            if nbltypesl >= 2:
                lt = read_prefix_code(r, nbltypesl + 2)
                lc = read_prefix_code(r, 26)
                lsw.setup(r, lt, lc)
            nbltypesi = _decode_varlen_count(r)
            isw = _BlockSwitcher(nbltypesi)
            if nbltypesi >= 2:
                it = read_prefix_code(r, nbltypesi + 2)
                ic = read_prefix_code(r, 26)
                isw.setup(r, it, ic)
            nbltypesd = _decode_varlen_count(r)
            dsw = _BlockSwitcher(nbltypesd)
            if nbltypesd >= 2:
                dt = read_prefix_code(r, nbltypesd + 2)
                dc = read_prefix_code(r, 26)
                dsw.setup(r, dt, dc)

            npostfix = r.read(2)
            ndirect = r.read(4) << npostfix
            postfix_mask = (1 << npostfix) - 1

            lit_modes = [r.read(2) for _ in range(nbltypesl)]
            ntreesl = _decode_varlen_count(r)
            cmapl = _read_context_map(r, 64 * nbltypesl, ntreesl)
            ntreesd = _decode_varlen_count(r)
            cmapd = _read_context_map(r, 4 * nbltypesd, ntreesd)

            lit_trees = [read_prefix_code(r, 256) for _ in range(ntreesl)]
            ic_trees = [read_prefix_code(r, 704) for _ in range(nbltypesi)]
            dist_trees = [read_prefix_code(r, 16 + ndirect + (48 << npostfix))
                          for _ in range(ntreesd)]

            # --- meta-block data ---
            out = self.out
            mlen_end = len(out) + mlen
            while len(out) < mlen_end:
                if isw.left <= 0:
                    isw.switch(r)
                isw.left -= 1
                cmd = ic_trees[isw.btype].decode(r)
                insert_code, copy_code, dist_zero = _split_cmd(cmd)
                ins_len = _INS_BASE[insert_code] + r.read(_INS_EXTRA[insert_code])
                copy_len = _COPY_BASE[copy_code] + r.read(_COPY_EXTRA[copy_code])

                # literals
                for _ in range(ins_len):
                    if lsw.left <= 0:
                        lsw.switch(r)
                    lsw.left -= 1
                    p1 = out[-1] if len(out) >= 1 else 0
                    p2 = out[-2] if len(out) >= 2 else 0
                    mode = lit_modes[lsw.btype]
                    ctx = self._ctx_literal(mode, p1, p2)
                    tree = lit_trees[cmapl[64 * lsw.btype + ctx]]
                    out.append(tree.decode(r))

                if len(out) >= mlen_end:
                    break  # last copy ignored (RFC 9.3)

                if dist_zero:
                    dist = dist_rb[0]  # implicit last distance: never pushed
                    push_dist = False
                else:
                    if dsw.left <= 0:
                        dsw.switch(r)
                    dsw.left -= 1
                    dctx = 0 if copy_len == 2 else 1 if copy_len == 3 else 2 if copy_len == 4 else 3
                    dcode = dist_trees[cmapd[4 * dsw.btype + dctx]].decode(r)
                    dist, push_dist = self._resolve_distance(
                        dcode, dist_rb, ndirect, npostfix, postfix_mask, r
                    )

                max_allowed = min(len(out), window)
                if dist <= 0:
                    raise BrotliError(f"distance {dist} resolved to <= 0")
                if dist <= max_allowed:
                    src = len(out) - dist
                    for i in range(copy_len):
                        out.append(out[src + i])
                    if push_dist:
                        dist_rb[3], dist_rb[2], dist_rb[1], dist_rb[0] = \
                            dist_rb[2], dist_rb[1], dist_rb[0], dist
                else:
                    # static dictionary reference
                    if copy_len < 4 or copy_len > 24:
                        raise BrotliError("dictionary copy length out of range")
                    word_id = dist - max_allowed - 1
                    nwords = 1 << SIZE_BITS[copy_len]
                    index = word_id % nwords
                    tid = word_id >> SIZE_BITS[copy_len]
                    if tid > 120:
                        raise BrotliError("dictionary transform id too large")
                    off = OFFSETS[copy_len] + index * copy_len
                    word = DICT[off: off + copy_len]
                    out += _transform_word(word, tid)
            if islast:
                break
        return bytes(self.out)

    def _resolve_distance(self, dcode, rb, ndirect, npostfix, postfix_mask, r):
        """Distance symbol -> (backward distance, push_to_ring_buffer).

        RFC Section 4: distance symbol 0 reuses the last distance and is
        NOT pushed to the ring buffer; symbols 1..15, the NDIRECT codes
        and the extra-bits codes all push. Dictionary references (caller)
        never push.
        """
        if dcode == 0:
            return rb[0], False
        if dcode <= 3:
            return rb[dcode], True
        if dcode <= 9:  # last distance -3..+3
            return rb[0] + {4: -1, 5: 1, 6: -2, 7: 2, 8: -3, 9: 3}[dcode], True
        if dcode <= 15:  # second-to-last distance -3..+3
            d = rb[1] + {10: -1, 11: 1, 12: -2, 13: 2, 14: -3, 15: 3}[dcode]
            return d, True
        if dcode <= 15 + ndirect:
            return dcode - 15, True
        ndistbits = 1 + ((dcode - ndirect - 16) >> (npostfix + 1))
        dextra = r.read(ndistbits)
        hcode = (dcode - ndirect - 16) >> npostfix
        lcode = (dcode - ndirect - 16) & postfix_mask
        offset = ((2 + (hcode & 1)) << ndistbits) - 4
        return (((offset + dextra) << npostfix) + lcode + ndirect + 1), True


def decompress(data: bytes) -> bytes:
    """Decompress a complete brotli stream (RFC 7932). Raises BrotliError."""
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError(f"brotli decompress expects bytes, got {type(data).__name__}")
    data = bytes(data)
    if not data:
        raise BrotliError("empty brotli stream")
    return _Decoder(data).run()
