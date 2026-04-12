export class PointPairSchnorrP256 {
  private readonly P =
    0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn;
  private readonly N =
    0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
  private readonly G: [bigint, bigint] = [
    0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296n,
    0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5n,
  ];

  private readonly SHA256_K = new Uint32Array([
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
  ]);
  private readonly _W = new Uint32Array(64);

  // ─── mod P 正規化 (常に [0, P) を返す) ───────────────────────────
  private m(x: bigint): bigint {
    const r = x % this.P;
    return r < 0n ? r + this.P : r;
  }

  private readonly G_precomp_window: [bigint, bigint, bigint][][] = (() => {
    const table: [bigint, bigint, bigint][][] = [];
    let base: [bigint, bigint, bigint] = [this.G[0], this.G[1], 1n];
    for (let i = 0; i < 32; i++) {
      const row: [bigint, bigint, bigint][] = new Array(256);
      row[0] = [0n, 1n, 0n];
      row[1] = base;
      for (let j = 2; j < 256; j++) row[j] = this.addJJ(row[j - 1]!, base);
      table.push(row);
      for (let j = 0; j < 8; j++) base = this.dblJ(base);
    }
    return table;
  })();

  // ─── Mixed add: P1 Jacobian, Q affine (Z=1) ──────────────────────
  private addMJ(
    P1: [bigint, bigint, bigint],
    X2: bigint,
    Y2: bigint,
  ): [bigint, bigint, bigint] {
    const [X1, Y1, Z1] = P1;
    if (Z1 === 0n) return [X2, Y2, 1n];
    const p = this.P;
    const Z1Z1 = (Z1 * Z1) % p;
    const U2 = (X2 * Z1Z1) % p;
    const S2 = (Y2 * ((Z1Z1 * Z1) % p)) % p;
    const H = this.m(U2 - X1);
    const RR = this.m(S2 - Y1);
    if (H === 0n) {
      if (RR === 0n) return this.dblJ(P1);
      return [0n, 1n, 0n];
    }
    const HH = (H * H) % p;
    const HHH = (HH * H) % p;
    const U1HH = (X1 * HH) % p;
    const X3 = this.m(RR * RR - HHH - 2n * U1HH);
    const Y3 = this.m(RR * this.m(U1HH - X3) - Y1 * HHH);
    const Z3 = (H * Z1) % p;
    return [X3, Y3, Z3];
  }

  // ─── Full Jacobian + Jacobian ─────────────────────────────────────
  private addJJ(
    P1: [bigint, bigint, bigint],
    Q: [bigint, bigint, bigint],
  ): [bigint, bigint, bigint] {
    const [X1, Y1, Z1] = P1;
    const [X2, Y2, Z2] = Q;
    if (Z1 === 0n) return Q;
    if (Z2 === 0n) return P1;
    if (Z2 === 1n) return this.addMJ(P1, X2, Y2);
    if (Z1 === 1n) return this.addMJ(Q, X1, Y1);
    const p = this.P;
    const Z1Z1 = (Z1 * Z1) % p;
    const Z2Z2 = (Z2 * Z2) % p;
    const U1 = (X1 * Z2Z2) % p;
    const U2 = (X2 * Z1Z1) % p;
    const S1 = (Y1 * ((Z2Z2 * Z2) % p)) % p;
    const S2 = (Y2 * ((Z1Z1 * Z1) % p)) % p;
    const H = this.m(U2 - U1);
    const RR = this.m(S2 - S1);
    if (H === 0n) {
      if (RR === 0n) return this.dblJ(P1);
      return [0n, 1n, 0n];
    }
    const HH = (H * H) % p;
    const HHH = (HH * H) % p;
    const U1HH = (U1 * HH) % p;
    const X3 = this.m(RR * RR - HHH - 2n * U1HH);
    const Y3 = this.m(RR * this.m(U1HH - X3) - S1 * HHH);
    const Z3 = (((H * Z1) % p) * Z2) % p;
    return [X3, Y3, Z3];
  }

  // ─── Doubling: a = -3 specialization ──────────────────────────────
  private dblJ(Pt: [bigint, bigint, bigint]): [bigint, bigint, bigint] {
    const [X, Y, Z] = Pt;
    if (Z === 0n) return Pt;
    const p = this.P;
    const YY = (Y * Y) % p;
    const YYYY = (YY * YY) % p;
    const ZZ = (Z * Z) % p;
    const S = (4n * ((X * YY) % p)) % p;
    const M = (3n * (((X + ZZ) * this.m(X - ZZ)) % p)) % p;
    const X3 = this.m(M * M - 2n * S);
    const Y3 = this.m(M * this.m(S - X3) - 8n * YYYY);
    return [X3, Y3, (2n * ((Y * Z) % p)) % p];
  }

  private toAffine(Pt: [bigint, bigint, bigint]): [bigint, bigint] {
    if (Pt[2] === 0n) return [0n, 0n];
    const invZ = this.inv(Pt[2], this.P);
    const invZ2 = this.m(invZ * invZ);
    const invZ3 = this.m(invZ2 * invZ);
    return [this.m(Pt[0] * invZ2), this.m(Pt[1] * invZ3)];
  }

  // Pre-cached shift amounts for scalarMultGJac
  private readonly _shifts: bigint[] = (() => {
    const s: bigint[] = [];
    for (let i = 0; i < 256; i += 8) s.push(BigInt(i));
    return s;
  })();

  private scalarMultGJac(k: bigint): [bigint, bigint, bigint] {
    const win0 = Number(k & 0xffn);
    const firstRow = this.G_precomp_window[0]!;
    let R: [bigint, bigint, bigint] = [...firstRow[win0]!] as [
      bigint,
      bigint,
      bigint,
    ];
    const shifts = this._shifts;
    for (let i = 1; i < 32; i++) {
      const win = Number((k >> shifts[i]!) & 0xffn);
      if (win !== 0) R = this.addJJ(R, this.G_precomp_window[i]![win]!);
    }
    return R;
  }
  private scalarMultG(k: bigint): [bigint, bigint] {
    return this.toAffine(this.scalarMultGJac(k));
  }

  private scalarMult(Pt: [bigint, bigint], k: bigint): [bigint, bigint] {
    if (k < 0n) {
      Pt = this.negate(Pt);
      k = -k;
    }
    let R: [bigint, bigint, bigint] = [0n, 1n, 0n];
    let addend: [bigint, bigint, bigint] = [Pt[0], Pt[1], 1n];
    while (k > 0n) {
      if (k & 1n) R = this.addJJ(R, addend);
      addend = this.dblJ(addend);
      k >>= 1n;
    }
    return this.toAffine(R);
  }

  // ─── Arbitrary-point wNAF w=5 scalar mult (Jacobian result) ──────
  private scalarMultWNAF5Jac(
    Pt: [bigint, bigint],
    k: bigint,
  ): [bigint, bigint, bigint] {
    if (k === 0n) return [0n, 1n, 0n];
    if (k < 0n) {
      Pt = this.negate(Pt);
      k = -k;
    }
    const p = this.P;
    // Precomp odd multiples: table[i] = (2i+1)*Pt, i=0..15
    const Px = Pt[0],
      Py = Pt[1];
    const table: [bigint, bigint, bigint][] = new Array(16);
    table[0] = [Px, Py, 1n];
    const P2 = this.dblJ(table[0]);
    for (let i = 1; i < 16; i++) table[i] = this.addJJ(table[i - 1]!, P2);

    // Compute wNAF-5 representation
    const naf: number[] = [];
    let kk = k;
    while (kk > 0n) {
      if (kk & 1n) {
        let digit = Number(kk & 0x1fn); // mod 32
        if (digit >= 16) digit -= 32;
        kk -= BigInt(digit);
        naf.push(digit);
      } else {
        naf.push(0);
      }
      kk >>= 1n;
    }

    // Process from MSB
    let R: [bigint, bigint, bigint] = [0n, 1n, 0n];
    for (let i = naf.length - 1; i >= 0; i--) {
      R = this.dblJ(R);
      const d = naf[i]!;
      if (d > 0) {
        R = this.addJJ(R, table[(d - 1) >> 1]!);
      } else if (d < 0) {
        const [tx, ty, tz] = table[(-d - 1) >> 1]!;
        R = this.addJJ(R, [tx, (p - ty) % p, tz]);
      }
    }
    return R;
  }

  private negate(P: [bigint, bigint]): [bigint, bigint] {
    return [P[0], this.m(-P[1])];
  }

  private inv(a: bigint, m: bigint): bigint {
    a %= m;
    if (a < 0n) a += m;
    if (a === 0n) throw new Error("inv: a == 0");
    let t = 0n,
      newT = 1n,
      r = m,
      newR = a;
    while (newR !== 0n) {
      const q = r / newR;
      const t0 = t;
      t = newT;
      newT = t0 - q * newT;
      const r0 = r;
      r = newR;
      newR = r0 - q * newR;
    }
    if (r !== 1n) throw new Error("inv: not invertible");
    if (t < 0n) t += m;
    return t;
  }

  public isPointOnCurve(Pt: [bigint, bigint]): boolean {
    const [x, y] = Pt;
    if (x === 0n && y === 0n) return false;
    const p = this.P;
    const x2 = (x * x) % p;
    const rhs =
      (((x2 * x) % p) -
        ((3n * x) % p) +
        0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604bn +
        2n * p) %
      p;
    return (y * y) % p === rhs;
  }

  public sign(
    message: Uint8Array,
    privKey: Uint8Array,
    publicKey?: [Uint8Array, Uint8Array],
  ): [Uint8Array, Uint8Array, Uint8Array] {
    const messageBigint = this.bytesToBigInt(message);
    const privKeyBigint = this.bytesToBigInt(privKey);
    const pubKeyBigint: [bigint, bigint] = publicKey
      ? [this.bytesToBigInt(publicKey[0]), this.bytesToBigInt(publicKey[1])]
      : this.scalarMultG(privKeyBigint);
    const mB = this.BigintToBytes(messageBigint);
    const k = this.generateK(mB, this.BigintToBytes(privKeyBigint));
    const R = this.scalarMultG(k);
    const e =
      this.bytesToBigInt(
        this.sha256(
          this.concat(
            this.BigintToBytes(R[0]),
            this.BigintToBytes(R[1]),
            this.BigintToBytes(pubKeyBigint[0]),
            this.BigintToBytes(pubKeyBigint[1]),
            mB,
          ),
        ),
      ) % this.N;
    if (e === 0n) throw new Error("e==0, retry");
    const s = (k + privKeyBigint * e) % this.N;
    return [
      this.BigintToBytes(R[0]),
      this.BigintToBytes(R[1]),
      this.BigintToBytes(s),
    ];
  }

  public verify(
    message: Uint8Array,
    pubKey: [Uint8Array, Uint8Array],
    signature: [Uint8Array, Uint8Array, Uint8Array],
  ): boolean {
    const messageBigint = this.bytesToBigInt(message);
    const pubKeyBigint: [bigint, bigint] = [
      this.bytesToBigInt(pubKey[0]),
      this.bytesToBigInt(pubKey[1]),
    ];
    const R: [bigint, bigint] = [
      this.bytesToBigInt(signature[0]),
      this.bytesToBigInt(signature[1]),
    ];
    const e =
      this.bytesToBigInt(
        this.sha256(
          this.concat(
            this.BigintToBytes(R[0]),
            this.BigintToBytes(R[1]),
            this.BigintToBytes(pubKeyBigint[0]),
            this.BigintToBytes(pubKeyBigint[1]),
            this.BigintToBytes(messageBigint),
          ),
        ),
      ) % this.N;
    if (e === 0n) return false;
    const s = this.bytesToBigInt(signature[2]);
    if (s === 0n) return false;

    // sG via precomp table (no doublings!) + (-e)P via w=4 window
    const negE = this.N - e;
    const sGJ = this.scalarMultGJac(s);
    const negEP = this.scalarMultWNAF5Jac(pubKeyBigint, negE);
    const lhs = this.addJJ(sGJ, negEP);

    // Compare Jacobian lhs with affine R without inversion
    if (lhs[2] === 0n) return false;
    const Z2 = this.m(lhs[2] * lhs[2]);
    const Z3 = this.m(Z2 * lhs[2]);
    return (
      this.m(lhs[0]) === this.m(R[0] * Z2) &&
      this.m(lhs[1]) === this.m(R[1] * Z3)
    );
  }

  public generateKeyPair(): {
    privateKey: Uint8Array;
    publicKey: [Uint8Array, Uint8Array];
  } {
    const privKey = this.getRandomBigInt(this.N);
    const pubKey = this.scalarMultG(privKey);
    return {
      privateKey: this.BigintToBytes(privKey),
      publicKey: [this.BigintToBytes(pubKey[0]), this.BigintToBytes(pubKey[1])],
    };
  }

  public sha256(data: Uint8Array): Uint8Array {
    const K = this.SHA256_K;
    const W = this._W;
    const rotr = (x: number, n: number) => (x >>> n) | (x << (32 - n));
    let h0 = 0x6a09e667,
      h1 = 0xbb67ae85,
      h2 = 0x3c6ef372,
      h3 = 0xa54ff53a;
    let h4 = 0x510e527f,
      h5 = 0x9b05688c,
      h6 = 0x1f83d9ab,
      h7 = 0x5be0cd19;
    const len = data.length,
      bitLen = len * 8;
    const blockCount = Math.ceil((len + 9) / 64);
    const blocks = new Uint8Array(blockCount * 64);
    blocks.set(data);
    blocks[len] = 0x80;
    const view = new DataView(blocks.buffer);
    view.setUint32(blocks.length - 8, Math.floor(bitLen / 0x100000000), false);
    view.setUint32(blocks.length - 4, bitLen >>> 0, false);
    for (let i = 0; i < blocks.length; i += 64) {
      for (let t = 0; t < 16; t++) W[t] = view.getUint32(i + t * 4, false);
      for (let t = 16; t < 64; t++) {
        const s0 =
          rotr(W[t - 15]!, 7) ^ rotr(W[t - 15]!, 18) ^ (W[t - 15]! >>> 3);
        const s1 =
          rotr(W[t - 2]!, 17) ^ rotr(W[t - 2]!, 19) ^ (W[t - 2]! >>> 10);
        W[t] = (W[t - 16]! + s0 + W[t - 7]! + s1) >>> 0;
      }
      let a = h0,
        b = h1,
        c = h2,
        d = h3,
        e = h4,
        f = h5,
        g = h6,
        h = h7;
      for (let t = 0; t < 64; t++) {
        const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        const ch = (e & f) ^ ((~e >>> 0) & g);
        const temp1 = (h + S1 + ch + K[t]! + W[t]!) >>> 0;
        const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        const maj = (a & b) ^ (a & c) ^ (b & c);
        const temp2 = (S0 + maj) >>> 0;
        h = g;
        g = f;
        f = e;
        e = (d + temp1) >>> 0;
        d = c;
        c = b;
        b = a;
        a = (temp1 + temp2) >>> 0;
      }
      h0 = (h0 + a) >>> 0;
      h1 = (h1 + b) >>> 0;
      h2 = (h2 + c) >>> 0;
      h3 = (h3 + d) >>> 0;
      h4 = (h4 + e) >>> 0;
      h5 = (h5 + f) >>> 0;
      h6 = (h6 + g) >>> 0;
      h7 = (h7 + h) >>> 0;
    }
    const result = new Uint8Array(32);
    const rv = new DataView(result.buffer);
    rv.setUint32(0, h0, false);
    rv.setUint32(4, h1, false);
    rv.setUint32(8, h2, false);
    rv.setUint32(12, h3, false);
    rv.setUint32(16, h4, false);
    rv.setUint32(20, h5, false);
    rv.setUint32(24, h6, false);
    rv.setUint32(28, h7, false);
    return result;
  }

  private hmacSha256(key: Uint8Array, data: Uint8Array): Uint8Array {
    const BLOCK = 64;
    const k = key.length > BLOCK ? this.sha256(key) : key;
    const kp = new Uint8Array(BLOCK);
    kp.set(k);
    const ipad = new Uint8Array(BLOCK),
      opad = new Uint8Array(BLOCK);
    for (let i = 0; i < BLOCK; i++) {
      ipad[i] = kp[i]! ^ 0x36;
      opad[i] = kp[i]! ^ 0x5c;
    }
    return this.sha256(this.concat(opad, this.sha256(this.concat(ipad, data))));
  }

  private generateK(message: Uint8Array, privateKey: Uint8Array): bigint {
    const qLen = 32,
      h1 = this.sha256(message);
    let V = new Uint8Array(qLen).fill(0x01),
      K = new Uint8Array(qLen).fill(0x00);
    const b0 = new Uint8Array([0x00]),
      b1 = new Uint8Array([0x01]);
    K = this.hmacSha256(
      K,
      this.concat(V, b0, privateKey, h1),
    ) as Uint8Array<ArrayBuffer>;
    V = this.hmacSha256(K, V) as Uint8Array<ArrayBuffer>;
    K = this.hmacSha256(
      K,
      this.concat(V, b1, privateKey, h1),
    ) as Uint8Array<ArrayBuffer>;
    V = this.hmacSha256(K, V) as Uint8Array<ArrayBuffer>;
    while (true) {
      let T = new Uint8Array(0);
      while (T.length < qLen) {
        V = this.hmacSha256(K, V) as Uint8Array<ArrayBuffer>;
        const next = new Uint8Array(T.length + V.length);
        next.set(T);
        next.set(V, T.length);
        T = next;
      }
      const k = this.bytesToBigInt(T.subarray(0, qLen));
      if (k >= 1n && k < this.N) return k;
      K = this.hmacSha256(K, this.concat(V, b0)) as Uint8Array<ArrayBuffer>;
      V = this.hmacSha256(K, V) as Uint8Array<ArrayBuffer>;
    }
  }

  private concat(...arrays: Uint8Array[]): Uint8Array {
    let total = 0;
    for (const a of arrays) total += a.length;
    const out = new Uint8Array(total);
    let off = 0;
    for (const a of arrays) {
      out.set(a, off);
      off += a.length;
    }
    return out;
  }
  private BigintToBytes(n: bigint): Uint8Array {
    const b = new Uint8Array(32);
    for (let i = 31; i >= 0; i--) {
      b[i] = Number(n & 0xffn);
      n >>= 8n;
    }
    return b;
  }
  private bytesToBigInt(bytes: Uint8Array): bigint {
    const len = bytes.length,
      view = new DataView(bytes.buffer, bytes.byteOffset, len);
    let r = 0n,
      i = 0;
    for (; i <= len - 8; i += 8) r = (r << 64n) + view.getBigUint64(i);
    for (; i < len; i++) r = (r << 8n) + BigInt(bytes[i]!);
    return r;
  }
  public bytesToHex(bytes: Uint8Array): string {
    let hex = "";
    for (const b of bytes) hex += b.toString(16).toUpperCase().padStart(2, "0");
    return hex;
  }

  public hexToBytes(hex: string): Uint8Array {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < bytes.length; i++)
      bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    return bytes;
  }

  private getRandomBigInt(max: bigint): bigint {
    const bytes = Math.ceil(max.toString(2).length / 8);
    let r: bigint;
    do {
      const b = new Uint8Array(bytes);
      globalThis.crypto.getRandomValues(b);
      r = this.bytesToBigInt(b);
    } while (r >= max);
    return r;
  }
  public privatekeytoPublicKey(privKey: Uint8Array): [Uint8Array, Uint8Array] {
    const privKeyBigint = this.bytesToBigInt(privKey);
    const pubKey = this.scalarMultG(privKeyBigint);
    return [this.BigintToBytes(pubKey[0]), this.BigintToBytes(pubKey[1])];
  }
}