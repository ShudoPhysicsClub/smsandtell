export declare class PointPairSchnorrP256 {
    private readonly P;
    private readonly N;
    private readonly G;
    private readonly SHA256_K;
    private readonly _W;
    private m;
    private readonly G_precomp_window;
    private addMJ;
    private addJJ;
    private dblJ;
    private toAffine;
    private readonly _shifts;
    private scalarMultGJac;
    private scalarMultG;
    private scalarMult;
    private scalarMultWNAF5Jac;
    private negate;
    private inv;
    isPointOnCurve(Pt: [bigint, bigint]): boolean;
    sign(message: Uint8Array, privKey: Uint8Array, publicKey?: [Uint8Array, Uint8Array]): [Uint8Array, Uint8Array, Uint8Array];
    verify(message: Uint8Array, pubKey: [Uint8Array, Uint8Array], signature: [Uint8Array, Uint8Array, Uint8Array]): boolean;
    generateKeyPair(): {
        privateKey: Uint8Array;
        publicKey: [Uint8Array, Uint8Array];
    };
    sha256(data: Uint8Array): Uint8Array;
    private hmacSha256;
    private generateK;
    private concat;
    private BigintToBytes;
    private bytesToBigInt;
    bytesToHex(bytes: Uint8Array): string;
    hexToBytes(hex: string): Uint8Array;
    private getRandomBigInt;
    privatekeytoPublicKey(privKey: Uint8Array): [Uint8Array, Uint8Array];
}
