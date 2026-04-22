/** 32バイトのエントロピーからランダムな秘密鍵を生成し、対応するBIP39ニーモニック（24語）と16進文字列を返す */
export declare function generateMnemonic(): Promise<{
    privateKeyHex: string;
    mnemonic: string;
}>;
/**
 * BIP39ニーモニック（24語）を秘密鍵の16進文字列に変換する。
 * チェックサムの検証も行う。
 */
export declare function mnemonicToPrivateKeyHex(mnemonic: string): Promise<string>;
