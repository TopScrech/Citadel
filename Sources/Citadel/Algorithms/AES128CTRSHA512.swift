import Crypto
import NIOSSH

public final class AES128CTRSHA512: AES128CTR {
    public override class var macName: String? { "hmac-sha2-512" }
    public override class var keySizes: ExpectedKeySizes {
        ExpectedKeySizes(ivSize: 16, encryptionKeySize: 16, macKeySize: SHA512.byteCount)
    }
}
