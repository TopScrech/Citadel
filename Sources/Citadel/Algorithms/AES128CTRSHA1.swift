import Crypto
import NIOSSH

public final class AES128CTRSHA1: AES128CTR {
    public override class var macName: String? { "hmac-sha1" }
    public override class var keySizes: ExpectedKeySizes {
        ExpectedKeySizes(ivSize: 16, encryptionKeySize: 16, macKeySize: Insecure.SHA1.byteCount)
    }
}
