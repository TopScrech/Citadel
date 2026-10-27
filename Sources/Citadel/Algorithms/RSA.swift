import Crypto
import _CryptoExtras

extension Insecure {
    public enum RSA {
        public typealias PublicKey = _RSA.Signing.PublicKey
        public typealias PrivateKey = _RSA.Signing.PrivateKey
    }
}
