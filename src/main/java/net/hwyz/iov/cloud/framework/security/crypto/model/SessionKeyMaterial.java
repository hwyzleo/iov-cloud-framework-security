package net.hwyz.iov.cloud.framework.security.crypto.model;

import java.util.Arrays;

/**
 * SESSION 模式内部对象（不落库）
 * <p>
 * sessionKey = HKDF-SHA256(root, salt, info)；AES-256-GCM 加解密、密文头作 AAD。
 *
 * @param root       派生根（来自 bizType.prov.keyName / KMS）
 * @param salt       HKDF salt（写入密文头，解密端现算）
 * @param info       HKDF info
 * @param nonce      GCM nonce / IV（写入密文头，解密端现算）
 * @param sessionKey 会话密钥（仅内存）
 */
public record SessionKeyMaterial(byte[] root, byte[] salt, byte[] info, byte[] nonce, byte[] sessionKey) {

    public SessionKeyMaterial {
        root = root == null ? null : root.clone();
        salt = salt == null ? null : salt.clone();
        info = info == null ? null : info.clone();
        nonce = nonce == null ? null : nonce.clone();
        sessionKey = sessionKey == null ? null : sessionKey.clone();
    }

    public byte[] getRoot() {
        return root == null ? null : root.clone();
    }

    public byte[] getSalt() {
        return salt == null ? null : salt.clone();
    }

    public byte[] getInfo() {
        return info == null ? null : info.clone();
    }

    public byte[] getNonce() {
        return nonce == null ? null : nonce.clone();
    }

    public byte[] getSessionKey() {
        return sessionKey == null ? null : sessionKey.clone();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        SessionKeyMaterial that = (SessionKeyMaterial) o;
        return Arrays.equals(root, that.root)
                && Arrays.equals(salt, that.salt)
                && Arrays.equals(info, that.info)
                && Arrays.equals(nonce, that.nonce)
                && Arrays.equals(sessionKey, that.sessionKey);
    }

    @Override
    public int hashCode() {
        int result = Arrays.hashCode(root);
        result = 31 * result + Arrays.hashCode(salt);
        result = 31 * result + Arrays.hashCode(info);
        result = 31 * result + Arrays.hashCode(nonce);
        result = 31 * result + Arrays.hashCode(sessionKey);
        return result;
    }
}
