package net.hwyz.iov.cloud.framework.security.crypto.provider;

import net.hwyz.iov.cloud.framework.security.crypto.client.DerivationInput;
import net.hwyz.iov.cloud.framework.security.crypto.client.KmsClient;
import net.hwyz.iov.cloud.framework.security.crypto.client.KmsDerivedKeyReference;
import net.hwyz.iov.cloud.framework.security.crypto.client.KmsRecipient;
import net.hwyz.iov.cloud.framework.security.crypto.client.OperationContext;
import net.hwyz.iov.cloud.framework.security.crypto.model.DerivedWrappedKey;
import net.hwyz.iov.cloud.framework.security.crypto.model.businesskey.WrapMode;

import java.util.Objects;

/**
 * 既有 Feign business-key 派生封装路径适配器（FW-SEC-DSN-CR-019 §12 迁移兼容）。
 * <p>
 * 保持 {@code POST /v1/business-key/derived-keys:wrap} 现有行为；DERIVED_ROOT 由
 * 门面完成完整证书校验后，本适配器把命令转换为 {@link KmsClient#deriveAndWrap}
 * 既有的 {@code KmsDerivedKeyReference/DerivationInput/KmsRecipient/OperationContext} 调用，
 * 与迁移前输出字节级一致。迁移完成后移除本路径，不保留双写或运行时自动切换。
 */
public class KmsDerivedKeyProvider implements DerivedKeyProvider {

    public static final String PROVIDER_NAME = "openbao-business-key";
    private static final String ROOT_REF_PREFIX = "openbao-transit://transit/keys/";

    private final KmsClient kmsClient;

    public KmsDerivedKeyProvider(KmsClient kmsClient) {
        this.kmsClient = Objects.requireNonNull(kmsClient, "kmsClient must not be null");
    }

    @Override
    public DerivedWrappedKey deriveAndWrap(DerivedKeyCommand command) {
        Objects.requireNonNull(command, "command must not be null");
        ValidatedRecipientEvidence evidence = command.recipient();
        if (evidence == null) {
            throw new IllegalArgumentException("command.recipient() must not be null");
        }
        KmsRecipient recipient = KmsRecipient.deviceCertificate(
                evidence.certificateSerial(),
                evidence.leafCertificateDer(),
                evidence.sha256Fingerprint(),
                evidence.spki(),
                null);
        DerivationInput input = new DerivationInput(
                command.anchor(),
                command.purpose(),
                command.context().derivationVersion(),
                evidence.validatedWrapSuite(),
                evidence.requestId(),
                command.bizType().name(),
                command.context().businessKeyVersion());
        OperationContext operation = command.operation();
        KmsDerivedKeyReference rootRef = new KmsDerivedKeyReference(
                command.bizType().name(),
                ROOT_REF_PREFIX + command.bizType().prov().keyName());
        return kmsClient.deriveAndWrap(rootRef, input, recipient, operation);
    }

    @Override
    public DerivedKeyCapability capability() {
        // legacy 路径启动/运行期门禁由既有 business-key readiness 单独治理；
        // DERIVED_ROOT 不再以 business-key capability 作为启动依赖（FW-SEC-DSN-CR-019 §12）。
        return new DerivedKeyCapability(PROVIDER_NAME, true, null);
    }

    /**
     * 由已验证收方证据构造 KmsRecipient（供既有 Provider 调用；与迁移前一致）。
     *
     * @param evidence 已验证收方证据
     * @return KmsRecipient
     */
    public static KmsRecipient toKmsRecipient(ValidatedRecipientEvidence evidence) {
        return KmsRecipient.deviceCertificate(
                evidence.certificateSerial(),
                evidence.leafCertificateDer(),
                evidence.sha256Fingerprint(),
                evidence.spki(),
                null);
    }

    /**
     * 供外部校验收方模式是否为设备证书公钥封装。
     */
    public static boolean isDeviceCertPublicKey(ValidatedRecipientEvidence evidence) {
        return evidence != null && evidence.validatedWrapSuite() != null;
    }
}
