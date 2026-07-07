package net.hwyz.iov.cloud.framework.security.crypto.metrics;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import org.springframework.stereotype.Component;

import java.util.concurrent.TimeUnit;

/**
 * 加解密指标收集
 */
@Component
public class CryptoMetrics {

    private final Counter encryptCounter;
    private final Counter decryptCounter;
    private final Counter kmsCallCounter;
    private final Counter errorCounter;
    private final Counter provisioningDeriveCounter;
    private final Counter provisioningWrapCounter;
    private final Counter provisioningUnwrapCounter;
    private final Timer encryptTimer;
    private final Timer decryptTimer;
    private final Timer kmsCallTimer;
    private final Timer provisioningDeriveTimer;
    private final Timer provisioningWrapTimer;
    private final Timer provisioningUnwrapTimer;

    public CryptoMetrics(MeterRegistry meterRegistry) {
        this.encryptCounter = Counter.builder("crypto.encrypt.count")
                .description("加密次数")
                .register(meterRegistry);

        this.decryptCounter = Counter.builder("crypto.decrypt.count")
                .description("解密次数")
                .register(meterRegistry);

        this.kmsCallCounter = Counter.builder("crypto.kms.call.count")
                .description("KMS调用次数")
                .register(meterRegistry);

        this.errorCounter = Counter.builder("crypto.error.count")
                .description("错误计数")
                .register(meterRegistry);

        this.provisioningDeriveCounter = Counter.builder("crypto.provisioning.derive.count")
                .description("派生次数")
                .register(meterRegistry);

        this.provisioningWrapCounter = Counter.builder("crypto.provisioning.wrap.count")
                .description("封装次数")
                .register(meterRegistry);

        this.provisioningUnwrapCounter = Counter.builder("crypto.provisioning.unwrap.count")
                .description("解封次数")
                .register(meterRegistry);

        this.encryptTimer = Timer.builder("crypto.encrypt.duration")
                .description("加密时延")
                .register(meterRegistry);

        this.decryptTimer = Timer.builder("crypto.decrypt.duration")
                .description("解密时延")
                .register(meterRegistry);

        this.kmsCallTimer = Timer.builder("crypto.kms.call.duration")
                .description("KMS调用时延")
                .register(meterRegistry);

        this.provisioningDeriveTimer = Timer.builder("crypto.provisioning.derive.duration")
                .description("派生时延")
                .register(meterRegistry);

        this.provisioningWrapTimer = Timer.builder("crypto.provisioning.wrap.duration")
                .description("封装时延")
                .register(meterRegistry);

        this.provisioningUnwrapTimer = Timer.builder("crypto.provisioning.unwrap.duration")
                .description("解封时延")
                .register(meterRegistry);
    }

    /**
     * 记录加密操作
     *
     * @param duration 耗时（毫秒）
     */
    public void recordEncrypt(long duration) {
        encryptCounter.increment();
        encryptTimer.record(duration, TimeUnit.MILLISECONDS);
    }

    /**
     * 记录解密操作
     *
     * @param duration 耗时（毫秒）
     */
    public void recordDecrypt(long duration) {
        decryptCounter.increment();
        decryptTimer.record(duration, TimeUnit.MILLISECONDS);
    }

    /**
     * 记录KMS调用
     *
     * @param duration 耗时（毫秒）
     */
    public void recordKmsCall(long duration) {
        kmsCallCounter.increment();
        kmsCallTimer.record(duration, TimeUnit.MILLISECONDS);
    }

    /**
     * 记录错误
     */
    public void recordError() {
        errorCounter.increment();
    }

    /**
     * 记录派生操作
     *
     * @param duration 耗时（毫秒）
     */
    public void recordProvisioningDerive(long duration) {
        provisioningDeriveCounter.increment();
        provisioningDeriveTimer.record(duration, TimeUnit.MILLISECONDS);
    }

    /**
     * 记录封装操作
     *
     * @param duration 耗时（毫秒）
     */
    public void recordProvisioningWrap(long duration) {
        provisioningWrapCounter.increment();
        provisioningWrapTimer.record(duration, TimeUnit.MILLISECONDS);
    }

    /**
     * 记录解封操作
     *
     * @param duration 耗时（毫秒）
     */
    public void recordProvisioningUnwrap(long duration) {
        provisioningUnwrapCounter.increment();
        provisioningUnwrapTimer.record(duration, TimeUnit.MILLISECONDS);
    }
}
