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
    private final Timer encryptTimer;
    private final Timer decryptTimer;
    private final Timer kmsCallTimer;

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

        this.encryptTimer = Timer.builder("crypto.encrypt.duration")
                .description("加密时延")
                .register(meterRegistry);

        this.decryptTimer = Timer.builder("crypto.decrypt.duration")
                .description("解密时延")
                .register(meterRegistry);

        this.kmsCallTimer = Timer.builder("crypto.kms.call.duration")
                .description("KMS调用时延")
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
}
