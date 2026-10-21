package net.hwyz.iov.cloud.framework.security.crypto;

import org.springframework.beans.factory.SmartInitializingSingleton;

import java.util.Objects;

/**
 * Keyprov 启动就绪强校验器（FW-SEC-DSN-CR-018 §9.2）。
 * <p>
 * 使用 {@link SmartInitializingSingleton}：回调发生在普通 singleton 创建完成后、
 * 应用对外声明 READY 之前；失败抛异常终止启动。从结构上消除
 * validator↔readiness 的 Bean 创建期循环依赖：
 * readiness 可在运行时延迟取得 validator，validator 永不反向依赖 readiness（RD-018-6/7）。
 * <p>
 * 若 validator/provisioning/import-proof 独立关闭，readiness 按既有 capability 规则报告缺失；
 * 本校验器不得自动创建替代 Bean。
 */
public final class KeyprovStartupReadinessVerifier implements SmartInitializingSingleton {

    private final KeyprovReadiness readiness;
    private final boolean requireReadyAtStartup;

    public KeyprovStartupReadinessVerifier(KeyprovReadiness readiness, boolean requireReadyAtStartup) {
        this.readiness = Objects.requireNonNull(readiness, "readiness must not be null");
        this.requireReadyAtStartup = requireReadyAtStartup;
    }

    @Override
    public void afterSingletonsInstantiated() {
        if (requireReadyAtStartup) {
            readiness.verifyAtStartup();
        }
    }
}
