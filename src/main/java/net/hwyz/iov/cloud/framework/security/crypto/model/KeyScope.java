package net.hwyz.iov.cloud.framework.security.crypto.model;

import java.util.Objects;

/**
 * 签名密钥作用域（定位「用哪把 KMS 非对称私钥」）
 * <p>
 * 与 {@link BizType.Prov#anchor()} 必须一致：
 * <ul>
 *   <li>{@code ORG} -> {@link #org()}（组织级全局一把，无主体）</li>
 *   <li>{@code VEHICLE} -> {@link #vin(String)}（绑 VIN）</li>
 *   <li>{@code DEVICE} -> {@link #device(String)}（绑芯片 SN）</li>
 *   <li>{@code USER} -> {@link #uid(String)}（绑用户，预留）</li>
 * </ul>
 * 二者拼出唯一 KMS keyName：ORG 为 {@code prov.keyName}；其余为 {@code prov.keyName + ":" + subject}。
 */
public sealed interface KeyScope permits KeyScope.OrgScope, KeyScope.VinScope, KeyScope.UidScope, KeyScope.DeviceScope {

    /**
     * 组织级作用域（全局一把，无主体）
     */
    static KeyScope org() {
        return OrgScope.INSTANCE;
    }

    /**
     * 车辆级作用域（绑 VIN）
     */
    static KeyScope vin(String vin) {
        return new VinScope(vin);
    }

    /**
     * 用户级作用域（绑 UID）
     */
    static KeyScope uid(String uid) {
        return UidScope.of(uid);
    }

    /**
     * 设备级作用域（绑芯片 SN）
     */
    static KeyScope device(String deviceSn) {
        return DeviceScope.of(deviceSn);
    }

    /**
     * @return 对应的锚定层级
     */
    BizType.Anchor anchor();

    /**
     * @return 主体标识（VIN/UID/deviceSn），ORG 返回 null
     */
    String subject();

    /**
     * ORG 作用域（单例，无主体）
     */
    final class OrgScope implements KeyScope {
        private static final OrgScope INSTANCE = new OrgScope();

        private OrgScope() {
        }

        @Override
        public BizType.Anchor anchor() {
            return BizType.Anchor.ORG;
        }

        @Override
        public String subject() {
            return null;
        }

        @Override
        public String toString() {
            return "KeyScope.org()";
        }
    }

    /**
     * VEHICLE 作用域（绑 VIN）
     *
     * @param vin VIN
     */
    record VinScope(String vin) implements KeyScope {
        public VinScope {
            Objects.requireNonNull(vin, "vin must not be null");
        }

        @Override
        public BizType.Anchor anchor() {
            return BizType.Anchor.VEHICLE;
        }

        @Override
        public String subject() {
            return vin.trim().toUpperCase();
        }
    }

    /**
     * USER 作用域（绑 UID）
     *
     * @param uid 用户唯一标识
     */
    record UidScope(String uid) implements KeyScope {
        public UidScope {
            Objects.requireNonNull(uid, "uid must not be null");
        }

        static UidScope of(String uid) {
            return new UidScope(uid);
        }

        @Override
        public BizType.Anchor anchor() {
            return BizType.Anchor.USER;
        }

        @Override
        public String subject() {
            return uid.trim();
        }
    }

    /**
     * DEVICE 作用域（绑芯片 SN）
     *
     * @param deviceSn 设备 SN
     */
    record DeviceScope(String deviceSn) implements KeyScope {
        public DeviceScope {
            Objects.requireNonNull(deviceSn, "deviceSn must not be null");
        }

        static DeviceScope of(String deviceSn) {
            return new DeviceScope(deviceSn);
        }

        @Override
        public BizType.Anchor anchor() {
            return BizType.Anchor.DEVICE;
        }

        @Override
        public String subject() {
            return deviceSn.trim();
        }
    }
}
