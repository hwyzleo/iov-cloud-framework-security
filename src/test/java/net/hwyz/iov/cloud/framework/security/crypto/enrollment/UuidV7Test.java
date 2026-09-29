package net.hwyz.iov.cloud.framework.security.crypto.enrollment;

import org.junit.jupiter.api.Test;

import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

/**
 * UuidV7 单元测试（FW-SEC-DSN-CR-008 §5.2）
 */
class UuidV7Test {

    @Test
    void random_shouldProduceVersion7Uuid() {
        UUID uuid = UuidV7.random();
        // version = 7
        assertEquals(7, uuid.version());
        // variant = 10xx
        assertEquals(2, uuid.variant());
    }

    @Test
    void random_shouldBeUnique() {
        UUID first = UuidV7.random();
        UUID second = UuidV7.random();
        assertNotEquals(first, second);
    }

    @Test
    void random_shouldBeTimeOrdered() throws InterruptedException {
        UUID first = UuidV7.random();
        Thread.sleep(2); // 跨毫秒，保证时间戳递增（UUIDv7 排序语义）
        UUID second = UuidV7.random();
        assertTrue(first.compareTo(second) <= 0);
    }

    @Test
    void random_shouldProduceStandardString() {
        UUID uuid = UuidV7.random();
        assertEquals(uuid.toString(), UuidV7.toString(uuid));
        // 标准 8-4-4-4-12 格式
        assertTrue(uuid.toString().matches(
                "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"));
    }
}
