package net.hwyz.iov.cloud.framework.security.crypto.revocation;

import org.springframework.beans.factory.ObjectProvider;

import java.util.Collections;
import java.util.Iterator;
import java.util.List;

/**
 * 单元测试用 ObjectProvider：返回单个（可为 null）值。
 */
final class TestObjectProvider<T> implements ObjectProvider<T> {

    private final T value;

    TestObjectProvider(T value) {
        this.value = value;
    }

    @Override
    public T getObject() {
        return getObject(new Object[0]);
    }

    @Override
    public T getObject(Object... args) {
        if (value == null) {
            throw new org.springframework.beans.factory.NoSuchBeanDefinitionException("test provider is empty");
        }
        return value;
    }

    @Override
    public T getIfAvailable() {
        return value;
    }

    @Override
    public T getIfUnique() {
        return value;
    }

    @Override
    public Iterator<T> iterator() {
        return value == null ? Collections.emptyIterator() : List.of(value).iterator();
    }
}
