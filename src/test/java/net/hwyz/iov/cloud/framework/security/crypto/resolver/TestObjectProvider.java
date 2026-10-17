package net.hwyz.iov.cloud.framework.security.crypto.resolver;

import org.springframework.beans.factory.ObjectProvider;

import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.stream.Stream;

/**
 * 单元测试用 ObjectProvider：支持 0..N 个 Bean，实现 {@code orderedStream()}。
 */
public final class TestObjectProvider<T> implements ObjectProvider<T> {

    private final List<T> values;

    @SafeVarargs
    public TestObjectProvider(T... values) {
        this.values = values == null ? List.of() : List.of(values);
    }

    public TestObjectProvider(List<T> values) {
        this.values = values == null ? List.of() : List.copyOf(values);
    }

    @Override
    public T getObject() {
        if (values.isEmpty()) {
            throw new org.springframework.beans.factory.NoSuchBeanDefinitionException("test provider is empty");
        }
        return values.get(0);
    }

    @Override
    public T getObject(Object... args) {
        return getObject();
    }

    @Override
    public T getIfAvailable() {
        return values.isEmpty() ? null : values.get(0);
    }

    @Override
    public T getIfUnique() {
        return values.size() == 1 ? values.get(0) : null;
    }

    @Override
    public Iterator<T> iterator() {
        return values.isEmpty() ? Collections.emptyIterator() : values.iterator();
    }

    @Override
    public Stream<T> orderedStream() {
        return values.stream();
    }
}
