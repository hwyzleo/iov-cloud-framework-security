package net.hwyz.iov.cloud.framework.security.annotation;

import org.springframework.cloud.openfeign.EnableFeignClients;
import org.springframework.core.annotation.AliasFor;

import java.lang.annotation.*;

/**
 * 自定义feign注解
 * 添加basePackages路径
 *
 * @author hwyz_leo
 */
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@Documented
@EnableFeignClients
public @interface EnableCustomFeignClients {

    @AliasFor(annotation = EnableFeignClients.class, attribute = "value")
    String[] value() default {};

    @AliasFor(annotation = EnableFeignClients.class, attribute = "basePackages")
    String[] basePackages() default {"net.hwyz.iov.cloud.*"};

    @AliasFor(annotation = EnableFeignClients.class, attribute = "basePackageClasses")
    Class<?>[] basePackageClasses() default {};

    @AliasFor(annotation = EnableFeignClients.class, attribute = "defaultConfiguration")
    Class<?>[] defaultConfiguration() default {};

    @AliasFor(annotation = EnableFeignClients.class, attribute = "clients")
    Class<?>[] clients() default {};
}
