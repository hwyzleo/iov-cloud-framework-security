package net.hwyz.iov.cloud.framework.security.config;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.springframework.context.annotation.Bean;

import java.time.ZoneId;
import java.util.TimeZone;

/**
 * 系统配置
 *
 * @author hwyz_leo
 */
public class ApplicationConfig {
    /**
     * 时区配置
     */
    @Bean
    public ObjectMapper jacksonObjectMapper() {
        ObjectMapper objectMapper = new ObjectMapper();

        // 注册Java 8日期和时间模块，以便正确处理相关类型
        JavaTimeModule javaTimeModule = new JavaTimeModule();
        objectMapper.registerModule(javaTimeModule);

        // 设置时区为系统默认时区
        objectMapper.setTimeZone(TimeZone.getTimeZone(ZoneId.systemDefault()));

        // 设置日期时间格式为ISO 8601
        objectMapper.configure(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS, false);

        // 忽略未知属性
        objectMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);

        return objectMapper;
    }
}
