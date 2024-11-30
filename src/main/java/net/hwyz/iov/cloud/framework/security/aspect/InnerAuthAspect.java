package net.hwyz.iov.cloud.framework.security.aspect;

import cn.hutool.core.util.StrUtil;
import net.hwyz.iov.cloud.framework.common.constant.MptSecurityConstants;
import net.hwyz.iov.cloud.framework.common.exception.InnerAuthException;
import net.hwyz.iov.cloud.framework.common.util.ServletUtil;
import net.hwyz.iov.cloud.framework.security.annotation.InnerAuth;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.springframework.core.Ordered;
import org.springframework.stereotype.Component;

/**
 * 内部服务调用验证处理
 *
 * @author hwyz_leo
 */
@Aspect
@Component
public class InnerAuthAspect implements Ordered {
    @Around("@annotation(innerAuth)")
    public Object innerAround(ProceedingJoinPoint point, InnerAuth innerAuth) throws Throwable {
        String source = ServletUtil.getRequest().getHeader(MptSecurityConstants.FROM_SOURCE);
        // 内部请求验证
        if (!StrUtil.equals(MptSecurityConstants.INNER, source)) {
            throw new InnerAuthException("没有内部访问权限，不允许访问");
        }

        String userid = ServletUtil.getRequest().getHeader(MptSecurityConstants.DETAILS_USER_ID);
        String username = ServletUtil.getRequest().getHeader(MptSecurityConstants.DETAILS_USERNAME);
        // 用户信息验证
        if (innerAuth.isUser() && (StrUtil.isEmpty(userid) || StrUtil.isEmpty(username))) {
            throw new InnerAuthException("没有设置用户信息，不允许访问 ");
        }
        return point.proceed();
    }

    /**
     * 确保在权限认证aop执行前执行
     */
    @Override
    public int getOrder() {
        return Ordered.HIGHEST_PRECEDENCE + 1;
    }
}
