package net.hwyz.iov.cloud.framework.security.feign;

import cn.hutool.core.util.ObjUtil;
import cn.hutool.core.util.StrUtil;
import feign.RequestInterceptor;
import feign.RequestTemplate;
import jakarta.servlet.http.HttpServletRequest;
import net.hwyz.iov.cloud.framework.common.constant.SecurityConstants;
import net.hwyz.iov.cloud.framework.common.util.IpUtil;
import net.hwyz.iov.cloud.framework.common.util.ServletUtil;
import org.springframework.stereotype.Component;

import java.util.Map;

/**
 * feign 请求拦截器
 *
 * @author hwyz_leo
 */
@Component
public class FeignRequestInterceptor implements RequestInterceptor {
    @Override
    public void apply(RequestTemplate requestTemplate) {
        HttpServletRequest httpServletRequest = ServletUtil.getRequest();
        if (ObjUtil.isNotNull(httpServletRequest)) {
            Map<String, String> headers = ServletUtil.getHeaders(httpServletRequest);
            // 传递用户信息请求头，防止丢失
            String userId = headers.get(SecurityConstants.USER_ID);
            if (StrUtil.isNotEmpty(userId)) {
                requestTemplate.header(SecurityConstants.USER_ID, userId);
            }
            String userKey = headers.get(SecurityConstants.USER_KEY);
            if (StrUtil.isNotEmpty(userKey)) {
                requestTemplate.header(SecurityConstants.USER_KEY, userKey);
            }
            String userName = headers.get(SecurityConstants.USERNAME);
            if (StrUtil.isNotEmpty(userName)) {
                requestTemplate.header(SecurityConstants.USERNAME, userName);
            }
            String authentication = headers.get(SecurityConstants.AUTHORIZATION_HEADER);
            if (StrUtil.isNotEmpty(authentication)) {
                requestTemplate.header(SecurityConstants.AUTHORIZATION_HEADER, authentication);
            }

            // 配置客户端IP
            requestTemplate.header("X-Forwarded-For", IpUtil.getIpAddr());
        }
    }
}