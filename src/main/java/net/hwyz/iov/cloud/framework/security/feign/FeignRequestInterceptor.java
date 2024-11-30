package net.hwyz.iov.cloud.framework.security.feign;

import cn.hutool.core.util.ObjUtil;
import cn.hutool.core.util.StrUtil;
import feign.RequestInterceptor;
import feign.RequestTemplate;
import jakarta.servlet.http.HttpServletRequest;
import net.hwyz.iov.cloud.framework.common.constant.MptSecurityConstants;
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
            String userId = headers.get(MptSecurityConstants.DETAILS_USER_ID);
            if (StrUtil.isNotEmpty(userId)) {
                requestTemplate.header(MptSecurityConstants.DETAILS_USER_ID, userId);
            }
            String userKey = headers.get(MptSecurityConstants.USER_KEY);
            if (StrUtil.isNotEmpty(userKey)) {
                requestTemplate.header(MptSecurityConstants.USER_KEY, userKey);
            }
            String userName = headers.get(MptSecurityConstants.DETAILS_USERNAME);
            if (StrUtil.isNotEmpty(userName)) {
                requestTemplate.header(MptSecurityConstants.DETAILS_USERNAME, userName);
            }
            String authentication = headers.get(MptSecurityConstants.AUTHORIZATION_HEADER);
            if (StrUtil.isNotEmpty(authentication)) {
                requestTemplate.header(MptSecurityConstants.AUTHORIZATION_HEADER, authentication);
            }

            // 配置客户端IP
            requestTemplate.header("X-Forwarded-For", IpUtil.getIpAddr());
        }
    }
}