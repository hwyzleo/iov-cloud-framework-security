package net.hwyz.iov.cloud.framework.security.interceptor;

import cn.hutool.core.util.ObjUtil;
import cn.hutool.core.util.StrUtil;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import net.hwyz.iov.cloud.edd.mpt.api.model.LoginUser;
import net.hwyz.iov.cloud.framework.common.constant.CustomHeaders;
import net.hwyz.iov.cloud.framework.common.constant.SecurityConstants;
import net.hwyz.iov.cloud.framework.common.enums.ClientType;
import net.hwyz.iov.cloud.framework.common.util.ServletUtil;
import net.hwyz.iov.cloud.framework.security.service.TokenService;
import net.hwyz.iov.cloud.framework.web.context.SecurityContextHolder;
import net.hwyz.iov.cloud.framework.web.util.SpringUtil;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.AsyncHandlerInterceptor;


/**
 * 自定义请求头拦截器，将Header数据封装到线程变量中方便获取
 * 注意：此拦截器会根据客户端类型决定是否验证当前用户有效期自动刷新有效期
 *
 * @author hwyz_leo
 */
public class HeaderInterceptor implements AsyncHandlerInterceptor {

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        if (!(handler instanceof HandlerMethod)) {
            return true;
        }

        SecurityContextHolder.setUserId(ServletUtil.getHeader(request, CustomHeaders.USER_ID));
        SecurityContextHolder.setUserName(ServletUtil.getHeader(request, CustomHeaders.USERNAME));
        SecurityContextHolder.setUserKey(ServletUtil.getHeader(request, CustomHeaders.USER_KEY));
        SecurityContextHolder.setClientId(ServletUtil.getHeader(request, CustomHeaders.CLIENT_ID));
        SecurityContextHolder.setClientType(ServletUtil.getHeader(request, CustomHeaders.CLIENT_TYPE));
        SecurityContextHolder.setDeviceId(ServletUtil.getHeader(request, CustomHeaders.DEVICE_ID));
        SecurityContextHolder.setPlatform(ServletUtil.getHeader(request, CustomHeaders.PLATFORM));
        SecurityContextHolder.setOsVersion(ServletUtil.getHeader(request, CustomHeaders.OS_VERSION));
        SecurityContextHolder.setAppVersion(ServletUtil.getHeader(request, CustomHeaders.APP_VERSION));
        SecurityContextHolder.setSessionId(ServletUtil.getHeader(request, CustomHeaders.SESSION_ID));
        SecurityContextHolder.setScope(ServletUtil.getHeader(request, CustomHeaders.SCOPE));

        String clientType = SecurityContextHolder.getClientType();

        if (StrUtil.equals(ClientType.MPT.name(), clientType)) {
            TokenService tokenService = SpringUtil.getBean(TokenService.class);
            LoginUser loginUser = tokenService.getLoginUser(request);
            if (ObjUtil.isNotNull(loginUser)) {
                tokenService.verifyToken(loginUser);
                SecurityContextHolder.set(SecurityConstants.LOGIN_USER, loginUser);
            }
        }
        return true;
    }

    @Override
    public void afterCompletion(HttpServletRequest request, HttpServletResponse response, Object handler, Exception ex)
            throws Exception {
        SecurityContextHolder.remove();
    }
}