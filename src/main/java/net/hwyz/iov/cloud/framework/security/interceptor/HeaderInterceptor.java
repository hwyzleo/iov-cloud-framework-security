package net.hwyz.iov.cloud.framework.security.interceptor;

import cn.hutool.core.util.ObjUtil;
import cn.hutool.core.util.StrUtil;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import net.hwyz.iov.cloud.framework.common.constant.MptSecurityConstants;
import net.hwyz.iov.cloud.framework.common.context.SecurityContextHolder;
import net.hwyz.iov.cloud.framework.common.util.ServletUtil;
import net.hwyz.iov.cloud.framework.security.auth.AuthUtil;
import net.hwyz.iov.cloud.framework.security.util.SecurityUtils;
import net.hwyz.iov.cloud.mpt.system.api.model.LoginUser;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.AsyncHandlerInterceptor;


/**
 * 自定义请求头拦截器，将Header数据封装到线程变量中方便获取
 * 注意：此拦截器会同时验证当前用户有效期自动刷新有效期
 *
 * @author hwyz_leo
 */
public class HeaderInterceptor implements AsyncHandlerInterceptor {
    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        if (!(handler instanceof HandlerMethod)) {
            return true;
        }

        SecurityContextHolder.setUserId(ServletUtil.getHeader(request, MptSecurityConstants.DETAILS_USER_ID));
        SecurityContextHolder.setUserName(ServletUtil.getHeader(request, MptSecurityConstants.DETAILS_USERNAME));
        SecurityContextHolder.setUserKey(ServletUtil.getHeader(request, MptSecurityConstants.USER_KEY));

        String token = SecurityUtils.getToken();
        if (StrUtil.isNotEmpty(token)) {
            LoginUser loginUser = AuthUtil.getLoginUser(token);
            if (ObjUtil.isNotNull(loginUser)) {
                AuthUtil.verifyLoginUserExpire(loginUser);
                SecurityContextHolder.set(MptSecurityConstants.LOGIN_USER, loginUser);
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
