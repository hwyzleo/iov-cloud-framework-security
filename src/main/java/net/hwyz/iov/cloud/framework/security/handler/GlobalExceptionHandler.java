package net.hwyz.iov.cloud.framework.security.handler;

import jakarta.servlet.http.HttpServletRequest;
import net.hwyz.iov.cloud.framework.common.bean.ApiResponse;
import net.hwyz.iov.cloud.framework.web.exception.InnerAuthException;
import net.hwyz.iov.cloud.framework.web.exception.WebErrorCode;
import net.hwyz.iov.cloud.edd.mpt.api.exception.NotPermissionException;
import net.hwyz.iov.cloud.edd.mpt.api.exception.NotRoleException;
import net.hwyz.iov.cloud.edd.mpt.api.exception.MptErrorCode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;


/**
 * Security 模块全局异常处理器
 * <p>
 * 仅处理 security 模块特有的异常，其他异常由 framework-web 模块的 GlobalExceptionHandler 统一处理。
 *
 * @author hwyz_leo
 */
@RestControllerAdvice
public class GlobalExceptionHandler {
    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    /**
     * 权限码异常
     */
    @ExceptionHandler(NotPermissionException.class)
    public ApiResponse<Void> handleNotPermissionException(NotPermissionException e, HttpServletRequest request) {
        String requestURI = request.getRequestURI();
        log.error("请求地址'{}',权限码校验失败'{}'", requestURI, e.getMessage());
        return ApiResponse.fail(MptErrorCode.FORBIDDEN, "没有访问权限，请联系管理员授权");
    }

    /**
     * 角色权限异常
     */
    @ExceptionHandler(NotRoleException.class)
    public ApiResponse<Void> handleNotRoleException(NotRoleException e, HttpServletRequest request) {
        String requestURI = request.getRequestURI();
        log.error("请求地址'{}',角色权限校验失败'{}'", requestURI, e.getMessage());
        return ApiResponse.fail(MptErrorCode.FORBIDDEN, "没有访问权限，请联系管理员授权");
    }

    /**
     * 内部认证异常
     */
    @ExceptionHandler(InnerAuthException.class)
    public ApiResponse<Void> handleInnerAuthException(InnerAuthException e, HttpServletRequest request) {
        String requestURI = request.getRequestURI();
        log.error("请求地址'{}',内部认证失败'{}'", requestURI, e.getMessage());
        return ApiResponse.fail(WebErrorCode.INNER_AUTH_FAILED, e.getMessage());
    }

}