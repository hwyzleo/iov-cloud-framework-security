package net.hwyz.iov.cloud.framework.security.crypto.revocation;

import java.net.URI;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

/**
 * 单元测试用传输桩：按请求体/URI 返回预置响应或抛出预置传输异常。
 */
public class StubRevocationTransport implements RevocationHttpTransport {

    @FunctionalInterface
    public interface PostHandler {
        Response respond(byte[] body) throws Exception;
    }

    @FunctionalInterface
    public interface GetHandler {
        Response respond(URI uri) throws Exception;
    }

    private PostHandler postHandler;
    private GetHandler getHandler;

    public int postCount;
    public int getCount;
    public final List<byte[]> postedBodies = new ArrayList<>();
    public final List<URI> requestedUris = new ArrayList<>();

    public StubRevocationTransport onPost(PostHandler handler) {
        this.postHandler = handler;
        return this;
    }

    public StubRevocationTransport onGet(GetHandler handler) {
        this.getHandler = handler;
        return this;
    }

    @Override
    public Response post(URI uri, byte[] body, String contentType, String accept, Duration readTimeout) {
        postCount++;
        postedBodies.add(body);
        requestedUris.add(uri);
        if (postHandler == null) {
            throw new IllegalStateException("No post handler configured");
        }
        try {
            return postHandler.respond(body);
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalStateException("stub post handler failed", e);
        }
    }

    @Override
    public Response get(URI uri, Duration readTimeout, String accept) {
        getCount++;
        requestedUris.add(uri);
        if (getHandler == null) {
            throw new IllegalStateException("No get handler configured");
        }
        try {
            return getHandler.respond(uri);
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalStateException("stub get handler failed", e);
        }
    }

    public static Response ok(byte[] body) {
        return new Response(200, body, null);
    }

    public static Response ok(byte[] body, URI finalUri) {
        return new Response(200, body, finalUri);
    }

    public static Response status(int statusCode) {
        return new Response(statusCode, new byte[0], null);
    }

    public static RuntimeException transportError(RevocationTransportException.Phase phase) {
        return new RevocationTransportException(phase, "stub transport failure: " + phase, null);
    }
}
