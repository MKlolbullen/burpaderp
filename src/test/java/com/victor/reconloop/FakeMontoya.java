package com.victor.reconloop;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.RedirectionMode;
import burp.api.montoya.http.RequestOptions;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.internal.MontoyaObjectFactory;
import burp.api.montoya.internal.ObjectFactoryLocator;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;
import java.net.URI;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.Predicate;

/** Test-only in-memory Montoya implementation: no sockets, sleeps or production fallback sender. */
final class FakeMontoya implements AutoCloseable {
    private final MontoyaObjectFactory previous = ObjectFactoryLocator.FACTORY;
    final List<HttpRequest> sent = new CopyOnWriteArrayList<>();
    final List<RedirectionMode> redirectModes = new CopyOnWriteArrayList<>();
    final List<HttpRequestResponse> siteMap = new CopyOnWriteArrayList<>();
    final List<String> scopeChanges = new CopyOnWriteArrayList<>();
    final List<String> apiAccesses = new CopyOnWriteArrayList<>();
    final List<String> errors = new CopyOnWriteArrayList<>();
    private final Map<RequestOptions, RedirectionMode> options = Collections.synchronizedMap(new IdentityHashMap<>());
    Predicate<String> inScope = url -> true;
    Function<HttpRequest, HttpResponse> responder = request -> response(200, "", Map.of());
    Consumer<HttpRequest> onSend = request -> {};
    final MontoyaApi api;

    FakeMontoya() {
        ObjectFactoryLocator.FACTORY = proxy(MontoyaObjectFactory.class, (self, method, args) -> switch (method.getName()) {
            case "httpRequestFromUrl" -> request((String) args[0]);
            case "httpRequest" -> parseRequest((HttpService) args[0], (String) args[1]);
            case "parameter", "urlParameter", "bodyParameter", "cookieParameter" -> parameter(
                    (String) args[0], (String) args[1], args.length > 2 && args[2] instanceof HttpParameterType t
                            ? t : method.getName().equals("cookieParameter") ? HttpParameterType.COOKIE : HttpParameterType.URL);
            case "httpHeader" -> header((String) args[0], (String) args[1]);
            case "httpRequestResponse" -> pair((HttpRequest) args[0], (HttpResponse) args[1]);
            case "requestOptions" -> proxy(RequestOptions.class, (value, call, parameters) -> {
                if (call.getName().equals("withRedirectionMode")) options.put((RequestOptions) value, (RedirectionMode) parameters[0]);
                return value;
            });
            default -> empty(method.getReturnType());
        });
        api = proxy(MontoyaApi.class, (self, method, args) -> {
            apiAccesses.add(method.getName());
            return switch (method.getName()) {
            case "http" -> proxy(method.getReturnType(), (http, call, parameters) -> {
                if (!call.getName().equals("sendRequest")) throw new AssertionError("Uncontrolled HTTP API: " + call);
                HttpRequest request = (HttpRequest) parameters[0];
                if (parameters.length != 2 || !(parameters[1] instanceof RequestOptions supplied)) {
                    throw new AssertionError("Native sends must specify one-hop RequestOptions");
                }
                RedirectionMode mode = options.get(supplied);
                if (mode != RedirectionMode.NEVER) throw new AssertionError("Automatic redirect escaped the gate");
                sent.add(request);
                redirectModes.add(mode);
                onSend.accept(request);
                return pair(request, responder.apply(request));
            });
            case "scope" -> proxy(method.getReturnType(), (scope, call, parameters) -> {
                if (call.getName().equals("isInScope")) return inScope.test((String) parameters[0]);
                if (call.getName().equals("includeInScope") || call.getName().equals("excludeFromScope")) scopeChanges.add(call.getName());
                return empty(call.getReturnType());
            });
            case "siteMap" -> proxy(method.getReturnType(), (map, call, parameters) -> switch (call.getName()) {
                case "requestResponses" -> new ArrayList<>(siteMap);
                case "issues" -> List.of();
                case "add" -> { if (parameters[0] instanceof HttpRequestResponse rr) siteMap.add(rr); yield null; }
                default -> empty(call.getReturnType());
            });
            case "logging" -> proxy(method.getReturnType(), (logger, call, parameters) -> {
                if (call.getName().equals("logToError")) errors.add(Arrays.toString(parameters));
                return empty(call.getReturnType());
            });
            default -> empty(method.getReturnType());
            };
        });
    }

    HttpRequest request(String url) {
        Request state = new Request(url);
        String query = URI.create(url).getRawQuery();
        if (query != null) for (String item : query.split("&")) {
            String[] pair = item.split("=", 2);
            state.params.add(parameter(URLDecoder.decode(pair[0], StandardCharsets.UTF_8),
                    pair.length == 2 ? URLDecoder.decode(pair[1], StandardCharsets.UTF_8) : "", HttpParameterType.URL));
        }
        return state.value();
    }

    private HttpRequest parseRequest(HttpService service, String raw) {
        String[] sections = raw.split("\\r?\\n\\r?\\n", 2);
        String[] lines = sections[0].split("\\r?\\n");
        String[] first = lines[0].split(" ", 3);
        String url = (service.secure() ? "https://" : "http://") + service.host() + ":" + service.port() + first[1];
        HttpRequest request = request(url).withMethod(first[0]);
        for (int i = 1; i < lines.length; i++) {
            int colon = lines[i].indexOf(':');
            if (colon > 0) request = request.withHeader(lines[i].substring(0, colon), lines[i].substring(colon + 1).strip());
        }
        return request.withBody(sections.length == 2 ? sections[1] : "");
    }

    static HttpParameter parameter(String name, String value, HttpParameterType type) {
        return proxy(ParsedHttpParameter.class, (self, method, args) -> switch (method.getName()) {
            case "name" -> name;
            case "value" -> value;
            case "type" -> type;
            default -> empty(method.getReturnType());
        });
    }

    static HttpHeader header(String name, String value) {
        return proxy(HttpHeader.class, (self, method, args) -> switch (method.getName()) {
            case "name" -> name;
            case "value" -> value;
            default -> empty(method.getReturnType());
        });
    }

    static HttpResponse response(int status, String body, Map<String, String> headers) {
        return proxy(HttpResponse.class, (self, method, args) -> switch (method.getName()) {
            case "statusCode" -> (short) status;
            case "bodyToString" -> body;
            case "headerValue" -> getHeader(headers, (String) args[0]);
            case "hasHeader" -> getHeader(headers, (String) args[0]) != null;
            case "headers" -> headers.entrySet().stream().map(e -> header(e.getKey(), e.getValue())).toList();
            case "toString" -> "HTTP/1.1 " + status + " OK\r\n\r\n" + body;
            default -> method.getReturnType() == HttpResponse.class ? self : empty(method.getReturnType());
        });
    }

    static HttpRequestResponse pair(HttpRequest request, HttpResponse response) {
        return proxy(HttpRequestResponse.class, (self, method, args) -> switch (method.getName()) {
            case "request" -> request;
            case "response" -> response;
            case "hasResponse" -> response != null;
            default -> method.getReturnType() == HttpRequestResponse.class ? self : empty(method.getReturnType());
        });
    }

    private final class Request {
        String url, method = "GET", body = "";
        HttpService serviceOverride;
        final Map<String, String> headers = new LinkedHashMap<>();
        final List<HttpParameter> params = new ArrayList<>();
        Request(String url) { this.url = url; }
        Request copy() {
            Request result = new Request(url); result.method = method; result.body = body; result.serviceOverride = serviceOverride;
            result.headers.putAll(headers); result.params.addAll(params); return result;
        }
        HttpRequest value() {
            return proxy(HttpRequest.class, (self, call, args) -> {
                switch (call.getName()) {
                    case "copyToTempFile": return self;
                    case "url": return url;
                    case "method": return method;
                    case "bodyToString": return body;
                    case "toByteArray": return bytes(self.toString());
                    case "isInScope": return inScope.test(url);
                    case "parameters": return List.copyOf(params);
                    case "parameterValue": return params.stream().filter(p -> p.name().equals(args[0]))
                            .map(HttpParameter::value).findFirst().orElse(null);
                    case "hasParameters": return !params.isEmpty();
                    case "headerValue": return getHeader(headers, (String) args[0]);
                    case "hasHeader": return getHeader(headers, (String) args[0]) != null;
                    case "headers": return headers.entrySet().stream().map(e -> header(e.getKey(), e.getValue())).toList();
                    case "pathWithoutQuery": return URI.create(url).getRawPath();
                    case "path": return URI.create(url).getRawPath() + (URI.create(url).getRawQuery() == null ? "" : "?" + URI.create(url).getRawQuery());
                    case "httpService": {
                        if (serviceOverride != null) return serviceOverride;
                        URI uri = URI.create(url);
                        return proxy(HttpService.class, (service, m, a) -> switch (m.getName()) {
                            case "host" -> uri.getHost();
                            case "port" -> uri.getPort() >= 0 ? uri.getPort() : uri.getScheme().equals("https") ? 443 : 80;
                            case "secure" -> uri.getScheme().equals("https");
                            default -> empty(m.getReturnType());
                        });
                    }
                    case "hasParameter": return params.stream().anyMatch(p -> p.name().equals(args[0]) && p.type() == args[1]);
                    case "toString": return method + " " + URI.create(url).getRawPath() + (URI.create(url).getRawQuery() == null ? "" : "?" + URI.create(url).getRawQuery()) + " HTTP/1.1\r\n" + headers.entrySet().stream()
                            .map(e -> e.getKey() + ": " + e.getValue() + "\r\n").reduce("", String::concat) + "\r\n" + body;
                }
                Request next = copy();
                switch (call.getName()) {
                    case "withService": next.serviceOverride = (HttpService) args[0]; break;
                    case "withMethod": next.method = (String) args[0]; break;
                    case "withBody": next.body = args[0].toString(); break;
                    case "withPath": next.url = URI.create(url).resolve((String) args[0]).toString(); break;
                    case "withHeader", "withUpdatedHeader", "withAddedHeader": {
                        String name = args[0] instanceof HttpHeader h ? h.name() : (String) args[0];
                        String value = args[0] instanceof HttpHeader h ? h.value() : (String) args[1];
                        next.headers.keySet().removeIf(k -> k.equalsIgnoreCase(name)); next.headers.put(name, value); break;
                    }
                    case "withRemovedHeader": next.headers.keySet().removeIf(k -> k.equalsIgnoreCase((String) args[0])); break;
                    case "withUpdatedParameters", "withAddedParameters": {
                        List<?> values = args[0] instanceof List<?> list ? list : Arrays.asList((Object[]) args[0]);
                        for (Object raw : values) {
                            HttpParameter p = (HttpParameter) raw;
                            next.params.removeIf(old -> old.name().equals(p.name()) && old.type() == p.type()); next.params.add(p);
                        }
                        String base = next.url.split("\\?", 2)[0];
                        next.url = base + "?" + next.params.stream().filter(p -> p.type() == HttpParameterType.URL)
                                .map(p -> URLEncoder.encode(p.name(), StandardCharsets.UTF_8) + "=" + URLEncoder.encode(p.value(), StandardCharsets.UTF_8))
                                .reduce((a, b) -> a + "&" + b).orElse(""); break;
                    }
                    default: return empty(call.getReturnType());
                }
                return next.value();
            });
        }
    }

    static ByteArray bytes(String text) {
        byte[] data = text.getBytes(StandardCharsets.UTF_8);
        return proxy(ByteArray.class, (self, method, args) -> switch (method.getName()) {
            case "getBytes" -> data.clone();
            case "length" -> data.length;
            case "toString" -> text;
            default -> empty(method.getReturnType());
        });
    }

    private static String getHeader(Map<String, String> headers, String name) {
        return headers.entrySet().stream().filter(e -> e.getKey().equalsIgnoreCase(name)).map(Map.Entry::getValue).findFirst().orElse(null);
    }

    @SuppressWarnings("unchecked")
    static <T> T proxy(Class<T> type, InvocationHandler handler) {
        return (T) Proxy.newProxyInstance(type.getClassLoader(), new Class<?>[]{type}, (self, method, args) -> {
            if (method.getName().equals("hashCode")) return System.identityHashCode(self);
            if (method.getName().equals("equals")) return self == args[0];
            return handler.invoke(self, method, args);
        });
    }

    private static Object empty(Class<?> type) {
        if (type == void.class) return null;
        if (type == boolean.class) return false;
        if (type == int.class) return 0;
        if (type == short.class) return (short) 0;
        if (type == long.class) return 0L;
        if (type == byte.class) return (byte) 0;
        if (type == float.class) return 0f;
        if (type == double.class) return 0d;
        if (List.class.isAssignableFrom(type)) return List.of();
        if (type == String.class) return "";
        if (type.isInterface()) return proxy(type, (self, method, args) -> empty(method.getReturnType()));
        return null;
    }

    @Override public void close() { ObjectFactoryLocator.FACTORY = previous; }
}
