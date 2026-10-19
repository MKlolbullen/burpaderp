package com.victor.reconloop;

import burp.api.montoya.MontoyaApi;
import com.sun.source.tree.ClassTree;
import com.sun.source.tree.MemberReferenceTree;
import com.sun.source.tree.MethodInvocationTree;
import com.sun.source.tree.NewClassTree;
import com.sun.source.util.JavacTask;
import com.sun.source.util.TreePath;
import com.sun.source.util.TreePathScanner;
import com.sun.source.util.Trees;
import org.junit.Test;

import javax.lang.model.element.ExecutableElement;
import javax.lang.model.element.TypeElement;
import javax.tools.*;
import java.io.File;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.junit.Assert.*;

/** Resolve API owners, rather than matching one spelling of a send expression. */
public class OutboundGatewayInvariantTest {
    private static final String PACKAGE = "com.victor.reconloop.";
    private static final Set<String> SERVICE_CLIENTS = Set.of(
            PACKAGE + "LlmClient", PACKAGE + "PassiveOsintClient", PACKAGE + "PdcpClient",
            PACKAGE + "ReconHoundCli"); // Deliberately outside this native Montoya invariant.

    @Test
    public void nativeTargetSourcesHaveOneTransportBinding() throws Exception {
        JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
        assertNotNull("Run architecture checks on a JDK", compiler);
        try (StandardJavaFileManager manager = compiler.getStandardFileManager(null, null, null);
             Stream<Path> paths = Files.walk(Path.of("src/main/java"))) {
            List<File> files = paths.filter(p -> p.toString().endsWith(".java"))
                    .map(Path::toFile).toList();
            assertEquals(List.of(), violations(manager.getJavaFileObjectsFromFiles(files)));
        }
    }

    @Test
    public void detectsAliasesReferencesWhitespaceBatchesAndRequestEngines() throws Exception {
        for (String operation : List.of(
                "http.sendRequest(request);",
                "http\n . sendRequest (request);",
                "var alias = http; alias.sendRequest(request);",
                "java.util.function.Function<burp.api.montoya.http.message.requests.HttpRequest, "
                        + "burp.api.montoya.http.message.HttpRequestResponse> send = http::sendRequest;",
                "http.sendRequests(java.util.List.of(request));",
                "http.createRequestEngine();")) {
            assertFalse(operation, violations(List.of(fixture(operation))).isEmpty());
        }
    }

    @Test
    public void enginesCannotUseRawGatewaySenderEither() throws Exception {
        JavaFileObject source = new SimpleJavaFileObject(URI.create("string:///Bypass.java"),
                JavaFileObject.Kind.SOURCE) {
            @Override public CharSequence getCharContent(boolean ignoreEncodingErrors) {
                return "package com.victor.reconloop; class Bypass { void run("
                        + "ActiveRequestGateway.Sender sender, "
                        + "burp.api.montoya.http.message.requests.HttpRequest request) throws Exception {"
                        + "sender.send(request); } }";
            }
        };
        assertFalse(violations(List.of(source)).isEmpty());
    }

    private static JavaFileObject fixture(String operation) {
        return new SimpleJavaFileObject(URI.create("string:///Bypass.java"), JavaFileObject.Kind.SOURCE) {
            @Override public CharSequence getCharContent(boolean ignoreEncodingErrors) {
                return "class Bypass { void run(burp.api.montoya.http.Http http, "
                        + "burp.api.montoya.http.message.requests.HttpRequest request) { "
                        + operation + " } }";
            }
        };
    }

    private static List<String> violations(Iterable<? extends JavaFileObject> sources) throws Exception {
        JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
        assertNotNull("Run architecture checks on a JDK", compiler);
        DiagnosticCollector<JavaFileObject> diagnostics = new DiagnosticCollector<>();
        String classpath = Stream.of(MontoyaApi.class, ReconController.class)
                .map(c -> Path.of(URI.create(c.getProtectionDomain().getCodeSource().getLocation().toString())).toString())
                .collect(Collectors.joining(File.pathSeparator));
        try (StandardJavaFileManager manager = compiler.getStandardFileManager(diagnostics, null, null)) {
            JavacTask task = (JavacTask) compiler.getTask(null, manager, diagnostics,
                    List.of("-proc:none", "--release", "21", "-classpath", classpath), null, sources);
            var units = task.parse();
            task.analyze(); // An unresolved owner must fail the test, not silently evade the guard.
            List<String> errors = diagnostics.getDiagnostics().stream()
                    .filter(d -> d.getKind() == Diagnostic.Kind.ERROR).map(Object::toString).toList();
            assertEquals("Architecture fixtures/sources must compile", List.of(), errors);
            Trees trees = Trees.instance(task);
            List<String> failures = new ArrayList<>();
            TreePathScanner<Void, Void> scanner = new TreePathScanner<>() {
                private void inspect() {
                    if (!(trees.getElement(getCurrentPath()) instanceof ExecutableElement method)
                            || !(method.getEnclosingElement() instanceof TypeElement owner)) return;
                    String type = owner.getQualifiedName().toString();
                    String name = method.getSimpleName().toString();
                    String caller = enclosingClass();
                    boolean forbidden = false;
                    if (type.equals("burp.api.montoya.http.Http")) {
                        if (name.equals("sendRequest")) {
                            forbidden = !Set.of(PACKAGE + "MontoyaTargetTransport",
                                    PACKAGE + "CertificateTransparencyClient").contains(caller);
                        } else if (Set.of("sendRequests", "createRequestEngine").contains(name)) forbidden = true;
                    } else if (type.equals(PACKAGE + "ActiveRequestGateway.Sender") && name.equals("send")) {
                        forbidden = !caller.equals(PACKAGE + "ActiveRequestGateway");
                    } else if (type.equals(PACKAGE + "MontoyaTargetTransport")) {
                        forbidden = !name.equals("<init>") || !caller.equals(PACKAGE + "ReconController");
                    } else if (type.equals("java.net.http.HttpClient") && Set.of("send", "sendAsync").contains(name)) {
                        forbidden = !SERVICE_CLIENTS.contains(caller);
                    }
                    if (forbidden) failures.add(caller + " -> " + type + "." + name);
                }
                private String enclosingClass() {
                    for (TreePath p = getCurrentPath(); p != null; p = p.getParentPath()) {
                        if (p.getLeaf() instanceof ClassTree && trees.getElement(p) instanceof TypeElement t) {
                            return t.getQualifiedName().toString();
                        }
                    }
                    return "";
                }
                @Override public Void visitMethodInvocation(MethodInvocationTree tree, Void unused) {
                    inspect(); return super.visitMethodInvocation(tree, unused);
                }
                @Override public Void visitMemberReference(MemberReferenceTree tree, Void unused) {
                    inspect(); return super.visitMemberReference(tree, unused);
                }
                @Override public Void visitNewClass(NewClassTree tree, Void unused) {
                    inspect(); return super.visitNewClass(tree, unused);
                }
            };
            units.forEach(unit -> scanner.scan(unit, null));
            return failures;
        }
    }
}
