package com.victor.reconloop;

import org.junit.Test;
import java.nio.file.*;
import java.util.*;
import static org.junit.Assert.*;

public class ReconWorkflowIntegrationTest {
    @Test public void actualSidecarToNativeGatewayToCapturedReviewRunsWithoutRealProvidersOrTargets()throws Exception{
        String binary=System.getenv("RECONCTL_TEST_BINARY");org.junit.Assume.assumeTrue("CI builds the sidecar for this offline test",binary!=null);
        Path root=Files.createTempDirectory("recon-whole-chain");Path tools=root.resolve("tools");Files.createDirectory(tools);
        for(String name:DomainReconProcess.WORKFLOW_TOOLS){
            String body=switch(name){
                case "amass" -> "if [ \"$1\" = -version ]; then printf '%s\\n' v3.23.3; exit; fi\nprintf '%s\\n' '{\"name\":\"www.example.com\"}'\n";
                case "dnsx" -> "printf '%s\\n' '{\"host\":\"example.com\",\"a\":[\"93.184.216.34\"]}'\n";
                case "waybackurls","waybackpy","urlfinder" -> "printf '%s\\n' 'https://example.com/archive.js?b=2&a=%2f'\n";
                default -> "printf '%s\\n' www.example.com\n";
            };
            Path script=tools.resolve(name);Files.writeString(script,"#!/bin/sh\n"+body);assertTrue(script.toFile().setExecutable(true));
        }
        Path wrapper=root.resolve("reconctl-fixture");
        Files.writeString(wrapper,"#!/bin/sh\nexport PATH='"+tools+"'\nexec '"+binary.replace("'","'\\''")+"' \"$@\"\n");assertTrue(wrapper.toFile().setExecutable(true));
        var plan=new DomainReconProcess.Plan("example.com",wrapper.toString(),root.resolve("runs"),UUID.randomUUID().toString(),20,5,true,100,8,2);
        List<DomainReconProcess.Event> events=new ArrayList<>();
        var sidecar=new DomainReconProcess().run(plan,events::add);
        assertEquals(sidecar.detail(),"SUCCESS",sidecar.state());assertEquals(2,sidecar.count());
        assertEquals(8,events.stream().filter(e->e.type().equals("tool")).count());
        assertEquals(1,events.stream().filter(e->e.type().equals("url")).count());
        NativeReconChain.Inputs inputs=ReconWorkflowInputs.load(plan);assertEquals(1,inputs.urls().size());assertEquals(1,inputs.dns().size());
        try(var fake=new FakeMontoya()){
            fake.responder=request->FakeMontoya.response(200,request.pathWithoutQuery().endsWith(".js")?"fetch('/api/items?z=%2f&a=+');":"<title>Fixture</title><script src='/app.js'></script>",Map.of("Content-Type",request.pathWithoutQuery().endsWith(".js")?"application/javascript":"text/html"));
            var nativeRun=NativeReconChainTest.run(plan);
            var result=new NativeReconChain(new ActiveRequestGateway(RequestPolicy.safeDefault(fake.inScope),fake.transport()),fake::request).run(plan,inputs,nativeRun,events::add);
            assertTrue(result.detail(),result.responses()>0);assertTrue(result.dispatched()<=8);assertEquals(result.dispatched(),fake.sent.size());
            assertTrue(ReconWorkflowInputs.review(plan).stream().anyMatch(source->source.kind()==AiAnalysis.Kind.JAVASCRIPT));
            assertEquals(0,fake.scopeChanges.size());assertEquals(0,fake.issues.size());
            assertTrue(Files.readString(plan.runDir().resolve("native/urls.jsonl")).contains("z=%2f&a=+"));
        }
        try(var fake=new FakeMontoya()){
            fake.responder=request->FakeMontoya.response(200,"<script src='/app.js'></script>",Map.of("Content-Type","text/html"));
            var second=new DomainReconProcess.Plan("example.com",wrapper.toString(),root.resolve("runs"),UUID.randomUUID().toString(),20,5,true,100,4,1);
            var controller=ReconControllerRunLifecycleTest.controller(fake,new ManualExecutor());
            var completed=new java.util.concurrent.CompletableFuture<DomainReconProcess.Outcome>();
            try{
                controller.enumerateDomain(second,event->{},completed::complete).get(10,java.util.concurrent.TimeUnit.SECONDS);
                var result=completed.get(3,java.util.concurrent.TimeUnit.SECONDS);assertTrue(result.detail(),Set.of("SUCCESS","PARTIAL").contains(result.state()));
                assertTrue(fake.sent.size()>0);assertTrue(fake.sent.size()<=4);
                assertTrue(fake.responseTimeouts.stream().allMatch(timeout->timeout==15000));
                var saved=Json.asObject(Json.parseStrict(Files.readString(second.runDir().resolve("chain-result.json"))));
                assertEquals("SUCCESS",saved.get("sidecar_state"));assertEquals(fake.sent.size(),((Number)saved.get("native_dispatches")).intValue());
                assertTrue(Files.exists(second.runDir().resolve("native/summary.json")));
            }finally{controller.shutdown();}
        }
        try(var paths=Files.walk(root)){for(Path path:paths.sorted(Comparator.reverseOrder()).toList())Files.delete(path);}
    }

    @Test public void sidecarImportIsNotStarvedByTheLongRunningCrawlerWorker()throws Exception{
        try(var fake=new FakeMontoya()){
            var controller=new ReconController(fake.api,new ReconModel.FindingTableModel(),new ReconModel.DiscoveryTableModel(),new ReconModel.ParameterTableModel(),new ReconModel.ReflectionTableModel(),new ReconModel.ActiveTableModel(),new ReconModel.AssetTableModel(),new ManualExecutor(),true,fake.destinations());
            Path file=Files.createTempFile("recon-import",".jsonl");Files.writeString(file,"{\"kind\":\"hostname\",\"value\":\"example.com\",\"tool\":\"fixture\"}\n");
            var imported=new java.util.concurrent.CompletableFuture<String>();
            try{controller.importSidecarJsonl(file,imported::complete);assertTrue(imported.get(3,java.util.concurrent.TimeUnit.SECONDS).contains("Imported 1"));assertTrue(fake.sent.isEmpty());}
            finally{controller.shutdown();Files.delete(file);}
        }
    }
}
