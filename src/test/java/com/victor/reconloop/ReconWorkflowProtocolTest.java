package com.victor.reconloop;

import org.junit.Test;
import java.nio.file.Path;
import java.util.*;
import static org.junit.Assert.*;

public class ReconWorkflowProtocolTest {
    static DomainReconProcess.Plan plan(){return new DomainReconProcess.Plan("example.com","reconctl",Path.of("runs"),DomainReconProcessTest.ID,5,5,true,10,3,2);}
    static Map<String,Object> event(String type,int hosts,int urls,int dns){return new LinkedHashMap<>(Map.of("version",2,"type",type,"run_id",DomainReconProcessTest.ID,"domain","example.com","hosts",hosts,"urls",urls,"resolved",dns));}
    static String start(){var e=event("start",0,0,0);e.put("state","RUNNING");return Json.write(e);}
    static String seed(){var e=event("record",1,0,0);e.put("record",Map.of("kind","hostname","value","example.com","hostname","example.com","tool","seed","source","seed","run_id",DomainReconProcessTest.ID));return Json.write(e);}
    static String tool(String name,String state){var e=event("tool",1,0,0);e.put("tool_result",Map.of("tool",name,"state",state,"added",0,"run",Map.of("tool",name,"run_id",DomainReconProcessTest.ID)));return Json.write(e);}
    @Test public void terminalRequiresAllEightStagesAndSuccessfulExit(){
        var p=new ReconWorkflowProtocol(plan());p.accept(start());p.accept(seed());
        var done=event("done",1,0,0);done.put("state","SUCCESS");
        assertThrows(IllegalArgumentException.class,()->p.accept(Json.write(done)));
        for(String name:DomainReconProcess.WORKFLOW_TOOLS)p.accept(tool(name,"SUCCESS"));
        p.accept(Json.write(done));assertEquals("SUCCESS",p.finish(0).state());assertThrows(IllegalArgumentException.class,()->p.finish(1));
    }
    @Test public void wrongCorrelationScopeKindCountsAndToolOrderFailClosed(){
        for(String bad:List.of(seed().replace("example.com","evil-example.com"),seed().replace(DomainReconProcessTest.ID,"00000000-0000-0000-0000-000000000000"),tool("dnsx","SUCCESS"),seed().replace("\"hosts\":1","\"hosts\":5"))){
            var p=new ReconWorkflowProtocol(plan());p.accept(start());assertThrows(bad,IllegalArgumentException.class,()->p.accept(bad));
        }
    }
    @Test public void previewDisclosesNativeBudgetAndDoesNotLaunchAnything(){
        var plan=plan();assertEquals("workflow",plan.command().get(1));assertTrue(plan.command().contains("--max-urls"));
        assertTrue(plan.preview().contains("at most 3 total GET"));assertTrue(plan.preview().contains("BLOCKED"));assertTrue(plan.preview().contains("No captured authentication"));
    }
}
