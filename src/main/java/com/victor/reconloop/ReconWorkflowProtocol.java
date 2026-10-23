package com.victor.reconloop;

import java.util.*;

/** Version two sidecar events are bounded, correlated and stage/kind checked before GUI use. */
final class ReconWorkflowProtocol {
    private final DomainReconProcess.Plan plan;
    private final Set<String> hosts=new HashSet<>(),urls=new HashSet<>(),resolved=new HashSet<>();
    private int stage,added; private boolean started,done,degraded; private String terminal;
    ReconWorkflowProtocol(DomainReconProcess.Plan plan){this.plan=plan;}
    int hosts(){return hosts.size();}
    DomainReconProcess.Event accept(String line){
        var obj=Json.asObject(Json.parseStrict(line));
        require(obj!=null&&obj.keySet().stream().allMatch(Set.of("version","type","run_id","domain","state","hosts","urls","resolved","record","tool_result")::contains));
        require(integer(obj,"version")==2&&plan.runId().equals(obj.get("run_id"))&&plan.domain().equals(obj.get("domain"))&&!done);
        String type=string(obj,"type"),state=obj.containsKey("state")?string(obj,"state"):"",tool="",value="",detail="";
        switch(type){
            case "start" -> {require(!started&&"RUNNING".equals(state)&&!obj.containsKey("record")&&!obj.containsKey("tool_result"));started=true;}
            case "record" -> {
                require(started&&stage<DomainReconProcess.WORKFLOW_TOOLS.size()&&state.isEmpty()&&!obj.containsKey("tool_result"));
                var wire=Json.asObject(obj.get("record"));require(wire!=null&&wire.keySet().stream().allMatch(Set.of("kind","value","hostname","addresses","cnames","url","tool","source","run_id","created_at")::contains));
                var record=SidecarEvent.parse(Json.write(wire));tool=record.tool();
                require(plan.runId().equals(record.runId()));
                String current=DomainReconProcess.WORKFLOW_TOOLS.get(stage);
                if(tool.equals("seed"))require(stage==0&&hosts.isEmpty()&&record.kind()==SidecarEvent.Kind.HOSTNAME&&plan.domain().equals(record.hostname()));
                else {require(tool.equals(current));added++;}
                switch(record.kind()){
                    case HOSTNAME -> {require(stage<4&&record.url()==null&&record.addresses().isEmpty()&&record.cnames().isEmpty()&&inDomain(record.hostname())&&DomainReconProcess.domain(record.hostname()).equals(record.hostname())&&record.hostname().equals(record.value())&&hosts.size()<plan.maxHosts()&&hosts.add(record.hostname()));value=record.hostname();type="host";}
                    case RESOLVED_HOST -> {require(current.equals("dnsx")&&hosts.contains(record.hostname())&&resolved.size()<plan.maxHosts()&&resolved.add(record.hostname()));value=record.hostname();type="dns";detail=String.join(", ",record.addresses())+" · CNAME "+String.join(", ",record.cnames());}
                    case URL -> {require(stage>=5);value=NativeReconChain.canonical(record.url(),plan.domain());require(value!=null&&value.equals(record.url())&&urls.size()<plan.maxUrls()&&urls.add(value));type="url";detail=record.source();}
                    default -> throw new IllegalArgumentException("Unexpected workflow record kind");
                }
            }
            case "tool" -> {
                require(started&&stage<DomainReconProcess.WORKFLOW_TOOLS.size()&&state.isEmpty()&&!obj.containsKey("record"));
                var result=Json.asObject(obj.get("tool_result"));require(result!=null);
                tool=string(result,"tool");state=string(result,"state");
                require(tool.equals(DomainReconProcess.WORKFLOW_TOOLS.get(stage))&&Set.of("SUCCESS","PARTIAL","FAILED","TIMEOUT","CANCELLED").contains(state)&&integer(result,"added")==added);
                var run=Json.asObject(result.get("run"));require(run!=null&&plan.runId().equals(run.get("run_id"))&&tool.equals(run.get("tool")));
                degraded|=!state.equals("SUCCESS");stage++;added=0;detail=resolved.size()+" resolved hosts; "+urls.size()+" URLs. See workflow-summary.json.";
            }
            case "done" -> {
                require(started&&!obj.containsKey("record")&&!obj.containsKey("tool_result")&&Set.of("SUCCESS","PARTIAL","FAILED","CANCELLED").contains(state));
                if(Set.of("SUCCESS","PARTIAL").contains(state))require(stage==DomainReconProcess.WORKFLOW_TOOLS.size());
                if(state.equals("SUCCESS"))require(!degraded);
                terminal=state;done=true;
            }
            default -> throw new IllegalArgumentException("Unknown workflow event");
        }
        require(integer(obj,"hosts")==hosts.size()&&integer(obj,"urls")==urls.size()&&integer(obj,"resolved")==resolved.size());
        return new DomainReconProcess.Event(type,tool,state,value,hosts.size(),detail);
    }
    DomainReconProcess.Outcome finish(int exit){
        require(done&&(Set.of("SUCCESS","PARTIAL").contains(terminal)?exit==0:exit!=0));
        return new DomainReconProcess.Outcome(terminal,hosts.size(),resolved.size()+" resolved hosts; "+urls.size()+" archive URLs. External target tools were not executed.");
    }
    private boolean inDomain(String host){return host!=null&&(host.equals(plan.domain())||host.endsWith("."+plan.domain()));}
    private static void require(boolean value){if(!value)throw new IllegalArgumentException("Invalid workflow protocol");}
    private static String string(Map<String,Object> obj,String key){Object v=obj.get(key);require(v instanceof String);return(String)v;}
    private static int integer(Map<String,Object> obj,String key){Object v=obj.get(key);require(v instanceof Number);double n=((Number)v).doubleValue();require(n>=0&&n<=Integer.MAX_VALUE&&n==Math.rint(n));return(int)n;}
}
