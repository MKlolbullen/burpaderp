package com.victor.reconloop;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;

/** Local artifacts are parsed and scoped again before they can become native request candidates. */
final class ReconWorkflowInputs {
    static NativeReconChain.Inputs load(DomainReconProcess.Plan plan)throws IOException {
        List<String> hosts=new ArrayList<>(),urls=new ArrayList<>();Map<String,SidecarEvent.Event> dns=new LinkedHashMap<>();
        Set<String> hostSet=new HashSet<>();
        for(String name:List.of("hosts.jsonl","dns.jsonl","urls.jsonl")) {
            Path path=plan.runDir().resolve(name);
            if(!Files.isRegularFile(path,LinkOption.NOFOLLOW_LINKS)||Files.size(path)>64L*1024*1024)throw new IOException("missing, symlinked or oversized workflow artifact");
            try(var in=Files.newBufferedReader(path,StandardCharsets.UTF_8)) {
                String line;int count=0;
                while((line=boundedLine(in))!=null){
                    if(++count>25000)throw new IOException("workflow record limit");
                    var event=SidecarEvent.parse(line);if(!plan.runId().equals(event.runId()))throw new IOException("run correlation mismatch");
                    switch(name){
                        case "hosts.jsonl" -> {if(event.kind()!=SidecarEvent.Kind.HOSTNAME||!inDomain(event.hostname(),plan.domain())||!hostSet.add(event.hostname()))throw new IOException("invalid host artifact");hosts.add(event.hostname());}
                        case "dns.jsonl" -> {if(event.kind()!=SidecarEvent.Kind.RESOLVED_HOST||!hostSet.contains(event.hostname())||dns.containsKey(event.hostname()))throw new IOException("invalid DNS artifact");dns.put(event.hostname(),event);}
                        case "urls.jsonl" -> {String value=NativeReconChain.canonical(event.url(),plan.domain());if(event.kind()!=SidecarEvent.Kind.URL||value==null||!value.equals(event.url()))throw new IOException("invalid URL artifact");urls.add(value);}
                    }
                }
            }catch(IllegalArgumentException e){throw new IOException("workflow artifact validation failed",e);}
        }
        if(hosts.size()>plan.maxHosts()||urls.size()>plan.maxUrls())throw new IOException("workflow bounds mismatch");
        return new NativeReconChain.Inputs(hosts,urls,dns);
    }
    private static boolean inDomain(String host,String domain){return host!=null&&(host.equals(domain)||host.endsWith("."+domain));}
    private static String boundedLine(Reader in)throws IOException{StringBuilder line=new StringBuilder();int c;while((c=in.read())!=-1){if(c=='\n')return line.toString();if(line.length()>=32768)throw new IOException("oversized workflow record");line.append((char)c);}if(!line.isEmpty())throw new IOException("incomplete workflow record");return null;}
    static List<AiAnalysis.Source> review(DomainReconProcess.Plan plan)throws IOException{
        Path path=plan.runDir().resolve("native/review-sources.json");
        if(!Files.isRegularFile(path,LinkOption.NOFOLLOW_LINKS)||Files.size(path)>2L*1024*1024)throw new IOException("missing or oversized review sources");
        try {
            byte[] bytes;try(var in=Files.newInputStream(path)){bytes=in.readNBytes((2<<20)+1);}if(bytes.length>2<<20)throw new IOException("review source byte limit");
            var root=Json.asObject(Json.parseStrict(new String(bytes,StandardCharsets.UTF_8)));if(root==null||!plan.runId().equals(root.get("workflow_run_id")))throw new IllegalArgumentException();
            var items=Json.asArray(root.get("sources"));if(items==null||items.size()>AiAnalysis.MAX_SOURCES)throw new IllegalArgumentException();
            List<AiAnalysis.Source> result=new ArrayList<>();
            for(Object item:items){var row=Json.asObject(item);result.add(new AiAnalysis.Source(Json.str(row,"id"),AiAnalysis.Kind.valueOf(Json.str(row,"kind")),Json.str(row,"name"),Json.str(row,"text")));}
            if(!result.isEmpty())AiAnalysis.validateSources(result);return List.copyOf(result);
        }catch(RuntimeException e){throw new IOException("invalid review sources",e);}
    }
}
