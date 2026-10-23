package com.victor.reconloop;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import java.io.*;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Instant;
import java.util.*;
import java.util.function.*;
import java.util.regex.Pattern;

/** Bounded native HTTP probe/fingerprint/crawl/JS phase. All sends use the mandatory gateway. */
final class NativeReconChain {
    record Inputs(List<String> hosts,List<String> urls,Map<String,SidecarEvent.Event> dns) {
        Inputs { hosts=List.copyOf(hosts);urls=List.copyOf(urls);dns=Map.copyOf(dns); }
    }
    record Outcome(String state,int dispatched,int responses,int denied,int urls,String detail) {}
    private record Node(String url,int depth,int redirects,String source,boolean fallback) {}
    private static final int BODY_LIMIT=64*1024, PENDING_LIMIT=10000;
    private static final Pattern LINKS=Pattern.compile("https?://[^\\s\\\"'<>`]+|(?:src|href)\\s*=\\s*[\\\"']([^\\\"'<>]{1,2048})[\\\"']|[\\\"']((?:/|\\./|\\.\\./)[^\\\"'\\s<>]{1,2048})[\\\"']",Pattern.CASE_INSENSITIVE);
    private static final Pattern TITLE=Pattern.compile("<title[^>]*>(.{0,512}?)</title>",Pattern.CASE_INSENSITIVE|Pattern.DOTALL);
    private final ActiveRequestGateway gateway;
    private final Function<String,HttpRequest> requests;
    NativeReconChain(ActiveRequestGateway gateway,Function<String,HttpRequest> requests){this.gateway=gateway;this.requests=requests;}

    Outcome run(DomainReconProcess.Plan plan,Inputs inputs,ScanRun run,Consumer<DomainReconProcess.Event> events) {
        if(plan.httpBudget()==0) return new Outcome("SKIPPED",0,0,0,0,"Native HTTP phase disabled.");
        if(!run.requestLimits().equals(new ScanRun.RequestLimits(plan.httpBudget(),plan.perHost(),3,plan.httpBudget())))throw new IllegalArgumentException("HTTP ledger must match previewed quotas");
        int responses=0,denied=0,truncated=0,errors=0,omitted=0;long retained=0;
        boolean limited=false,timeLimit=false;String state="SUCCESS",detail="";
        LinkedHashMap<String,String> discovered=new LinkedHashMap<>();
        Deque<Node> queue=new ArrayDeque<>();Set<String> queued=new HashSet<>();
        Deque<Node> roots=new ArrayDeque<>(),archives=new ArrayDeque<>();
        long deadline=System.nanoTime()+java.util.concurrent.TimeUnit.SECONDS.toNanos(plan.toolSeconds());int turn=0;
        List<AiAnalysis.Source> sources=new ArrayList<>();int sourceChars=0;
        Set<String> scripts=new TreeSet<>();
        Path dir=plan.runDir().resolve("native");
        try {
            if(Thread.currentThread().isInterrupted()||!run.isRunning()) {run.cancel();state="CANCELLED";return new Outcome("CANCELLED",0,0,0,0,"Cancelled before native phase.");}
            createPrivateDirectory(dir);
            int count=0;
            for(String host:inputs.hosts()) {
                if(count++>=PENDING_LIMIT||discovered.size()>=plan.maxUrls()){limited=true;break;}
                String value=canonical("https://"+host+"/",plan.domain());if(value!=null){roots.add(new Node(value,0,0,"seed",true));queued.add(value);discovered.put(value,"seed");}
            }
            for(String raw:inputs.urls()) {
                String value=canonical(raw,plan.domain());if(value==null)continue;
                if(discovered.size()>=plan.maxUrls()){limited=true;break;}discovered.putIfAbsent(value,"archive");
                if(roots.size()+archives.size()<PENDING_LIMIT&&queued.add(value))archives.add(new Node(value,0,0,"archive",false));
                else if(!queued.contains(value))limited=true;
            }
            try(BufferedWriter metadata=writer(dir.resolve("http.jsonl"));BufferedWriter evidence=writer(dir.resolve("evidence.jsonl"));BufferedWriter urls=writer(dir.resolve("urls.jsonl"))) {
                while(!queue.isEmpty()||!roots.isEmpty()||!archives.isEmpty()) {
                    if(Thread.currentThread().isInterrupted()||!run.isRunning()){run.cancel();state="CANCELLED";break;}
                    if(System.nanoTime()>deadline){limited=true;timeLimit=true;break;}
                    if(run.requestBudget().exhausted()){limited=true;break;}
                    Node node=switch(turn++%3){case 0->roots.pollFirst();case 1->archives.pollFirst();default->queue.pollFirst();};
                    if(node==null)node=!queue.isEmpty()?queue.removeFirst():!roots.isEmpty()?roots.removeFirst():archives.removeFirst();
                    HttpRequest request=requests.apply(node.url());
                    if(!"GET".equals(request.method())||!node.url().equals(request.url()))throw new IllegalStateException("request factory must preserve planned GET URL");
                    RequestPlan binding=RequestPlan.safe(request,"recon-chain");
                    var result=gateway.send(run,binding,request);
                    Map<String,Object> row=new LinkedHashMap<>();row.put("workflow_run_id",plan.runId());row.put("native_run_id",run.id().toString());row.put("url",node.url());row.put("method","GET");row.put("source",node.source());
                    row.put("decision",result.decision().code().name());row.put("dispatched",result.dispatched());row.put("transport_elapsed_nanos",Long.toString(result.transportElapsedNanos()));
                    if(!result.dispatched())denied++;
                    if(result.error()!=null)errors++;
                    if(result.exchange()!=null) {
                        EvidenceCapture capture=new EvidenceCapture(run,request,"NATIVE_HELPER","recon-chain");capture.record(result);
                        FindingEvidence observation=capture.snapshot(VerificationState.SIGNAL,"Recon observation only; no vulnerability or exploitability established.");
                        String encoded=Json.write(ActiveEvidenceCodec.evidenceMap(observation));
                        if(retained+encoded.length()>32L*1024*1024){encoded=Json.write(ActiveEvidenceCodec.evidenceMap(observation.withoutBytes()));omitted++;}
                        retained+=encoded.length();line(evidence,Map.of("workflow_run_id",plan.runId(),"schema_version",2,"evidence",Json.parseStrict(encoded)));
                    }
                    HttpResponse response=result.response()==null?null:result.response().response();
                    if(response==null) {
                        if(node.fallback()&&result.dispatched()&&URI.create(node.url()).getScheme().equals("https")) {
                            String fallback="http"+node.url().substring(5);
                            if(!discovered.containsKey(fallback)&&discovered.size()>=plan.maxUrls())limited=true;
                            else if(queue.size()+roots.size()+archives.size()<PENDING_LIMIT&&queued.add(fallback)) {queue.addFirst(new Node(fallback,node.depth(),0,"https-transport-fallback",false));discovered.putIfAbsent(fallback,"fallback");}
                        }
                    } else {
                        responses++;String body=prefix(response);boolean clipped=response.body().length()>BODY_LIMIT;if(clipped)truncated++;
                        String contentType=header(response,"Content-Type");
                        boolean text=contentType.isBlank()||contentType.toLowerCase(Locale.ROOT).matches(".*(?:text|json|javascript|xml|html).*" );
                        if(isJavaScript(node.url(),contentType))scripts.add(node.url());
                        row.put("status",(int)response.statusCode());row.put("server",header(response,"Server"));row.put("content_type",contentType);row.put("body_length",response.body().length());row.put("body_prefix_truncated",clipped);
                        String location=header(response,"Location");row.put("location",location);
                        var title=TITLE.matcher(text?body:"");row.put("title",title.find()?title.group(1).replaceAll("\\s+"," ").strip():"");
                        row.put("technology_signals",fingerprints(response,text?body:""));
                        var dns=inputs.dns().get(URI.create(node.url()).getHost());
                        row.put("dns_addresses",dns==null?List.of():dns.addresses());row.put("dns_cnames",dns==null?List.of():dns.cnames());
                        row.put("tls",URI.create(node.url()).getScheme().equals("https")?"HTTPS transport; certificate/TLS-grab details unavailable":"plain HTTP");
                        row.put("observed_at",Instant.now().toString());
                        if(text&&sources.size()<AiAnalysis.MAX_SOURCES&&body.indexOf('\0')<0) {
                            String sourceText="URL: "+node.url()+"\nStatus: "+response.statusCode()+"\nContent-Type: "+contentType+"\nServer: "+header(response,"Server")+"\n\n"+body;
                            if(!isJavaScript(node.url(),contentType))sourceText="URL: "+node.url()+"\nCaptured request prefix:\n"+prefix(request.toByteArray(),1500)+"\nCaptured response prefix:\n"+prefix(response.toByteArray(),10000);
                            int available=Math.min(12000,Math.min(AiAnalysis.MAX_SOURCE_CHARS,AiAnalysis.MAX_TOTAL_CHARS-sourceChars));
                            if(available>256){sourceText=sourceText.substring(0,Math.min(sourceText.length(),available));sources.add(new AiAnalysis.Source("s"+(sources.size()+1),isJavaScript(node.url(),contentType)?AiAnalysis.Kind.JAVASCRIPT:AiAnalysis.Kind.HTTP_EXCHANGE,shortText(node.url(),300),sourceText));sourceChars+=sourceText.length();}
                        }
                        if(response.statusCode()>=300&&response.statusCode()<400&&!location.isBlank()) {
                            String next=resolve(node.url(),location,plan.domain());
                            if(next!=null) {
                                if(!discovered.containsKey(next)&&discovered.size()>=plan.maxUrls())limited=true;
                                else{discovered.putIfAbsent(next,"redirect");
                                    if(node.redirects()<5&&queue.size()+roots.size()+archives.size()<PENDING_LIMIT&&queued.add(next))queue.addFirst(new Node(next,node.depth(),node.redirects()+1,"redirect",false));
                                    else if(node.redirects()>=5)limited=true;}
                            }
                        }
                        if(text)for(String next:extract(node.url(),body,plan.domain())) {
                            if(!discovered.containsKey(next)&&discovered.size()>=plan.maxUrls()){limited=true;continue;}
                            discovered.putIfAbsent(next,isJavaScript(node.url(),contentType)?"javascript":"crawl");
                            if(!queued.contains(next)){
                                if(node.depth()<plan.depth()&&queue.size()+roots.size()+archives.size()<PENDING_LIMIT&&queued.add(next))queue.addLast(new Node(next,node.depth()+1,0,"crawl-or-js",false));
                                else limited=true;
                            }
                        }
                    }
                    line(metadata,row);
                    events.accept(new DomainReconProcess.Event("http","native-gateway",result.decision().code().name(),node.url(),inputs.hosts().size(),response==null?"No response":"HTTP "+response.statusCode()));
                    if(result.dispatched())Thread.sleep(100);
                }
                for(var item:discovered.entrySet())line(urls,Map.of("kind","url","url",item.getKey(),"value",item.getKey(),"tool","native-chain","source",item.getValue(),"run_id",plan.runId()));
            }
            try(var all=writer(dir.resolve("sorted_urls.txt"));var js=writer(dir.resolve("javascript-candidates.txt"))){
                for(String value:new TreeSet<>(discovered.keySet())){all.write(value);all.newLine();if(isJavaScript(value,""))scripts.add(value);}
                for(String value:scripts){js.write(value);js.newLine();}
            }
            writeJson(dir.resolve("review-sources.json"),Map.of("schema_version",1,"workflow_run_id",plan.runId(),"sources",sources.stream().map(s->Map.of("id",s.id(),"kind",s.kind().name(),"name",s.name(),"text",s.text())).toList()));
            if(!state.equals("CANCELLED")&&(limited||truncated>0||errors>0||denied>0))state="PARTIAL";
            if(!state.equals("CANCELLED")&&responses==0)state="FAILED";
            detail="Native GET probe/crawl/JS phase; "+responses+" responses, "+denied+" policy denials. No external target tool or AI call was made.";
        } catch(Exception e) {
            if(e instanceof InterruptedException)Thread.currentThread().interrupt();
            if(Thread.currentThread().isInterrupted()||run.isCancelled()){run.cancel();state="CANCELLED";detail="Native phase cancelled; admitted in-flight work may finish before its transport timeout.";}
            else{state="FAILED";detail="Native phase failed; partial evidence may remain. Output directories are exclusive.";run.fail("native chain failed");}
        } finally {
            boolean interrupted=Thread.interrupted();
            try {
                if(Files.isDirectory(dir))writeJson(dir.resolve("summary.json"),Map.ofEntries(Map.entry("workflow_run_id",plan.runId()),Map.entry("native_run_id",run.id().toString()),Map.entry("state",state),Map.entry("dispatched",run.requestBudget().used()),Map.entry("responses",responses),Map.entry("denied",denied),Map.entry("urls",discovered.size()),Map.entry("limited",limited),Map.entry("time_limit_reached",timeLimit),Map.entry("truncated_bodies",truncated),Map.entry("omitted_evidence_records",omitted),Map.entry("limits",Map.of("global",run.requestLimits().global(),"host",run.requestLimits().perHost(),"endpoint",run.requestLimits().perEndpoint(),"probe",run.requestLimits().perProbe())),Map.entry("external_target_tools","BLOCKED")));
            }catch(IOException e){state="FAILED";detail="Native summary could not be saved.";}
            if(interrupted)Thread.currentThread().interrupt();
            if(state.equals("CANCELLED"))run.cancel();else if(state.equals("FAILED"))run.fail("native chain failed");else run.complete();
        }
        return new Outcome(state,run.requestBudget().used(),responses,denied,discovered.size(),detail);
    }

    static String canonical(String raw,String domain) {
        try {
            if(raw==null||raw.length()>8192)return null;URI u=URI.create(raw);String scheme=u.getScheme()==null?"":u.getScheme().toLowerCase(Locale.ROOT);
            if(!(scheme.equals("https")||scheme.equals("http"))||u.getRawUserInfo()!=null||u.getHost()==null||u.isOpaque())return null;
            String host=DomainReconProcess.domain(u.getHost());if(!(host.equals(domain)||host.endsWith("."+domain)))return null;
            int port=u.getPort();if(port==0||port>65535||port< -1)return null;
            String authority=host+(port==-1||(scheme.equals("https")&&port==443)||(scheme.equals("http")&&port==80)?"":":"+port);
            return scheme+"://"+authority+(u.getRawPath()==null||u.getRawPath().isEmpty()?"/":u.getRawPath())+(u.getRawQuery()==null?"":"?"+u.getRawQuery());
        }catch(IllegalArgumentException e){return null;}
    }
    private static String resolve(String base,String raw,String domain){try{return canonical(URI.create(base).resolve(raw.replace("&amp;","&").replace("\\/","/")).toString(),domain);}catch(IllegalArgumentException e){return null;}}
    static Set<String> extract(String base,String body,String domain){
        Set<String> found=new LinkedHashSet<>();var matcher=LINKS.matcher(body);
        while(found.size()<200&&matcher.find()){String value=matcher.group(1)!=null?matcher.group(1):matcher.group(2)!=null?matcher.group(2):matcher.group();String next=resolve(base,value,domain);if(next!=null)found.add(next);}return found;
    }
    private static boolean isJavaScript(String url,String type){String path=URI.create(url).getPath().toLowerCase(Locale.ROOT);return path.endsWith(".js")||path.endsWith(".mjs")||path.endsWith(".cjs")||type.toLowerCase(Locale.ROOT).contains("javascript");}
    private static List<String> fingerprints(HttpResponse response,String body){
        Set<String> signals=new LinkedHashSet<>();String powered=header(response,"X-Powered-By");if(!powered.isBlank())signals.add("X-Powered-By: "+powered);
        for(var entry:Map.of("__NEXT_DATA__","Next.js","ng-version=","Angular","data-reactroot","React","wp-content/","WordPress","data-v-","Vue").entrySet())if(body.contains(entry.getKey()))signals.add(entry.getValue());return List.copyOf(signals);
    }
    private static String header(HttpResponse response,String name){String value=response.headerValue(name);return value==null?"":shortText(value,2048);}
    private static String shortText(String s,int length){return s.length()>length?s.substring(0,length):s;}
    private static String prefix(HttpResponse response){return prefix(response.body(),BODY_LIMIT);}
    private static String prefix(burp.api.montoya.core.ByteArray body,int limit){int length=Math.min(limit,body.length());byte[] bytes=new byte[length];for(int i=0;i<length;i++)bytes[i]=body.getByte(i);return new String(bytes,StandardCharsets.UTF_8);}
    private static void line(BufferedWriter out,Object value)throws IOException{out.write(Json.write(value));out.newLine();out.flush();}
    static void createPrivateDirectory(Path path)throws IOException{try{Files.createDirectory(path,PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));}catch(UnsupportedOperationException e){Files.createDirectory(path);}}
    static BufferedWriter writer(Path path)throws IOException{
        java.nio.channels.SeekableByteChannel channel;
        try{channel=Files.newByteChannel(path,Set.of(StandardOpenOption.CREATE_NEW,StandardOpenOption.WRITE),PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));}
        catch(UnsupportedOperationException e){channel=Files.newByteChannel(path,Set.of(StandardOpenOption.CREATE_NEW,StandardOpenOption.WRITE));}
        return new BufferedWriter(new OutputStreamWriter(java.nio.channels.Channels.newOutputStream(channel),StandardCharsets.UTF_8));
    }
    static void writeJson(Path path,Object value)throws IOException{try(var out=writer(path)){line(out,value);}}
}
