package com.victor.reconloop;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

final class RegexHound {
    record Rule(
            String id,
            String name,
            String provider,
            String category,
            Severity severity,
            Confidence confidence,
            Pattern pattern,
            int capture,
            double minEntropy
    ) {}

    record Finding(
            Rule rule,
            String value,
            int start,
            int end,
            double entropy,
            String location,
            String url
    ) {}

    enum Severity { CRITICAL, HIGH, MEDIUM, LOW, INFO }
    enum Confidence { HIGH, MEDIUM, LOW }

    private static final Set<String> PLACEHOLDERS = Set.of(
            "example", "sample", "placeholder", "changeme", "change_me",
            "your_api_key", "your-api-key", "your_token", "your-token",
            "your_secret", "your-secret", "not-a-real", "dummy", "test123",
            "password123"
    );

    private static Pattern ci(String regex) {
        return Pattern.compile(regex, Pattern.CASE_INSENSITIVE | Pattern.MULTILINE);
    }

    private static Pattern cs(String regex) {
        return Pattern.compile(regex, Pattern.MULTILINE);
    }

    private static Pattern dotall(String regex) {
        return Pattern.compile(regex, Pattern.MULTILINE | Pattern.DOTALL);
    }

    private static Rule r(String id, String name, String provider, String category,
                          Severity severity, Confidence confidence, Pattern pattern) {
        return new Rule(id, name, provider, category, severity, confidence, pattern, 0, 0);
    }

    private static Rule r(String id, String name, String provider, String category,
                          Severity severity, Confidence confidence, Pattern pattern,
                          int capture, double minEntropy) {
        return new Rule(id, name, provider, category, severity, confidence, pattern, capture, minEntropy);
    }

    static final List<Rule> RULES = List.of(
            // Network / embedded credentials
            r("ipv4", "IPv4 address", "generic", "network", Severity.INFO, Confidence.HIGH,
                    cs("\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b")),
            r("ipv6", "IPv6 address", "generic", "network", Severity.INFO, Confidence.MEDIUM,
                    cs("(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![0-9A-Fa-f:])")),
            r("url-basic-auth", "URL with embedded credentials", "generic", "credential", Severity.CRITICAL, Confidence.HIGH,
                    ci("\\b[a-z][a-z0-9+.-]*://[^\\s/@:'\\\"<>]+:[^\\s/@'\\\"<>]+@[^\\s'\\\"<>]+")),
            r("database-uri-credentials", "Database URI with credentials", "generic", "credential", Severity.CRITICAL, Confidence.HIGH,
                    ci("\\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\\+srv)?|redis|rediss|amqp|amqps)://[^\\s/@:'\\\"<>]+:[^\\s/@'\\\"<>]+@[^\\s'\\\"<>]+")),

            // GitHub / GitLab
            r("github-fine-grained-pat", "GitHub fine-grained personal access token", "github", "secret", Severity.CRITICAL, Confidence.HIGH,
                    cs("\\bgithub_pat_[A-Za-z0-9_]{20,255}\\b")),
            r("github-classic-pat", "GitHub classic personal access token", "github", "secret", Severity.CRITICAL, Confidence.HIGH,
                    cs("\\bghp_[A-Za-z0-9]{20,255}\\b")),
            r("github-oauth-token", "GitHub OAuth access token", "github", "secret", Severity.CRITICAL, Confidence.HIGH,
                    cs("\\bgho_[A-Za-z0-9]{20,255}\\b")),
            r("github-app-user-token", "GitHub App user access token", "github", "secret", Severity.CRITICAL, Confidence.HIGH,
                    cs("\\bghu_[A-Za-z0-9]{20,255}\\b")),
            r("github-app-installation-token", "GitHub App installation access token", "github", "secret", Severity.CRITICAL, Confidence.HIGH,
                    cs("\\bghs_[A-Za-z0-9]{20,255}\\b")),
            r("github-refresh-token", "GitHub App refresh token", "github", "secret", Severity.CRITICAL, Confidence.HIGH,
                    cs("\\bghr_[A-Za-z0-9]{20,255}\\b")),
            r("gitlab-default-access-token", "GitLab access token", "gitlab", "secret", Severity.CRITICAL, Confidence.HIGH,
                    cs("\\bglpat-[A-Za-z0-9_-]{16,255}\\b")),
            r("gitlab-token-assignment", "GitLab token in assignment/header", "gitlab", "secret", Severity.CRITICAL, Confidence.MEDIUM,
                    ci("\\b(?:PRIVATE-TOKEN|JOB-TOKEN|DEPLOY-TOKEN|GITLAB_TOKEN|GITLAB_ACCESS_TOKEN)\\b\\s*(?:=|:)\\s*[\\\"']?([^\\s\\\"'`,;}{]{16,512})"), 1, 2.8),

            // AWS
            r("aws-access-key-id", "AWS access key ID", "aws", "identifier", Severity.HIGH, Confidence.HIGH,
                    cs("\\b(?:AKIA|ASIA)[A-Z0-9]{16}\\b")),
            r("aws-secret-access-key", "AWS secret access key", "aws", "secret", Severity.CRITICAL, Confidence.HIGH,
                    cs("\\b(?:AWS_SECRET_ACCESS_KEY|aws_secret_access_key|SecretAccessKey)\\b\\s*(?:=|:)\\s*[\\\"']?([A-Za-z0-9/+=]{40})"), 1, 3.5),
            r("aws-session-token", "AWS session token", "aws", "secret", Severity.CRITICAL, Confidence.HIGH,
                    cs("\\b(?:AWS_SESSION_TOKEN|aws_session_token|SessionToken)\\b\\s*(?:=|:)\\s*[\\\"']?([A-Za-z0-9/+=]{80,4096})"), 1, 3.5),

            // Google / Microsoft / Oracle
            r("google-api-key", "Google API key", "google", "secret", Severity.HIGH, Confidence.MEDIUM,
                    cs("\\bAIza[0-9A-Za-z_-]{35}\\b")),
            r("google-oauth-client-secret", "Google OAuth client secret", "google", "secret", Severity.CRITICAL, Confidence.MEDIUM,
                    cs("\\bGOCSPX-[A-Za-z0-9_-]{20,128}\\b")),
            r("google-service-account-private-key-id", "Google service-account private key ID", "google", "identifier", Severity.MEDIUM, Confidence.MEDIUM,
                    ci("[\\\"']private_key_id[\\\"']\\s*:\\s*[\\\"']([a-f0-9]{40})[\\\"']"), 1, 0),
            r("azure-storage-connection-string", "Azure Storage connection string with account key", "microsoft", "secret", Severity.CRITICAL, Confidence.HIGH,
                    ci("\\bDefaultEndpointsProtocol=https?;AccountName=[A-Za-z0-9-]{3,24};AccountKey=[A-Za-z0-9+/=]{40,256}(?:;EndpointSuffix=[A-Za-z0-9.-]+)?")),
            r("azure-storage-account-key", "Azure Storage account key", "microsoft", "secret", Severity.CRITICAL, Confidence.HIGH,
                    cs("\\bAccountKey\\s*=\\s*([A-Za-z0-9+/]{80,100}={0,2})"), 1, 4.0),
            r("azure-sas-signature", "Azure Shared Access Signature", "microsoft", "secret", Severity.CRITICAL, Confidence.HIGH,
                    ci("(?:[?&](?:sv|ss|srt|sp|se|st|spr|sig)=[^\\s&#\\\"']+){3,}")),
            r("azure-client-secret-assignment", "Microsoft Entra/Azure client secret assignment", "microsoft", "secret", Severity.CRITICAL, Confidence.MEDIUM,
                    ci("\\b(?:AZURE_CLIENT_SECRET|ARM_CLIENT_SECRET|client[_-]?secret)\\b\\s*(?:=|:)\\s*[\\\"']?([^\\s\\\"'`,;}{]{16,512})"), 1, 3.0),
            r("oci-auth-token-assignment", "Oracle Cloud auth token assignment", "oracle", "secret", Severity.CRITICAL, Confidence.MEDIUM,
                    ci("\\b(?:OCI_AUTH_TOKEN|ORACLE_AUTH_TOKEN|auth[_-]?token)\\b\\s*(?:=|:)\\s*[\\\"']?([^\\s\\\"'`,;}{]{16,512})"), 1, 3.0),
            r("oci-ocid", "Oracle Cloud Identifier (OCID)", "oracle", "identifier", Severity.INFO, Confidence.HIGH,
                    ci("\\bocid1\\.[a-z0-9_-]+\\.[a-z0-9_-]*\\.[a-z0-9_-]*\\.[a-z0-9._-]+\\b")),

            // Trello / Slack
            r("trello-api-key", "Trello API key in context", "trello", "secret", Severity.HIGH, Confidence.MEDIUM,
                    ci("\\b(?:TRELLO_API_KEY|trello[_-]?key|key)\\b\\s*(?:=|:)\\s*[\\\"']?([a-f0-9]{32})\\b"), 1, 0),
            r("trello-api-token", "Trello API token in context", "trello", "secret", Severity.CRITICAL, Confidence.MEDIUM,
                    ci("\\b(?:TRELLO_TOKEN|trello[_-]?token|token)\\b\\s*(?:=|:)\\s*[\\\"']?([a-f0-9]{40,128})\\b"), 1, 3.0),
            r("trello-url-credentials", "Trello API key/token in URL", "trello", "credential", Severity.CRITICAL, Confidence.HIGH,
                    ci("https?://api\\.trello\\.com/[^\\s\\\"']*[?&]key=([^&\\s\\\"']+)(?:[^\\s\\\"']*&token=[^&\\s\\\"']+)?")),
            r("slack-token", "Slack token", "slack", "secret", Severity.CRITICAL, Confidence.HIGH,
                    cs("\\bxox[a-zA-Z](?:[.-])[A-Za-z0-9.-]{10,512}\\b")),
            r("slack-webhook", "Slack incoming webhook URL", "slack", "secret", Severity.CRITICAL, Confidence.HIGH,
                    cs("https://hooks\\.slack\\.com/(?:services|workflows)/[A-Za-z0-9/_-]{20,512}")),
            r("slack-signing-secret", "Slack signing secret in context", "slack", "secret", Severity.CRITICAL, Confidence.MEDIUM,
                    ci("\\b(?:SLACK_SIGNING_SECRET|slack[_-]?signing[_-]?secret)\\b\\s*(?:=|:)\\s*[\\\"']?([a-f0-9]{32,128})\\b"), 1, 3.0),

            // Common providers
            r("stripe-live-secret-key", "Stripe live secret/restricted key", "stripe", "secret", Severity.CRITICAL, Confidence.HIGH,
                    cs("\\b(?:sk|rk)_live_[A-Za-z0-9]{16,255}\\b")),
            r("sendgrid-api-key", "SendGrid API key", "sendgrid", "secret", Severity.CRITICAL, Confidence.HIGH,
                    cs("\\bSG\\.[A-Za-z0-9_-]{16,64}\\.[A-Za-z0-9_-]{20,128}\\b")),
            r("npm-access-token", "npm access token", "npm", "secret", Severity.CRITICAL, Confidence.HIGH,
                    cs("\\bnpm_[A-Za-z0-9]{20,255}\\b")),
            r("pypi-api-token", "PyPI API token", "pypi", "secret", Severity.CRITICAL, Confidence.HIGH,
                    cs("\\bpypi-[A-Za-z0-9_-]{20,512}\\b")),
            r("huggingface-token", "Hugging Face access token", "huggingface", "secret", Severity.CRITICAL, Confidence.MEDIUM,
                    cs("\\bhf_[A-Za-z0-9]{20,255}\\b")),
            r("digitalocean-token", "DigitalOcean token", "digitalocean", "secret", Severity.CRITICAL, Confidence.MEDIUM,
                    cs("\\bdop_v1_[A-Fa-f0-9]{32,128}\\b")),
            r("shopify-access-token", "Shopify access token", "shopify", "secret", Severity.CRITICAL, Confidence.MEDIUM,
                    cs("\\bshpat_[A-Fa-f0-9]{20,128}\\b")),
            r("discord-webhook", "Discord webhook URL", "discord", "secret", Severity.CRITICAL, Confidence.HIGH,
                    cs("https://(?:canary\\.|ptb\\.)?discord(?:app)?\\.com/api/webhooks/\\d+/[A-Za-z0-9._-]{20,255}")),
            r("telegram-bot-token", "Telegram bot token", "telegram", "secret", Severity.CRITICAL, Confidence.MEDIUM,
                    cs("\\b\\d{6,12}:[A-Za-z0-9_-]{30,64}\\b")),
            r("twilio-auth-token", "Twilio auth token in context", "twilio", "secret", Severity.CRITICAL, Confidence.MEDIUM,
                    ci("\\b(?:TWILIO_AUTH_TOKEN|twilio[_-]?auth[_-]?token)\\b\\s*(?:=|:)\\s*[\\\"']?([A-Fa-f0-9]{32})\\b"), 1, 0),
            r("datadog-api-or-app-key", "Datadog API/application key in context", "datadog", "secret", Severity.CRITICAL, Confidence.MEDIUM,
                    ci("\\b(?:DD_API_KEY|DD_APP_KEY|DATADOG_API_KEY|DATADOG_APP_KEY)\\b\\s*(?:=|:)\\s*[\\\"']?([A-Fa-f0-9]{32,40})\\b"), 1, 0),

            // Generic cryptographic / auth material
            r("private-key-pem", "PEM private key", "generic", "private-key", Severity.CRITICAL, Confidence.HIGH,
                    dotall("-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----.*?-----END (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----")),
            r("pgp-private-key", "PGP private key block", "generic", "private-key", Severity.CRITICAL, Confidence.HIGH,
                    dotall("-----BEGIN PGP PRIVATE KEY BLOCK-----.*?-----END PGP PRIVATE KEY BLOCK-----")),
            r("jwt", "JSON Web Token", "generic", "token", Severity.HIGH, Confidence.MEDIUM,
                    cs("\\beyJ[A-Za-z0-9_-]{5,}\\.[A-Za-z0-9_-]{5,}\\.[A-Za-z0-9_-]{5,}\\b")),
            r("authorization-bearer", "Authorization Bearer token", "generic", "token", Severity.CRITICAL, Confidence.HIGH,
                    ci("\\bAuthorization\\s*:\\s*Bearer\\s+([A-Za-z0-9._~+/-]{16,4096}={0,2})"), 1, 2.8),
            r("authorization-basic", "Authorization Basic credential", "generic", "credential", Severity.CRITICAL, Confidence.HIGH,
                    ci("\\bAuthorization\\s*:\\s*Basic\\s+([A-Za-z0-9+/]{8,2048}={0,2})"), 1, 2.5),
            r("docker-config-auth", "Docker config auth value", "docker", "credential", Severity.CRITICAL, Confidence.HIGH,
                    cs("[\\\"']auth[\\\"']\\s*:\\s*[\\\"']([A-Za-z0-9+/]{8,2048}={0,2})[\\\"']"), 1, 2.5),
            r("generic-password-assignment", "Password assignment", "generic", "credential", Severity.HIGH, Confidence.LOW,
                    ci("\\b(?:password|passwd|pwd|passphrase|db_password|database_password)\\b\\s*(?:=|:|=>)\\s*[\\\"']?([^\\s\\\"'`,;}{]{8,512})"), 1, 2.3),
            r("generic-secret-assignment", "Generic secret/token/API-key assignment", "generic", "secret", Severity.HIGH, Confidence.LOW,
                    ci("\\b(?:api[_-]?key|apikey|api[_-]?secret|secret[_-]?key|client[_-]?secret|access[_-]?token|auth[_-]?token|refresh[_-]?token|private[_-]?token|service[_-]?token|bearer[_-]?token)\\b\\s*(?:=|:|=>)\\s*[\\\"']?([^\\s\\\"'`,;}{]{12,2048})"), 1, 2.8)
    );

    List<Finding> scan(String text, String location, String url, boolean includeInfo) {
        if (text == null || text.isEmpty()) return List.of();
        List<Finding> out = new ArrayList<>();
        Set<String> dedupe = new HashSet<>();

        for (Rule rule : RULES) {
            if (!includeInfo && rule.severity() == Severity.INFO) continue;
            Matcher matcher = rule.pattern().matcher(text);
            while (matcher.find()) {
                int group = rule.capture() > 0 && matcher.groupCount() >= rule.capture() ? rule.capture() : 0;
                String value = matcher.group(group);
                if (value == null || value.isBlank()) continue;
                if (isPlaceholder(value)) continue;
                if (rule.id().equals("ipv4") && !validIpv4(value)) continue;
                if (rule.id().equals("ipv6") && !validIpv6(value)) continue;

                double entropy = shannonEntropy(value);
                if (rule.minEntropy() > 0 && entropy < rule.minEntropy()) continue;

                int start = matcher.start(group);
                int end = matcher.end(group);
                String key = rule.id() + "\0" + value + "\0" + location + "\0" + url;
                if (!dedupe.add(key)) continue;
                out.add(new Finding(rule, value, start, end, entropy, location, url));
            }
        }
        return out;
    }

    /** Extracts syntactically valid IPv4/IPv6 literals from arbitrary text (independent of severity). */
    static List<String> extractIps(String text) {
        if (text == null || text.isEmpty()) return List.of();
        LinkedHashSet<String> out = new LinkedHashSet<>();
        for (Rule rule : RULES) {
            boolean v4 = rule.id().equals("ipv4");
            boolean v6 = rule.id().equals("ipv6");
            if (!v4 && !v6) continue;
            Matcher matcher = rule.pattern().matcher(text);
            while (matcher.find()) {
                String value = matcher.group();
                if (v4 && !validIpv4(value)) continue;
                if (v6 && !validIpv6(value)) continue;
                out.add(value);
            }
        }
        return new ArrayList<>(out);
    }

    static String redact(String value) {
        if (value == null) return "";
        if (value.length() <= 10) return "***";
        return value.substring(0, 5) + "…" + value.substring(value.length() - 4);
    }

    private static boolean isPlaceholder(String value) {
        String lower = value.toLowerCase(Locale.ROOT);
        return PLACEHOLDERS.stream().anyMatch(lower::contains);
    }

    private static double shannonEntropy(String value) {
        if (value == null || value.isEmpty()) return 0;
        Map<Character, Integer> counts = new HashMap<>();
        for (char c : value.toCharArray()) counts.merge(c, 1, Integer::sum);
        double entropy = 0;
        for (int count : counts.values()) {
            double p = (double) count / value.length();
            entropy -= p * (Math.log(p) / Math.log(2));
        }
        return entropy;
    }

    private static boolean validIpv4(String value) {
        String[] parts = value.split("\\.");
        if (parts.length != 4) return false;
        for (String part : parts) {
            if (!part.matches("\\d{1,3}")) return false;
            if (part.length() > 1 && part.startsWith("0")) return false;
            int n;
            try { n = Integer.parseInt(part); } catch (NumberFormatException e) { return false; }
            if (n < 0 || n > 255) return false;
        }
        return true;
    }

    private static boolean validIpv6(String value) {
        try {
            return java.net.InetAddress.getByName(value).getHostAddress().contains(":");
        } catch (Exception e) {
            return false;
        }
    }
}
