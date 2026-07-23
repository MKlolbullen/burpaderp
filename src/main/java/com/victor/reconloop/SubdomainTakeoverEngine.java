package com.victor.reconloop;

import java.util.List;

/**
 * Subdomain-takeover fingerprinting: matches a fetched host's response body against the
 * "unclaimed resource" pages that hosting providers serve for dangling CNAMEs. A match means the
 * DNS record points at a backend that no longer exists and could be (re)claimed by an attacker to
 * serve content on the subdomain. Signatures are a curated subset of the community
 * can-i-take-over-xyz list.
 */
final class SubdomainTakeoverEngine {

    private record Fingerprint(String service, String signature) {}

    private static final List<Fingerprint> FINGERPRINTS = List.of(
            new Fingerprint("GitHub Pages", "There isn't a GitHub Pages site here"),
            new Fingerprint("AWS/S3", "The specified bucket does not exist"),
            new Fingerprint("AWS/S3", "NoSuchBucket"),
            new Fingerprint("Heroku", "herokucdn.com/error-pages/no-such-app.html"),
            new Fingerprint("Heroku", "No such app"),
            new Fingerprint("Fastly", "Fastly error: unknown domain"),
            new Fingerprint("Shopify", "Sorry, this shop is currently unavailable"),
            new Fingerprint("Surge.sh", "project not found"),
            new Fingerprint("Bitbucket", "Repository not found"),
            new Fingerprint("Zendesk", "Help Center Closed"),
            new Fingerprint("Netlify", "Not Found - Request ID"),
            new Fingerprint("Pantheon", "The gods are wise, but do not know of the site which you seek"),
            new Fingerprint("Tumblr", "Whatever you were looking for doesn't currently exist at this address"),
            new Fingerprint("WordPress.com", "Do you want to register"),
            new Fingerprint("Ghost", "The thing you were looking for is no longer here"),
            new Fingerprint("Unbounce", "The requested URL was not found on this server"),
            new Fingerprint("Read the Docs", "unknown to Read the Docs"),
            new Fingerprint("Help Scout", "No settings were found for this company"),
            new Fingerprint("Cargo", "404 Not Found. If you're the owner"),
            new Fingerprint("Intercom", "Uh oh. That page doesn't exist"),
            new Fingerprint("Webflow", "The page you are looking for doesn't exist or has been moved")
    );

    /** Returns the matched service name if the body looks like an unclaimed-resource page, else null. */
    static String match(String body) {
        if (body == null || body.isBlank()) return null;
        for (Fingerprint fingerprint : FINGERPRINTS) {
            if (body.contains(fingerprint.signature())) return fingerprint.service();
        }
        return null;
    }
}
