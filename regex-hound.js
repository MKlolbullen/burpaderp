'use strict';

/**
 * RegexHound - dependency-free JavaScript regex/signature library for finding
 * secrets, tokens, credentials, IPs and security-relevant artifacts in text.
 *
 * Intended for authorized source-code / response / artifact scanning.
 * CommonJS, Node >= 18 recommended. The core scanner has no Node-only APIs.
 */

const RX_FLAGS = 'g';

function rule({
  id,
  name,
  provider = 'generic',
  category = 'secret',
  severity = 'high',
  confidence = 'medium',
  regex,
  capture = 0,
  tags = [],
  minEntropy = 0,
  validate = null,
  description = '',
}) {
  return Object.freeze({
    id,
    name,
    provider,
    category,
    severity,
    confidence,
    regex,
    capture,
    tags: Object.freeze(tags),
    minEntropy,
    validate,
    description,
  });
}

function isValidIPv4(value) {
  const parts = value.split('.');
  return parts.length === 4 && parts.every((part) => {
    if (!/^\d{1,3}$/.test(part)) return false;
    if (part.length > 1 && part.startsWith('0')) return false;
    const n = Number(part);
    return n >= 0 && n <= 255;
  });
}

// A pragmatic IPv6 validator. Regex finds candidates; this validates structure,
// including :: compression and IPv4-mapped tails.
function isValidIPv6(value) {
  if (!value || !value.includes(':') || !/[0-9a-f]/i.test(value)) return false;

  let input = value.toLowerCase();
  if (input.includes('%')) input = input.split('%', 1)[0]; // strip zone id

  if ((input.match(/::/g) || []).length > 1) return false;

  const hasCompression = input.includes('::');
  let [leftRaw, rightRaw = ''] = hasCompression ? input.split('::') : [input, ''];
  const left = leftRaw ? leftRaw.split(':') : [];
  const right = rightRaw ? rightRaw.split(':') : [];

  const expandIpv4Tail = (parts) => {
    if (!parts.length || !parts.at(-1).includes('.')) return parts;
    const tail = parts.at(-1);
    if (!isValidIPv4(tail)) return null;
    return [...parts.slice(0, -1), 'ffff', 'ffff']; // counts as two hextets
  };

  const l = expandIpv4Tail(left);
  const r = expandIpv4Tail(right);
  if (!l || !r) return false;

  const validHextet = (part) => /^[0-9a-f]{1,4}$/.test(part);
  if (![...l, ...r].every(validHextet)) return false;

  const count = l.length + r.length;
  return hasCompression ? count < 8 : count === 8;
}

function isPrivateIPv4(ip) {
  if (!isValidIPv4(ip)) return false;
  const [a, b] = ip.split('.').map(Number);
  return (
    a === 10 ||
    a === 127 ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168)
  );
}

const PATTERNS = Object.freeze([
  // -------------------------------------------------------------------------
  // Network / recon artifacts
  // -------------------------------------------------------------------------
  rule({
    id: 'ipv4',
    name: 'IPv4 address',
    category: 'network',
    severity: 'info',
    confidence: 'high',
    regex: /\b(?:\d{1,3}\.){3}\d{1,3}\b/g,
    validate: isValidIPv4,
    tags: ['ip', 'network', 'recon'],
  }),
  rule({
    id: 'ipv6',
    name: 'IPv6 address',
    category: 'network',
    severity: 'info',
    confidence: 'medium',
    // Candidate matcher; structural correctness is handled by isValidIPv6().
    regex: /(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![0-9A-Fa-f:])/g,
    validate: isValidIPv6,
    tags: ['ip', 'network', 'recon'],
  }),
  rule({
    id: 'url-basic-auth',
    name: 'URL with embedded credentials',
    category: 'credential',
    severity: 'critical',
    confidence: 'high',
    regex: /\b[a-z][a-z0-9+.-]*:\/\/[^\s/@:'"<>]+:[^\s/@'"<>]+@[^\s'"<>]+/gi,
    tags: ['url', 'password', 'basic-auth'],
  }),
  rule({
    id: 'database-uri-credentials',
    name: 'Database URI with credentials',
    category: 'credential',
    severity: 'critical',
    confidence: 'high',
    regex: /\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqp|amqps):\/\/[^\s/@:'"<>]+:[^\s/@'"<>]+@[^\s'"<>]+/gi,
    tags: ['database', 'uri', 'password'],
  }),

  // -------------------------------------------------------------------------
  // GitHub
  // -------------------------------------------------------------------------
  rule({
    id: 'github-fine-grained-pat',
    name: 'GitHub fine-grained personal access token',
    provider: 'github',
    severity: 'critical',
    confidence: 'high',
    regex: /\bgithub_pat_[A-Za-z0-9_]{20,255}\b/g,
    tags: ['github', 'pat'],
  }),
  rule({
    id: 'github-classic-pat',
    name: 'GitHub classic personal access token',
    provider: 'github',
    severity: 'critical',
    confidence: 'high',
    regex: /\bghp_[A-Za-z0-9]{20,255}\b/g,
    tags: ['github', 'pat'],
  }),
  rule({
    id: 'github-oauth-token',
    name: 'GitHub OAuth access token',
    provider: 'github',
    severity: 'critical',
    confidence: 'high',
    regex: /\bgho_[A-Za-z0-9]{20,255}\b/g,
    tags: ['github', 'oauth'],
  }),
  rule({
    id: 'github-app-user-token',
    name: 'GitHub App user access token',
    provider: 'github',
    severity: 'critical',
    confidence: 'high',
    regex: /\bghu_[A-Za-z0-9]{20,255}\b/g,
    tags: ['github', 'app-token'],
  }),
  rule({
    id: 'github-app-installation-token',
    name: 'GitHub App installation access token',
    provider: 'github',
    severity: 'critical',
    confidence: 'high',
    regex: /\bghs_[A-Za-z0-9]{20,255}\b/g,
    tags: ['github', 'app-token'],
  }),
  rule({
    id: 'github-refresh-token',
    name: 'GitHub App refresh token',
    provider: 'github',
    severity: 'critical',
    confidence: 'high',
    regex: /\bghr_[A-Za-z0-9]{20,255}\b/g,
    tags: ['github', 'refresh-token'],
  }),

  // -------------------------------------------------------------------------
  // GitLab
  // -------------------------------------------------------------------------
  rule({
    id: 'gitlab-default-access-token',
    name: 'GitLab access token (default prefix)',
    provider: 'gitlab',
    severity: 'critical',
    confidence: 'high',
    regex: /\bglpat-[A-Za-z0-9_-]{16,255}\b/g,
    tags: ['gitlab', 'pat', 'access-token'],
    description: 'GitLab instances may configure a custom access-token prefix.',
  }),
  rule({
    id: 'gitlab-token-assignment',
    name: 'GitLab token in assignment/header',
    provider: 'gitlab',
    severity: 'critical',
    confidence: 'medium',
    regex: /\b(?:PRIVATE-TOKEN|JOB-TOKEN|DEPLOY-TOKEN|GITLAB_TOKEN|GITLAB_ACCESS_TOKEN)\b\s*(?:=|:)\s*["']?([^\s"'`,;}{]{16,512})/gi,
    capture: 1,
    minEntropy: 2.8,
    tags: ['gitlab', 'contextual'],
  }),

  // -------------------------------------------------------------------------
  // AWS
  // -------------------------------------------------------------------------
  rule({
    id: 'aws-access-key-id',
    name: 'AWS access key ID',
    provider: 'aws',
    category: 'identifier',
    severity: 'high',
    confidence: 'high',
    regex: /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g,
    tags: ['aws', 'iam', 'access-key'],
  }),
  rule({
    id: 'aws-secret-access-key',
    name: 'AWS secret access key',
    provider: 'aws',
    severity: 'critical',
    confidence: 'high',
    regex: /\b(?:AWS_SECRET_ACCESS_KEY|aws_secret_access_key|SecretAccessKey)\b\s*(?:=|:)\s*["']?([A-Za-z0-9/+=]{40})/g,
    capture: 1,
    minEntropy: 3.5,
    tags: ['aws', 'iam', 'secret-key'],
  }),
  rule({
    id: 'aws-session-token',
    name: 'AWS session token',
    provider: 'aws',
    severity: 'critical',
    confidence: 'high',
    regex: /\b(?:AWS_SESSION_TOKEN|aws_session_token|SessionToken)\b\s*(?:=|:)\s*["']?([A-Za-z0-9/+=]{80,4096})/g,
    capture: 1,
    minEntropy: 3.5,
    tags: ['aws', 'sts', 'session-token'],
  }),

  // -------------------------------------------------------------------------
  // Google / GCP
  // -------------------------------------------------------------------------
  rule({
    id: 'google-api-key',
    name: 'Google API key',
    provider: 'google',
    severity: 'high',
    confidence: 'medium',
    regex: /\bAIza[0-9A-Za-z_-]{35}\b/g,
    tags: ['google', 'gcp', 'api-key', 'heuristic'],
  }),
  rule({
    id: 'google-oauth-client-secret',
    name: 'Google OAuth client secret',
    provider: 'google',
    severity: 'critical',
    confidence: 'medium',
    regex: /\bGOCSPX-[A-Za-z0-9_-]{20,128}\b/g,
    tags: ['google', 'oauth', 'client-secret', 'heuristic'],
  }),
  rule({
    id: 'google-service-account-private-key-id',
    name: 'Google service-account private key ID',
    provider: 'google',
    category: 'identifier',
    severity: 'medium',
    confidence: 'medium',
    regex: /["']private_key_id["']\s*:\s*["']([a-f0-9]{40})["']/gi,
    capture: 1,
    tags: ['google', 'gcp', 'service-account'],
  }),

  // -------------------------------------------------------------------------
  // Microsoft / Azure
  // -------------------------------------------------------------------------
  rule({
    id: 'azure-storage-connection-string',
    name: 'Azure Storage connection string with account key',
    provider: 'microsoft',
    severity: 'critical',
    confidence: 'high',
    regex: /\bDefaultEndpointsProtocol=https?;AccountName=[A-Za-z0-9-]{3,24};AccountKey=[A-Za-z0-9+/=]{40,256}(?:;EndpointSuffix=[A-Za-z0-9.-]+)?/gi,
    tags: ['azure', 'storage', 'connection-string'],
  }),
  rule({
    id: 'azure-storage-account-key',
    name: 'Azure Storage account key',
    provider: 'microsoft',
    severity: 'critical',
    confidence: 'high',
    regex: /\bAccountKey\s*=\s*([A-Za-z0-9+/]{80,100}={0,2})/g,
    capture: 1,
    minEntropy: 4,
    tags: ['azure', 'storage', 'account-key'],
  }),
  rule({
    id: 'azure-sas-signature',
    name: 'Azure Shared Access Signature',
    provider: 'microsoft',
    severity: 'critical',
    confidence: 'high',
    regex: /(?:[?&](?:sv|ss|srt|sp|se|st|spr|sig)=[^\s&#"']+){3,}/gi,
    tags: ['azure', 'storage', 'sas'],
  }),
  rule({
    id: 'azure-client-secret-assignment',
    name: 'Microsoft Entra/Azure client secret assignment',
    provider: 'microsoft',
    severity: 'critical',
    confidence: 'medium',
    regex: /\b(?:AZURE_CLIENT_SECRET|ARM_CLIENT_SECRET|client[_-]?secret)\b\s*(?:=|:)\s*["']?([^\s"'`,;}{]{16,512})/gi,
    capture: 1,
    minEntropy: 3,
    tags: ['azure', 'entra', 'client-secret', 'contextual'],
  }),

  // -------------------------------------------------------------------------
  // Oracle / OCI
  // -------------------------------------------------------------------------
  rule({
    id: 'oci-auth-token-assignment',
    name: 'Oracle Cloud auth token assignment',
    provider: 'oracle',
    severity: 'critical',
    confidence: 'medium',
    regex: /\b(?:OCI_AUTH_TOKEN|ORACLE_AUTH_TOKEN|auth[_-]?token)\b\s*(?:=|:)\s*["']?([^\s"'`,;}{]{16,512})/gi,
    capture: 1,
    minEntropy: 3,
    tags: ['oracle', 'oci', 'auth-token', 'contextual'],
  }),
  rule({
    id: 'oci-ocid',
    name: 'Oracle Cloud Identifier (OCID)',
    provider: 'oracle',
    category: 'identifier',
    severity: 'info',
    confidence: 'high',
    regex: /\bocid1\.[a-z0-9_-]+\.[a-z0-9_-]*\.[a-z0-9_-]*\.[a-z0-9._-]+\b/gi,
    tags: ['oracle', 'oci', 'ocid'],
  }),

  // -------------------------------------------------------------------------
  // Trello / Atlassian
  // -------------------------------------------------------------------------
  rule({
    id: 'trello-api-key',
    name: 'Trello API key in context',
    provider: 'trello',
    severity: 'high',
    confidence: 'medium',
    regex: /\b(?:TRELLO_API_KEY|trello[_-]?key|key)\b\s*(?:=|:)\s*["']?([a-f0-9]{32})\b/gi,
    capture: 1,
    tags: ['trello', 'api-key', 'contextual'],
  }),
  rule({
    id: 'trello-api-token',
    name: 'Trello API token in context',
    provider: 'trello',
    severity: 'critical',
    confidence: 'medium',
    regex: /\b(?:TRELLO_TOKEN|trello[_-]?token|token)\b\s*(?:=|:)\s*["']?([a-f0-9]{40,128})\b/gi,
    capture: 1,
    minEntropy: 3,
    tags: ['trello', 'api-token', 'contextual'],
  }),
  rule({
    id: 'trello-url-credentials',
    name: 'Trello API key/token in URL',
    provider: 'trello',
    severity: 'critical',
    confidence: 'high',
    regex: /https?:\/\/api\.trello\.com\/[^\s"']*[?&]key=([^&\s"']+)(?:[^\s"']*&token=[^&\s"']+)?/gi,
    tags: ['trello', 'url', 'credential'],
  }),

  // -------------------------------------------------------------------------
  // Slack
  // -------------------------------------------------------------------------
  rule({
    id: 'slack-token',
    name: 'Slack token',
    provider: 'slack',
    severity: 'critical',
    confidence: 'high',
    regex: /\bxox[a-zA-Z](?:[.-])[A-Za-z0-9.-]{10,512}\b/g,
    tags: ['slack', 'token'],
  }),
  rule({
    id: 'slack-webhook',
    name: 'Slack incoming webhook URL',
    provider: 'slack',
    severity: 'critical',
    confidence: 'high',
    regex: /https:\/\/hooks\.slack\.com\/(?:services|workflows)\/[A-Za-z0-9/_-]{20,512}/g,
    tags: ['slack', 'webhook'],
  }),
  rule({
    id: 'slack-signing-secret',
    name: 'Slack signing secret in context',
    provider: 'slack',
    severity: 'critical',
    confidence: 'medium',
    regex: /\b(?:SLACK_SIGNING_SECRET|slack[_-]?signing[_-]?secret)\b\s*(?:=|:)\s*["']?([a-f0-9]{32,128})\b/gi,
    capture: 1,
    minEntropy: 3,
    tags: ['slack', 'signing-secret', 'contextual'],
  }),

  // -------------------------------------------------------------------------
  // Common third-party providers
  // -------------------------------------------------------------------------
  rule({
    id: 'stripe-live-secret-key',
    name: 'Stripe live secret/restricted key',
    provider: 'stripe',
    severity: 'critical',
    confidence: 'high',
    regex: /\b(?:sk|rk)_live_[A-Za-z0-9]{16,255}\b/g,
    tags: ['stripe', 'api-key'],
  }),
  rule({
    id: 'sendgrid-api-key',
    name: 'SendGrid API key',
    provider: 'sendgrid',
    severity: 'critical',
    confidence: 'high',
    regex: /\bSG\.[A-Za-z0-9_-]{16,64}\.[A-Za-z0-9_-]{20,128}\b/g,
    tags: ['sendgrid', 'api-key'],
  }),
  rule({
    id: 'npm-access-token',
    name: 'npm access token',
    provider: 'npm',
    severity: 'critical',
    confidence: 'high',
    regex: /\bnpm_[A-Za-z0-9]{20,255}\b/g,
    tags: ['npm', 'token'],
  }),
  rule({
    id: 'pypi-api-token',
    name: 'PyPI API token',
    provider: 'pypi',
    severity: 'critical',
    confidence: 'high',
    regex: /\bpypi-[A-Za-z0-9_-]{20,512}\b/g,
    tags: ['pypi', 'token'],
  }),
  rule({
    id: 'huggingface-token',
    name: 'Hugging Face access token',
    provider: 'huggingface',
    severity: 'critical',
    confidence: 'medium',
    regex: /\bhf_[A-Za-z0-9]{20,255}\b/g,
    tags: ['huggingface', 'token'],
  }),
  rule({
    id: 'digitalocean-token',
    name: 'DigitalOcean token',
    provider: 'digitalocean',
    severity: 'critical',
    confidence: 'medium',
    regex: /\bdop_v1_[A-Fa-f0-9]{32,128}\b/g,
    tags: ['digitalocean', 'token'],
  }),
  rule({
    id: 'shopify-access-token',
    name: 'Shopify access token',
    provider: 'shopify',
    severity: 'critical',
    confidence: 'medium',
    regex: /\bshpat_[A-Fa-f0-9]{20,128}\b/g,
    tags: ['shopify', 'token'],
  }),
  rule({
    id: 'discord-webhook',
    name: 'Discord webhook URL',
    provider: 'discord',
    severity: 'critical',
    confidence: 'high',
    regex: /https:\/\/(?:canary\.|ptb\.)?discord(?:app)?\.com\/api\/webhooks\/\d+\/[A-Za-z0-9._-]{20,255}/g,
    tags: ['discord', 'webhook'],
  }),
  rule({
    id: 'telegram-bot-token',
    name: 'Telegram bot token',
    provider: 'telegram',
    severity: 'critical',
    confidence: 'medium',
    regex: /\b\d{6,12}:[A-Za-z0-9_-]{30,64}\b/g,
    tags: ['telegram', 'bot-token'],
  }),
  rule({
    id: 'twilio-auth-token',
    name: 'Twilio auth token in context',
    provider: 'twilio',
    severity: 'critical',
    confidence: 'medium',
    regex: /\b(?:TWILIO_AUTH_TOKEN|twilio[_-]?auth[_-]?token)\b\s*(?:=|:)\s*["']?([A-Fa-f0-9]{32})\b/gi,
    capture: 1,
    tags: ['twilio', 'auth-token', 'contextual'],
  }),
  rule({
    id: 'datadog-api-or-app-key',
    name: 'Datadog API/application key in context',
    provider: 'datadog',
    severity: 'critical',
    confidence: 'medium',
    regex: /\b(?:DD_API_KEY|DD_APP_KEY|DATADOG_API_KEY|DATADOG_APP_KEY)\b\s*(?:=|:)\s*["']?([A-Fa-f0-9]{32,40})\b/gi,
    capture: 1,
    tags: ['datadog', 'api-key', 'contextual'],
  }),

  // -------------------------------------------------------------------------
  // Generic cryptographic / authentication material
  // -------------------------------------------------------------------------
  rule({
    id: 'private-key-pem',
    name: 'PEM private key',
    category: 'private-key',
    severity: 'critical',
    confidence: 'high',
    regex: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----[\s\S]{20,}?-----END (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----/g,
    tags: ['private-key', 'pem'],
  }),
  rule({
    id: 'pgp-private-key',
    name: 'PGP private key block',
    category: 'private-key',
    severity: 'critical',
    confidence: 'high',
    regex: /-----BEGIN PGP PRIVATE KEY BLOCK-----[\s\S]{20,}?-----END PGP PRIVATE KEY BLOCK-----/g,
    tags: ['private-key', 'pgp'],
  }),
  rule({
    id: 'jwt',
    name: 'JSON Web Token',
    category: 'token',
    severity: 'high',
    confidence: 'medium',
    regex: /\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b/g,
    tags: ['jwt', 'bearer-token'],
  }),
  rule({
    id: 'authorization-bearer',
    name: 'Authorization Bearer token',
    category: 'token',
    severity: 'critical',
    confidence: 'high',
    regex: /\bAuthorization\s*:\s*Bearer\s+([A-Za-z0-9._~+\/-]{16,4096}={0,2})/gi,
    capture: 1,
    minEntropy: 2.8,
    tags: ['authorization', 'bearer'],
  }),
  rule({
    id: 'authorization-basic',
    name: 'Authorization Basic credential',
    category: 'credential',
    severity: 'critical',
    confidence: 'high',
    regex: /\bAuthorization\s*:\s*Basic\s+([A-Za-z0-9+/]{8,2048}={0,2})/gi,
    capture: 1,
    minEntropy: 2.5,
    tags: ['authorization', 'basic-auth'],
  }),
  rule({
    id: 'docker-config-auth',
    name: 'Docker config auth value',
    category: 'credential',
    severity: 'critical',
    confidence: 'high',
    regex: /["']auth["']\s*:\s*["']([A-Za-z0-9+/]{8,2048}={0,2})["']/g,
    capture: 1,
    minEntropy: 2.5,
    tags: ['docker', 'registry', 'basic-auth'],
  }),
  rule({
    id: 'generic-password-assignment',
    name: 'Password assignment',
    category: 'credential',
    severity: 'high',
    confidence: 'low',
    regex: /\b(?:password|passwd|pwd|passphrase|db_password|database_password)\b\s*(?:=|:|=>)\s*["']?([^\s"'`,;}{]{8,512})/gi,
    capture: 1,
    minEntropy: 2.3,
    tags: ['password', 'generic', 'contextual'],
  }),
  rule({
    id: 'generic-secret-assignment',
    name: 'Generic secret/token/API-key assignment',
    category: 'secret',
    severity: 'high',
    confidence: 'low',
    regex: /\b(?:api[_-]?key|apikey|api[_-]?secret|secret[_-]?key|client[_-]?secret|access[_-]?token|auth[_-]?token|refresh[_-]?token|private[_-]?token|service[_-]?token|bearer[_-]?token)\b\s*(?:=|:|=>)\s*["']?([^\s"'`,;}{]{12,2048})/gi,
    capture: 1,
    minEntropy: 2.8,
    tags: ['secret', 'token', 'api-key', 'generic', 'contextual'],
  }),
]);

const DEFAULT_PLACEHOLDERS = Object.freeze([
  'example',
  'sample',
  'placeholder',
  'changeme',
  'change_me',
  'your_api_key',
  'your-api-key',
  'your_token',
  'your-token',
  'your_secret',
  'your-secret',
  'not-a-real',
  'dummy',
  'test123',
  'password123',
]);

function shannonEntropy(input) {
  const value = String(input ?? '');
  if (!value.length) return 0;

  const counts = new Map();
  for (const char of value) counts.set(char, (counts.get(char) || 0) + 1);

  let entropy = 0;
  for (const count of counts.values()) {
    const p = count / value.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

function lineColumn(text, index) {
  let line = 1;
  let column = 1;
  for (let i = 0; i < index; i += 1) {
    if (text.charCodeAt(i) === 10) {
      line += 1;
      column = 1;
    } else {
      column += 1;
    }
  }
  return { line, column };
}

function redact(value, visible = 4) {
  const s = String(value);
  if (s.includes('-----BEGIN ') && s.includes('PRIVATE KEY')) {
    const first = s.split(/\r?\n/, 1)[0];
    return `${first}\n[REDACTED PRIVATE KEY]`;
  }
  if (s.length <= visible * 2 + 3) return '*'.repeat(Math.min(s.length, 12));
  return `${s.slice(0, visible)}…${s.slice(-visible)}`;
}

function looksLikePlaceholder(value, placeholders = DEFAULT_PLACEHOLDERS) {
  const normalized = String(value).trim().toLowerCase();
  if (!normalized) return true;
  if (/^(?:x+|\*+|0+|1+|-+|_+)$/.test(normalized)) return true;
  if (/^(?:\$\{[^}]+\}|\{\{[^}]+\}\}|<[^>]+>|process\.env\.[a-z0-9_]+)$/i.test(normalized)) {
    return true;
  }
  return placeholders.some((placeholder) => normalized.includes(placeholder));
}

function cloneRegex(regex) {
  const flags = regex.flags.includes('g') ? regex.flags : `${regex.flags}${RX_FLAGS}`;
  return new RegExp(regex.source, flags);
}

function selectPatterns({ providers, categories, tags, ids } = {}) {
  const providerSet = providers ? new Set(providers.map((v) => v.toLowerCase())) : null;
  const categorySet = categories ? new Set(categories.map((v) => v.toLowerCase())) : null;
  const tagSet = tags ? new Set(tags.map((v) => v.toLowerCase())) : null;
  const idSet = ids ? new Set(ids) : null;

  return PATTERNS.filter((p) => {
    if (providerSet && !providerSet.has(p.provider.toLowerCase())) return false;
    if (categorySet && !categorySet.has(p.category.toLowerCase())) return false;
    if (idSet && !idSet.has(p.id)) return false;
    if (tagSet && !p.tags.some((tag) => tagSet.has(tag.toLowerCase()))) return false;
    return true;
  });
}

/**
 * Scan text and return structured findings.
 *
 * Options:
 *   reveal: false       -> return full matched secret in `value` when true
 *   context: 80         -> chars of surrounding context
 *   providers: [...]    -> filter providers
 *   categories: [...]   -> filter categories
 *   tags: [...]         -> require at least one matching tag
 *   ids: [...]          -> exact rule IDs
 *   includePlaceholders -> include obvious examples/placeholders
 *   dedupe: true
 */
function scan(text, options = {}) {
  if (typeof text !== 'string') throw new TypeError('scan(text): text must be a string');

  const {
    reveal = false,
    context = 80,
    includePlaceholders = false,
    placeholders = DEFAULT_PLACEHOLDERS,
    dedupe = true,
    suppressGenericOverlaps = true,
  } = options;

  const selected = selectPatterns(options);
  const findings = [];
  const seen = new Set();

  for (const p of selected) {
    const regex = cloneRegex(p.regex);
    let match;

    while ((match = regex.exec(text)) !== null) {
      const value = match[p.capture] ?? match[0];
      if (!value) continue;

      const relative = match[0].indexOf(value);
      const start = match.index + Math.max(0, relative);
      const end = start + value.length;

      if (p.validate && !p.validate(value)) continue;
      if (!includePlaceholders && p.category !== 'network' && looksLikePlaceholder(value, placeholders)) continue;

      const entropy = shannonEntropy(value);
      if (p.minEntropy && entropy < p.minEntropy) continue;

      const key = `${p.id}\u0000${start}\u0000${value}`;
      if (dedupe && seen.has(key)) continue;
      seen.add(key);

      const { line, column } = lineColumn(text, start);
      const before = Math.max(0, start - context);
      const after = Math.min(text.length, end + context);

      const displayValue = reveal || p.category === 'network' ? value : redact(value);

      const finding = {
        id: p.id,
        name: p.name,
        provider: p.provider,
        category: p.category,
        severity: p.severity,
        confidence: p.confidence,
        tags: [...p.tags],
        value: displayValue,
        length: value.length,
        entropy: Number(entropy.toFixed(3)),
        index: start,
        end,
        line,
        column,
        context: `${text.slice(before, start)}${displayValue}${text.slice(end, after)}`,
      };

      if (p.id === 'ipv4') finding.private = isPrivateIPv4(value);
      findings.push(finding);

      // Protect against zero-length regex matches.
      if (match[0].length === 0) regex.lastIndex += 1;
    }
  }

  const sorted = findings.sort((a, b) => a.index - b.index || a.id.localeCompare(b.id));

  if (!suppressGenericOverlaps) return sorted;

  return sorted.filter((finding) => {
    if (finding.provider !== 'generic' || finding.confidence !== 'low') return true;
    return !sorted.some((other) => (
      other !== finding &&
      other.index === finding.index &&
      other.end === finding.end &&
      other.provider !== 'generic' &&
      other.confidence !== 'low'
    ));
  });
}

function groupFindings(findings, key = 'provider') {
  return findings.reduce((acc, finding) => {
    const bucket = finding[key] ?? 'unknown';
    (acc[bucket] ||= []).push(finding);
    return acc;
  }, {});
}

/**
 * Export selected patterns in the familiar gf JSON shape.
 * Note: validators and entropy gates cannot be represented in gf JSON.
 */
function toGfJson(options = {}) {
  const selected = selectPatterns(options);
  return {
    flags: '-E',
    patterns: selected.map((p) => p.regex.source),
  };
}

function getPattern(id) {
  return PATTERNS.find((p) => p.id === id) || null;
}

module.exports = {
  PATTERNS,
  scan,
  groupFindings,
  selectPatterns,
  getPattern,
  toGfJson,
  shannonEntropy,
  redact,
  isValidIPv4,
  isValidIPv6,
  isPrivateIPv4,
};

// Minimal CLI: node regex-hound.js file1.js file2.txt
if (require.main === module) {
  const fs = require('node:fs');
  const paths = process.argv.slice(2);

  if (!paths.length) {
    console.error('Usage: node regex-hound.js <file> [file ...]');
    process.exitCode = 2;
  } else {
    const output = [];
    for (const path of paths) {
      try {
        const text = fs.readFileSync(path, 'utf8');
        for (const finding of scan(text)) output.push({ file: path, ...finding });
      } catch (error) {
        output.push({ file: path, error: error.message });
      }
    }
    process.stdout.write(`${JSON.stringify(output, null, 2)}\n`);
  }
}
