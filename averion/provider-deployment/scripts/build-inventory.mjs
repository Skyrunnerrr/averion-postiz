import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync, readdirSync, statSync } from 'node:fs';
import { dirname, join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
export const deploymentRoot = dirname(here);
export const repoRoot = dirname(dirname(deploymentRoot));

export const SOURCE_SHA = 'c3f00d015c591d7927e338f4641c1b1b379c733d';
export const EXPECTED_LOCKFILE_SHA256 =
  '75b7a994e472d48be947fd6a9e538b65028827210d802abe60543727a99650bf';
export const BUILD_TIMESTAMP = '2026-09-28T08:05:37Z';

export const META_CALLBACKS = [
  '/integrations/social/facebook',
  '/integrations/social/instagram',
  '/integrations/social/instagram-standalone',
  '/integrations/social/threads',
];

export const EGRESS_ALLOW = [
  'api.instagram.com',
  'graph.facebook.com',
  'graph.instagram.com',
  'graph.threads.net',
  'www.facebook.com',
  'www.instagram.com',
  'www.threads.net',
];

const WRITE = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);
const CLASSES = new Set([
  'PUBLIC_REQUIRED',
  'PRIVATE_SERVICE',
  'OPS_ONLY',
  'DENY',
]);

const methodRe =
  /@(Get|Post|Put|Patch|Delete|Head|Options|All)\(\s*(?:'([^']*)'|"([^"]*)"|`([^`]*)`)?\s*\)/g;
const controllerRe =
  /@Controller\(\s*(?:'([^']*)'|"([^"]*)"|`([^`]*)`)?\s*\)/g;

function walk(dir, predicate, out = []) {
  for (const name of readdirSync(dir)) {
    if (name === 'node_modules' || name === 'dist' || name === '.git') continue;
    const path = join(dir, name);
    const st = statSync(path);
    if (st.isDirectory()) walk(path, predicate, out);
    else if (predicate(path)) out.push(path);
  }
  return out;
}

function joinRoute(prefix, sub) {
  const left = (prefix || '').replace(/^\/+|\/+$/g, '');
  const right = (sub || '').replace(/^\/+|\/+$/g, '');
  const parts = [left, right].filter(Boolean);
  return '/' + parts.join('/');
}

function publicApiPath(internalPath) {
  if (internalPath === '/') return '/api/';
  return '/api' + internalPath;
}

function writeSurface(source, method, internalPath) {
  const write = WRITE.has(method);
  if (internalPath === '/autopost' || internalPath.startsWith('/autopost/')) {
    return 'autopost';
  }
  if (internalPath === '/public/v1' || internalPath.startsWith('/public/v1/')) {
    return write ? 'public-api' : 'public-api-read';
  }
  if (
    internalPath === '/mcp' ||
    internalPath.startsWith('/mcp/') ||
    internalPath.startsWith('/mcp-oauth') ||
    internalPath.startsWith('/sse/') ||
    internalPath.startsWith('/message/') ||
    internalPath.startsWith('/.well-known/oauth-') ||
    internalPath.startsWith('/.well-known/openid-configuration') ||
    internalPath === '/.well-known/openai-apps-challenge'
  ) {
    return 'mcp';
  }
  if (internalPath.includes('/api-key') || internalPath === '/user/self') {
    return 'org-api-key';
  }
  if (
    write &&
    (source.includes('posts.controller') ||
      source.includes('media.controller') ||
      source.includes('auth.controller') ||
      source.includes('settings.controller') ||
      source.includes('integrations.controller') ||
      source.includes('no.auth.integrations') ||
      source.includes('copilot.controller') ||
      source.includes('billing.controller') ||
      source.includes('webhooks.controller') ||
      source.includes('signature.controller') ||
      source.includes('sets.controller') ||
      source.includes('announcements.controller') ||
      source.includes('clipping.controller') ||
      source.includes('third-party.controller') ||
      source.includes('oauth') ||
      source.includes('enterprise.controller') ||
      source.includes('stripe.controller') ||
      source.includes('payment.controller') ||
      source.includes('public.controller') ||
      source.includes('users.controller') ||
      source.includes('admin.controller') ||
      source.includes('media.widget') ||
      source.includes('approved-apps'))
  ) {
    return 'dashboard';
  }
  if (write) return 'dashboard';
  return '';
}

export function assertControllerMethodsParsed() {
  const files = walk(repoRoot, (path) => path.endsWith('.controller.ts'));
  let loose = 0;
  let parsed = 0;
  for (const file of files) {
    const text = readFileSync(file, 'utf8');
    loose += (text.match(/@(Get|Post|Put|Patch|Delete|Head|Options|All)\(/g) || []).length;
    parsed += [...text.matchAll(methodRe)].length;
  }
  if (loose !== parsed) {
    throw new Error(`controller parser missed methods loose=${loose} parsed=${parsed}`);
  }
  return parsed;
}

function parseControllers() {
  const files = walk(repoRoot, (path) => path.endsWith('.controller.ts'));
  const routes = [];
  for (const file of files) {
    const text = readFileSync(file, 'utf8');
    const markers = [];
    for (const match of text.matchAll(controllerRe)) {
      markers.push({
        index: match.index,
        kind: 'controller',
        prefix: match[1] ?? match[2] ?? match[3] ?? '',
      });
    }
    for (const match of text.matchAll(methodRe)) {
      markers.push({
        index: match.index,
        kind: 'method',
        method: match[1].toUpperCase(),
        sub: match[2] ?? match[3] ?? match[4] ?? '',
      });
    }
    markers.sort((a, b) => a.index - b.index);
    let prefix = '';
    for (const marker of markers) {
      if (marker.kind === 'controller') {
        prefix = marker.prefix;
        continue;
      }
      const internalPath = joinRoute(prefix, marker.sub);
      const source = relative(repoRoot, file);
      const methods =
        marker.method === 'ALL'
          ? ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS']
          : [marker.method];
      const opsHealth = source.startsWith('apps/orchestrator/') && internalPath === '/health/status';
      routes.push({
        kind: 'http',
        methods,
        path: opsHealth ? internalPath : publicApiPath(internalPath),
        internalPath,
        class: opsHealth ? 'OPS_ONLY' : 'DENY',
        otherMethods: 'DENY',
        plane: opsHealth ? 'ops' : 'public',
        source,
        writeSurface: opsHealth
          ? ''
          : writeSurface(source, marker.method === 'ALL' ? 'POST' : marker.method, internalPath),
        note: opsHealth
          ? 'Orchestrator health is probe-only on port 3002, not on the public edge.'
          : 'Application HTTP is not selected by the public edge.',
      });
    }
  }
  return routes;
}

function pageRoute(file) {
  let rel = relative(join(repoRoot, 'apps/frontend/src/app'), file);
  rel = rel.replace(/\/page\.tsx$/, '').replace(/\/route\.ts$/, '');
  const parts = rel
    .split('/')
    .filter((part) => part && !part.startsWith('('))
    .map((part) => part.replace(/^\[\[\.\.\.(.+)\]\]$/, '*').replace(/^\[(.+)\]$/, ':$1'));
  return '/' + parts.join('/');
}

function frontendRoutes() {
  const files = walk(
    join(repoRoot, 'apps/frontend/src/app'),
    (path) => path.endsWith('/page.tsx') || path.endsWith('/route.ts')
  );
  const routes = [];
  for (const file of files) {
    const path = pageRoute(file);
    const source = relative(repoRoot, file);
    if (path === '/integrations/social/:provider') {
      for (const callback of META_CALLBACKS) {
        routes.push({
          kind: 'http',
          methods: ['GET', 'HEAD'],
          path: callback,
          internalPath: callback,
          class: 'PUBLIC_REQUIRED',
          otherMethods: 'DENY',
          plane: 'public',
          source,
          writeSurface: 'meta-callback',
          note: 'Meta browser redirect only. Static page, no Postiz SPA and no write.',
        });
        routes.push({
          kind: 'http',
          methods: ['POST', 'PUT', 'PATCH', 'DELETE'],
          path: callback,
          internalPath: callback,
          class: 'DENY',
          otherMethods: 'DENY',
          plane: 'public',
          source,
          writeSurface: 'dashboard',
          note: 'Write methods on the callback path are denied.',
        });
      }
      routes.push({
        kind: 'http',
        methods: ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE'],
        path: '/integrations/social/:provider',
        internalPath: '/integrations/social/:provider',
        class: 'DENY',
        otherMethods: 'DENY',
        plane: 'public',
        source,
        writeSurface: 'dashboard',
        note: 'Any provider other than the four Meta callbacks is denied.',
      });
      continue;
    }
    routes.push({
      kind: 'http',
      methods: ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE'],
      path,
      internalPath: path,
      class: 'DENY',
      otherMethods: 'DENY',
      plane: 'public',
      source,
      writeSurface: path.startsWith('/auth') || path.startsWith('/launches') ? 'dashboard' : '',
      note: 'Postiz UI is not served by the provider edge.',
    });
  }
  return routes;
}

function extraHttp() {
  const mcp = [
    ['/.well-known/openai-apps-challenge', 'libraries/nestjs-libraries/src/chat/start.mcp.ts'],
    ['/.well-known/oauth-protected-resource', 'libraries/nestjs-libraries/src/chat/start.mcp.ts'],
    ['/.well-known/oauth-authorization-server', 'libraries/nestjs-libraries/src/chat/start.mcp.ts'],
    ['/.well-known/openid-configuration', 'libraries/nestjs-libraries/src/chat/start.mcp.ts'],
    ['/mcp-oauth-chatgpt', 'libraries/nestjs-libraries/src/chat/start.mcp.ts'],
    ['/mcp-oauth', 'libraries/nestjs-libraries/src/chat/start.mcp.ts'],
    ['/mcp-oauth-claude', 'libraries/nestjs-libraries/src/chat/start.mcp.ts'],
    ['/mcp-oauth-dynamic', 'libraries/nestjs-libraries/src/chat/start.mcp.ts'],
    ['/mcp', 'libraries/nestjs-libraries/src/chat/start.mcp.ts'],
    ['/mcp/:id', 'libraries/nestjs-libraries/src/chat/start.mcp.ts'],
    ['/sse/:id', 'libraries/nestjs-libraries/src/chat/start.mcp.ts'],
    ['/message/:id', 'libraries/nestjs-libraries/src/chat/start.mcp.ts'],
    ['/docs', 'libraries/helpers/src/swagger/load.swagger.ts'],
  ];
  const routes = [];
  for (const [internalPath, source] of mcp) {
    routes.push({
      kind: 'http',
      methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'],
      path: publicApiPath(internalPath),
      internalPath,
      class: 'DENY',
      otherMethods: 'DENY',
      plane: 'public',
      source,
      writeSurface: writeSurface(source, 'POST', internalPath),
      note: 'MCP, OAuth metadata, and Swagger are not on the public edge.',
    });
  }
  routes.push({
    kind: 'http',
    methods: ['GET', 'HEAD'],
    path: '/healthz',
    internalPath: '/healthz',
    class: 'OPS_ONLY',
    otherMethods: 'DENY',
    plane: 'ops',
    source: 'averion/provider-deployment/ingress/nginx.provider.conf',
    writeSurface: '',
    note: 'Readiness on port 15021 only. Not selected by the public Service.',
  });
  routes.push({
    kind: 'http',
    methods: ['GET', 'HEAD', 'POST'],
    path: '/uploads/*',
    internalPath: '/uploads/*',
    class: 'DENY',
    otherMethods: 'DENY',
    plane: 'public',
    source: 'var/docker/nginx.conf',
    writeSurface: '',
    note: 'Stock nginx publishes /uploads/. The provider edge does not.',
  });
  return routes;
}

function exposures() {
  return [
    tcp('postiz-postgres', 5432, 'PRIVATE_SERVICE', 'Postgres is cluster-internal.'),
    tcp('postiz-redis', 6379, 'PRIVATE_SERVICE', 'Redis is cluster-internal.'),
    tcp('temporal', 7233, 'PRIVATE_SERVICE', 'Temporal frontend is cluster-internal.'),
    tcp('temporal-postgresql', 5432, 'PRIVATE_SERVICE', 'Temporal database is cluster-internal.'),
    tcp('temporal-elasticsearch', 9200, 'PRIVATE_SERVICE', 'Temporal search is cluster-internal.'),
    tcp('orchestrator', 3002, 'OPS_ONLY', 'Orchestrator health is probe-only.'),
    tcp('backend', 3000, 'DENY', 'Backend HTTP is not in any Service.'),
    tcp('frontend', 4200, 'DENY', 'Postiz frontend is not deployed.'),
    tcp('host-temporal', 7233, 'DENY', 'Stock compose publishes 7233. Provider compose does not.'),
    tcp('host-temporal-ui', 8080, 'DENY', 'Temporal UI is not deployed.'),
    tcp('host-spotlight', 8969, 'DENY', 'Spotlight is not deployed.'),
    tcp('public-edge', 5000, 'PUBLIC_REQUIRED', 'Only the classified public listener.'),
    tcp('ops-edge', 15021, 'OPS_ONLY', 'Probe port, not in the public Service.'),
    {
      kind: 'udp',
      methods: ['UDP'],
      path: 'kube-dns:53',
      internalPath: 'kube-dns:53',
      class: 'PRIVATE_SERVICE',
      otherMethods: 'DENY',
      plane: 'cluster',
      source: 'averion/provider-deployment/k8s/networkpolicy.yaml',
      writeSurface: '',
      note: 'Cluster DNS only.',
    },
  ];
}

function tcp(name, port, klass, note) {
  return {
    kind: 'tcp',
    methods: ['TCP'],
    path: `${name}:${port}`,
    internalPath: `${name}:${port}`,
    class: klass,
    otherMethods: 'DENY',
    plane: klass === 'PUBLIC_REQUIRED' ? 'public' : klass === 'OPS_ONLY' ? 'ops' : klass === 'PRIVATE_SERVICE' ? 'cluster' : 'closed',
    source: 'averion/provider-deployment/k8s/networkpolicy.yaml',
    writeSurface: '',
    note,
  };
}

export function buildMatrix() {
  const routes = [
    ...parseControllers(),
    ...frontendRoutes(),
    ...extraHttp(),
    ...exposures(),
  ].sort((a, b) =>
    a.path === b.path
      ? a.methods.join(',').localeCompare(b.methods.join(',')) || a.class.localeCompare(b.class)
      : a.path.localeCompare(b.path)
  );
  for (const route of routes) {
    if (!CLASSES.has(route.class) || route.otherMethods !== 'DENY') {
      throw new Error(`invalid class for ${route.path}`);
    }
  }
  const publicRoutes = routes.filter((route) => route.class === 'PUBLIC_REQUIRED' && route.kind === 'http');
  return {
    version: 1,
    sourceSha: SOURCE_SHA,
    defaultClass: 'DENY',
    publicListener: '0.0.0.0:5000',
    opsListener: 'pod:15021',
    classes: ['PUBLIC_REQUIRED', 'PRIVATE_SERVICE', 'OPS_ONLY', 'DENY'],
    publicHttp: publicRoutes.map((route) => ({
      methods: route.methods,
      path: route.path,
    })),
    routes,
  };
}

function renderNginx(matrix) {
  const locations = matrix.publicHttp
    .filter((route) => route.methods.includes('GET'))
    .map((route) => route.path)
    .sort();
  if (locations.join('\n') !== META_CALLBACKS.join('\n')) {
    throw new Error('public allowlist drifted from the Meta callbacks');
  }
  const blocks = locations
    .map(
      (path) => `        location = ${path} {
            limit_except GET HEAD { deny all; }
            root /averion/www;
            default_type text/html;
            try_files /callback.html =403;
        }`
    )
    .join('\n\n');
  return `worker_processes 1;
error_log /var/log/nginx/error.log warn;
pid /run/nginx.pid;

events {
    worker_connections 128;
}

http {
    server_tokens off;
    client_max_body_size 1m;
    default_type application/octet-stream;
    access_log /var/log/nginx/access.log;
    absolute_redirect off;

    server {
        listen 5000;
        server_name _;
        add_header X-Content-Type-Options nosniff always;
        add_header Referrer-Policy no-referrer always;
        add_header Content-Security-Policy "default-src 'none'; script-src 'none'; frame-ancestors 'none'" always;

${blocks}

        location / {
            return 403;
        }
    }

    server {
        listen 15021;
        server_name _;

        location = /healthz {
            limit_except GET HEAD { deny all; }
            default_type application/json;
            return 200 '{"status":"ready","profile":"averion-provider"}';
        }

        location / {
            return 403;
        }
    }
}
`;
}

function collectHosts() {
  const files = walk(repoRoot, (path) => {
    if (path.includes(`${join('averion', 'provider-deployment')}`)) return false;
    return ['.ts', '.tsx', '.js', '.mjs'].some((ext) => path.endsWith(ext));
  });
  const found = new Map();
  const hostRe = /https?:\/\/([A-Za-z0-9._-]+)/g;
  for (const file of files) {
    const text = readFileSync(file, 'utf8');
    for (const match of text.matchAll(hostRe)) {
      const host = match[1].toLowerCase().replace(/\.$/, '');
      if (!host || host === 'localhost' || host === '127.0.0.1' || host === '0.0.0.0') {
        continue;
      }
      const source = relative(repoRoot, file);
      if (!found.has(host)) found.set(host, new Set());
      found.get(host).add(source);
    }
  }
  return found;
}

export function buildEgress(discovered) {
  const found = discovered || collectHosts();
  const privateHosts = [
    ['postiz-postgres', 'Postgres'],
    ['postiz-redis', 'Redis'],
    ['temporal', 'Temporal frontend'],
    ['temporal-postgresql', 'Temporal database'],
    ['temporal-elasticsearch', 'Temporal search'],
    ['kube-dns', 'Cluster DNS'],
  ];
  const entries = [];
  for (const [host, sources] of found) {
    const allow = EGRESS_ALLOW.includes(host);
    entries.push({
      host,
      class: allow ? 'ALLOW' : 'DENY',
      purpose: allow ? 'Meta provider API or OAuth host' : 'Discovered in source; not on the Meta allowlist',
      sources: [...sources].sort(),
    });
  }
  for (const [host, purpose] of privateHosts) {
    entries.push({
      host,
      class: 'PRIVATE',
      purpose,
      sources: ['averion/provider-deployment/k8s/networkpolicy.yaml'],
    });
  }
  entries.sort((a, b) => a.host.localeCompare(b.host) || a.class.localeCompare(b.class));
  const allow = entries.filter((entry) => entry.class === 'ALLOW').map((entry) => entry.host);
  if (allow.join('\n') !== [...EGRESS_ALLOW].sort().join('\n')) {
    throw new Error(`egress allowlist drift: ${allow.join(',')}`);
  }
  return {
    version: 1,
    sourceSha: SOURCE_SHA,
    defaultClass: 'DENY',
    match: 'exact-host',
    entries,
  };
}

export function lockfileSha256() {
  const bytes = readFileSync(join(repoRoot, 'pnpm-lock.yaml'));
  return createHash('sha256').update(bytes).digest('hex');
}

function writeJson(path, value) {
  writeFileSync(path, JSON.stringify(value, null, 2) + '\n');
}

export function materialize() {
  assertControllerMethodsParsed();
  const matrix = buildMatrix();
  const egress = buildEgress();
  const nginx = renderNginx(matrix);
  const allowlist = EGRESS_ALLOW.map((host) => host).sort().join('\n') + '\n';
  mkdirSync(join(deploymentRoot, 'ingress'), { recursive: true });
  mkdirSync(join(deploymentRoot, 'egress'), { recursive: true });
  writeJson(join(deploymentRoot, 'ingress/ingress-matrix.json'), matrix);
  writeFileSync(join(deploymentRoot, 'ingress/nginx.provider.conf'), nginx);
  writeJson(join(deploymentRoot, 'egress/egress-map.json'), egress);
  writeFileSync(join(deploymentRoot, 'egress/allowlist.txt'), allowlist);
  const helmFiles = join(deploymentRoot, 'helm/postiz-provider/files');
  mkdirSync(helmFiles, { recursive: true });
  writeFileSync(join(helmFiles, 'nginx.provider.conf'), nginx);
  writeFileSync(join(helmFiles, 'allowlist.txt'), allowlist);
  return { matrix, egress, nginx };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const lock = lockfileSha256();
  if (lock !== EXPECTED_LOCKFILE_SHA256) {
    console.error(`LOCKFILE_SHA256 mismatch ${lock}`);
    process.exit(1);
  }
  const { matrix, egress } = materialize();
  const counts = {};
  for (const route of matrix.routes) counts[route.class] = (counts[route.class] || 0) + 1;
  console.log(JSON.stringify({ routes: matrix.routes.length, counts, egress: egress.entries.length, lock }, null, 2));
}
