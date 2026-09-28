import { spawn, spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import http from 'node:http';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { buildImage } from './build-oci.mjs';
import {
  deploymentRoot,
  EGRESS_ALLOW,
  materialize,
  META_CALLBACKS,
  repoRoot,
} from './build-inventory.mjs';
import { generateDocuments } from './generate-sbom.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const gates = {};
const notes = [
  'LIVE_INFRA=SIMULATED. No cluster and no container daemon. The edge was proven with host nginx using the committed config.',
  'IMAGE_DIGEST is the provider edge (nginx 1.27.5-alpine pinned by manifest sha256:62223d644fa234c3a1cc785ee14242ec47a77364226f1c811d2f669f96dc2ac8 plus the deployment layer). Dockerfile.dev was not built.',
  'External egress is default-deny in the network policy. Meta hosts are an exact allowlist for a later FQDN controller. No live Meta calls.',
  'Twelve lockfile packages have license NOASSERTION. They are listed in the license manifest.',
];

function fail(gate, message) {
  gates[gate] = 'FAIL';
  throw new Error(`${gate} ${message}`);
}

function pass(gate) {
  gates[gate] = 'PASS';
}

function concrete(path) {
  return path.replace(/:([A-Za-z0-9_]+)/g, 'redteam').replace(/\*/g, 'redteam');
}

function request(port, method, path) {
  return new Promise((resolve, reject) => {
    const req = http.request(
      { hostname: '127.0.0.1', port, method, path, timeout: 3000 },
      (res) => {
        const chunks = [];
        res.on('data', (chunk) => chunks.push(chunk));
        res.on('end', () =>
          resolve({
            status: res.statusCode,
            body: Buffer.concat(chunks).toString('utf8'),
          })
        );
      }
    );
    req.on('error', reject);
    req.on('timeout', () => {
      req.destroy(new Error('timeout'));
    });
    req.end();
  });
}

function assertMatrix(matrix) {
  const classes = new Set(['PUBLIC_REQUIRED', 'PRIVATE_SERVICE', 'OPS_ONLY', 'DENY']);
  const publicHttp = [];
  for (const route of matrix.routes) {
    if (!classes.has(route.class)) fail('INGRESS_MATRIX', `bad class ${route.class}`);
    if (route.otherMethods !== 'DENY') fail('INGRESS_MATRIX', 'other methods not deny');
    if (
      ['dashboard', 'public-api', 'public-api-read', 'mcp', 'org-api-key', 'autopost'].includes(
        route.writeSurface
      ) &&
      route.class !== 'DENY'
    ) {
      fail('INGRESS_MATRIX', `${route.path} ${route.writeSurface} is ${route.class}`);
    }
    if (route.kind === 'http' && route.class === 'PUBLIC_REQUIRED') {
      publicHttp.push(`${route.methods.join(',')} ${route.path}`);
    }
  }
  const expected = META_CALLBACKS.flatMap((path) => [`GET,HEAD ${path}`]).sort();
  if (publicHttp.sort().join('\n') !== expected.join('\n')) {
    fail('INGRESS_MATRIX', `public routes ${publicHttp.join(' | ')}`);
  }
  if (matrix.defaultClass !== 'DENY') fail('INGRESS_MATRIX', 'default');
  const surfaces = ['dashboard', 'public-api', 'mcp', 'org-api-key', 'autopost'];
  for (const surface of surfaces) {
    if (!matrix.routes.some((route) => route.writeSurface === surface && route.class === 'DENY')) {
      fail('INGRESS_MATRIX', `missing ${surface}`);
    }
  }
}

function decideHost(host) {
  const normalized = host.toLowerCase().replace(/\.$/, '').replace(/:\d+$/, '');
  if (!normalized || normalized.includes('/') || /^\d+\.\d+\.\d+\.\d+$/.test(normalized)) {
    return 'DENY';
  }
  if (EGRESS_ALLOW.includes(normalized)) return 'ALLOW';
  if (
    [
      'postiz-postgres',
      'postiz-redis',
      'temporal',
      'temporal-postgresql',
      'temporal-elasticsearch',
      'kube-dns',
    ].includes(normalized)
  ) {
    return 'PRIVATE';
  }
  return 'DENY';
}

function assertEgress(egress) {
  if (egress.defaultClass !== 'DENY' || egress.match !== 'exact-host') {
    fail('EGRESS_MAP', 'default');
  }
  const allow = [];
  for (const entry of egress.entries) {
    if (!['ALLOW', 'DENY', 'PRIVATE'].includes(entry.class)) {
      fail('EGRESS_MAP', entry.host);
    }
    if (decideHost(entry.host) !== entry.class) {
      fail('EGRESS_MAP', `${entry.host} classified ${entry.class}`);
    }
    if (entry.class === 'ALLOW') allow.push(entry.host);
  }
  if (allow.sort().join('\n') !== [...EGRESS_ALLOW].sort().join('\n')) {
    fail('EGRESS_MAP', 'allowlist');
  }
  for (const host of [
    'graph.facebook.com.evil.example',
    'evilgraph.facebook.com',
    '1.2.3.4',
    'api.openai.com',
    'redirectmeto.com',
  ]) {
    if (decideHost(host) === 'ALLOW') fail('EGRESS_MAP', host);
  }
  if (decideHost('GRAPH.FACEBOOK.COM') !== 'ALLOW') fail('EGRESS_MAP', 'case');
}

function assertManifests(digest) {
  const deployment = readFileSync(join(deploymentRoot, 'k8s/deployment.yaml'), 'utf8');
  const service = readFileSync(join(deploymentRoot, 'k8s/service.yaml'), 'utf8');
  const policy = readFileSync(join(deploymentRoot, 'k8s/networkpolicy.yaml'), 'utf8');
  const compose = readFileSync(join(deploymentRoot, 'compose/docker-compose.provider.yaml'), 'utf8');
  const helm = readFileSync(
    join(deploymentRoot, 'helm/postiz-provider/templates/deployment.yaml'),
    'utf8'
  );
  const values = readFileSync(join(deploymentRoot, 'helm/postiz-provider/values.yaml'), 'utf8');
  const joined = [deployment, service, compose, helm, values].join('\n');
  const imageLines = joined
    .split('\n')
    .filter((line) => /^\s*(image:|repository:)/.test(line));
  if (imageLines.some((line) => /:latest\b/.test(line) || line.includes('ghcr.io/gitroomhq/postiz-app'))) {
    fail('IMAGE_DIGEST', 'mutable image reference');
  }
  if (!deployment.includes(`image: averion/postiz-provider@${digest}`)) {
    fail('IMAGE_DIGEST', 'deployment digest');
  }
  if (!compose.includes(`image: averion/postiz-provider@${digest}`)) {
    fail('IMAGE_DIGEST', 'compose digest');
  }
  if (!service.includes('port: 5000') || service.includes('15021') || service.includes('7233')) {
    fail('INGRESS_MATRIX', 'service ports');
  }
  if (policy.includes('0.0.0.0/0') || !policy.includes('egress: []')) {
    fail('EGRESS_MAP', 'network policy opens world egress');
  }
  if (deployment.includes('stringData:') || compose.includes('postiz-password')) {
    fail('SECRET_INJECTION', 'inline secret');
  }
  if (!deployment.includes('secretKeyRef:')) fail('SECRET_INJECTION', 'secretKeyRef');
  if (!helm.includes('required "image.digest')) fail('IMAGE_DIGEST', 'helm digest required');
  if (!values.includes('digest: ""')) fail('IMAGE_DIGEST', 'helm values must not pin a tag');
}

function stampDigest(digest) {
  for (const path of [
    join(deploymentRoot, 'k8s/deployment.yaml'),
    join(deploymentRoot, 'compose/docker-compose.provider.yaml'),
  ]) {
    const text = readFileSync(path, 'utf8');
    const next = text.replace(
      /averion\/postiz-provider@sha256:(?:pending|[a-f0-9]{64})/g,
      `averion/postiz-provider@${digest}`
    );
    if (next !== text) writeFileSync(path, next);
  }
}

async function withNginx(nginxText, fn) {
  const dir = mkdtempSync(join(tmpdir(), 'averion-nginx-'));
  for (const name of ['body', 'proxy', 'fastcgi', 'uwsgi', 'scgi']) {
    mkdirSync(join(dir, name));
  }
  const conf = nginxText
    .replace('pid /run/nginx.pid;', `pid ${dir}/nginx.pid;`)
    .replace('error_log /var/log/nginx/error.log warn;', `error_log ${dir}/error.log warn;`)
    .replace('access_log /var/log/nginx/access.log;', `access_log ${dir}/access.log;`)
    .replace('listen 5000;', 'listen 127.0.0.1:18080;')
    .replace('listen 15021;', 'listen 127.0.0.1:18081;')
    .replaceAll('root /averion/www;', `root ${join(deploymentRoot, 'ingress')};`)
    .replace(
      'http {',
      `http {\n    client_body_temp_path ${dir}/body;\n    proxy_temp_path ${dir}/proxy;\n    fastcgi_temp_path ${dir}/fastcgi;\n    uwsgi_temp_path ${dir}/uwsgi;\n    scgi_temp_path ${dir}/scgi;`
    );
  writeFileSync(join(dir, 'nginx.conf'), conf);
  const child = spawn('nginx', ['-p', dir, '-c', join(dir, 'nginx.conf'), '-g', 'daemon off;'], {
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let stderr = '';
  child.stderr.on('data', (chunk) => {
    stderr += chunk.toString();
  });
  try {
    await waitForPort(18080);
    await fn();
  } catch (error) {
    throw new Error(`${error.message}\n${stderr}\n${readSafe(join(dir, 'error.log'))}`);
  } finally {
    child.kill('SIGTERM');
    rmSync(dir, { recursive: true, force: true });
  }
}

function readSafe(path) {
  try {
    return readFileSync(path, 'utf8');
  } catch {
    return '';
  }
}

async function waitForPort(port) {
  for (let i = 0; i < 50; i += 1) {
    try {
      await request(port, 'GET', '/healthz');
      return;
    } catch {
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
  }
  throw new Error('nginx did not listen');
}

async function redTeam(matrix) {
  const seen = new Set();
  for (const route of matrix.routes) {
    if (route.kind !== 'http') continue;
    const path = concrete(route.path);
    for (const method of route.methods) {
      const key = `${method} ${path} ${route.class}`;
      if (seen.has(key)) continue;
      seen.add(key);
      if (route.class === 'PUBLIC_REQUIRED') {
        const res = await request(18080, method, path);
        if (res.status !== 200) fail('WRITE_BYPASS_RED_TEAM', `${method} ${path} ${res.status}`);
        if (method === 'GET' && /<form|fetch\(|social-connect|<script/i.test(res.body)) {
          fail('WRITE_BYPASS_RED_TEAM', 'callback exposes a write plane');
        }
        const posted = await request(18080, 'POST', path);
        if (posted.status !== 403) fail('WRITE_BYPASS_RED_TEAM', `POST ${path} ${posted.status}`);
        continue;
      }
      const res = await request(18080, method, path.startsWith('/') ? path : `/${path}`);
      if (res.status !== 403) {
        fail('WRITE_BYPASS_RED_TEAM', `${method} ${path} ${res.status}`);
      }
    }
  }
  const extras = [
    ['POST', '/api/posts'],
    ['PUT', '/api/posts/1/date'],
    ['DELETE', '/api/posts/group'],
    ['POST', '/api/public/v1/posts'],
    ['POST', '/api/public/v1/upload'],
    ['DELETE', '/api/public/v1/posts/1'],
    ['PUT', '/api/public/v1/posts/1/settings'],
    ['POST', '/api/mcp'],
    ['POST', '/api/mcp/orgkey'],
    ['POST', '/mcp'],
    ['POST', '/api/sse/orgkey'],
    ['POST', '/api/message/orgkey'],
    ['POST', '/api/user/api-key/rotate'],
    ['GET', '/api/user/self'],
    ['POST', '/api/autopost'],
    ['PUT', '/api/autopost/1'],
    ['POST', '/api/autopost/1/active'],
    ['POST', '/api/autopost/send'],
    ['POST', '/api/integrations/social-connect/facebook'],
    ['POST', '/integrations/social/facebook'],
    ['GET', '/launches'],
    ['GET', '/api/docs'],
    ['GET', '/uploads/a.png'],
    ['POST', '/api/auth/register'],
    ['POST', '/api/auth/login'],
    ['GET', '/integrations/social/x'],
    ['GET', '/healthz'],
    ['GET', '/this-route-is-not-classified'],
    ['GET', '/integrations/social/facebook/../../launches'],
  ];
  for (const [method, path] of extras) {
    const res = await request(18080, method, path);
    if (res.status !== 403) fail('WRITE_BYPASS_RED_TEAM', `${method} ${path} ${res.status}`);
  }
  const health = await request(18081, 'GET', '/healthz');
  if (health.status !== 200) fail('READINESS_FAIL_CLOSED', `ops health ${health.status}`);
  const opsLeak = await request(18081, 'POST', '/api/posts');
  if (opsLeak.status !== 403) fail('WRITE_BYPASS_RED_TEAM', 'ops port accepts writes');
  const publicHealth = await request(18080, 'GET', '/healthz');
  if (publicHealth.status !== 403) fail('INGRESS_MATRIX', 'healthz is public');
}

function entryEnv(overrides = {}) {
  return {
    PATH: process.env.PATH,
    AVERION_FAIL_CLOSED_ONLY: '1',
    AVERION_PROVIDER_PROFILE: 'true',
    TOKEN_ENCRYPTION_REQUIRED: 'true',
    MCP_WRITE_DISABLED: 'true',
    PUBLIC_API_WRITE_DISABLED: 'true',
    ORG_API_KEY_BROWSER_EXPOSURE: 'false',
    AUTOPOST_ENABLED: 'false',
    DISABLE_REGISTRATION: 'true',
    TOKEN_ENCRYPTION_KEY: Buffer.alloc(32, 9).toString('base64'),
    JWT_SECRET: 'averion-provider-test-jwt-secret-value',
    DATABASE_URL: 'postgresql://postiz-user:averion-test@postiz-postgres:5432/postiz',
    REDIS_URL: 'redis://postiz-redis:6379',
    FACEBOOK_APP_ID: 'averion-fb-app',
    FACEBOOK_APP_SECRET: 'averion-fb-secret',
    INSTAGRAM_APP_ID: 'averion-ig-app',
    INSTAGRAM_APP_SECRET: 'averion-ig-secret',
    THREADS_APP_ID: 'averion-th-app',
    THREADS_APP_SECRET: 'averion-th-secret',
    OPENAI_API_KEY: '',
    ...overrides,
  };
}

function assertReadiness() {
  const entry = join(here, 'entrypoint.sh');
  const ok = spawnSync('sh', [entry], { env: entryEnv() });
  if (ok.status !== 0) {
    fail('READINESS_FAIL_CLOSED', ok.stderr.toString());
  }
  const hex = spawnSync('sh', [entry], {
    env: entryEnv({ TOKEN_ENCRYPTION_KEY: 'ab'.repeat(32) }),
  });
  if (hex.status !== 0) {
    fail('READINESS_FAIL_CLOSED', hex.stderr.toString());
  }
  const cases = [
    { TOKEN_ENCRYPTION_KEY: '' },
    { TOKEN_ENCRYPTION_KEY: 'short' },
    { AUTOPOST_ENABLED: 'true' },
    { MCP_WRITE_DISABLED: 'false' },
    { PUBLIC_API_WRITE_DISABLED: '' },
    { ORG_API_KEY_BROWSER_EXPOSURE: 'true' },
    { AVERION_PROVIDER_PROFILE: '' },
    { OPENAI_API_KEY: 'sk-real' },
    { JWT_SECRET: 'random string that is unique to every install' },
    { DATABASE_URL: 'postgresql://postiz-user:postiz-password@postiz-postgres:5432/postiz' },
  ];
  for (const overrides of cases) {
    const result = spawnSync('sh', [entry], { env: entryEnv(overrides) });
    if (result.status === 0) {
      fail('READINESS_FAIL_CLOSED', `accepted ${Object.keys(overrides).join(',')}`);
    }
  }
}

function assertSecrets(image) {
  const config = JSON.parse(image.configBytes.toString('utf8'));
  const env = config.config.Env.join('\n');
  if (/TOKEN_ENCRYPTION_KEY|JWT_SECRET|FACEBOOK_APP_SECRET|postgresql:\/\//.test(env)) {
    fail('SECRET_INJECTION', 'secret baked into image config');
  }
  const flags = readFileSync(join(deploymentRoot, 'config/provider.flags.env'), 'utf8');
  if (/TOKEN_ENCRYPTION_KEY|JWT_SECRET|SECRET=/.test(flags)) {
    fail('SECRET_INJECTION', 'flags file');
  }
  const layer = image.layer.toString('utf8');
  if (layer.includes('BEGIN PRIVATE KEY') || layer.includes('AKIA')) {
    fail('SECRET_INJECTION', 'layer');
  }
}

const { matrix, egress, nginx } = materialize();
assertMatrix(matrix);
pass('INGRESS_MATRIX');
assertEgress(egress);
pass('EGRESS_MAP');

const first = buildImage();
const second = buildImage();
if (first.digest !== second.digest || !first.digest.startsWith('sha256:')) {
  fail('PROVIDER_IMAGES_REPRODUCIBLE', `${first.digest} ${second.digest}`);
}
pass('PROVIDER_IMAGES_REPRODUCIBLE');
pass('IMAGE_DIGEST');
assertSecrets(first);
pass('SECRET_INJECTION');

stampDigest(first.digest);
assertManifests(first.digest);

if (nginx.includes('proxy_pass')) fail('INGRESS_MATRIX', 'proxy_pass');

assertReadiness();
pass('READINESS_FAIL_CLOSED');

await withNginx(nginx, async () => {
  await redTeam(matrix);
});
pass('WRITE_BYPASS_RED_TEAM');

const docs = await generateDocuments();
mkdirSync(join(deploymentRoot, 'provenance'), { recursive: true });
writeFileSync(join(deploymentRoot, 'provenance/sbom.cdx.json'), JSON.stringify(docs.sbom) + '\n');
writeFileSync(
  join(deploymentRoot, 'provenance/license-manifest.json'),
  JSON.stringify(docs.licenseManifest) + '\n'
);
if (docs.packageCount < 100) fail('SBOM', `packages ${docs.packageCount}`);
pass('SBOM');
if (docs.unknown > Math.ceil(docs.packageCount * 0.02)) {
  fail('LICENSE_MANIFEST', `${docs.unknown} NOASSERTION of ${docs.packageCount}`);
}
pass('LICENSE_MANIFEST');

const report = {
  SOURCE_SHA: first.sourceSha,
  LOCKFILE_SHA256: first.lockfileSha256,
  IMAGE_DIGEST: first.digest,
  BUILD_TIMESTAMP: first.buildTimestamp,
  BASE_IMAGE: `nginx:1.27.5-alpine@${first.baseDigest}`,
  LIVE_INFRA: 'SIMULATED',
  SBOM: 'averion/provider-deployment/provenance/sbom.cdx.json',
  LICENSE_MANIFEST: 'averion/provider-deployment/provenance/license-manifest.json',
  packageCount: docs.packageCount,
  noassertionCount: docs.unknown,
  routes: matrix.routes.length,
  egressEntries: egress.entries.length,
  gates,
  notes,
};
writeFileSync(join(deploymentRoot, 'provenance/build.json'), JSON.stringify(report, null, 2) + '\n');
console.log(JSON.stringify(report, null, 2));
