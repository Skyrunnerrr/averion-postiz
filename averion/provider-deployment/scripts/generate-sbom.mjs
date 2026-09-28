import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  BUILD_TIMESTAMP,
  deploymentRoot,
  EXPECTED_LOCKFILE_SHA256,
  lockfileSha256,
  repoRoot,
  SOURCE_SHA,
} from './build-inventory.mjs';

const cachePath = join(deploymentRoot, 'provenance/license-cache.json');

function parseLockPackages() {
  const text = readFileSync(join(repoRoot, 'pnpm-lock.yaml'), 'utf8');
  const lines = text.split('\n');
  const packages = [];
  let inPackages = false;
  let current = null;
  const push = () => {
    if (current) packages.push(current);
    current = null;
  };
  for (const line of lines) {
    if (line === 'packages:') {
      inPackages = true;
      continue;
    }
    if (!inPackages) continue;
    if (line.length && !line.startsWith(' ')) {
      push();
      break;
    }
    const quoted = line.match(/^  '(.+)':$/);
    const plain = line.match(/^  ([^' "][^:]*):$/);
    if (quoted || plain) {
      push();
      current = { key: (quoted || plain)[1], integrity: '' };
      continue;
    }
    if (current && !current.integrity) {
      const integrity = line.match(/integrity: (sha512-[A-Za-z0-9+/=]+)/);
      if (integrity) current.integrity = integrity[1];
    }
  }
  push();
  const components = new Map();
  for (const pkg of packages) {
    const base = pkg.key.split('(')[0];
    const at = base.lastIndexOf('@');
    const name = base.slice(0, at);
    const version = base.slice(at + 1);
    if (!name || !version) continue;
    const id = `${name}@${version}`;
    if (!components.has(id)) {
      components.set(id, {
        name,
        version,
        integrity: pkg.integrity,
        purl: purlFor(name, version),
      });
    }
  }
  return [...components.values()].sort((a, b) => a.purl.localeCompare(b.purl));
}

function purlFor(name, version) {
  const encoded = name.startsWith('@') ? `%40${name.slice(1)}` : name;
  return `pkg:npm/${encoded}@${version}`;
}

function readCache() {
  if (!existsSync(cachePath)) return {};
  return JSON.parse(readFileSync(cachePath, 'utf8'));
}

async function fetchLicense(name, version) {
  const path = name.startsWith('@')
    ? `${encodeURIComponent(name)}/${encodeURIComponent(version)}`
    : `${name}/${encodeURIComponent(version)}`;
  const response = await fetch(`https://registry.npmjs.org/${path}`, {
    headers: { accept: 'application/json' },
  });
  if (!response.ok) return 'NOASSERTION';
  const body = await response.json();
  const license = body.license;
  if (typeof license === 'string' && license.trim()) return license.trim();
  if (license && typeof license === 'object' && license.type) return String(license.type);
  if (Array.isArray(body.licenses) && body.licenses[0]?.type) return String(body.licenses[0].type);
  return 'NOASSERTION';
}

async function mapPool(items, limit, worker) {
  const out = new Array(items.length);
  let cursor = 0;
  async function run() {
    while (cursor < items.length) {
      const index = cursor;
      cursor += 1;
      out[index] = await worker(items[index], index);
    }
  }
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, () => run()));
  return out;
}

export async function generateDocuments() {
  const lock = lockfileSha256();
  if (lock !== EXPECTED_LOCKFILE_SHA256) {
    throw new Error(`lockfile hash ${lock}`);
  }
  const packages = parseLockPackages();
  const cache = readCache();
  const missing = packages.filter((pkg) => !cache[`${pkg.name}@${pkg.version}`]);
  if (missing.length) {
    await mapPool(missing, 16, async (pkg) => {
      const key = `${pkg.name}@${pkg.version}`;
      try {
        cache[key] = await fetchLicense(pkg.name, pkg.version);
      } catch {
        cache[key] = 'NOASSERTION';
      }
    });
    mkdirSync(dirname(cachePath), { recursive: true });
    const ordered = Object.fromEntries(Object.entries(cache).sort(([a], [b]) => a.localeCompare(b)));
    writeFileSync(cachePath, JSON.stringify(ordered, null, 2) + '\n');
  }
  const components = packages.map((pkg) => {
    const license = cache[`${pkg.name}@${pkg.version}`] || 'NOASSERTION';
    const component = {
      type: 'library',
      name: pkg.name,
      version: pkg.version,
      purl: pkg.purl,
      licenses: [licenseEntry(license)],
    };
    if (pkg.integrity) {
      component.hashes = [
        {
          alg: 'SHA-512',
          content: Buffer.from(pkg.integrity.replace(/^sha512-/, ''), 'base64').toString('hex'),
        },
      ];
    }
    return component;
  });
  const unknown = components.filter((component) =>
    component.licenses.some((item) => item.license.id === 'NOASSERTION' || item.license.name === 'NOASSERTION')
  );
  const sbom = {
    bomFormat: 'CycloneDX',
    specVersion: '1.6',
    version: 1,
    metadata: {
      timestamp: BUILD_TIMESTAMP,
      component: {
        type: 'application',
        name: 'averion-postiz-provider',
        version: SOURCE_SHA,
        licenses: [{ license: { id: 'AGPL-3.0-only' } }],
        properties: [
          { name: 'averion:lockfileSha256', value: lock },
          {
            name: 'averion:baseImage',
            value:
              'nginx:1.27.5-alpine@sha256:62223d644fa234c3a1cc785ee14242ec47a77364226f1c811d2f669f96dc2ac8',
          },
        ],
      },
      tools: [{ name: 'averion-provider-deployment' }],
    },
    components: [
      {
        type: 'container',
        name: 'nginx',
        version: '1.27.5-alpine',
        purl: 'pkg:oci/nginx@sha256:62223d644fa234c3a1cc785ee14242ec47a77364226f1c811d2f669f96dc2ac8',
        licenses: [{ license: { id: 'BSD-2-Clause' } }],
      },
      ...components,
    ],
  };
  const licenseManifest = {
    sourceSha: SOURCE_SHA,
    lockfileSha256: lock,
    repositoryLicense: 'AGPL-3.0-only',
    repositoryLicenseEvidence: 'LICENSE',
    workspaceDeclarations: [
      { name: 'gitroom', license: 'AGPL-3.0' },
      { name: 'backend', license: 'ISC' },
      { name: 'frontend', license: 'ISC' },
      { name: 'orchestrator', license: 'ISC' },
      { name: 'commands', license: 'ISC' },
      { name: 'sdk', license: 'AGPL-3.0' },
    ],
    nginx: 'BSD-2-Clause',
    packageCount: components.length,
    noassertionCount: unknown.length,
    packages: components.map((component) => ({
      name: component.name,
      version: component.version,
      license: component.licenses[0].license.id || component.licenses[0].license.name,
    })),
  };
  return { sbom, licenseManifest, unknown: unknown.length, packageCount: components.length };
}

function licenseEntry(license) {
  if (/^[A-Za-z0-9][A-Za-z0-9.+-]*$/.test(license)) {
    return { license: { id: license } };
  }
  return { license: { name: license } };
}

function digest(value) {
  return createHash('sha256').update(JSON.stringify(value)).digest('hex');
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const docs = await generateDocuments();
  mkdirSync(join(deploymentRoot, 'provenance'), { recursive: true });
  writeFileSync(
    join(deploymentRoot, 'provenance/sbom.cdx.json'),
    JSON.stringify(docs.sbom) + '\n'
  );
  writeFileSync(
    join(deploymentRoot, 'provenance/license-manifest.json'),
    JSON.stringify(docs.licenseManifest) + '\n'
  );
  console.log(
    JSON.stringify({
      packages: docs.packageCount,
      noassertion: docs.unknown,
      sbomSha256: digest(docs.sbom),
    })
  );
}
