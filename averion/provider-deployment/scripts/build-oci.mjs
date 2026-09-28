import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import {
  BUILD_TIMESTAMP,
  deploymentRoot,
  EXPECTED_LOCKFILE_SHA256,
  lockfileSha256,
  SOURCE_SHA,
} from './build-inventory.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const baseManifestPath = join(
  deploymentRoot,
  'image/base/nginx-1.27.5-alpine-amd64.manifest.json'
);
const baseConfigPath = join(
  deploymentRoot,
  'image/base/nginx-1.27.5-alpine-amd64.config.json'
);
const BASE_MANIFEST_SHA256 =
  '62223d644fa234c3a1cc785ee14242ec47a77364226f1c811d2f669f96dc2ac8';
const BASE_CONFIG_SHA256 =
  '6769dc3a703c719c1d2756bda113659be28ae16cf0da58dd5fd823d6b9a050ea';

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function fileBytes(path) {
  return readFileSync(path);
}

export function layerFiles() {
  const root = deploymentRoot;
  const copy = (from, arcname, mode) => ({
    path: join(root, from),
    arcname,
    mode,
  });
  const identity =
    `SOURCE_SHA=${SOURCE_SHA}\n` +
    `LOCKFILE_SHA256=${EXPECTED_LOCKFILE_SHA256}\n` +
    `BUILD_TIMESTAMP=${BUILD_TIMESTAMP}\n`;
  return [
    copy('scripts/entrypoint.sh', 'averion/scripts/entrypoint.sh', 0o755),
    copy('scripts/fail-closed.sh', 'averion/scripts/fail-closed.sh', 0o755),
    copy('config/provider.flags.env', 'averion/config/provider.flags.env', 0o644),
    copy('ingress/nginx.provider.conf', 'averion/ingress/nginx.provider.conf', 0o644),
    copy('ingress/nginx.provider.conf', 'etc/nginx/nginx.conf', 0o644),
    copy('ingress/callback.html', 'averion/www/callback.html', 0o644),
    copy('ingress/ingress-matrix.json', 'averion/ingress/ingress-matrix.json', 0o644),
    copy('egress/egress-map.json', 'averion/egress/egress-map.json', 0o644),
    copy('egress/allowlist.txt', 'averion/egress/allowlist.txt', 0o644),
    copy('SECRETS.md', 'averion/SECRETS.md', 0o644),
    { contents: identity, arcname: 'averion/provenance/identity.txt', mode: 0o644 },
  ];
}

function tarLayer(files) {
  const payload = files.map((file) => ({
    arcname: file.arcname,
    mode: file.mode,
    contentsB64: Buffer.from(
      file.contents !== undefined ? file.contents : fileBytes(file.path)
    ).toString('base64'),
  }));
  const script = `
import base64, io, json, sys, tarfile
items = json.load(sys.stdin)
dirs = set()
for item in items:
    parent = item["arcname"]
    while "/" in parent:
        parent = parent.rsplit("/", 1)[0]
        if not parent or parent in dirs:
            break
        dirs.add(parent)
buf = io.BytesIO()
with tarfile.open(fileobj=buf, mode="w", format=tarfile.USTAR_FORMAT) as tar:
    for name in sorted(dirs):
        info = tarfile.TarInfo(name)
        info.type = tarfile.DIRTYPE
        info.mode = 0o755
        info.mtime = ${Math.floor(Date.parse(BUILD_TIMESTAMP) / 1000)}
        info.uid = 0
        info.gid = 0
        info.uname = "root"
        info.gname = "root"
        tar.addfile(info)
    for item in sorted(items, key=lambda i: i["arcname"]):
        data = base64.b64decode(item["contentsB64"])
        info = tarfile.TarInfo(item["arcname"])
        info.size = len(data)
        info.mode = int(item["mode"])
        info.mtime = ${Math.floor(Date.parse(BUILD_TIMESTAMP) / 1000)}
        info.uid = 0
        info.gid = 0
        info.uname = "root"
        info.gname = "root"
        tar.addfile(info, io.BytesIO(data))
sys.stdout.buffer.write(buf.getvalue())
`;
  const child = spawnSync('python3', ['-c', script], {
    input: JSON.stringify(payload),
    maxBuffer: 32 * 1024 * 1024,
  });
  if (child.status !== 0) {
    throw new Error(child.stderr.toString() || 'tar failed');
  }
  return child.stdout;
}

function assertBase() {
  const manifestBytes = readFileSync(baseManifestPath);
  const configBytes = readFileSync(baseConfigPath);
  if (sha256(manifestBytes) !== BASE_MANIFEST_SHA256) {
    throw new Error('vendored nginx manifest hash mismatch');
  }
  if (sha256(configBytes) !== BASE_CONFIG_SHA256) {
    throw new Error('vendored nginx config hash mismatch');
  }
  return {
    manifest: JSON.parse(manifestBytes.toString('utf8')),
    config: JSON.parse(configBytes.toString('utf8')),
  };
}

export function buildImage() {
  const lock = lockfileSha256();
  if (lock !== EXPECTED_LOCKFILE_SHA256) {
    throw new Error(`lockfile hash ${lock}`);
  }
  const base = assertBase();
  const layer = tarLayer(layerFiles());
  const diffId = sha256(layer);
  const labels = {
    'averion.base.image': `nginx:1.27.5-alpine@sha256:${BASE_MANIFEST_SHA256}`,
    'averion.deployment.profile': 'provider-edge',
    'org.opencontainers.image.created': BUILD_TIMESTAMP,
    'org.opencontainers.image.revision': SOURCE_SHA,
    'org.opencontainers.image.source.lockfile.sha256': lock,
    'org.opencontainers.image.title': 'averion-postiz-provider',
  };
  const config = {
    created: BUILD_TIMESTAMP,
    architecture: 'amd64',
    os: 'linux',
    config: {
      User: '0',
      Env: [
        ...base.config.config.Env,
        'AVERION_PROVIDER_PROFILE=true',
        'TOKEN_ENCRYPTION_REQUIRED=true',
        'MCP_WRITE_DISABLED=true',
        'PUBLIC_API_WRITE_DISABLED=true',
        'ORG_API_KEY_BROWSER_EXPOSURE=false',
        'AUTOPOST_ENABLED=false',
        'DISABLE_REGISTRATION=true',
      ],
      Entrypoint: ['/averion/scripts/entrypoint.sh'],
      WorkingDir: '/averion',
      ExposedPorts: { '5000/tcp': {} },
      Labels: labels,
      StopSignal: 'SIGQUIT',
    },
    rootfs: {
      type: 'layers',
      diff_ids: [...base.config.rootfs.diff_ids, `sha256:${diffId}`],
    },
    history: [
      ...base.config.history,
      {
        created: BUILD_TIMESTAMP,
        created_by: 'averion provider deployment edge',
        comment: 'default-deny ingress, Meta callbacks, fail-closed entrypoint',
      },
    ],
  };
  const configBytes = Buffer.from(JSON.stringify(config));
  const configDigest = sha256(configBytes);
  const layers = base.manifest.layers.map((layerInfo) => ({
    mediaType: layerInfo.mediaType,
    digest: layerInfo.digest,
    size: layerInfo.size,
  }));
  layers.push({
    mediaType: 'application/vnd.oci.image.layer.v1.tar',
    digest: `sha256:${diffId}`,
    size: layer.length,
  });
  const manifest = {
    schemaVersion: 2,
    mediaType: 'application/vnd.oci.image.manifest.v1+json',
    config: {
      mediaType: 'application/vnd.oci.image.config.v1+json',
      digest: `sha256:${configDigest}`,
      size: configBytes.length,
    },
    layers,
  };
  const manifestBytes = Buffer.from(JSON.stringify(manifest));
  return {
    digest: `sha256:${sha256(manifestBytes)}`,
    manifestBytes,
    configBytes,
    layer,
    sourceSha: SOURCE_SHA,
    lockfileSha256: lock,
    buildTimestamp: BUILD_TIMESTAMP,
    baseDigest: `sha256:${BASE_MANIFEST_SHA256}`,
  };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const image = buildImage();
  console.log(image.digest);
}
