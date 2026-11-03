import { execFileSync } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const cargo = JSON.parse(execFileSync('cargo', ['metadata', '--locked', '--format-version', '1', '--filter-platform', 'x86_64-pc-windows-msvc', ...(process.argv.includes('--offline') ? ['--offline'] : [])], { cwd: root, encoding: 'utf8', maxBuffer: 32 * 1024 * 1024, windowsHide: true }));
const lock = JSON.parse(readFileSync(join(root, 'package-lock.json'), 'utf8'));
const rust = cargo.packages.filter((pkg) => pkg.source).map((pkg) => ({ name: pkg.name, version: pkg.version, license: pkg.license, url: `https://crates.io/crates/${pkg.name}/${pkg.version}` }));
const npm = Object.entries(lock.packages).filter(([path]) => path).map(([path, pkg]) => {
  const name = path.slice(path.lastIndexOf('node_modules/') + 'node_modules/'.length);
  return { name, version: pkg.version, license: pkg.license, url: `https://www.npmjs.com/package/${name}/v/${pkg.version}` };
});
for (const entry of [...rust, ...npm]) {
  if (!entry.license || /[\r\n|]/.test(entry.name + entry.version)) throw new Error(`Missing or invalid dependency license metadata: ${entry.name}`);
}
const table = (entries) => ['| Package | Version | License |', '|---|---|---|', ...entries.sort((a,b) => (a.name + a.version).localeCompare(b.name + b.version, 'en')).map((entry) => `| [${entry.name}](${entry.url}) | ${entry.version} | ${entry.license.replaceAll('|', '\\|')} |`)].join('\n');
writeFileSync(join(root, 'THIRD_PARTY_NOTICES.md'), `# Third-party dependency inventory\n\nGenerated from the lockfiles and Windows-target Cargo metadata. Includes build/dev dependencies and optional npm platform packages; it is not a list of files bundled in every binary.\n\nDependencies retain their original copyrights and license terms. Project Apache-2.0 licensing does not relicense dependencies. This source distribution does not vendor dependency source. For binary distribution, collect the original license/NOTICE texts and fulfill applicable source-availability obligations, including MPL-covered files. This metadata inventory is not a substitute for those obligations.\n\n## Rust (${rust.length})\n\n${table(rust)}\n\n## npm (${npm.length})\n\n${table(npm)}\n`, 'utf8');
console.log(`Dependency inventory generated: ${rust.length} Rust, ${npm.length} npm packages`);
