const fs = require('fs');
const path = require('path');

const rootDir = path.resolve(__dirname, '..');
const publicDir = path.join(rootDir, 'public');
const publicMirrors = [
  publicDir,
  path.join(publicDir, 'www.immigration.govt.nz'),
];

const copyTargets = [
  '_resources',
  'assets',
  path.join('login', 'css'),
];

function resetDirectory(dirPath) {
  fs.rmSync(dirPath, { recursive: true, force: true });
  fs.mkdirSync(dirPath, { recursive: true });
}

function copyIntoPublic(relativePath) {
  const sourcePath = path.join(rootDir, relativePath);

  if (!fs.existsSync(sourcePath)) {
    console.warn(`Skipping missing path: ${relativePath}`);
    return;
  }

  for (const mirrorDir of publicMirrors) {
    const targetPath = path.join(mirrorDir, relativePath);
    fs.mkdirSync(path.dirname(targetPath), { recursive: true });
    fs.cpSync(sourcePath, targetPath, { recursive: true });
    const mirrorLabel = path.relative(rootDir, targetPath);
    console.log(`Copied ${relativePath} -> ${mirrorLabel}`);
  }
}

for (const mirrorDir of publicMirrors) {
  resetDirectory(mirrorDir);
}
copyTargets.forEach(copyIntoPublic);
