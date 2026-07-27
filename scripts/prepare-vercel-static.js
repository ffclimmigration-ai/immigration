const fs = require('fs');
const path = require('path');

const rootDir = path.resolve(__dirname, '..');
const publicDir = path.join(rootDir, 'public');

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
  const targetPath = path.join(publicDir, relativePath);

  if (!fs.existsSync(sourcePath)) {
    console.warn(`Skipping missing path: ${relativePath}`);
    return;
  }

  fs.mkdirSync(path.dirname(targetPath), { recursive: true });
  fs.cpSync(sourcePath, targetPath, { recursive: true });
  console.log(`Copied ${relativePath} -> public/${relativePath}`);
}

resetDirectory(publicDir);
copyTargets.forEach(copyIntoPublic);
