const fs = require('fs');
const path = require('path');
const { parse } = require('url');

// Function to recursively find all .htm files
function findHtmlFiles(dir, fileList = []) {
    const files = fs.readdirSync(dir);
    for (const file of files) {
        const filePath = path.join(dir, file);
        const stat = fs.statSync(filePath);
        if (stat.isDirectory()) {
            findHtmlFiles(filePath, fileList);
        } else if (filePath.endsWith('.htm')) {
            fileList.push(filePath);
        }
    }
    return fileList;
}

// Function to check links in a file
function checkLinksInFile(filePath, rootDir) {
    const content = fs.readFileSync(filePath, 'utf8');
    const brokenLinks = [];
    
    // Simple regex to find href attributes
    const hrefRegex = /href\s*=\s*(["'])(.*?)\1/gi;
    let match;
    
    while ((match = hrefRegex.exec(content)) !== null) {
        let href = match[2];
        
        // Skip external links, mailto, and anchors
        if (href.startsWith('http://') || href.startsWith('https://') || 
            href.startsWith('mailto:') || href.startsWith('#')) {
            continue;
        }
        
        // Decode URL
        href = decodeURIComponent(href);
        
        // Remove query parameters
        href = href.split('?')[0];
        
        // Resolve path
        let absPath;
        if (href.startsWith('/')) {
            absPath = path.join(rootDir, href.slice(1));
        } else {
            const fileDir = path.dirname(filePath);
            absPath = path.normalize(path.join(fileDir, href));
        }
        
        // Check if file exists
        if (fs.existsSync(absPath)) {
            const stat = fs.statSync(absPath);
            if (stat.isFile()) {
                continue;
            } else if (stat.isDirectory()) {
                const indexPath = path.join(absPath, 'index.htm');
                if (fs.existsSync(indexPath) && fs.statSync(indexPath).isFile()) {
                    continue;
                }
            }
        }
        
        // If we get here, it's broken
        brokenLinks.push({
            href,
            resolvedPath: absPath
        });
    }
    
    return brokenLinks;
}

// Main function
function main() {
    const rootDir = __dirname;
    const htmlFiles = findHtmlFiles(rootDir);
    const allBrokenLinks = [];
    
    for (const file of htmlFiles) {
        const brokenLinks = checkLinksInFile(file, rootDir);
        if (brokenLinks.length > 0) {
            allBrokenLinks.push({
                file,
                brokenLinks
            });
        }
    }
    
    if (allBrokenLinks.length > 0) {
        console.log(`Found broken links in ${allBrokenLinks.length} files:\n`);
        for (const item of allBrokenLinks) {
            console.log(`File: ${item.file}`);
            for (const link of item.brokenLinks) {
                console.log(`  - Href: ${link.href}`);
                console.log(`    Resolved path: ${link.resolvedPath}`);
            }
            console.log();
        }
    } else {
        console.log('No broken links found!');
    }
}

main();