import fs from 'fs';
import path from 'path';
import https from 'https';
import http from 'http';
import { exec, spawn } from 'child_process';
import { promisify } from 'util';

const execAsync = promisify(exec);

class RemoteRepositoryManager {
  constructor(options = {}) {
    this.tempDir = options.tempDir || './temp';
    this.timeout = options.timeout || 300000;
    this.maxFileSize = options.maxFileSize || 100 * 1024 * 1024;
    this.init();
  }

  init() {
    try {
      if (!fs.existsSync(this.tempDir)) {
        fs.mkdirSync(this.tempDir, { recursive: true });
      }
    } catch (error) {
      console.warn(`Failed to initialize temp directory: ${error.message}`);
    }
  }

  generateTempDir() {
    const timestamp = Date.now();
    const random = Math.random().toString(36).substring(2, 9);
    const tempPath = path.join(this.tempDir, `repo_${timestamp}_${random}`);
    
    if (!fs.existsSync(tempPath)) {
      fs.mkdirSync(tempPath, { recursive: true });
    }
    
    return tempPath;
  }

  async downloadZipFromUrl(url, destination) {
    return new Promise((resolve, reject) => {
      const protocol = url.startsWith('https') ? https : http;
      let receivedBytes = 0;

      const req = protocol.get(url, (res) => {
        if (res.statusCode !== 200) {
          return reject(new Error(`HTTP error! status: ${res.statusCode}`));
        }

        const contentLength = parseInt(res.headers['content-length'], 10);
        if (contentLength > this.maxFileSize) {
          return reject(new Error(`File size exceeds maximum allowed size of ${this.maxFileSize} bytes`));
        }

        const writeStream = fs.createWriteStream(destination);
        
        res.on('data', (chunk) => {
          receivedBytes += chunk.length;
          if (receivedBytes > this.maxFileSize) {
            req.destroy();
            writeStream.destroy();
            reject(new Error(`File size exceeds maximum allowed size`));
          }
        });

        res.pipe(writeStream);

        writeStream.on('finish', () => {
          writeStream.close(() => {
            resolve(destination);
          });
        });

        writeStream.on('error', (err) => {
          reject(err);
        });
      });

      req.on('error', (err) => {
        reject(err);
      });

      req.setTimeout(this.timeout, () => {
        req.destroy();
        reject(new Error('Request timeout'));
      });

      req.end();
    });
  }

  async extractZip(zipPath, extractTo) {
    return new Promise((resolve, reject) => {
      const platform = process.platform;
      let command, args;

      if (platform === 'win32') {
        command = 'powershell';
        args = [
          '-Command',
          `Expand-Archive -Path "${zipPath}" -DestinationPath "${extractTo}" -Force`
        ];
      } else {
        command = 'unzip';
        args = ['-o', zipPath, '-d', extractTo];
      }

      const child = spawn(command, args, { cwd: this.tempDir });

      let errorOutput = '';
      child.stderr.on('data', (data) => {
        errorOutput += data.toString();
      });

      child.on('close', (code) => {
        if (code === 0) {
          resolve(extractTo);
        } else {
          reject(new Error(`Failed to extract ZIP: ${errorOutput}`));
        }
      });

      child.on('error', (err) => {
        reject(err);
      });
    });
  }

  async cloneGitRepository(url, destination, options = {}) {
    const { branch = 'main', depth = 1 } = options;
    
    const args = [
      'clone',
      '--depth', depth.toString(),
      '--branch', branch
    ];

    if (options.singleBranch) {
      args.push('--single-branch');
    }

    args.push(url, destination);

    return new Promise((resolve, reject) => {
      const child = spawn('git', args, { cwd: this.tempDir });

      let errorOutput = '';
      child.stderr.on('data', (data) => {
        errorOutput += data.toString();
      });

      child.on('close', (code) => {
        if (code === 0) {
          resolve(destination);
        } else {
          reject(new Error(`Failed to clone repository: ${errorOutput}`));
        }
      });

      child.on('error', (err) => {
        reject(err);
      });
    });
  }

  async downloadAndExtract(url, options = {}) {
    const tempDir = this.generateTempDir();
    
    if (url.startsWith('zip:')) {
      const zipUrl = url.substring(4);
      const zipPath = path.join(tempDir, 'downloaded.zip');
      
      try {
        await this.downloadZipFromUrl(zipUrl, zipPath);
        await this.extractZip(zipPath, tempDir);
        
        fs.unlinkSync(zipPath);
        
        const extractedDir = this.findExtractedDirectory(tempDir);
        return extractedDir || tempDir;
      } catch (error) {
        this.cleanup(tempDir);
        throw error;
      }
    } else if (url.startsWith('git:')) {
      const gitUrl = url.substring(4);
      const repoDir = path.join(tempDir, 'repo');
      
      try {
        await this.cloneGitRepository(gitUrl, repoDir, options);
        return repoDir;
      } catch (error) {
        this.cleanup(tempDir);
        throw error;
      }
    } else if (url.startsWith('local:')) {
      const localPath = url.substring(6);
      if (fs.existsSync(localPath)) {
        return localPath;
      }
      throw new Error(`Local path not found: ${localPath}`);
    } else {
      throw new Error(`Unsupported URL scheme: ${url}`);
    }
  }

  findExtractedDirectory(baseDir) {
    try {
      const entries = fs.readdirSync(baseDir, { withFileTypes: true });
      for (const entry of entries) {
        if (entry.isDirectory() && entry.name !== 'node_modules') {
          const subEntries = fs.readdirSync(path.join(baseDir, entry.name));
          if (subEntries.length > 0) {
            return path.join(baseDir, entry.name);
          }
        }
      }
    } catch (error) {
      console.warn(`Failed to find extracted directory: ${error.message}`);
    }
    return null;
  }

  validatePath(filePath) {
    const resolved = path.resolve(filePath);
    const allowedPrefixes = [process.cwd(), this.tempDir];
    
    for (const prefix of allowedPrefixes) {
      if (resolved.startsWith(path.resolve(prefix))) {
        return true;
      }
    }
    
    return false;
  }

  cleanup(directory) {
    try {
      if (fs.existsSync(directory)) {
        fs.rmSync(directory, { recursive: true, force: true });
      }
    } catch (error) {
      console.warn(`Failed to cleanup directory ${directory}: ${error.message}`);
    }
  }

  cleanupAll() {
    try {
      if (fs.existsSync(this.tempDir)) {
        fs.rmSync(this.tempDir, { recursive: true, force: true });
      }
      this.init();
    } catch (error) {
      console.warn(`Failed to cleanup temp directory: ${error.message}`);
    }
  }

  async getRepositoryInfo(url) {
    if (url.startsWith('git:')) {
      const gitUrl = url.substring(4);
      try {
        const { stdout } = await execAsync(`git ls-remote --get-url "${gitUrl}" 2>/dev/null || echo "unknown"`);
        return { type: 'git', url: gitUrl, valid: stdout.trim() !== 'unknown' };
      } catch (error) {
        return { type: 'git', url: gitUrl, valid: false, error: error.message };
      }
    } else if (url.startsWith('zip:')) {
      const zipUrl = url.substring(4);
      return { type: 'zip', url: zipUrl, valid: this.isValidUrl(zipUrl) };
    } else if (url.startsWith('local:')) {
      const localPath = url.substring(6);
      return { type: 'local', path: localPath, valid: fs.existsSync(localPath) };
    }
    
    return { type: 'unknown', valid: false };
  }

  isValidUrl(string) {
    try {
      new URL(string);
      return true;
    } catch (_) {
      return false;
    }
  }
}

export { RemoteRepositoryManager };