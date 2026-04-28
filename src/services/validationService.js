import { promises as fs } from "node:fs";
import path from "node:path";

/**
 * 漏洞验证服务
 * 负责验证漏洞发现的准确性，包括：
 * - 代码片段验证
 * - 行号修正
 * - 状态更新
 */
export class ValidationService {
  async validateCodeSnippet(filePath, line, codeSnippet, preloadedLines = null) {
    try {
      const lines = preloadedLines || (await fs.readFile(filePath, "utf8")).split("\n");
      
      if (line < 1 || line > lines.length) {
        return {
          valid: false,
          error: `行号 ${line} 超出范围 (1-${lines.length})`
        };
      }
      
      const codeLines = codeSnippet.split("\n").filter(l => l.trim());
      const keywords = codeLines
        .map(l => l.trim())
        .filter(l => l.length > 3);
      
      if (keywords.length === 0) {
        return {
          valid: false,
          error: "代码片段为空"
        };
      }

      const regexPattern = keywords[0].replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      const keywordRegex = new RegExp(regexPattern, "i");
      
      let grepMatchLine = null;
      let grepMatchContent = null;
      let grepFirstMatchLine = null;
      let grepFirstMatchContent = null;
      
      for (let i = 0; i < lines.length; i++) {
        if (keywordRegex.test(lines[i])) {
          if (i + 1 === line) {
            grepMatchLine = i + 1;
            grepMatchContent = lines[i].trim();
          }
          if (grepFirstMatchLine === null) {
            grepFirstMatchLine = i + 1;
            grepFirstMatchContent = lines[i].trim();
          }
          if (grepMatchLine !== null && grepFirstMatchLine !== null) {
            break;
          }
        }
      }
      
      if (grepMatchLine !== null) {
        return {
          valid: true,
          actualCode: grepMatchContent,
          verifiedBy: "keyword_search"
        };
      }
      
      if (grepFirstMatchLine !== null) {
        return {
          valid: true,
          correctedLine: grepFirstMatchLine,
          actualCode: grepFirstMatchContent,
          originalLine: line,
          verifiedBy: "keyword_search"
        };
      }
      
      const targetLine = lines[line - 1];
      const hasMatch = keywords.some(keyword => 
        targetLine.includes(keyword)
      );
      
      if (hasMatch) {
        return {
          valid: true,
          actualCode: targetLine.trim()
        };
      }
      
      const searchRange = 10;
      const startLine = Math.max(0, line - searchRange - 1);
      const endLine = Math.min(lines.length, line + searchRange);
      
      for (let i = startLine; i < endLine; i++) {
        const currentLine = lines[i];
        const lineHasMatch = keywords.some(keyword => 
          currentLine.includes(keyword)
        );
        
        if (lineHasMatch) {
          return {
            valid: true,
            correctedLine: i + 1,
            actualCode: currentLine.trim(),
            originalLine: line
          };
        }
      }
      
      return {
        valid: false,
        error: "代码片段未在文件中找到",
        searchedRange: `${startLine + 1}-${endLine}`
      };
      
    } catch (error) {
      return {
        valid: false,
        error: `读取文件失败：${error.message}`
      };
    }
  }
  
  /**
   * 批量验证漏洞发现
   * @param {Array} findings - 漏洞发现列表
   * @param {string} projectRoot - 项目根路径
   * @param {number} maxWorkers - 最大并发数
   * @returns {Promise<{validated: Array, hallucinations: Array, corrected: Array}>}
   */
  async validateFindings(findings, projectRoot, maxWorkers = 4) {
    const validated = [];
    const hallucinations = [];
    const corrected = [];
    
    // 按文件分组，批量读取
    const fileMap = new Map();
    for (const finding of findings) {
      let filePath;
      if (finding.file) {
        // 快速扫描和外部工具的发现
        filePath = path.join(projectRoot, finding.file);
      } else if (finding.location) {
        // 规则检测的发现，从location中提取文件路径
        const locationParts = finding.location.split(':');
        if (locationParts.length >= 1) {
          const relativePath = locationParts[0];
          filePath = path.join(projectRoot, relativePath);
        } else {
          // 无法提取文件路径，跳过验证
          hallucinations.push({
            ...finding,
            validationError: "无法提取文件路径"
          });
          continue;
        }
      } else {
        // 没有文件路径信息，跳过验证
        hallucinations.push({
          ...finding,
          validationError: "缺少文件路径信息"
        });
        continue;
      }
      
      if (!fileMap.has(filePath)) {
        fileMap.set(filePath, []);
      }
      fileMap.get(filePath).push(finding);
    }
    
    // 并发验证每个文件的发现
    const validationPromises = [];
    const batchSize = Math.ceil(fileMap.size / maxWorkers);
    const batches = [];
    
    let batch = [];
    for (const [filePath, fileFindings] of fileMap) {
      batch.push({ filePath, fileFindings });
      if (batch.length >= batchSize) {
        batches.push([...batch]);
        batch = [];
      }
    }
    if (batch.length > 0) {
      batches.push(batch);
    }
    
    for (const batch of batches) {
      const batchPromises = batch.map(async ({ filePath, fileFindings }) => {
        const results = [];
        
        try {
          const content = await fs.readFile(filePath, "utf8");
          const lines = content.split("\n");
          
          for (const finding of fileFindings) {
            const result = await this.validateSingleFinding(finding, lines, filePath);
            results.push(result);
          }
        } catch (error) {
          // 文件读取失败，所有发现都标记为幻觉
          for (const finding of fileFindings) {
            results.push({
              finding,
              valid: false,
              error: `文件读取失败：${error.message}`,
              isHallucination: true
            });
          }
        }
        
        return results;
      });
      
      const batchResults = await Promise.all(batchPromises);
      batchResults.flat().forEach(result => {
        if (result.valid) {
          validated.push(result.finding);
          if (result.corrected) {
            corrected.push(result);
          }
        } else {
          hallucinations.push({
            ...result.finding,
            validationError: result.error
          });
        }
      });
    }
    
    return {
      validated,
      hallucinations,
      corrected
    };
  }
  
  /**
   * 验证单个漏洞发现
   * @private
   */
  async validateSingleFinding(finding, lines, filePath) {
    let { line, codeSnippet } = finding;
    
    if (!line && finding.location) {
      const locationParts = finding.location.split(':');
      if (locationParts.length >= 2) {
        line = parseInt(locationParts[1], 10);
      }
    }
    
    if (!line) {
      return {
        finding,
        valid: false,
        error: "缺少行号信息",
        isHallucination: true
      };
    }
    
    if (!codeSnippet && line >= 1 && line <= lines.length) {
      codeSnippet = lines[line - 1];
    }
    
    const result = await this.validateCodeSnippet(filePath, line, codeSnippet || "", lines);
    
    if (result.valid) {
      const updatedFinding = {
        ...finding,
        status: "有效",
        validatedCode: result.actualCode
      };
      
      if (result.correctedLine) {
        updatedFinding.line = result.correctedLine;
        updatedFinding.location = `${finding.file}:${result.correctedLine}`;
        updatedFinding.correctedFrom = result.originalLine;
      }
      
      return {
        finding: updatedFinding,
        valid: true,
        corrected: !!result.correctedLine,
        originalLine: result.originalLine,
        correctedLine: result.correctedLine
      };
    }
    
    return {
      finding,
      valid: false,
      error: result.error,
      isHallucination: true
    };
  }
  
  /**
   * 更新漏洞状态
   * @param {Array} findings - 漏洞发现列表
   * @param {Array} validatedFindings - 验证通过的发现
   * @returns {Array} 更新后的发现列表
   */
  updateFindingStatus(findings, validatedFindings) {
    const validatedMap = new Map(
      validatedFindings.map(f => {
        // 构建键，使用title作为备选（如果没有vulnType）
        const vulnType = f.vulnType || f.title || 'unknown';
        const file = f.file || (f.location ? f.location.split(':')[0] : 'unknown');
        const line = f.line || (f.location ? parseInt(f.location.split(':')[1], 10) : 0);
        return [`${file}:${line}:${vulnType}`, f];
      })
    );
    
    return findings.map(finding => {
      // 构建键，使用title作为备选（如果没有vulnType）
      const vulnType = finding.vulnType || finding.title || 'unknown';
      const file = finding.file || (finding.location ? finding.location.split(':')[0] : 'unknown');
      const line = finding.line || (finding.location ? parseInt(finding.location.split(':')[1], 10) : 0);
      const key = `${file}:${line}:${vulnType}`;
      const validated = validatedMap.get(key);
      
      if (validated) {
        return { ...validated };
      }
      
      return finding;
    });
  }
}
