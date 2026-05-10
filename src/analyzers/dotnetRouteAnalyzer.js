/**
 * .NET 路由分析器
 * 支持分析 ASP.NET MVC、ASP.NET Core、Web Forms、Web API 等框架的路由配置
 */

import { AsyncBaseAnalyzer } from './baseAnalyzer.js';
import { promises as fs } from 'node:fs';
import path from 'node:path';

export class DotnetRouteAnalyzer extends AsyncBaseAnalyzer {
  constructor(rulesEngine, options = {}) {
    super(rulesEngine, options);
    this._supportedFrameworks = ['aspnet-mvc', 'aspnet-core', 'web-forms', 'web-api'];
  }

  getSupportedLanguages() {
    return ['csharp'];
  }

  getSupportedFrameworks() {
    return [...this._supportedFrameworks];
  }

  /**
   * 分析项目中的所有路由配置
   */
  async analyze(projectPath, context = {}) {
    const results = {
      success: true,
      projectType: null,
      routes: [],
      controllers: [],
      endpoints: [],
      summary: {
        totalRoutes: 0,
        totalControllers: 0,
        totalEndpoints: 0,
        unauthorizedEndpoints: 0
      }
    };

    try {
      // 识别项目类型
      const projectType = await this._detectProjectType(projectPath);
      results.projectType = projectType;

      // 根据项目类型提取路由
      switch (projectType) {
        case 'aspnet-core':
          await this._analyzeAspNetCore(projectPath, results);
          break;
        case 'aspnet-mvc':
          await this._analyzeAspNetMvc(projectPath, results);
          break;
        case 'web-api':
          await this._analyzeWebApi(projectPath, results);
          break;
        case 'web-forms':
          await this._analyzeWebForms(projectPath, results);
          break;
        default:
          await this._analyzeGenericDotnet(projectPath, results);
      }

      // 统计摘要
      results.summary.totalRoutes = results.routes.length;
      results.summary.totalControllers = results.controllers.length;
      results.summary.totalEndpoints = results.endpoints.length;
      results.summary.unauthorizedEndpoints = results.endpoints.filter(e => !e.authorized).length;

    } catch (error) {
      console.error("DotnetRouteAnalyzer 分析失败:", error);
      results.success = false;
      results.error = error.message;
    }

    return results;
  }

  /**
   * 检测项目类型
   */
  async _detectProjectType(projectPath) {
    const files = await fs.readdir(projectPath);
    
    // 检查 ASP.NET Core 特征
    if (files.includes('Program.cs') || files.includes('Startup.cs')) {
      const programPath = path.join(projectPath, 'Program.cs');
      const startupPath = path.join(projectPath, 'Startup.cs');
      
      try {
        if (await fs.access(programPath).then(() => true).catch(() => false)) {
          const content = await fs.readFile(programPath, 'utf8');
          if (content.includes('WebApplication.CreateBuilder') || 
              content.includes('app.MapControllerRoute') ||
              content.includes('app.MapGet') ||
              content.includes('app.MapPost')) {
            return 'aspnet-core';
          }
        }
        if (await fs.access(startupPath).then(() => true).catch(() => false)) {
          const content = await fs.readFile(startupPath, 'utf8');
          if (content.includes('ConfigureServices') && content.includes('Configure')) {
            return 'aspnet-core';
          }
        }
      } catch (e) {
        // ignore
      }
    }

    // 检查 ASP.NET MVC 特征
    if (files.includes('Global.asax')) {
      const globalPath = path.join(projectPath, 'Global.asax');
      const globalCsPath = path.join(projectPath, 'Global.asax.cs');
      try {
        // 先检查 Global.asax.cs 文件
        let content = '';
        if (await fs.access(globalCsPath).then(() => true).catch(() => false)) {
          content = await fs.readFile(globalCsPath, 'utf8');
        } else {
          content = await fs.readFile(globalPath, 'utf8');
        }
        if (content.includes('RouteConfig.RegisterRoutes')) {
          return 'aspnet-mvc';
        }
        if (content.includes('WebApiConfig.Register')) {
          return 'web-api';
        }
      } catch (e) {
        // ignore
      }
    }

    // 检查 Web Forms 特征
    if (files.includes('Web.config') && files.some(f => f.endsWith('.aspx'))) {
      return 'web-forms';
    }

    // 检查是否有 .csproj 文件
    const csprojFiles = files.filter(f => f.endsWith('.csproj'));
    if (csprojFiles.length > 0) {
      try {
        const csprojContent = await fs.readFile(path.join(projectPath, csprojFiles[0]), 'utf8');
        if (csprojContent.includes('Microsoft.NET.Sdk.Web')) {
          return 'aspnet-core';
        }
        if (csprojContent.includes('Microsoft.AspNet.Mvc')) {
          return 'aspnet-mvc';
        }
      } catch (e) {
        // ignore
      }
    }

    return 'unknown';
  }

  /**
   * 分析 ASP.NET Core 项目
   */
  async _analyzeAspNetCore(projectPath, results) {
    const controllers = [];
    const endpoints = [];

    // 查找控制器文件
    const controllerFiles = await this._findFiles(projectPath, '**/*Controller.cs');
    for (const file of controllerFiles) {
      const controller = await this._parseController(file, projectPath);
      if (controller) {
        controllers.push(controller);
        endpoints.push(...controller.actions.map(action => ({
          ...action,
          controller: controller.name,
          filePath: file
        })));
      }
    }

    // 查找 Program.cs 中的最小 API 路由
    const programPath = path.join(projectPath, 'Program.cs');
    if (await fs.access(programPath).then(() => true).catch(() => false)) {
      const content = await fs.readFile(programPath, 'utf8');
      const minApiRoutes = this._parseMinApiRoutes(content);
      endpoints.push(...minApiRoutes);
    }

    results.controllers = controllers;
    results.endpoints = endpoints;
    results.routes = this._generateRoutesFromEndpoints(endpoints);
  }

  /**
   * 分析 ASP.NET MVC 项目
   */
  async _analyzeAspNetMvc(projectPath, results) {
    const controllers = [];
    const routes = [];

    // 查找控制器文件
    const controllerFiles = await this._findFiles(projectPath, '**/*Controller.cs');
    for (const file of controllerFiles) {
      const controller = await this._parseController(file, projectPath);
      if (controller) {
        controllers.push(controller);
      }
    }

    // 解析 RouteConfig.cs 中的约定路由
    const routeConfigPath = path.join(projectPath, 'App_Start', 'RouteConfig.cs');
    if (await fs.access(routeConfigPath).then(() => true).catch(() => false)) {
      const content = await fs.readFile(routeConfigPath, 'utf8');
      const configRoutes = this._parseMvcRouteConfig(content);
      routes.push(...configRoutes);
    }

    // 从控制器生成路由
    const controllerRoutes = this._generateRoutesFromControllers(controllers);
    routes.push(...controllerRoutes);

    results.controllers = controllers;
    results.routes = routes;
    results.endpoints = this._generateEndpointsFromRoutes(routes);
  }

  /**
   * 分析 Web API 项目
   */
  async _analyzeWebApi(projectPath, results) {
    const controllers = [];
    const routes = [];

    // 查找控制器文件
    const controllerFiles = await this._findFiles(projectPath, '**/*Controller.cs');
    for (const file of controllerFiles) {
      const controller = await this._parseApiController(file, projectPath);
      if (controller) {
        controllers.push(controller);
      }
    }

    // 解析 WebApiConfig.cs
    const apiConfigPath = path.join(projectPath, 'App_Start', 'WebApiConfig.cs');
    if (await fs.access(apiConfigPath).then(() => true).catch(() => false)) {
      const content = await fs.readFile(apiConfigPath, 'utf8');
      const configRoutes = this._parseWebApiRouteConfig(content);
      routes.push(...configRoutes);
    }

    results.controllers = controllers;
    results.routes = routes;
    results.endpoints = this._generateEndpointsFromRoutes(routes);
  }

  /**
   * 分析 Web Forms 项目
   */
  async _analyzeWebForms(projectPath, results) {
    const routes = [];

    // 查找 ASPX 页面
    const aspxFiles = await this._findFiles(projectPath, '**/*.aspx');
    for (const file of aspxFiles) {
      const relativePath = path.relative(projectPath, file).replaceAll('\\', '/');
      routes.push({
        url: `/${relativePath}`,
        method: 'GET',
        type: 'web-form',
        file: relativePath,
        authorized: false,
        params: []
      });
    }

    // 检查 RouteConfig.cs 中的 MapPageRoute
    const routeConfigPath = path.join(projectPath, 'App_Start', 'RouteConfig.cs');
    if (await fs.access(routeConfigPath).then(() => true).catch(() => false)) {
      const content = await fs.readFile(routeConfigPath, 'utf8');
      const pageRoutes = this._parseWebFormsRouteConfig(content);
      routes.push(...pageRoutes);
    }

    results.routes = routes;
    results.endpoints = routes.map(r => ({
      url: r.url,
      method: r.method,
      controller: null,
      action: null,
      authorized: r.authorized,
      params: r.params,
      filePath: r.file
    }));
  }

  /**
   * 分析通用 .NET 项目
   */
  async _analyzeGenericDotnet(projectPath, results) {
    const controllerFiles = await this._findFiles(projectPath, '**/*Controller.cs');
    const controllers = [];

    for (const file of controllerFiles) {
      const controller = await this._parseController(file, projectPath);
      if (controller) {
        controllers.push(controller);
      }
    }

    const routes = this._generateRoutesFromControllers(controllers);

    results.controllers = controllers;
    results.routes = routes;
    results.endpoints = this._generateEndpointsFromRoutes(routes);
  }

  /**
   * 解析控制器文件
   */
  async _parseController(filePath, projectPath) {
    const content = await fs.readFile(filePath, 'utf8');
    const relativePath = path.relative(projectPath, filePath).replaceAll('\\', '/');

    // 提取控制器名称
    const controllerNameMatch = content.match(/public\s+class\s+(\w+)Controller\s*:/);
    if (!controllerNameMatch) return null;

    const controllerName = controllerNameMatch[1];
    
    // 检查控制器级别是否有 [Authorize] 属性（在类声明之前）
    const classDeclarationIndex = content.indexOf(`public class ${controllerName}Controller`);
    const classPrefix = content.substring(0, classDeclarationIndex);
    const hasAuthorize = classPrefix.includes('[Authorize');

    // 解析操作方法
    const actions = this._parseControllerActions(content, hasAuthorize);

    return {
      name: controllerName,
      file: relativePath,
      authorized: hasAuthorize,
      actions
    };
  }

  /**
   * 解析 API 控制器
   */
  async _parseApiController(filePath, projectPath) {
    const content = await fs.readFile(filePath, 'utf8');
    const relativePath = path.relative(projectPath, filePath).replaceAll('\\', '/');

    const controllerNameMatch = content.match(/public\s+class\s+(\w+)Controller\s*:/);
    if (!controllerNameMatch) return null;

    const controllerName = controllerNameMatch[1];
    const hasAuthorize = content.includes('[Authorize');
    const hasAllowAnonymous = content.includes('[AllowAnonymous');

    // 获取路由前缀
    const routePrefixMatch = content.match(/\[RoutePrefix\(\s*["']([^"']+)["']\s*\)\]/);
    const routePrefix = routePrefixMatch ? routePrefixMatch[1] : '';

    const actions = this._parseApiActions(content, hasAuthorize, routePrefix);

    return {
      name: controllerName,
      file: relativePath,
      authorized: hasAuthorize && !hasAllowAnonymous,
      routePrefix,
      actions
    };
  }

  /**
   * 解析控制器操作方法
   */
  _parseControllerActions(content, defaultAuthorized) {
    const actions = [];
    const methodRegex = /(public\s+(async\s+)?(Task<\w+>|\w+)\s+(\w+)\s*\()/g;
    
    let match;
    while ((match = methodRegex.exec(content)) !== null) {
      const methodName = match[4];
      
      // 跳过构造函数和私有方法
      if (methodName === 'Dispose' || methodName === 'Equals' || 
          methodName === 'GetHashCode' || methodName === 'GetType' ||
          methodName === 'ToString') {
        continue;
      }

      // 提取方法的上下文
      const methodContext = this._extractMethodContext(content, match.index);
      
      // 解析路由属性
      const routeAttrs = this._parseRouteAttributes(methodContext);
      const httpMethod = this._detectHttpMethod(methodContext, methodName);
      
      // 检查授权
      const hasAuthorize = methodContext.includes('[Authorize');
      const hasAllowAnonymous = methodContext.includes('[AllowAnonymous');
      const authorized = (defaultAuthorized || hasAuthorize) && !hasAllowAnonymous;
      
      // 解析参数
      const params = this._parseMethodParameters(methodContext);

      actions.push({
        name: methodName,
        httpMethod,
        routes: routeAttrs,
        authorized,
        params
      });
    }

    return actions;
  }

  /**
   * 解析 API 控制器操作方法
   */
  _parseApiActions(content, defaultAuthorized, routePrefix) {
    const actions = [];
    const methodRegex = /(public\s+(async\s+)?(Task<\w+>|\w+)\s+(\w+)\s*\()/g;
    
    let match;
    while ((match = methodRegex.exec(content)) !== null) {
      const methodName = match[4];
      
      if (methodName === 'Dispose' || methodName === 'Equals' || 
          methodName === 'GetHashCode' || methodName === 'GetType' ||
          methodName === 'ToString') {
        continue;
      }

      const methodContext = this._extractMethodContext(content, match.index);
      const routeAttrs = this._parseRouteAttributes(methodContext, routePrefix);
      const httpMethod = this._detectHttpMethod(methodContext, methodName);
      
      const hasAuthorize = methodContext.includes('[Authorize');
      const hasAllowAnonymous = methodContext.includes('[AllowAnonymous');
      const authorized = (defaultAuthorized || hasAuthorize) && !hasAllowAnonymous;
      
      const params = this._parseMethodParameters(methodContext);

      actions.push({
        name: methodName,
        httpMethod,
        routes: routeAttrs,
        authorized,
        params
      });
    }

    return actions;
  }

  /**
   * 提取方法上下文（包含方法之前的属性）
   */
  _extractMethodContext(content, startIndex) {
    // 先向上查找属性
    const prefixContent = content.substring(0, startIndex);
    const prefixLines = prefixContent.split('\n');
    let attributeContext = '';
    
    // 从后往前查找属性行
    for (let i = prefixLines.length - 1; i >= 0; i--) {
      const line = prefixLines[i].trim();
      // 如果是属性或空白行，继续向上查找
      if (line.startsWith('[') || line === '') {
        attributeContext = line + '\n' + attributeContext;
      } else {
        break;
      }
    }
    
    // 然后提取方法内容
    const lines = content.substring(startIndex).split('\n');
    let methodContext = '';
    let braceCount = 0;
    
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      methodContext += line + '\n';
      
      braceCount += (line.match(/\{/g) || []).length;
      braceCount -= (line.match(/\}/g) || []).length;
      
      if (braceCount > 0 && i > 0 && braceCount === 0) {
        break;
      }
      
      // 如果没有大括号，只取第一行
      if (i === 0 && !line.includes('{')) {
        break;
      }
    }
    
    return attributeContext + methodContext;
  }

  /**
   * 解析路由属性
   */
  _parseRouteAttributes(context, prefix = '') {
    const routes = [];
    
    // 匹配 [Route("...")]
    const routeRegex = /\[Route\(\s*["']([^"']+)["']\s*\)\]/g;
    let match;
    while ((match = routeRegex.exec(context)) !== null) {
      let route = match[1];
      if (prefix) {
        route = prefix + (route.startsWith('/') ? '' : '/') + route;
      }
      routes.push(route);
    }
    
    // 如果没有路由属性，使用默认路由
    if (routes.length === 0) {
      routes.push('');
    }
    
    return routes;
  }

  /**
   * 检测 HTTP 方法
   */
  _detectHttpMethod(context, methodName) {
    // 优先检查属性
    if (context.includes('[HttpGet')) return 'GET';
    if (context.includes('[HttpPost')) return 'POST';
    if (context.includes('[HttpPut')) return 'PUT';
    if (context.includes('[HttpDelete')) return 'DELETE';
    if (context.includes('[HttpPatch')) return 'PATCH';
    if (context.includes('[HttpHead')) return 'HEAD';
    if (context.includes('[HttpOptions')) return 'OPTIONS';
    
    // 根据方法名推断
    const lowerName = methodName.toLowerCase();
    if (lowerName.startsWith('get')) return 'GET';
    if (lowerName.startsWith('post')) return 'POST';
    if (lowerName.startsWith('put')) return 'PUT';
    if (lowerName.startsWith('delete')) return 'DELETE';
    if (lowerName.startsWith('patch')) return 'PATCH';
    
    // 默认 GET
    return 'GET';
  }

  /**
   * 解析方法参数
   */
  _parseMethodParameters(context) {
    const params = [];
    
    // 匹配方法签名中的参数
    const paramRegex = /\(([^)]+)\)/;
    const match = context.match(paramRegex);
    
    if (match) {
      const paramStr = match[1];
      // 处理带属性的参数，按逗号分隔但跳过属性内部的逗号
      const paramTokens = this._splitParams(paramStr);
      
      for (const token of paramTokens) {
        if (!token) continue;
        
        // 移除属性装饰器，获取类型和名称
        const cleanedToken = token.replace(/\[[^\]]+\]/g, '').trim();
        const parts = cleanedToken.split(' ').filter(p => p);
        
        if (parts.length >= 2) {
          const type = parts[0];
          const name = parts[1];
          
          // 判断参数来源
          let source = 'unknown';
          if (token.includes('[FromQuery')) source = 'query';
          else if (token.includes('[FromForm')) source = 'form';
          else if (token.includes('[FromBody')) source = 'body';
          else if (token.includes('[FromRoute')) source = 'route';
          else if (token.includes('[FromHeader')) source = 'header';
          else if (token.includes('[FromServices')) source = 'service';
          
          params.push({
            name,
            type,
            source
          });
        }
      }
    }
    
    return params;
  }

  /**
   * 安全地分割参数字符串（处理属性中的逗号）
   */
  _splitParams(paramStr) {
    const result = [];
    let current = '';
    let bracketCount = 0;
    
    for (const char of paramStr) {
      if (char === '[') bracketCount++;
      else if (char === ']') bracketCount--;
      else if (char === ',' && bracketCount === 0) {
        result.push(current.trim());
        current = '';
        continue;
      }
      current += char;
    }
    
    if (current.trim()) {
      result.push(current.trim());
    }
    
    return result;
  }

  /**
   * 解析最小 API 路由
   */
  _parseMinApiRoutes(content) {
    const routes = [];
    
    // 匹配 app.MapGet, app.MapPost 等
    const mapRegex = /app\.Map(Post|Get|Put|Delete|Patch|Options|Head)\(\s*["']([^"']+)["']/g;
    
    let match;
    while ((match = mapRegex.exec(content)) !== null) {
      const method = match[1].toUpperCase();
      const url = match[2];
      
      routes.push({
        url,
        method,
        type: 'min-api',
        controller: null,
        action: null,
        authorized: false,
        params: this._extractMinApiParams(url)
      });
    }
    
    return routes;
  }

  /**
   * 从 URL 中提取参数
   */
  _extractMinApiParams(url) {
    const params = [];
    const paramRegex = /\{(\w+)(?::(\w+))?\}/g;
    
    let match;
    while ((match = paramRegex.exec(url)) !== null) {
      params.push({
        name: match[1],
        type: match[2] || 'string',
        source: 'route'
      });
    }
    
    return params;
  }

  /**
   * 解析 MVC 路由配置
   */
  _parseMvcRouteConfig(content) {
    const routes = [];
    
    // 匹配 routes.MapRoute(...)
    const routeRegex = /routes\.MapRoute\(\s*["']([^"']+)["']/g;
    
    let match;
    while ((match = routeRegex.exec(content)) !== null) {
      const name = match[1];
      
      // 提取 URL 模式
      const urlMatch = content.substring(match.index).match(/,\s*["']([^"']+)["']/);
      const url = urlMatch ? urlMatch[1] : '';
      
      routes.push({
        name,
        url,
        method: 'GET',
        type: 'mvc-route',
        authorized: false,
        params: this._extractRouteParams(url)
      });
    }
    
    return routes;
  }

  /**
   * 解析 Web API 路由配置
   */
  _parseWebApiRouteConfig(content) {
    const routes = [];
    
    // 匹配 config.Routes.MapHttpRoute(...)
    const routeRegex = /config\.Routes\.MapHttpRoute\(\s*["']([^"']+)["']/g;
    
    let match;
    while ((match = routeRegex.exec(content)) !== null) {
      const name = match[1];
      
      const urlMatch = content.substring(match.index).match(/,\s*["']([^"']+)["']/);
      const url = urlMatch ? urlMatch[1] : '';
      
      routes.push({
        name,
        url,
        method: 'GET',
        type: 'webapi-route',
        authorized: false,
        params: this._extractRouteParams(url)
      });
    }
    
    return routes;
  }

  /**
   * 解析 Web Forms 路由配置
   */
  _parseWebFormsRouteConfig(content) {
    const routes = [];
    
    // 匹配 routes.MapPageRoute(...)
    const routeRegex = /routes\.MapPageRoute\(\s*["']([^"']+)["']/g;
    
    let match;
    while ((match = routeRegex.exec(content)) !== null) {
      const name = match[1];
      
      const urlMatch = content.substring(match.index).match(/,\s*["']([^"']+)["']/);
      const url = urlMatch ? urlMatch[1] : '';
      
      routes.push({
        name,
        url,
        method: 'GET',
        type: 'webforms-route',
        authorized: false,
        params: this._extractRouteParams(url)
      });
    }
    
    return routes;
  }

  /**
   * 从路由 URL 中提取参数
   */
  _extractRouteParams(url) {
    const params = [];
    const paramRegex = /\{(\w+)\}/g;
    
    let match;
    while ((match = paramRegex.exec(url)) !== null) {
      params.push({
        name: match[1],
        type: 'string',
        source: 'route'
      });
    }
    
    return params;
  }

  /**
   * 从控制器生成路由
   */
  _generateRoutesFromControllers(controllers) {
    const routes = [];
    
    for (const controller of controllers) {
      for (const action of controller.actions) {
        for (const route of action.routes) {
          const url = route || `/${controller.name}/${action.name}`;
          
          routes.push({
            url,
            method: action.httpMethod,
            type: 'controller-action',
            controller: controller.name,
            action: action.name,
            authorized: action.authorized,
            params: action.params,
            file: controller.file
          });
        }
      }
    }
    
    return routes;
  }

  /**
   * 从端点生成路由
   */
  _generateRoutesFromEndpoints(endpoints) {
    return endpoints.map(e => ({
      url: e.url || `/${e.controller}/${e.action}`,
      method: e.method,
      type: e.type || 'controller-action',
      controller: e.controller,
      action: e.action,
      authorized: e.authorized,
      params: e.params,
      file: e.filePath
    }));
  }

  /**
   * 从路由生成端点
   */
  _generateEndpointsFromRoutes(routes) {
    return routes.map(r => ({
      url: r.url,
      method: r.method,
      controller: r.controller,
      action: r.action,
      authorized: r.authorized,
      params: r.params,
      filePath: r.file
    }));
  }

  /**
   * 查找文件
   */
  async _findFiles(dir, pattern) {
    const glob = await import('glob');
    return glob.glob(pattern, { cwd: dir, absolute: true });
  }
}