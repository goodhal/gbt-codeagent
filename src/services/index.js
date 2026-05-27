/**
 * 服务模块统一入口
 * 提供所有服务的便捷访问方式
 */

export { CodeAnalysisTool } from './codeAnalysis.js';
export { RAGService, ragService } from './ragService.js';

export { LLMFactory, createLLMService } from './llmFactory.js';
export { DefensiveLlmReviewer } from './llmReviewService.js';
export { QuickScanService } from './quickScanService.js';
export { FingerprintService } from './fingerprintService.js';
export { ValidationService } from './validationService.js';
export { ExternalToolService } from './externalToolService.js';
export { writeAuditHtmlReport, writeSarifReport } from './reportWriter.js';
export { StreamService } from './streamService.js';
export { MemoryStore } from './memoryStore.js';
export { Splitter } from './splitter.js';
export { Sandbox } from './sandbox.js';

/**
 * AiCodeAudit 增强模块
 */
export { getSecurityHintProfile, securityHintScore, LANGUAGE_SECURITY_HINT_PATTERNS } from './securityHintProfile.js';
export { AuditCandidateFilter } from './auditCandidateFilter.js';
export { AuditFailureTracker, TokenPreChecker, AgentOutputValidator, buildDependencyContext, formatDependencyContextText } from './auditEnhancer.js';

/**
 * AST工具模块统一入口
 */

export { ASTBuilderService, QueryEngine, SearchHandler, ASTPersistenceManager } from '../utils/index.js';

/**
 * 分析器模块统一入口
 */

export { StaticAnalyzer, TaintAnalyzer, PatternAnalyzer, CompositeAnalyzer, RulesEngine, getRulesEngine } from '../analyzers/index.js';

/**
 * 知识模块统一入口
 */

export { KnowledgeIndex, globalKnowledgeIndex, VulnerabilityPatterns, CWE_CATEGORIES, Severity, KnowledgeCategory, ALL_VULNERABILITY_DOCS } from '../knowledge/index.js';

/**
 * 核心工具统一入口
 */

export { AgentRegistry, registerAgent } from '../core/agentRegistry.js';
export { CircuitBreaker } from '../core/circuitBreaker.js';
export { TokenBucketRateLimiter, RateLimiterRegistry } from '../core/rateLimiter.js';
export { withRetry, withRetryWithFallback, createRetryDecorator } from '../core/retry.js';
export { StatePersistence, globalStatePersistence } from '../core/stateManager.js';
// telemetry 已移除（未使用）


export { PromptCacheManager } from '../core/promptCache.js';
export { AgentGraphController, globalGraphController, MessageBus } from '../core/graphController.js';
export { errors } from '../core/errors.js';
