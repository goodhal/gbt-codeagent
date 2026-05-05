/**
 * 服务模块统一入口
 * 提供所有服务的便捷访问方式
 */

export { CodeAnalysisTool } from './codeAnalysis.js';
export { EmbeddingsService, OpenAIEmbedding, LocalEmbedding, EmbeddingProviderFactory, globalEmbeddingsService } from './embeddings.js';
export { VectorStore, SemanticSearchEngine, ChunkedVectorStore, getGlobalVectorStore, createSemanticSearchEngine } from './vectorStore.js';
export { RAGService, ragService } from './ragService.js';
export { LLMFactory, createLLMService } from './llmFactory.js';
export { DefensiveLlmReviewer } from './llmReviewService.js';
export { QuickScanService } from './quickScanService.js';
export { FingerprintService } from './fingerprintService.js';
export { ValidationService } from './validationService.js';
export { EnvironmentReport } from './environmentReport.js';
export { ExternalToolService } from './externalToolService.js';
export { ReportWriter } from './reportWriter.js';
export { StreamService } from './streamService.js';
export { MemoryStore } from './memoryStore.js';
export { SettingsStore } from './settingsStore.js';
export { Splitter } from './splitter.js';
export { Retriever } from './retriever.js';
export { Sandbox } from './sandbox.js';

/**
 * 分析器模块统一入口
 */

export { AnalyzerFactory, StaticAnalyzer, TaintAnalyzer, PatternAnalyzer, CompositeAnalyzer, RulesEngine, getRulesEngine } from '../analyzers/index.js';

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
export { withRetry } from '../core/retry.js';
export { StatePersistence, globalStatePersistence } from '../core/stateManager.js';
export { Tracer, getGlobalTracer } from '../core/telemetry.js';


export { PromptCacheManager } from '../core/promptCache.js';
export { AgentGraphController, globalGraphController, MessageBus } from '../core/graphController.js';
export { errors } from '../core/errors.js';
