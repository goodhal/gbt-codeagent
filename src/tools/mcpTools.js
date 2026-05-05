const MCP_TOOLS = [
  {
    name: 'local_file_content',
    description: '获取本地仓库中指定文件的完整内容，用于分析代码逻辑、函数定义、变量声明等',
    inputSchema: {
      type: 'object',
      properties: {
        file_path: {
          type: 'string',
          description: '文件路径（相对于仓库根目录）'
        },
        ref: {
          type: 'string',
          description: '分支或提交引用（可选，默认为当前分支）'
        }
      },
      required: ['file_path']
    }
  },
  {
    name: 'local_file_info',
    description: '获取本地仓库中指定文件的基本信息（行数、大小、类型等），用于了解文件结构',
    inputSchema: {
      type: 'object',
      properties: {
        file_path: {
          type: 'string',
          description: '文件路径（相对于仓库根目录）'
        }
      },
      required: ['file_path']
    }
  },
  {
    name: 'local_project_structure',
    description: '获取本地仓库的完整项目结构，包括所有文件和目录，用于了解项目组织架构',
    inputSchema: {
      type: 'object',
      properties: {
        include_content: {
          type: 'boolean',
          description: '是否包含文件内容预览（可选，默认false）'
        },
        file_type_filter: {
          type: 'string',
          description: '文件类型过滤（如 go、py、js 等，可选）'
        }
      }
    }
  },
  {
    name: 'local_search_code',
    description: '在本地仓库中搜索指定的文本或模式，用于查找相关代码、函数调用、变量使用等',
    inputSchema: {
      type: 'object',
      properties: {
        query: {
          type: 'string',
          description: '要搜索的文本或模式'
        },
        file_type: {
          type: 'string',
          description: '文件类型过滤（如 go、py、js）'
        },
        case_sensitive: {
          type: 'boolean',
          description: '是否区分大小写（可选，默认false）'
        }
      },
      required: ['query']
    }
  },
  {
    name: 'local_global_search',
    description: '全局搜索功能，支持多文件、多模式、跨文件搜索，用于深度代码分析',
    inputSchema: {
      type: 'object',
      properties: {
        search_patterns: {
          type: 'array',
          description: '搜索模式列表，支持多个关键词同时搜索',
          items: { type: 'string' }
        },
        file_patterns: {
          type: 'array',
          description: '文件模式过滤（如 *.go、*.py 等）',
          items: { type: 'string' }
        },
        exclude_patterns: {
          type: 'array',
          description: '排除的文件模式（如 *.test.go、vendor/* 等）',
          items: { type: 'string' }
        },
        case_sensitive: {
          type: 'boolean',
          description: '是否区分大小写（可选，默认false）'
        },
        include_context: {
          type: 'boolean',
          description: '是否包含上下文行（可选，默认true）'
        },
        context_lines: {
          type: 'integer',
          description: '上下文行数（可选，默认3行）'
        }
      },
      required: ['search_patterns']
    }
  },
  {
    name: 'local_context_analysis',
    description: '分析代码片段的上下文关系，包括前后代码、函数调用、数据流等，用于理解代码逻辑',
    inputSchema: {
      type: 'object',
      properties: {
        file_path: {
          type: 'string',
          description: '文件路径'
        },
        line_number: {
          type: 'integer',
          description: '行号'
        },
        context_lines: {
          type: 'integer',
          description: '上下文行数（可选，默认5行）'
        }
      },
      required: ['file_path', 'line_number']
    }
  },
  {
    name: 'local_function_analysis',
    description: '分析特定函数的完整定义、调用关系、参数传递等，用于深入理解函数逻辑',
    inputSchema: {
      type: 'object',
      properties: {
        file_path: {
          type: 'string',
          description: '文件路径'
        },
        function_name: {
          type: 'string',
          description: '函数名称'
        },
        include_calls: {
          type: 'boolean',
          description: '是否包含函数调用信息（可选，默认true）'
        }
      },
      required: ['file_path', 'function_name']
    }
  },
  {
    name: 'local_recursive_function_analysis',
    description: '递归分析函数调用链，追踪函数间的调用关系，深入分析被调用函数的实现',
    inputSchema: {
      type: 'object',
      properties: {
        file_path: {
          type: 'string',
          description: '起始文件路径'
        },
        function_name: {
          type: 'string',
          description: '起始函数名称'
        },
        max_depth: {
          type: 'integer',
          description: '最大递归深度（可选，默认3层）'
        },
        analyze_cross_file_calls: {
          type: 'boolean',
          description: '是否分析跨文件调用（可选，默认true）'
        }
      },
      required: ['file_path', 'function_name']
    }
  },
  {
    name: 'local_dependency_analysis',
    description: '分析项目依赖的基本信息，包括版本、依赖关系等',
    inputSchema: {
      type: 'object',
      properties: {
        file_path: {
          type: 'string',
          description: '依赖文件路径（如 go.mod、package.json、requirements.txt 等）'
        }
      },
      required: ['file_path']
    }
  }
];

const MCP_TOOL_NAMES = MCP_TOOLS.map(t => t.name);

function getMCPTool(toolName) {
  return MCP_TOOLS.find(t => t.name === toolName);
}

function isValidMCPTool(toolName) {
  return MCP_TOOL_NAMES.includes(toolName);
}

function formatToolsForPrompt() {
  return MCP_TOOLS.map(tool => {
    const inputSchema = JSON.stringify(tool.inputSchema, null, 2)
      .replace(/"([^"]+)":/g, '$1:')
      .replace(/"/g, "'");
    return `${tool.name}: ${tool.description}\nInput: ${inputSchema}`;
  }).join('\n\n');
}

export {
  MCP_TOOLS,
  MCP_TOOL_NAMES,
  getMCPTool,
  isValidMCPTool,
  formatToolsForPrompt
};