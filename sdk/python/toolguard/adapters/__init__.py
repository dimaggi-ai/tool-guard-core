"""
toolguard.adapters — framework-specific adapters for Tool Guard governance.

Each adapter lazily imports its framework dependency so the core package
remains lightweight. Install only the extras you need:

    pip install toolguard[langchain]    # LangChain / LangGraph
    pip install toolguard[autogen]      # Microsoft AutoGen
    pip install toolguard[openai]       # OpenAI native tool use
    pip install toolguard[anthropic]    # Anthropic native tool use
"""
