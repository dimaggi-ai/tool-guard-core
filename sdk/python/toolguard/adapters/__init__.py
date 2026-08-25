"""
toolguard.adapters — framework-specific adapters for Tool Guard governance.

Each adapter lazily imports its framework dependency so the core package
remains lightweight. Install the PyPI distribution with
``pip install "toolguard-core[extra]"``. Extras:

    [langchain]    # LangChain / LangGraph
    [autogen]      # Microsoft AutoGen
    [openai]       # OpenAI native tool use
    [anthropic]    # Anthropic native tool use
"""
