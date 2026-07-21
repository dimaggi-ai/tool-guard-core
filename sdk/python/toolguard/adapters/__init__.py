"""
toolguard.adapters — framework-specific adapters for Tool Guard governance.

Each adapter lazily imports its framework dependency so the core package
remains lightweight. Not yet published to PyPI — install from a clone of
this repo (pip install "./tool-guard-core/sdk/python[extra]"), extras:

    [langchain]    # LangChain / LangGraph
    [autogen]      # Microsoft AutoGen
    [openai]       # OpenAI native tool use
    [anthropic]    # Anthropic native tool use
"""
