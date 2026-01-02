try:
    from langchain.agents import create_tool_calling_agent
    from langchain.agents import AgentExecutor
    print("Success: standard import")
except ImportError as e:
    print(f"Failed standard: {e}")
    try:
        from langchain.agents import create_tool_calling_agent
        from langchain.agents.agent import AgentExecutor
        print("Success: split import")
    except ImportError as e2:
        print(f"Failed split: {e2}")
