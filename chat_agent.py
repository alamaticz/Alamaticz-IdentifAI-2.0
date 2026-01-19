import os
import asyncio
from dotenv import load_dotenv
from langchain_mcp_adapters.client import MultiServerMCPClient
from langchain_openai import ChatOpenAI
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
from langchain.agents import create_tool_calling_agent, AgentExecutor

# Load env variables if not already loaded (dashboard likely loaded them, but good for safety)
load_dotenv()

async def initialize_agent_executor(memory=None):
    """
    Initializes and returns an AgentExecutor connected to the OpenSearch MCP server.
    """
    mcp_url = os.getenv("MCP_SERVER_URL", "http://localhost:9900/sse")
    print(f"[DEBUG] MCP_SERVER_URL: {mcp_url}")
    
    # Connect to OpenSearch MCP
    mcp_server_config = {
        "opensearch": { 
            "url": mcp_url,
            "transport": "sse",
            "headers": {
                "Content-Type": "application/json",
                "Accept-Encoding": "identity",
            }
        }
    }
    
    client = MultiServerMCPClient(mcp_server_config)
    
    # Fetch tools asynchronously
    # Note: verify_tools=False might be needed if connection is flaky, but we verified it works.
    tools = await client.get_tools() 
    
    if not tools:
        raise ValueError("No tools found from MCP server.")

    model = ChatOpenAI(model="gpt-4o", streaming=True)
    
    prompt = ChatPromptTemplate.from_messages([
        ("system", "You are a helpful Log Analysis Assistant. You have access to OpenSearch logs. You usually don't need to mention Tool names. IMPORTANT: Always check the index mapping using get_mapping or similar tools before performing any searches to ensure you use the correct fields. Ensure you build syntactically correct OpenSearch DSL queries relative to the mapping found. When searching for errors or logs, ALWAYS search across 'log.message', 'exception_message', and 'log.exception.exception_message' fields. Do not rely on a single field."),
        MessagesPlaceholder(variable_name="chat_history"),
        ("human", "{input}"),
        MessagesPlaceholder(variable_name="agent_scratchpad"),
    ])

    agent = create_tool_calling_agent(
        llm=model,
        tools=tools,
        prompt=prompt
    )

    agent_executor = AgentExecutor(
        agent=agent,
        tools=tools,
        verbose=True,
        memory=memory,
        handle_parsing_errors=True,
        return_intermediate_steps=True
    )
    
    return agent_executor

async def initialize_group_chat_agent(group_id, group_context_str, memory=None):
    """
    Initializes an agent specifically for chatting about a log group.
    Has access to a local tool to update the analysis.
    """
    from langchain.tools import tool
    import Analysis_Diagnosis

    mcp_url = os.getenv("MCP_SERVER_URL", "http://localhost:9900/sse")
    
    # Connect to OpenSearch MCP
    mcp_server_config = {
        "opensearch": { 
            "url": mcp_url,
            "transport": "sse",
            "headers": {
                "Content-Type": "application/json",
                "Accept-Encoding": "identity",
            }
        }
    }
    
    client = MultiServerMCPClient(mcp_server_config)
    mcp_tools = await client.get_tools()
    
    # Define Local Tool for Updating Analysis
    @tool
    def update_group_analysis(new_report: str) -> str:
        """
        Updates the diagnosis report for the THIS current group in the database.
        Use this when the user asks to save the analysis or replace the old one.
        The input should be the full, clean text of the new report.
        """
        try:
            # We create a fresh client here to ensure thread safety / no loop issues
            os_client = Analysis_Diagnosis.get_opensearch_client()
            Analysis_Diagnosis.update_diagnosis_in_opensearch(os_client, group_id, new_report)
            return "Successfully updated the diagnosis report in the database."
        except Exception as e:
            return f"Failed to update report: {str(e)}"

    # Combine tools
    all_tools = mcp_tools + [update_group_analysis]

    model = ChatOpenAI(model="gpt-4o", streaming=True)
    
    # Escape braces in JSON for LangChain prompt template
    safe_context_str = group_context_str.replace("{", "{{").replace("}", "}}")
    
    system_prompt = f"""You are a specialized Log Analysis Assistant focusing on a SINGLE Error Group.
    
    CONTEXT_ID: {group_id}
    
    CURRENT GROUP CONTEXT:
    {safe_context_str}
    
    Your Goal:
    1. Answer questions about this specific error group.
    2. If the user asks to "save" or "update" the analysis/diagnosis, use the `update_group_analysis` tool.
    3. You can still use other OpenSearch tools to look up related logs if needed, but prioritize the context provided.
    
    When generating a new analysis to be saved, ensure it follows the standard format:
    - EXECUTIVE SUMMARY
    - SEVERITY ASSESSMENT
    - ERROR FLOW
    - ROOT CAUSE
    - IMPACT
    - RESOLUTION
    
    Keep the report text clean (no markdown in the tool input, or minimal markdown).
    """

    prompt = ChatPromptTemplate.from_messages([
        ("system", system_prompt),
        MessagesPlaceholder(variable_name="chat_history"),
        ("human", "{input}"),
        MessagesPlaceholder(variable_name="agent_scratchpad"),
    ])

    agent = create_tool_calling_agent(
        llm=model,
        tools=all_tools,
        prompt=prompt
    )

    agent_executor = AgentExecutor(
        agent=agent,
        tools=all_tools,
        verbose=True,
        memory=memory,
        handle_parsing_errors=True,
        return_intermediate_steps=True
    )
    
    return agent_executor
