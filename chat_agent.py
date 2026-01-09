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
