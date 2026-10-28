import json
from dotenv import load_dotenv
from google import genai
from google.genai import types

load_dotenv()
client = genai.Client()

# 1. Deterministic local function with type annotations and docstring
def lookup_cve_details(cve_id: str) -> str:
    """Look up the CVSS severity score and technical summary for a given CVE identifier.

    Args:
        cve_id: The official CVE string, for example 'CVE-2024-3094'.
    """
    mock_db = {
        "CVE-2024-3094": {
            "cvss": 10.0,
            "affected": "xz-utils 5.6.0 and 5.6.1",
            "summary": "Malicious backdoor injected into liblzma build process hooking RSA_public_decrypt in sshd.",
        },
        "CVE-2021-44228": {
            "cvss": 10.0,
            "affected": "Apache Log4j2 2.0-beta9 to 2.14.1",
            "summary": "Unauthenticated remote code execution via JNDI lookup in logged messages (Log4Shell).",
        },
    }
    record = mock_db.get(cve_id.upper(), {"error": f"No record found for {cve_id}"})
    return json.dumps(record)

def get_installed_packages(hostname: str):
  """List the packages installed on a host, with their versions.

    Args:
        hostname: The host to inspect, for example 'db-prod-01'.
    """
  if hostname == 'db-prod-01':
    return ["openssh-server 9.6", "xz-utils 5.6.1", "postgresql 16"]    
  return []

TOOLS = {
    "lookup_cve_details": lookup_cve_details,
    "get_installed_packages": get_installed_packages
}

def run_tool(name: str, args: dict):
    func = TOOLS.get(name)
    if func is None:
        return {"error": f"Unknown tool: {name}"}
    try:
        return func(**args)   # same as lookup_cve_details(cve_id="CVE-2024-3094")
    except Exception as e:
        return {"error": str(e)}

def call_llm(messages, config):
    response = client.models.generate_content(
        model="gemini-3.5-flash-lite",
        contents=messages,
        config=config,
    )
    return response

def extract_tool_and_call(tool_call):
    print(f"[LLM Requested Tool] Name: {tool_call.name} | Args: {tool_call.args}")
    tool_output = run_tool(tool_call.name, tool_call.args)
    print(f"[Local Function Output] {tool_output}")

    return tool_output

def run_manual_tool_roundtrip(user_prompt: str):
    # We disable automatic_function_calling so you can build the 4-step round-trip yourself
    config = types.GenerateContentConfig(
        system_instruction="You are a cybersecurity assistant. Always use tools to verify CVE data.",
        tools=[lookup_cve_details, get_installed_packages],
        automatic_function_calling=types.AutomaticFunctionCallingConfig(disable=True),
        temperature=0.0,
    )

    messages = [types.Content(role="user", parts=[types.Part.from_text(text=user_prompt)])]
    response = call_llm(messages, config)
    nr_iterations = 5
  
    for _ in range(nr_iterations):
        if not response.function_calls:
            print(f"Final Result:\n{response.text}")
            break

        messages.append(response.candidates[0].content)

        response_parts = []
        for fc in response.function_calls:
            tool_output = extract_tool_and_call(fc)
            response_parts.append(
                types.Part.from_function_response(
                    name=fc.name,
                    response={"result": tool_output},
                )
            )
        messages.append(types.Content(role="user", parts=response_parts))

        response = call_llm(messages, config)
    else:
        print(f"Stopped after {nr_iterations} iterations without a final answer")

if __name__ == "__main__":
    run_manual_tool_roundtrip("What is CVE-2024-3094, what versions are affected, and how severe is it?")

