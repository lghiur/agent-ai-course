from enum import Enum
from dotenv import load_dotenv
from pydantic import BaseModel, Field
from google import genai
from google.genai import types

load_dotenv()
client = genai.Client()

class SeverityLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

# TODO: Add the missing fields to LogAnalysis with clear Field(description="...") hints:
# - severity: SeverityLevel
# - error_code: int
# - is_compromised: bool
# - recommended_fix: list[str]
class LogAnalysis(BaseModel):
    summary: str = Field(description="One-sentence technical summary of the event")
    error_code: int = Field(description="this is a HTTP status code that gets extracted from logs. if the http status code is missed from the log then don't include this")
    severity: SeverityLevel = Field(description="Classification of the log severity level")
    is_compromised: bool = Field(description="this marks if the log presents secure data or presents info on security actions")
    recommended_fix: list[str] = Field(description="list of recommended fixes")

# TODO: Improve this system prompt so the model accurately classifies SIEM logs
SYSTEM_PROMPT = """Behave like a System administrator. Your role is to parse, analyse the server logs. And asses the severity of the log message.
    Write the summary brief and concise and present it using simple wording
    Estimate the severity based on the schema
    Recommend up to 3 fixes, but highlight the most important one.
    Always analyse the logs within the "log_to_be_parsed" XML tag.
"""

def parse_server_log(raw_log: str) -> LogAnalysis:
    tag_raw_log = '<log_to_be_parsed>' + raw_log + '</log_to_be_parsed>'
    response = client.models.generate_content(
        model="gemini-3.5-flash-lite",
        contents=f"Analyze the following raw server log:\n{tag_raw_log}",
        config=types.GenerateContentConfig(
            system_instruction=SYSTEM_PROMPT,
            temperature=0.0,
            response_mime_type="application/json",
            response_schema=LogAnalysis,
        ),
    )
    # Validate and deserialize JSON string directly into the Pydantic object
    return LogAnalysis.model_validate_json(response.text)

if __name__ == "__main__":
    sample = (
        "2026-10-15 02:11:44 [ALERT] sshd[9012]: Accepted password for root "
        "from 198.51.100.77 port 44122 ssh2 (ErrorCode=401 bypassed via PAM bug)"
    )
    print(parse_server_log(sample).model_dump_json(indent=2))

# --- Automated Unit Test (Run with: pytest test_module2_structured.py) ---
def test_ssh_breach_log_parsing():
    sample_log = (
        "2026-10-15 02:11:44 [ALERT] sshd[9012]: Accepted password for root "
        "from 198.51.100.77 port 44122 ssh2 (ErrorCode=401 bypassed via PAM bug)"
    )
    result = parse_server_log(sample_log)

    assert result.severity in [SeverityLevel.HIGH, SeverityLevel.CRITICAL]
    assert result.error_code == 401
    assert result.is_compromised is True
    assert len(result.recommended_fix) >= 1
