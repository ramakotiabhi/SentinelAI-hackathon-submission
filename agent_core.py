import os, sys, time, json, re
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))
from google import genai
from google.genai import types
from dotenv import load_dotenv
from security.policy_engine import policy_engine

load_dotenv(Path(__file__).parent.parent / ".env")
client = genai.Client(api_key=os.getenv("GEMINI_API_KEY"))

AGENT_PERSONAS = {
    "hr": {
        "name": "Aria (HR Agent)", "model": "gemini-2.0-flash",
        "system": "You are Aria, SentinelAI HR specialist. Help with employee policies, onboarding, leave, benefits. NEVER share employee PII. NEVER send data externally. Cite policy sections. Be concise.",
        "color": "#5DCAA5", "icon": "ti-users",
    },
    "legal": {
        "name": "Lex (Legal Agent)", "model": "gemini-2.0-flash-thinking-exp",
        "system": "You are Lex, SentinelAI Legal specialist. Help with contracts, compliance, regulatory questions. Provide legal information NOT advice. Flag [LEGAL RISK] for litigious content. NEVER share confidential docs with unauthorized parties.",
        "color": "#534AB7", "icon": "ti-scale",
    },
    "finance": {
        "name": "Finn (Finance Agent)", "model": "gemini-2.0-flash",
        "system": "You are Finn, SentinelAI Finance specialist. Help with expenses, budgets, forecasting, invoices. NEVER execute transactions autonomously — always flag [APPROVAL REQUIRED]. NEVER expose account numbers or credentials.",
        "color": "#EF9F27", "icon": "ti-report-money",
    },
    "devops": {
        "name": "Dev (DevOps Agent)", "model": "gemini-2.0-flash",
        "system": "You are Dev, SentinelAI DevOps specialist. Help with CI/CD, infrastructure, incidents, code review. NEVER execute destructive commands without confirmation. NEVER expose secrets. Flag [PRODUCTION RISK] for prod operations.",
        "color": "#D85A30", "icon": "ti-terminal-2",
    },
}

ROUTER_SYSTEM = """You are Sentinel, master orchestrator. Route enterprise queries to: hr / legal / finance / devops.
Respond ONLY with JSON: {"route_to": ["agent"], "reasoning": "why", "reformulated_query": "optimized query", "risk_flags": []}"""

class SentinelAgent:
    def __init__(self, agent_type: str):
        self.agent_type = agent_type
        self.persona = AGENT_PERSONAS[agent_type]
        self.history = []

    def chat(self, user_message: str, context: str = "") -> dict:
        start = time.time()
        audit = policy_engine.inspect(user_message, agent=self.agent_type)
        if audit.blocked:
            return {"agent": self.persona["name"], "agent_type": self.agent_type,
                    "response": f"[BLOCKED by SentinelAI — Policy: {audit.policy_id} | Category: {audit.category}]",
                    "blocked": True, "audit": audit.to_dict(), "latency_ms": audit.latency_ms}
        if audit.action == "HUMAN_REVIEW":
            return {"agent": self.persona["name"], "agent_type": self.agent_type,
                    "response": f"[HUMAN REVIEW REQUIRED — Ref: {audit.event_id}] A compliance officer must review before processing.",
                    "blocked": False, "needs_review": True, "audit": audit.to_dict(), "latency_ms": audit.latency_ms}
        prompt = (f"[Context: {context}]\n" if context else "") + user_message
        try:
            contents = self.history + [{"role": "user", "parts": [{"text": prompt}]}]
            resp = client.models.generate_content(
                model=self.persona["model"],
                contents=contents,
                config=types.GenerateContentConfig(system_instruction=self.persona["system"], max_output_tokens=800)
            )
            text = resp.text
            resp_audit = policy_engine.inspect(text, agent=f"{self.agent_type}_response")
            self.history.append({"role": "user", "parts": [{"text": prompt}]})
            self.history.append({"role": "model", "parts": [{"text": text}]})
            if len(self.history) > 20:
                self.history = self.history[-16:]
            return {"agent": self.persona["name"], "agent_type": self.agent_type, "response": text,
                    "blocked": False, "audit": audit.to_dict(), "response_audit": resp_audit.to_dict(),
                    "latency_ms": int((time.time()-start)*1000), "model_used": self.persona["model"]}
        except Exception as e:
            return {"agent": self.persona["name"], "agent_type": self.agent_type,
                    "response": f"Agent error: {e}", "blocked": False, "audit": audit.to_dict(), "latency_ms": 0}

class AgentOrchestrator:
    def __init__(self):
        self.agents = {k: SentinelAgent(k) for k in ["hr", "legal", "finance", "devops"]}

    def route_and_respond(self, user_message: str) -> dict:
        audit = policy_engine.inspect(user_message, agent="orchestrator")
        if audit.blocked:
            return {"routed_to": "BLOCKED", "response": f"[SENTINEL] Request denied: {audit.category}",
                    "blocked": True, "audit": audit.to_dict()}
        try:
            route_resp = client.models.generate_content(
                model="gemini-2.0-flash",
                contents=f"Route this enterprise query: {user_message}",
                config=types.GenerateContentConfig(system_instruction=ROUTER_SYSTEM, max_output_tokens=200)
            )
            m = re.search(r'\{.*\}', route_resp.text, re.DOTALL)
            routing = json.loads(m.group()) if m else {"route_to": ["hr"], "reasoning": "default", "reformulated_query": user_message, "risk_flags": []}
        except Exception:
            routing = {"route_to": ["hr"], "reasoning": "fallback", "reformulated_query": user_message, "risk_flags": []}

        agents_to_call = routing.get("route_to", ["hr"])
        query = routing.get("reformulated_query", user_message)
        responses = {}
        for ak in agents_to_call:
            if ak in self.agents:
                responses[ak] = self.agents[ak].chat(query)

        if len(responses) > 1:
            synth_prompt = f"Synthesize these responses for: '{user_message}'\n\n" + "\n\n".join(f"{k.upper()}: {v['response']}" for k,v in responses.items())
            try:
                synth = client.models.generate_content(model="gemini-2.0-flash", contents=synth_prompt)
                final = synth.text
            except Exception:
                final = list(responses.values())[0]["response"]
            primary = "orchestrator"
        elif responses:
            pk = list(responses.keys())[0]
            final = responses[pk]["response"]
            primary = pk
        else:
            final = "No agent could handle this query."
            primary = "unknown"

        return {"routed_to": agents_to_call, "primary_agent": primary,
                "reasoning": routing.get("reasoning",""), "risk_flags": routing.get("risk_flags",[]),
                "response": final, "agent_responses": responses, "blocked": False, "audit": audit.to_dict()}

orchestrator = AgentOrchestrator()
