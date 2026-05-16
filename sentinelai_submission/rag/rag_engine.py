import os, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))
import chromadb
from google import genai
from dotenv import load_dotenv

load_dotenv(Path(__file__).parent.parent / ".env")
client = genai.Client(api_key=os.getenv("GEMINI_API_KEY"))

SAMPLE_DOCUMENTS = [
    {"id":"hr_001","category":"hr","title":"Parental Leave Policy","content":"Employees are entitled to 16 weeks paid parental leave upon birth or adoption. Primary caregivers: 16 weeks; secondary: 6 weeks. Apply via HR portal 60 days in advance. Must be taken within 12 months of qualifying event."},
    {"id":"hr_002","category":"hr","title":"Remote Work Policy","content":"Employees may work remotely up to 3 days per week with manager approval. Core hours 10am-3pm local time. VPN required. Equipment provided. Home office stipend: $500/year."},
    {"id":"hr_003","category":"hr","title":"Performance Review Process","content":"Annual reviews in December. Mid-year check-ins in June. 1-5 scale across: delivery, collaboration, innovation, communication, leadership. Ratings above 4 qualify for promotion consideration."},
    {"id":"legal_001","category":"legal","title":"NDA Template — Standard","content":"Standard NDA covers confidential information between parties. Duration: 2 years post-engagement. Carve-outs: publicly available info, independently developed IP, legally compelled disclosures. Governing law: Delaware. Requires Legal countersignature."},
    {"id":"legal_002","category":"legal","title":"Data Processing Agreement","content":"DPA required for all third-party processors handling EU personal data. GDPR Article 28 compliance mandatory. Sub-processors must be listed. 72-hour breach notification. Annual audit rights included."},
    {"id":"finance_001","category":"finance","title":"Expense Policy Q3 2024","content":"Meal limits: $75/person client, $25 team. Travel: economy domestic, business for 6+ hour flights. Hotel: $250/night major cities. All expenses over $500 require VP approval. Submit within 30 days."},
    {"id":"finance_002","category":"finance","title":"Budget Allocation FY2025","content":"Total: $12.4M. Engineering: $5.2M (42%). Sales: $3.1M (25%). Marketing: $1.8M (15%). Operations: $1.4M (11%). R&D: $0.9M (7%). Q1 on track. Q2 projected 8% under budget."},
    {"id":"finance_003","category":"finance","title":"Vendor Payment Terms","content":"Standard terms: Net 30. Strategic vendors: Net 15 with 2% early payment discount. Invoices require PO number. Over $10K requires dual approval. ACH preferred."},
    {"id":"devops_001","category":"devops","title":"Incident Response Runbook","content":"P0: Page on-call immediately, war room in 15min, exec comms in 30min. P1: Respond within 1hr. P2: 4hrs. All incidents require post-mortem within 5 business days. Use PagerDuty."},
    {"id":"devops_002","category":"devops","title":"Deployment Process","content":"All deployments need: passing CI, 2-engineer code review, staging validation, release notes. Production: Tue-Thu 10am-3pm only. Feature flags mandatory for all new features."},
    {"id":"devops_003","category":"devops","title":"Security Scanning Requirements","content":"All code must pass: SAST (Semgrep), dependency scan (Snyk), container scan (Trivy). Critical/High vulnerabilities block deployment. DAST scan quarterly. Pen test annually."},
]

class RAGEngine:
    def __init__(self):
        self.db = chromadb.Client()
        self.col = self.db.get_or_create_collection("sentinelai_kb")
        self._ingest()

    def _embed(self, text: str) -> list[float]:
        try:
            r = client.models.embed_content(model="text-embedding-004", contents=text)
            return r.embeddings[0].values
        except Exception:
            import hashlib
            h = hashlib.md5(text.encode()).hexdigest()
            return [int(h[i:i+2],16)/255.0 for i in range(0,min(len(h)*2,1536),2)][:768]

    def _ingest(self):
        if self.col.count() >= len(SAMPLE_DOCUMENTS):
            return
        for doc in SAMPLE_DOCUMENTS:
            try:
                self.col.add(ids=[doc["id"]], embeddings=[self._embed(doc["content"])],
                             documents=[doc["content"]], metadatas=[{"category":doc["category"],"title":doc["title"]}])
            except Exception:
                pass

    def build_context(self, query: str, category: str = None) -> str:
        try:
            where = {"category": category} if category else None
            res = self.col.query(query_embeddings=[self._embed(query)],
                                 n_results=min(3, self.col.count()), where=where)
            if not res["documents"][0]:
                return ""
            ctx = "Relevant company knowledge base:\n\n"
            for i, doc in enumerate(res["documents"][0]):
                meta = res["metadatas"][0][i]
                ctx += f"[{meta['title']}]\n{doc}\n\n"
            return ctx
        except Exception:
            return ""

rag_engine = RAGEngine()
