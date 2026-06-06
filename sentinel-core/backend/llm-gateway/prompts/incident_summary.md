Summarize the security incident for entity `{{entity_id}}` for a SOC analyst.

Grounded data available to you:
- Threat score: {{threat_score}}
- Recent audit activity: {{audit_excerpt}}
- Current enforcement state: {{enforcement_state}}

Produce:
1. Bottom line (1 sentence): what appears to be happening and how urgent.
2. Evidence: the grounded facts, each with an inline citation.
3. Recommended next step: if enforcement is warranted, describe a reversible
   action to propose (do not execute it). Otherwise say monitoring suffices.

Cite every fact. If a field above is empty or says "none", treat it as
"no data available" rather than guessing.
