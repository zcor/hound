"""
Centralized schema definitions for LLM providers.
This ensures consistency across all providers and reduces code duplication.
"""


from pydantic import BaseModel


def get_schema_definition(schema: type[BaseModel]) -> str:
    """
    Get a consistent schema definition for any Pydantic model.
    Returns a string description suitable for LLM prompts.
    """
    schema_name = schema.__name__
    
    # Define schema descriptions for common models
    SCHEMA_DEFINITIONS = {
        "GraphUpdate": """Return JSON with these fields:
- target_graph: string (graph name)
- new_nodes: array of node objects, each with:
  - id: string (unique node identifier)
  - type: string (node type)
  - label: string (human-readable label)
  - refs: array of strings (references to other nodes)
- new_edges: array of edge objects, each with:
  - type: string (edge type)
  - src: string (source node ID)
  - dst: string (destination node ID)
- node_updates: array of node update objects, each with:
  - id: string (node ID to update)
  - description: string or null (new description)
  - properties: string or null (JSON string of properties)
  - new_observations: array (LEAVE EMPTY - only for agent phase)
  - new_assumptions: array (LEAVE EMPTY - only for agent phase)
- is_complete: boolean (whether this graph is complete)
- completeness_reason: string or null (why complete or what's missing)""",

        "GraphDiscovery": """Return JSON with these fields:
- graphs_needed: array of {name: string, focus: string}
- suggested_node_types: array of strings
- suggested_edge_types: array of strings""",

        "InvestigationPlan": """Return JSON with these fields:
- investigations: array of investigation items, each containing:
  - goal: string (investigation goal or question)
  - focus_areas: array of strings
  - priority: integer (1-10, where 10 is highest)
  - reasoning: string (rationale for why this is promising)
  - category: string ("aspect" or "suspicion")
  - expected_impact: string ("high", "medium", or "low")
  
IMPORTANT: You MUST return an array with the exact number of investigations requested.""",

        "PlanBatch": """Return JSON with these fields:
- investigations: array of investigation items; for each item include:
  - goal: string (investigation goal or question)
  - focus_areas: array of strings (may be empty)
  - priority: integer 1-10 (10 = highest urgency)
  - reasoning: string explaining why now and exit criteria
  - category: string ("aspect" or "suspicion")
  - expected_impact: string ("high", "medium", or "low")

Return exactly the number of investigations requested; if none apply, return an empty array.""",

        "AgentDecision": """Return JSON with these fields:
- action: string (one of: load_graph, load_nodes, update_node, form_hypothesis, update_hypothesis, complete)
- reasoning: string (your reasoning for this action)
- parameters: object with action-specific fields:
  - For load_graph: {"graph_name": "string"}
  - For load_nodes: {"node_ids": ["array", "of", "strings"]}
  - For update_node: {"node_id": "string", "observations": ["array"], "assumptions": ["array"]}
  - For form_hypothesis: {"title": "string", "description": "string", "confidence": number 0-1}
  - For update_hypothesis: {"hypothesis_id": "string", "confidence": number, "evidence": ["array"]}
  - For complete: {} or omit entirely

IMPORTANT: Only include the parameters required for your chosen action.""",

        "AuditorDecision": """Return JSON with these fields:
- action: string (one of: read_scope, write_candidate, validate_candidate, advance_scope, declare_coverage, complete)
- reasoning: string (your reasoning for this action)
- parameters: object with action-specific fields:
  - For read_scope: {"node_ids": ["array"], "card_ids": ["array"]}
  - For write_candidate: {"title": "string", "description": "string", "vulnerability_type": "string", "severity": "critical"|"high"|"medium"|"low", "confidence": number 0-1, "file_line_evidence": [{"relpath": "string", "line_start": int, "line_end": int, "snippet": "string"}], "reasoning": "string", "numeric_gap_measurement": "string"}
  - For validate_candidate: {"candidate_index": int}
  - For advance_scope: {}
  - For declare_coverage: {"surface_name": "string", "claimed_bounds": ["string"], "expected_absent_findings": ["string"]}
  - For complete: {}

IMPORTANT: Only include the parameters required for your chosen action.
CRITICAL: write_candidate MUST include numeric_gap_measurement — a quantitative measurement of the vulnerability's impact (e.g. "4.9% fee undercharge", "116 bps divergence", "0 wei — no gap found"). No finding is accepted without a measured gap.""",

        "CandidateFinding": """Return JSON with these fields:
- title: string (concise finding title, max 120 chars)
- description: string (detailed vulnerability description with root cause)
- vulnerability_type: string (e.g. "reentrancy", "precision_loss", "access_control", "logic_error")
- severity: string ("critical", "high", "medium", or "low")
- confidence: number (0.0 to 1.0)
- file_line_evidence: array of evidence objects, each with:
  - relpath: string (relative file path)
  - line_start: integer (1-based line number)
  - line_end: integer (1-based line number)
  - snippet: string (relevant code snippet)
- reasoning: string (step-by-step reasoning chain leading to this finding)
- numeric_gap_measurement: string (REQUIRED — quantitative impact measurement, e.g. "4.9% fee undercharge per swap", "116 bps divergence in calc_withdraw_one_coin", "overflow headroom: ~1.6e17x before trigger")

CRITICAL: Every candidate MUST include a numeric_gap_measurement. Findings without quantitative evidence are rejected.""",

        "CandidateFindingBatch": """Return JSON with these fields:
- candidates: array of candidate finding objects (see CandidateFinding schema)
- scope_summary: string (brief description of the scope analyzed)
- surfaces_examined: array of strings (list of code surfaces/functions reviewed)""",

        "FPCheckPhaseResult": """Return JSON with these fields:
- phase_name: string (name of this verification phase)
- passed: boolean (whether this phase passed)
- confidence: number (0.0 to 1.0)
- reasoning: string (detailed reasoning for this phase's verdict)
- evidence: string (supporting evidence or counter-evidence found)""",

        "FPCheckVerdict": """Return JSON with these fields:
- verdict: string ("confirmed", "rejected", or "uncertain")
- confidence: number (0.0 to 1.0)
- phase_results: array of phase result objects, each with:
  - phase_name: string
  - passed: boolean
  - confidence: number (0.0-1.0)
  - reasoning: string
  - evidence: string
- devil_advocate_notes: string (adversarial counter-arguments to the finding)
- poc_stub: string (executable proof-of-concept code stub)
- negative_poc: string (test demonstrating the fix or guard that prevents exploitation)
- reasoning: string (overall verdict reasoning synthesizing all phases)
- numeric_gap_verified: boolean (whether the claimed numeric gap was independently verified)
- verified_gap_value: string (independently measured gap value, may differ from candidate's claim)""",

        "CoverageDeclaration": """Return JSON with these fields:
- surface_name: string (name of the code surface/component being declared covered)
- claimed_bounds: array of strings (specific claims about what was checked, with measured bounds)
- expected_absent_findings: array of strings (findings that, if they existed, would invalidate this coverage claim — the "what would prove this wrong" gate)
- unchecked_surfaces: array of strings (surfaces explicitly acknowledged as not yet covered)
- status: string ("covered", "partial", or "needs_more_investigation")""",
    }
    
    # Return predefined schema if available
    if schema_name in SCHEMA_DEFINITIONS:
        return SCHEMA_DEFINITIONS[schema_name]
    
    # Otherwise, generate schema from Pydantic model
    schema_fields = []
    for field_name, field_info in schema.model_fields.items():
        field_type = str(field_info.annotation).replace('typing.', '')
        description = field_info.description or ""
        schema_fields.append(f"- {field_name}: {field_type} {f'({description})' if description else ''}")
    
    return "\nReturn JSON with these fields:\n" + "\n".join(schema_fields)
