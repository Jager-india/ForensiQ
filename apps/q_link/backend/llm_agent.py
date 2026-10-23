"""
Q-Link Agentic LLM & Tool-Calling Engine
Provides an autonomous forensic reasoning copilot equipped with function tools:
- get_entity_network: Traverses graph connections up to N hops.
- find_paths_between: Identifies direct and indirect conduit chains.
- get_entity_timeline: Reconstructs chronological interactions across modules.
- get_evidence_details: Fetches granular underlying evidence citations and URLs.
- evaluate_conflicts_of_interest: Checks multi-tool nexus between auditees and vendors.
- get_syndicate_overview: Synthesizes high-level network topology, high-risk clusters, and active alerts.

Supports local Model-Host (Llama-3.2-1B-Instruct), OpenAI-compatible endpoints, and resilient deterministic fallback.
"""

import re
from typing import Any

import requests
from django.conf import settings
from loguru import logger

from config import (
    DEFAULT_LLM_API_ENDPOINT,
    DEFAULT_LLM_API_KEY,
    DEFAULT_LLM_MODEL_NAME,
    DEFAULT_LLM_TIMEOUT,
    STOP_WORDS,
)
from core.prompts import render_prompt

from ..models import ForensicEntity, RelationshipAlert
from ..selectors import (
    find_paths_between,
    get_entity_evidence,
    get_entity_network,
    get_entity_timeline,
    get_high_risk_entities,
    get_link_dashboard_metrics,
    get_recent_alerts,
)


class ForensicToolRegistry:
    """
    Registry of forensic inquiry tools exposed for LLM function calling.
    """

    @staticmethod
    def get_tool_definitions() -> list[dict[str, Any]]:
        return [
            {
                "type": "function",
                "function": {
                    "name": "get_entity_network",
                    "description": "Traverses the forensic knowledge graph to find all directly and indirectly connected entities, relationship types, and confidence scores.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "entity_name": {
                                "type": "string",
                                "description": "Name or identifier of the entity to inspect (e.g. 'Vendor ABC', 'Employee X').",
                            },
                            "max_hops": {
                                "type": "integer",
                                "description": "Maximum traversal depth (default 2 hops).",
                                "default": 2,
                            },
                        },
                        "required": ["entity_name"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "find_paths_between",
                    "description": "Discovers direct and indirect multi-hop pathways connecting two entities (e.g. Employee X -> Vendor ABC -> Bank Account Y -> Person Z).",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "source_name": {
                                "type": "string",
                                "description": "Starting entity name.",
                            },
                            "target_name": {
                                "type": "string",
                                "description": "Destination entity name.",
                            },
                            "max_hops": {
                                "type": "integer",
                                "description": "Maximum number of intermediate conduits.",
                                "default": 3,
                            },
                        },
                        "required": ["source_name", "target_name"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "get_entity_timeline",
                    "description": "Retrieves the chronological sequence of all interactions involving an entity across all forensic modules (Q-Bank, Q-Ledger, Q-Mail, etc.).",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "entity_name": {
                                "type": "string",
                                "description": "Name or identifier of the entity.",
                            },
                        },
                        "required": ["entity_name"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "get_evidence_details",
                    "description": "Retrieves granular underlying evidence citations, transaction IDs, and direct URLs for an entity.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "entity_name": {
                                "type": "string",
                                "description": "Entity name to fetch evidence pointers for.",
                            },
                        },
                        "required": ["entity_name"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "evaluate_conflicts_of_interest",
                    "description": "Checks for undisclosed employee-vendor nexus, shared affiliations, shell company conduits, and multi-tool risk flags for an entity.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "entity_name": {
                                "type": "string",
                                "description": "Entity name to inspect for conflicts of interest.",
                            },
                        },
                        "required": ["entity_name"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "get_syndicate_overview",
                    "description": "Provides macro intelligence summary of the entire knowledge graph, including top high-risk entities, critical syndicate alerts, and network volume.",
                    "parameters": {"type": "object", "properties": {}},
                },
            },
        ]

    @classmethod
    def execute_tool(cls, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        """
        Executes a registered tool and returns structured JSON output.
        """
        try:
            if tool_name == "get_entity_network":
                entity_name = arguments.get("entity_name", "")
                max_hops = int(arguments.get("max_hops", 2))
                entity = cls._find_entity(entity_name)
                if not entity:
                    return {
                        "status": "error",
                        "message": f"Entity '{entity_name}' not found in Q-Link repository.",
                    }

                net = get_entity_network(str(entity.id), max_hops=max_hops)
                return {
                    "status": "success",
                    "target_entity": entity.display_name,
                    "type": entity.entity_type,
                    "risk_rating": entity.risk_rating,
                    "connected_nodes_count": len(net["nodes"]),
                    "connected_edges_count": len(net["edges"]),
                    "nodes": net["nodes"][:20],
                    "edges": net["edges"][:30],
                }

            elif tool_name == "find_paths_between":
                src_name = arguments.get("source_name", "")
                tgt_name = arguments.get("target_name", "")
                src = cls._find_entity(src_name)
                tgt = cls._find_entity(tgt_name)

                if not src:
                    return {"status": "error", "message": f"Source '{src_name}' not found."}
                if not tgt:
                    return {"status": "error", "message": f"Target '{tgt_name}' not found."}

                paths = find_paths_between(
                    str(src.id), str(tgt.id), max_hops=int(arguments.get("max_hops", 3))
                )
                return {
                    "status": "success",
                    "source": src.display_name,
                    "target": tgt.display_name,
                    "paths_found": len(paths),
                    "path_details": paths,
                }

            elif tool_name == "get_entity_timeline":
                entity_name = arguments.get("entity_name", "")
                entity = cls._find_entity(entity_name)
                if not entity:
                    return {"status": "error", "message": f"Entity '{entity_name}' not found."}

                events = get_entity_timeline(str(entity.id), limit=30)
                seen_events = set()
                timeline_data = []
                for e in events:
                    date_str = e.event_timestamp.strftime("%Y-%m-%d %H:%M")
                    k = (date_str, e.source_module, e.event_title)
                    if k in seen_events:
                        continue
                    seen_events.add(k)
                    timeline_data.append(
                        {
                            "date": date_str,
                            "module": e.source_module,
                            "title": e.event_title,
                            "description": e.event_description,
                            "severity": e.severity,
                        }
                    )
                return {
                    "status": "success",
                    "entity": entity.display_name,
                    "event_count": len(timeline_data),
                    "timeline": timeline_data,
                }

            elif tool_name == "get_evidence_details":
                entity_name = arguments.get("entity_name", "")
                entity = cls._find_entity(entity_name)
                if not entity:
                    return {"status": "error", "message": f"Entity '{entity_name}' not found."}

                evidences = get_entity_evidence(str(entity.id), limit=30)
                seen_evidence = set()
                ev_data = []
                for ev in evidences:
                    k = (ev.source_module, ev.summary_snippet)
                    if k in seen_evidence:
                        continue
                    seen_evidence.add(k)
                    ev_data.append(
                        {
                            "module": ev.source_module,
                            "model": ev.source_model,
                            "record_id": ev.source_record_id,
                            "url": ev.evidence_url,
                            "summary": ev.summary_snippet,
                            "occurred_at": ev.occurred_at.strftime("%Y-%m-%d")
                            if ev.occurred_at
                            else "N/A",
                        }
                    )
                return {
                    "status": "success",
                    "entity": entity.display_name,
                    "evidence_items": ev_data,
                }

            elif tool_name == "evaluate_conflicts_of_interest":
                entity_name = arguments.get("entity_name", "")
                entity = cls._find_entity(entity_name)
                if not entity:
                    return {"status": "error", "message": f"Entity '{entity_name}' not found."}

                alerts = list(
                    RelationshipAlert.objects.filter(primary_entity=entity).values(
                        "title", "alert_level", "is_acknowledged"
                    )[:10]
                )

                vendor_rels = []
                for r in entity.out_relations.select_related("target_entity").all()[:15]:
                    if r.target_entity.entity_type in (
                        ForensicEntity.EntityType.VENDOR,
                        ForensicEntity.EntityType.COMPANY,
                    ):
                        vendor_rels.append(
                            {
                                "target": r.target_entity.display_name,
                                "relation": r.relation_type,
                                "weight": r.weight,
                                "module": r.source_module,
                            }
                        )
                for r in entity.in_relations.select_related("source_entity").all()[:15]:
                    if r.source_entity.entity_type in (
                        ForensicEntity.EntityType.VENDOR,
                        ForensicEntity.EntityType.COMPANY,
                    ):
                        vendor_rels.append(
                            {
                                "source": r.source_entity.display_name,
                                "relation": r.relation_type,
                                "weight": r.weight,
                                "module": r.source_module,
                            }
                        )

                return {
                    "status": "success",
                    "entity": entity.display_name,
                    "risk_rating": entity.risk_rating,
                    "is_target": entity.is_target,
                    "conflicts_count": len(vendor_rels) + len(alerts),
                    "alerts": alerts,
                    "vendor_connections": vendor_rels,
                }

            elif tool_name == "get_syndicate_overview":
                metrics = get_link_dashboard_metrics()
                high_risks = list(
                    get_high_risk_entities(min_risk=40, limit=10).values(
                        "display_name", "entity_type", "risk_rating", "is_target"
                    )
                )
                recent_alerts = list(
                    get_recent_alerts(limit=5, unacknowledged_only=False).values(
                        "title", "alert_level"
                    )
                )
                return {
                    "status": "success",
                    "metrics": metrics,
                    "high_risk_entities": high_risks,
                    "recent_alerts": recent_alerts,
                }

            return {"status": "error", "message": f"Unknown tool: '{tool_name}'"}

        except Exception as err:
            logger.error(f"Error executing forensic tool {tool_name}: {err}")
            return {"status": "error", "message": str(err)}

    @classmethod
    def _find_entity(cls, query: str) -> ForensicEntity | None:
        clean = query.strip()
        if not clean:
            return None

        # 1. Exact case-insensitive match on display_name, identifier, or aliases
        exact = (
            ForensicEntity.objects.filter(display_name__iexact=clean).first()
            or ForensicEntity.objects.filter(identifier__iexact=clean).first()
            or ForensicEntity.objects.filter(aliases__alias_name__iexact=clean).first()
        )
        if exact:
            return exact

        # Prevent short tokens (< 3 chars) from matching arbitrary entities
        if len(clean) < 3:
            return None

        # 2. Substring matching for search tokens of 3 or more characters
        return (
            ForensicEntity.objects.filter(display_name__icontains=clean).first()
            or ForensicEntity.objects.filter(aliases__alias_name__icontains=clean).first()
        )

    @classmethod
    def _find_entities_in_text(cls, text: str) -> list[ForensicEntity]:
        """
        Scans freeform text for mentions of indexed entities or aliases using word boundary matching.
        Returns matched entities ordered by longest name match first to avoid partial substring collisions.
        """
        if not text:
            return []

        all_entities = list(ForensicEntity.objects.all().prefetch_related("aliases"))
        matched: list[ForensicEntity] = []
        matched_ids: set[Any] = set()
        lower_text = text.lower()

        # Sort candidates descending by length of display name
        sorted_entities = sorted(all_entities, key=lambda e: len(e.display_name), reverse=True)
        for ent in sorted_entities:
            name_lower = ent.display_name.lower().strip()
            if len(name_lower) < 3 or name_lower in STOP_WORDS:
                continue

            pattern = r"\b" + re.escape(name_lower) + r"\b"
            if re.search(pattern, lower_text):
                if ent.id not in matched_ids:
                    matched.append(ent)
                    matched_ids.add(ent.id)
                continue

            for a in ent.aliases.all():
                alias_lower = a.alias_name.lower().strip()
                if len(alias_lower) >= 3 and alias_lower not in STOP_WORDS:
                    if re.search(r"\b" + re.escape(alias_lower) + r"\b", lower_text):
                        if ent.id not in matched_ids:
                            matched.append(ent)
                            matched_ids.add(ent.id)
                        break

        return matched


class ForensicCopilotAgent:
    """
    Forensic Intelligence Agent with Tool-Calling capabilities.
    Coordinates between natural language prompts, dynamic tool calling,
    and forensic hypothesis generation. Supports local Model-Host (Llama-3.2-1B-Instruct),
    OpenAI-compatible endpoints, and deterministic fallback.
    """

    def __init__(self):
        self.endpoint = getattr(settings, "LLM_API_ENDPOINT", DEFAULT_LLM_API_ENDPOINT)
        self.api_key = getattr(settings, "LLM_API_KEY", DEFAULT_LLM_API_KEY)
        self.model = getattr(settings, "LLM_MODEL_NAME", DEFAULT_LLM_MODEL_NAME)
        self.timeout = float(getattr(settings, "LLM_API_TIMEOUT", DEFAULT_LLM_TIMEOUT))

    def analyze_investigative_query(
        self, user_query: str, active_entity_name: str | None = None
    ) -> dict[str, Any]:
        """
        Runs the agentic reasoning loop:
        1. Analyzes user request and resolves target entity or dual conduit targets.
        2. Executes investigative tools (network graph, timeline, evidence pointers, pathfinding).
        3. Attempts neural synthesis via the live LLM endpoint (Model-Host / Llama-3.2).
        4. Seamlessly falls back to structured deterministic synthesis if LLM is offline or refuses.
        """
        matched_entities = ForensicToolRegistry._find_entities_in_text(user_query)
        active_entity = (
            ForensicToolRegistry._find_entity(active_entity_name) if active_entity_name else None
        )

        query_lower = user_query.lower()
        is_path_query = any(
            w in query_lower
            for w in [
                "path",
                "between",
                "connect",
                "link",
                "conduit",
                "route",
                "nexus",
                "relation",
                "how is",
            ]
        )

        # -------------------------------------------------------------
        # Mode A: Dual-Entity / Conduit Path Analysis
        # -------------------------------------------------------------
        if (
            len(matched_entities) >= 2
            or (
                active_entity
                and len(matched_entities) >= 1
                and active_entity.id != matched_entities[0].id
            )
            or (is_path_query and len(matched_entities) >= 2)
        ):
            e1 = active_entity if active_entity else matched_entities[0]
            e2 = (
                matched_entities[0]
                if (active_entity and active_entity.id != matched_entities[0].id)
                else matched_entities[1]
            )
            return self._analyze_dual_entities(user_query, e1, e2)

        # -------------------------------------------------------------
        # Mode B: Macro Audit / Syndicate Threat Overview
        # -------------------------------------------------------------
        is_overview_query = any(
            w in query_lower
            for w in [
                "overview",
                "summary",
                "high risk",
                "top risk",
                "alerts",
                "syndicate",
                "threats",
                "clusters",
                "targets",
                "what are the risks in this audit",
                "audit risks",
            ]
        )
        if not matched_entities and not active_entity and is_overview_query:
            return self._analyze_syndicate_overview(user_query)

        # -------------------------------------------------------------
        # Mode C: Single-Entity Deep-Dive Dossier
        # -------------------------------------------------------------
        target = active_entity or (matched_entities[0] if matched_entities else None)

        if not target:
            return {
                "query": user_query,
                "response": "No matching forensic entity found for your inquiry. Select an entity on the graph or specify an indexed entity name.",
                "tool_calls": [],
                "mode": "entity_not_found",
            }

        return self._analyze_single_entity(user_query, target)

    def _analyze_single_entity(self, user_query: str, target: ForensicEntity) -> dict[str, Any]:
        """
        Executes single-entity investigation tools and synthesizes findings.
        """
        tool_calls = []

        # 1. Execute get_entity_network
        net_out = ForensicToolRegistry.execute_tool(
            "get_entity_network", {"entity_name": target.display_name, "max_hops": 2}
        )
        tool_calls.append(
            {
                "tool": "get_entity_network",
                "arguments": {"entity_name": target.display_name},
                "output": net_out,
            }
        )

        # 2. Execute get_entity_timeline
        timeline_out = ForensicToolRegistry.execute_tool(
            "get_entity_timeline", {"entity_name": target.display_name}
        )
        tool_calls.append(
            {
                "tool": "get_entity_timeline",
                "arguments": {"entity_name": target.display_name},
                "output": timeline_out,
            }
        )

        # 3. Execute get_evidence_details
        evidence_out = ForensicToolRegistry.execute_tool(
            "get_evidence_details", {"entity_name": target.display_name}
        )
        tool_calls.append(
            {
                "tool": "get_evidence_details",
                "arguments": {"entity_name": target.display_name},
                "output": evidence_out,
            }
        )

        # 4. Execute evaluate_conflicts_of_interest
        conflict_out = ForensicToolRegistry.execute_tool(
            "evaluate_conflicts_of_interest", {"entity_name": target.display_name}
        )
        tool_calls.append(
            {
                "tool": "evaluate_conflicts_of_interest",
                "arguments": {"entity_name": target.display_name},
                "output": conflict_out,
            }
        )

        # Synthesis via LLM endpoint or deterministic fallback
        llm_response = self._synthesize_single_with_llm(
            user_query, target, net_out, timeline_out, evidence_out, conflict_out
        )

        evidence_items = evidence_out.get("evidence_items", [])
        citations = []
        seen_cit = set()
        for item in evidence_items:
            k = (item.get("module"), item.get("summary"))
            if k in seen_cit:
                continue
            seen_cit.add(k)
            url_part = f" ([Inspect Record]({item['url']}))" if item.get("url") else ""
            citations.append(f"- **[{item['module'].upper()}]** {item['summary']}{url_part}")

        if not llm_response:
            return {
                "query": user_query,
                "response": "⚠️ Local AI Copilot service is currently offline or unreachable. Please ensure the LLM server is running.",
                "tool_calls": tool_calls,
                "mode": "llm_offline",
            }

        cit_block = (
            ("\n\n#### 🔗 Cross-Tool Converged Evidence:\n" + "\n".join(citations[:5]))
            if citations
            else ""
        )
        final_narrative = llm_response + cit_block

        return {
            "query": user_query,
            "response": final_narrative,
            "tool_calls": tool_calls,
            "mode": "agentic_tool_calling",
        }

    def _analyze_dual_entities(
        self, user_query: str, source: ForensicEntity, target: ForensicEntity
    ) -> dict[str, Any]:
        """
        Executes multi-entity conduit search, pathfinding, and relationship convergence.
        """
        tool_calls = []

        # 1. Execute find_paths_between
        path_out = ForensicToolRegistry.execute_tool(
            "find_paths_between",
            {"source_name": source.display_name, "target_name": target.display_name, "max_hops": 3},
        )
        tool_calls.append(
            {
                "tool": "find_paths_between",
                "arguments": {
                    "source_name": source.display_name,
                    "target_name": target.display_name,
                },
                "output": path_out,
            }
        )

        # 2. Execute get_entity_network for both
        net_src = ForensicToolRegistry.execute_tool(
            "get_entity_network", {"entity_name": source.display_name, "max_hops": 1}
        )
        tool_calls.append(
            {
                "tool": "get_entity_network",
                "arguments": {"entity_name": source.display_name},
                "output": net_src,
            }
        )

        net_tgt = ForensicToolRegistry.execute_tool(
            "get_entity_network", {"entity_name": target.display_name, "max_hops": 1}
        )
        tool_calls.append(
            {
                "tool": "get_entity_network",
                "arguments": {"entity_name": target.display_name},
                "output": net_tgt,
            }
        )

        # 3. Evidence details for both
        ev_src = ForensicToolRegistry.execute_tool(
            "get_evidence_details", {"entity_name": source.display_name}
        )
        ev_tgt = ForensicToolRegistry.execute_tool(
            "get_evidence_details", {"entity_name": target.display_name}
        )

        # LLM Synthesis or deterministic fallback
        llm_response = self._synthesize_dual_with_llm(user_query, source, target, path_out)

        combined_evidence = ev_src.get("evidence_items", []) + ev_tgt.get("evidence_items", [])
        citations = []
        seen_cit = set()
        for item in combined_evidence:
            k = (item.get("module"), item.get("summary"))
            if k in seen_cit:
                continue
            seen_cit.add(k)
            url_part = f" ([Inspect Record]({item['url']}))" if item.get("url") else ""
            citations.append(f"- **[{item['module'].upper()}]** {item['summary']}{url_part}")

        if not llm_response:
            return {
                "query": user_query,
                "response": "⚠️ Local AI Copilot service is currently offline or unreachable. Please ensure the LLM server is running.",
                "tool_calls": tool_calls,
                "mode": "llm_offline",
            }

        cit_block = (
            ("\n\n#### 🔗 Cross-Tool Converged Evidence:\n" + "\n".join(citations[:5]))
            if citations
            else ""
        )
        final_narrative = llm_response + cit_block

        return {
            "query": user_query,
            "response": final_narrative,
            "tool_calls": tool_calls,
            "mode": "agentic_tool_calling",
        }

    def _analyze_syndicate_overview(self, user_query: str) -> dict[str, Any]:
        """
        Executes syndicate macro inspection tools and generates an executive overview.
        """
        tool_calls = []
        overview_out = ForensicToolRegistry.execute_tool("get_syndicate_overview", {})
        tool_calls.append(
            {
                "tool": "get_syndicate_overview",
                "arguments": {},
                "output": overview_out,
            }
        )

        llm_response = self._synthesize_overview_with_llm(user_query, overview_out)
        if not llm_response:
            return {
                "query": user_query,
                "response": "⚠️ Local AI Copilot service is currently offline or unreachable. Please ensure the LLM server is running.",
                "tool_calls": tool_calls,
                "mode": "llm_offline",
            }

        return {
            "query": user_query,
            "response": llm_response,
            "tool_calls": tool_calls,
            "mode": "agentic_tool_calling",
        }

    def _synthesize_single_with_llm(
        self,
        query: str,
        target: ForensicEntity,
        net_out: dict[str, Any],
        timeline_out: dict[str, Any],
        evidence_out: dict[str, Any],
        conflict_out: dict[str, Any],
    ) -> str | None:
        """
        Calls Model-Host with readable relationship edges and deduplicated findings.
        """
        try:
            connected_count = max(0, net_out.get("connected_nodes_count", 1) - 1)
            edges_count = net_out.get("connected_edges_count", 0)
            events = timeline_out.get("timeline", [])
            evidence_items = evidence_out.get("evidence_items", [])

            # Format human-readable relationship edges
            node_labels = {
                n.get("id"): n.get("label", n.get("display_name", ""))
                for n in net_out.get("nodes", [])
            }
            readable_edges = []
            for e in net_out.get("edges", [])[:10]:
                src_lbl = node_labels.get(e.get("from"), "Entity")
                dst_lbl = node_labels.get(e.get("to"), "Entity")
                rel_lbl = e.get("label", "RELATED_TO")
                readable_edges.append(f"- {src_lbl} -> {dst_lbl} ({rel_lbl})")
            edges_text = "\n".join(readable_edges) if readable_edges else "Direct connections only."

            ev_snippets = [f"[{ev['module'].upper()}] {ev['summary']}" for ev in evidence_items[:5]]
            ev_str = (
                "\n".join(f"- {s}" for s in ev_snippets)
                if ev_snippets
                else "- No direct evidence records."
            )

            time_snippets = [
                f"{e['date']} [{e['module'].upper()}]: {e['title']}" for e in events[:4]
            ]
            time_str = (
                "\n".join(f"- {t}" for t in time_snippets)
                if time_snippets
                else "- No recorded timeline events."
            )

            conflicts_count = conflict_out.get("conflicts_count", 0)
            alerts = conflict_out.get("alerts", [])
            alert_str = (
                ", ".join(a.get("title", "") for a in alerts[:3]) if alerts else "None active"
            )

            fallback_prompt = (
                f"You are ForensiQ Copilot, a senior forensic data intelligence analyst.\n"
                f"Analyze the following cross-module entity intelligence dossier for '{target.display_name}':\n\n"
                f"Target Entity: {target.display_name} ({target.get_entity_type_display()}, Risk Score: {target.risk_rating}/100)\n"
                f"Network Connections ({connected_count} entities, {edges_count} edges):\n{edges_text}\n\n"
                f"Underlying Evidence Records:\n{ev_str}\n\n"
                f"Reconstructed Timeline Events:\n{time_str}\n\n"
                f"Conflicts & Syndicate Flags: {conflicts_count} total flags (Recent: {alert_str})\n\n"
                f"User Inquiry: {query}\n\n"
                f"Provide a concise, professional investigative summary with specific findings, connected counterparties, and recommendations:"
            )

            prompt = render_prompt(
                "q_link",
                "single_entity_dossier.txt",
                fallback=fallback_prompt,
                target_name=target.display_name,
                target_type=target.get_entity_type_display(),
                risk_rating=target.risk_rating,
                connected_count=connected_count,
                edges_count=edges_count,
                edges_text=edges_text,
                ev_str=ev_str,
                time_str=time_str,
                conflicts_count=conflicts_count,
                alert_str=alert_str,
                query=query,
            )

            return self._call_model_host(prompt)
        except Exception as err:
            logger.debug(f"LLM single synthesis failed: {err}")
            return None

    def _synthesize_dual_with_llm(
        self,
        query: str,
        source: ForensicEntity,
        target: ForensicEntity,
        path_out: dict[str, Any],
    ) -> str | None:
        """
        Synthesizes conduit paths and connection intelligence between two entities.
        """
        try:
            paths = path_out.get("path_details", [])
            paths_count = path_out.get("paths_found", 0)

            path_lines = []
            for idx, p in enumerate(paths[:4], 1):
                steps = []
                for hop in p:
                    steps.append(
                        f"{hop.get('from_name')} --[{hop.get('relation_type')}]--> {hop.get('to_name')}"
                    )
                path_lines.append(f"Route {idx}: " + " -> ".join(steps))

            paths_str = (
                "\n".join(path_lines) if path_lines else "No direct path within traversal limits."
            )

            fallback_prompt = (
                f"You are ForensiQ Copilot, an enterprise knowledge graph data analyst.\n"
                f"Analyze the connection pathways between Node 1 ({source.display_name}) and Node 2 ({target.display_name}):\n\n"
                f"Graph Pathways ({paths_count} routes found):\n{paths_str}\n\n"
                f"User Inquiry: {query}\n\n"
                f"Describe the connection path from {source.display_name} to {target.display_name}, noting any intermediate conduits or connecting entities in 3-4 professional sentences:"
            )

            prompt = render_prompt(
                "q_link",
                "dual_entity_pathways.txt",
                fallback=fallback_prompt,
                source_name=source.display_name,
                target_name=target.display_name,
                paths_count=paths_count,
                paths_str=paths_str,
                query=query,
            )

            return self._call_model_host(prompt)
        except Exception as err:
            logger.debug(f"LLM dual synthesis failed: {err}")
            return None

    def _synthesize_overview_with_llm(self, query: str, overview_out: dict[str, Any]) -> str | None:
        """
        Synthesizes audit-wide threat briefing from overview metrics.
        """
        try:
            metrics = overview_out.get("metrics", {})
            high_risks = overview_out.get("high_risk_entities", [])
            alerts = overview_out.get("recent_alerts", [])

            risk_lines = [
                f"- {e.get('display_name')} ({e.get('entity_type')}, Risk: {e.get('risk_rating')}/100)"
                for e in high_risks[:6]
            ]
            risk_str = "\n".join(risk_lines) if risk_lines else "None flagged above threshold."

            alert_lines = [f"- [{a.get('severity')}] {a.get('title')}" for a in alerts[:4]]
            alert_str = "\n".join(alert_lines) if alert_lines else "No active alerts."

            fallback_prompt = (
                f"You are ForensiQ Copilot, an enterprise audit and financial data reconciliation system.\n"
                f"Summarize the macro syndicate risks across the current audit:\n\n"
                f"Total Indexed Entities: {metrics.get('total_entities', 0)}\n"
                f"Total Inter-Tool Relationships: {metrics.get('total_relationships', 0)}\n"
                f"Unacknowledged Relationship Alerts: {metrics.get('unack_alerts', 0)}\n\n"
                f"Top High-Risk Entities:\n{risk_str}\n\n"
                f"Recent Syndicate Alerts:\n{alert_str}\n\n"
                f"User Inquiry: {query}\n\n"
                f"Provide an executive briefing detailing high-risk syndicates, primary focal targets, and recommended reconciliation actions:"
            )

            prompt = render_prompt(
                "q_link",
                "syndicate_overview.txt",
                fallback=fallback_prompt,
                total_entities=metrics.get("total_entities", 0),
                total_relationships=metrics.get("total_relationships", 0),
                unack_alerts=metrics.get("unack_alerts", 0),
                risk_str=risk_str,
                alert_str=alert_str,
                query=query,
            )

            return self._call_model_host(prompt)
        except Exception as err:
            logger.debug(f"LLM overview synthesis failed: {err}")
            return None

    def _call_model_host(self, prompt: str) -> str | None:
        """
        Dispatches request to Model-Host (port 8434) with low temperature and strict token limit.
        """
        try:
            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            }
            payload = {
                "model": self.model,
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.2,
                "max_tokens": 600,
            }

            resp = requests.post(self.endpoint, json=payload, headers=headers, timeout=self.timeout)  # nosec B113
            if resp.status_code == 200:
                content = resp.json()["choices"][0]["message"].get("content", "").strip()
                refusals = [
                    "cannot provide",
                    "cannot assist",
                    "unable to assist",
                    "cannot fulfill",
                    "i can't assist",
                    "i cannot help",
                    "i am not able to",
                    "illegal activities",
                    "commit fraud",
                ]
                if (
                    content
                    and not any(r in content.lower() for r in refusals)
                    and len(content) > 30
                ):
                    return content
        except Exception as exc:
            logger.debug(f"Model-Host request error: {exc}")
        return None
