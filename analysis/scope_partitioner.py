"""Partition a repository's knowledge graph into auditor-sized scope chunks.

The partitioner uses graph connectivity, coverage state, and a token budget
to produce chunks that:

* Fit within the auditor's context window.
* Preserve cross-component edges so cross-cutting bugs are not lost.
* Prioritise unvisited / under-investigated nodes.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class ScopeChunk:
    """A partition of the codebase that the auditor will review in one pass."""

    chunk_id: str
    node_ids: list[str]
    card_ids: list[str]
    cross_edges: list[dict[str, str]]  # [{src, dst, type}, ...]
    estimated_tokens: int = 0
    priority: float = 0.0  # higher = review first
    metadata: dict[str, Any] = field(default_factory=dict)


def _load_graphs(graphs_dir: Path) -> list[dict[str, Any]]:
    """Load all ``graph_*.json`` from *graphs_dir*.

    Resilient to per-file failures: a malformed or unreadable graph file
    is logged and skipped without aborting the rest of the load.
    """
    graphs: list[dict[str, Any]] = []
    try:
        graph_files = sorted(graphs_dir.glob("graph_*.json"))
    except OSError:
        logger.warning("Failed to enumerate graphs in %s", graphs_dir, exc_info=True)
        return graphs
    for gf in graph_files:
        try:
            data = json.loads(gf.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError, UnicodeDecodeError):
            logger.warning("Skipping unreadable graph file %s", gf, exc_info=True)
            continue
        data.setdefault("_source_file", gf.name)
        graphs.append(data)
    return graphs


def _collect_nodes_and_edges(
    graphs: list[dict[str, Any]],
) -> tuple[dict[str, dict], list[dict]]:
    """Flatten all nodes and edges from all graphs.

    Returns ``(node_map, edges)`` where *node_map* is ``{node_id: node_dict}``.
    """
    node_map: dict[str, dict] = {}
    edges: list[dict] = []
    for g in graphs:
        for n in g.get("nodes") or []:
            nid = n.get("id")
            if nid:
                node_map[nid] = n
        for e in g.get("edges") or []:
            edges.append(e)
    return node_map, edges


def _build_adjacency(
    node_ids: set[str], edges: list[dict],
) -> dict[str, set[str]]:
    """Build an undirected adjacency list for *node_ids*."""
    adj: dict[str, set[str]] = {nid: set() for nid in node_ids}
    for e in edges:
        src = e.get("src") or e.get("source_id") or e.get("source") or ""
        dst = e.get("dst") or e.get("target_id") or e.get("target") or ""
        if src in adj and dst in adj:
            adj[src].add(dst)
            adj[dst].add(src)
    return adj


def _connected_components(adj: dict[str, set[str]]) -> list[set[str]]:
    """Return a list of connected-component sets."""
    visited: set[str] = set()
    components: list[set[str]] = []
    for start in adj:
        if start in visited:
            continue
        comp: set[str] = set()
        stack = [start]
        while stack:
            nid = stack.pop()
            if nid in visited:
                continue
            visited.add(nid)
            comp.add(nid)
            stack.extend(adj[nid] - visited)
        if comp:
            components.append(comp)
    return components


def _node_priority(
    node_id: str,
    coverage_data: dict[str, Any],
) -> float:
    """Higher priority for nodes that have been seen less / have less evidence."""
    nodes_cov = coverage_data.get("nodes") or {}
    rec = nodes_cov.get(node_id)
    if rec is None:
        return 10.0  # completely unvisited → highest priority
    seen = int(rec.get("seen_count", 0))
    evidence = int(rec.get("evidence_count", 0))
    # Inverse of coverage depth — less-seen nodes get higher priority
    return max(0.0, 10.0 - seen - evidence * 0.5)


def _estimate_tokens(node_ids: list[str], node_map: dict[str, dict]) -> int:
    """Rough token estimate: ~4 chars per token for node label + properties."""
    total = 0
    for nid in node_ids:
        n = node_map.get(nid, {})
        total += len(str(n.get("label", ""))) // 4
        total += len(str(n.get("properties", ""))) // 4
        for obs in n.get("observations") or []:
            total += len(str(obs)) // 4
    return max(total, len(node_ids) * 100)  # minimum 100 tokens per node


def partition(
    graphs_dir: Path,
    coverage_data: dict[str, Any],
    card_index: dict[str, dict[str, Any]],
    file_to_cards: dict[str, list[str]],
    max_chunk_tokens: int = 50_000,
) -> list[ScopeChunk]:
    """Partition the knowledge graph into auditor-sized scope chunks.

    Parameters
    ----------
    graphs_dir:
        Directory containing ``graph_*.json`` files.
    coverage_data:
        Raw data dict from ``CoverageIndex`` (``_load_data()``).
    card_index:
        Card index from ``load_card_index()``.
    file_to_cards:
        File→card mapping from ``load_card_index()``.
    max_chunk_tokens:
        Maximum estimated tokens per chunk.

    Returns
    -------
    List of ``ScopeChunk`` objects, sorted by descending priority.
    """
    graphs = _load_graphs(graphs_dir)
    if not graphs:
        logger.warning("No graphs found in %s", graphs_dir)
        return []

    node_map, edges = _collect_nodes_and_edges(graphs)
    all_node_ids = set(node_map.keys())
    adj = _build_adjacency(all_node_ids, edges)
    components = _connected_components(adj)

    # Sort components: largest first (likely most important)
    components.sort(key=len, reverse=True)

    chunks: list[ScopeChunk] = []
    chunk_counter = 0

    for comp in components:
        # Sub-partition large components that exceed the token budget
        comp_list = sorted(comp)
        estimated = _estimate_tokens(comp_list, node_map)

        if estimated <= max_chunk_tokens:
            # Fits in one chunk
            chunk_counter += 1
            priority = sum(_node_priority(nid, coverage_data) for nid in comp_list) / max(len(comp_list), 1)
            # Collect card IDs for nodes in this chunk
            chunk_card_ids = _cards_for_nodes(comp_list, node_map, card_index, file_to_cards)
            # Collect cross-edges (edges where at least one endpoint is outside this chunk)
            cross = _cross_edges(comp, edges, all_node_ids)
            chunks.append(ScopeChunk(
                chunk_id=f"chunk_{chunk_counter:03d}",
                node_ids=comp_list,
                card_ids=chunk_card_ids,
                cross_edges=cross,
                estimated_tokens=estimated,
                priority=priority,
            ))
        else:
            # Split into sub-chunks by BFS order, respecting token budget
            ordered = _bfs_order(comp, adj)
            current: list[str] = []
            current_tokens = 0

            for nid in ordered:
                node_tokens = _estimate_tokens([nid], node_map)
                if current and current_tokens + node_tokens > max_chunk_tokens:
                    # Flush current chunk
                    chunk_counter += 1
                    priority = sum(_node_priority(n, coverage_data) for n in current) / max(len(current), 1)
                    chunk_card_ids = _cards_for_nodes(current, node_map, card_index, file_to_cards)
                    cross = _cross_edges(set(current), edges, all_node_ids)
                    chunks.append(ScopeChunk(
                        chunk_id=f"chunk_{chunk_counter:03d}",
                        node_ids=list(current),
                        card_ids=chunk_card_ids,
                        cross_edges=cross,
                        estimated_tokens=current_tokens,
                        priority=priority,
                    ))
                    current = []
                    current_tokens = 0
                current.append(nid)
                current_tokens += node_tokens

            if current:
                chunk_counter += 1
                priority = sum(_node_priority(n, coverage_data) for n in current) / max(len(current), 1)
                chunk_card_ids = _cards_for_nodes(current, node_map, card_index, file_to_cards)
                cross = _cross_edges(set(current), edges, all_node_ids)
                chunks.append(ScopeChunk(
                    chunk_id=f"chunk_{chunk_counter:03d}",
                    node_ids=list(current),
                    card_ids=chunk_card_ids,
                    cross_edges=cross,
                    estimated_tokens=current_tokens,
                    priority=priority,
                ))

    # Sort chunks by priority (highest first — most unvisited)
    chunks.sort(key=lambda c: c.priority, reverse=True)
    return chunks


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _bfs_order(component: set[str], adj: dict[str, set[str]]) -> list[str]:
    """BFS traversal order starting from the highest-degree node."""
    if not component:
        return []
    from collections import deque as _deque
    start = max(component, key=lambda n: len(adj.get(n, set())))
    visited: set[str] = set()
    order: list[str] = []
    queue = _deque([start])
    while queue:
        nid = queue.popleft()
        if nid in visited:
            continue
        visited.add(nid)
        order.append(nid)
        for neighbor in sorted(adj.get(nid, set())):
            if neighbor not in visited and neighbor in component:
                queue.append(neighbor)
    # Add any orphans not reached by BFS
    for nid in sorted(component):
        if nid not in visited:
            order.append(nid)
    return order


def _cards_for_nodes(
    node_ids: list[str],
    node_map: dict[str, dict],
    card_index: dict[str, dict[str, Any]],
    file_to_cards: dict[str, list[str]],
) -> list[str]:
    """Collect card IDs relevant to the given nodes."""
    card_ids: set[str] = set()
    for nid in node_ids:
        n = node_map.get(nid, {})
        # Cards referenced directly in node properties
        for cid in n.get("card_ids") or []:
            if cid in card_index:
                card_ids.add(cid)
        # Cards from source files referenced by the node
        for src in n.get("source_files") or n.get("refs") or []:
            for cid in file_to_cards.get(src) or []:
                card_ids.add(cid)
    return sorted(card_ids)


def _cross_edges(
    chunk_nodes: set[str],
    all_edges: list[dict],
    all_node_ids: set[str],
) -> list[dict[str, str]]:
    """Return edges that connect this chunk to nodes outside it."""
    cross: list[dict[str, str]] = []
    for e in all_edges:
        src = e.get("src") or e.get("source_id") or e.get("source") or ""
        dst = e.get("dst") or e.get("target_id") or e.get("target") or ""
        etype = e.get("type") or e.get("edge_type") or "related"
        in_src = src in chunk_nodes
        in_dst = dst in chunk_nodes
        if (in_src or in_dst) and not (in_src and in_dst):
            cross.append({"src": src, "dst": dst, "type": etype})
    return cross
