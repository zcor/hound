"""Tests for analysis.scope_partitioner."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from analysis.scope_partitioner import (
    _bfs_order,
    _build_adjacency,
    _connected_components,
    _estimate_tokens,
    partition,
)


@pytest.fixture()
def empty_graphs_dir(tmp_path: Path) -> Path:
    """An empty directory with no graph files."""
    d = tmp_path / "graphs"
    d.mkdir()
    return d


@pytest.fixture()
def single_graph_dir(tmp_path: Path) -> Path:
    """A directory with one small graph file."""
    d = tmp_path / "graphs"
    d.mkdir()
    graph = {
        "nodes": [
            {"id": "a", "label": "Contract A"},
            {"id": "b", "label": "Contract B"},
            {"id": "c", "label": "Contract C"},
        ],
        "edges": [
            {"src": "a", "dst": "b"},
        ],
    }
    (d / "graph_0.json").write_text(json.dumps(graph))
    return d


class TestPartitionEmptyGraph:
    """Partition with no graph files returns an empty list."""

    def test_empty_dir(self, empty_graphs_dir: Path) -> None:
        chunks = partition(
            graphs_dir=empty_graphs_dir,
            coverage_data={},
            card_index={},
            file_to_cards={},
        )
        assert chunks == []

    def test_nonexistent_dir(self, tmp_path: Path) -> None:
        chunks = partition(
            graphs_dir=tmp_path / "does_not_exist",
            coverage_data={},
            card_index={},
            file_to_cards={},
        )
        assert chunks == []


class TestPartitionSingleGraph:
    """Partition with a small graph produces chunks."""

    def test_produces_chunks(self, single_graph_dir: Path) -> None:
        chunks = partition(
            graphs_dir=single_graph_dir,
            coverage_data={},
            card_index={},
            file_to_cards={},
        )
        assert len(chunks) >= 1
        # All node IDs should be covered
        all_nodes = set()
        for ch in chunks:
            all_nodes.update(ch.node_ids)
        assert {"a", "b", "c"} <= all_nodes

    def test_connected_nodes_grouped(self, single_graph_dir: Path) -> None:
        """Nodes a-b are connected; c is isolated → separate components."""
        chunks = partition(
            graphs_dir=single_graph_dir,
            coverage_data={},
            card_index={},
            file_to_cards={},
        )
        # Find the chunk containing "a"
        ab_chunk = [ch for ch in chunks if "a" in ch.node_ids]
        assert len(ab_chunk) == 1
        assert "b" in ab_chunk[0].node_ids
        # "c" should be in a different chunk
        c_chunk = [ch for ch in chunks if "c" in ch.node_ids]
        assert len(c_chunk) == 1
        assert c_chunk[0].chunk_id != ab_chunk[0].chunk_id


class TestBfsOrder:
    """Test BFS ordering helper (uses deque)."""

    def test_single_node(self) -> None:
        adj = {"x": set()}
        order = _bfs_order({"x"}, adj)
        assert order == ["x"]

    def test_linear_chain(self) -> None:
        adj = {"a": {"b"}, "b": {"a", "c"}, "c": {"b"}}
        order = _bfs_order({"a", "b", "c"}, adj)
        assert set(order) == {"a", "b", "c"}
        # BFS starts from highest-degree node (b)
        assert order[0] == "b"


class TestBuildAdjacency:
    def test_empty(self) -> None:
        adj = _build_adjacency(set(), [])
        assert adj == {}

    def test_single_edge(self) -> None:
        adj = _build_adjacency({"x", "y"}, [{"src": "x", "dst": "y"}])
        assert "y" in adj["x"]
        assert "x" in adj["y"]


class TestConnectedComponents:
    def test_empty(self) -> None:
        assert _connected_components({}) == []

    def test_two_components(self) -> None:
        adj = {"a": {"b"}, "b": {"a"}, "c": set()}
        comps = _connected_components(adj)
        assert len(comps) == 2


class TestEstimateTokens:
    def test_minimum_per_node(self) -> None:
        """Each node gets at least 100 tokens."""
        tokens = _estimate_tokens(["x", "y"], {})
        assert tokens >= 200
