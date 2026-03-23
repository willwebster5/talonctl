"""
Unit tests for ResourceGraph dependency management
"""

import pytest
import sys
from pathlib import Path

# Add scripts directory to path
SCRIPTS_DIR = Path(__file__).parent.parent.parent / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))

from core.resource_graph import ResourceGraph, DependencyCycle


class TestResourceGraph:
    """Test suite for ResourceGraph"""

    def test_empty_graph(self):
        """Test initialization of empty graph"""
        graph = ResourceGraph()
        assert len(graph) == 0
        assert graph.nodes == set()

    def test_add_node(self):
        """Test adding nodes to graph"""
        graph = ResourceGraph()
        graph.add_node("detection.test1")
        graph.add_node("workflow.test2")

        assert len(graph) == 2
        assert "detection.test1" in graph
        assert "workflow.test2" in graph

    def test_add_dependency(self):
        """Test adding dependencies between resources"""
        graph = ResourceGraph()
        graph.add_dependency("workflow.notify", "detection.alert")

        assert len(graph) == 2
        assert "workflow.notify" in graph
        assert "detection.alert" in graph

        deps = graph.get_dependencies("workflow.notify")
        assert "detection.alert" in deps

    def test_get_dependents(self):
        """Test finding resources that depend on a given resource"""
        graph = ResourceGraph()
        graph.add_dependency("workflow.notify", "detection.alert")
        graph.add_dependency("correlation.check", "detection.alert")

        dependents = graph.get_dependents("detection.alert")
        assert len(dependents) == 2
        assert "workflow.notify" in dependents
        assert "correlation.check" in dependents

    def test_topological_sort_simple(self):
        """Test topological sort with simple dependency chain"""
        graph = ResourceGraph()
        graph.add_dependency("detection.c", "saved_search.b")
        graph.add_dependency("saved_search.b", "lookup_file.a")

        sorted_nodes = graph.topological_sort()

        # lookup_file.a should come before saved_search.b
        # saved_search.b should come before detection.c
        assert sorted_nodes.index("lookup_file.a") < sorted_nodes.index("saved_search.b")
        assert sorted_nodes.index("saved_search.b") < sorted_nodes.index("detection.c")

    def test_topological_sort_no_dependencies(self):
        """Test topological sort with independent resources"""
        graph = ResourceGraph()
        graph.add_node("detection.a")
        graph.add_node("detection.b")
        graph.add_node("saved_search.c")

        sorted_nodes = graph.topological_sort()
        assert len(sorted_nodes) == 3
        assert set(sorted_nodes) == {"detection.a", "detection.b", "saved_search.c"}

    def test_detect_cycle_simple(self):
        """Test cycle detection with simple circular dependency"""
        graph = ResourceGraph()
        graph.add_dependency("a", "b")
        graph.add_dependency("b", "c")
        graph.add_dependency("c", "a")  # Creates cycle

        cycles = graph.detect_cycles()
        assert len(cycles) > 0
        assert "a" in cycles[0].cycle_path
        assert "b" in cycles[0].cycle_path
        assert "c" in cycles[0].cycle_path

    def test_topological_sort_with_cycle_raises(self):
        """Test that topological sort raises error on circular dependency"""
        graph = ResourceGraph()
        graph.add_dependency("a", "b")
        graph.add_dependency("b", "a")  # Cycle

        with pytest.raises(ValueError, match="Circular dependency"):
            graph.topological_sort()

    def test_deployment_waves_simple(self):
        """Test deployment wave calculation"""
        graph = ResourceGraph()
        # Wave 1: No dependencies
        graph.add_node("saved_search.a")
        graph.add_node("lookup_file.b")

        # Wave 2: Depends on Wave 1
        graph.add_dependency("detection.c", "saved_search.a")
        graph.add_dependency("detection.d", "lookup_file.b")

        # Wave 3: Depends on Wave 2
        graph.add_dependency("workflow.e", "detection.c")

        waves = graph.get_deployment_waves()

        assert len(waves) == 3

        # Wave 1 should have saved_search.a and lookup_file.b
        assert set(waves[0]) == {"saved_search.a", "lookup_file.b"}

        # Wave 2 should have detection.c and detection.d
        assert set(waves[1]) == {"detection.c", "detection.d"}

        # Wave 3 should have workflow.e
        assert set(waves[2]) == {"workflow.e"}

    def test_deployment_waves_complex(self):
        """Test deployment waves with complex dependencies"""
        graph = ResourceGraph()

        # Multiple levels of dependencies
        graph.add_dependency("d", "c")
        graph.add_dependency("d", "b")
        graph.add_dependency("c", "a")
        graph.add_dependency("b", "a")

        waves = graph.get_deployment_waves()

        # a should be in first wave (no dependencies)
        assert "a" in waves[0]

        # b and c should be in second wave (depend only on a)
        assert "b" in waves[1]
        assert "c" in waves[1]

        # d should be in third wave (depends on b and c)
        assert "d" in waves[2]

    def test_subgraph(self):
        """Test creating a subgraph with specific resources"""
        graph = ResourceGraph()
        graph.add_dependency("workflow.notify", "detection.alert")
        graph.add_dependency("detection.alert", "saved_search.find")
        graph.add_node("detection.other")  # Not in subgraph

        subgraph = graph.get_subgraph(["workflow.notify"])

        # Should include workflow.notify and all its transitive dependencies
        assert "workflow.notify" in subgraph
        assert "detection.alert" in subgraph
        assert "saved_search.find" in subgraph

        # Should NOT include unrelated nodes
        assert "detection.other" not in subgraph

    def test_to_dict_from_dict(self):
        """Test serialization and deserialization"""
        graph = ResourceGraph()
        graph.add_dependency("b", "a")
        graph.add_dependency("c", "a")
        graph.add_dependency("d", "b")

        # Serialize
        graph_dict = graph.to_dict()

        # Deserialize
        restored_graph = ResourceGraph.from_dict(graph_dict)

        # Verify structure is preserved
        assert len(restored_graph) == len(graph)
        assert restored_graph.nodes == graph.nodes
        assert restored_graph.get_dependencies("b") == graph.get_dependencies("b")
        assert restored_graph.get_dependencies("d") == graph.get_dependencies("d")

    def test_complex_diamond_dependency(self):
        """Test diamond-shaped dependency graph"""
        graph = ResourceGraph()
        #     a
        #    / \
        #   b   c
        #    \ /
        #     d

        graph.add_dependency("b", "a")
        graph.add_dependency("c", "a")
        graph.add_dependency("d", "b")
        graph.add_dependency("d", "c")

        waves = graph.get_deployment_waves()

        # Should have 3 waves
        assert len(waves) == 3

        # a in wave 1
        assert waves[0] == ["a"]

        # b and c in wave 2 (can deploy in parallel)
        assert set(waves[1]) == {"b", "c"}

        # d in wave 3
        assert waves[2] == ["d"]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
