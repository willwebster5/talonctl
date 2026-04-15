"""
Resource Dependency Graph

This module provides dependency tracking and resolution for resources.
It builds a directed acyclic graph (DAG) of resource dependencies and provides
topological sorting to determine safe deployment order.
"""

from typing import Dict, List, Set, Tuple, Optional
from collections import defaultdict, deque
from dataclasses import dataclass


@dataclass
class DependencyCycle:
    """Represents a circular dependency detected in the graph"""
    cycle_path: List[str]

    def __str__(self) -> str:
        return " -> ".join(self.cycle_path)


class ResourceGraph:
    """
    Manages dependency relationships between resources.

    Provides:
    - Dependency tracking (resource A depends on resource B)
    - Cycle detection (circular dependencies)
    - Topological sorting (safe deployment order)
    - Deployment wave calculation (parallel deployment groups)
    """

    def __init__(self):
        """Initialize an empty resource graph"""
        self.nodes: Set[str] = set()
        # edges[A] = set of resources that A depends on (A → B means A depends on B)
        self.edges: Dict[str, Set[str]] = defaultdict(set)

    def add_node(self, resource_id: str) -> None:
        """
        Add a resource to the graph.

        Args:
            resource_id: Resource identifier in format "type.name" (e.g., "detection.aws_root_login")
        """
        self.nodes.add(resource_id)

    def add_dependency(self, resource_id: str, depends_on: str) -> None:
        """
        Declare that resource_id depends on depends_on.

        This means depends_on must be deployed BEFORE resource_id.

        Args:
            resource_id: Resource that has the dependency
            depends_on: Resource that is depended upon
        """
        self.nodes.add(resource_id)
        self.nodes.add(depends_on)
        self.edges[resource_id].add(depends_on)

    def get_dependencies(self, resource_id: str) -> Set[str]:
        """
        Get all direct dependencies for a resource.

        Args:
            resource_id: Resource to query

        Returns:
            Set of resource IDs that this resource depends on
        """
        return self.edges.get(resource_id, set()).copy()

    def get_dependents(self, resource_id: str) -> Set[str]:
        """
        Get all resources that depend on the given resource.

        Args:
            resource_id: Resource to query

        Returns:
            Set of resource IDs that depend on this resource
        """
        dependents = set()
        for node, deps in self.edges.items():
            if resource_id in deps:
                dependents.add(node)
        return dependents

    def detect_cycles(self) -> List[DependencyCycle]:
        """
        Detect circular dependencies in the graph.

        Uses depth-first search with recursion stack tracking.

        Returns:
            List of DependencyCycle objects (empty if acyclic)
        """
        visited = set()
        rec_stack = set()
        cycles = []

        def dfs(node: str, path: List[str]) -> None:
            """DFS helper to detect cycles"""
            visited.add(node)
            rec_stack.add(node)
            path.append(node)

            for dep in self.edges.get(node, []):
                if dep not in visited:
                    dfs(dep, path.copy())
                elif dep in rec_stack:
                    # Found cycle - extract the cycle portion
                    cycle_start = path.index(dep)
                    cycle_path = path[cycle_start:] + [dep]
                    cycles.append(DependencyCycle(cycle_path))

            rec_stack.remove(node)

        for node in self.nodes:
            if node not in visited:
                dfs(node, [])

        return cycles

    def topological_sort(self) -> List[str]:
        """
        Return deployment order using topological sort (Kahn's algorithm).

        Resources with no dependencies come first, followed by resources
        that only depend on previously sorted resources.

        Returns:
            List of resource IDs in safe deployment order

        Raises:
            ValueError: If circular dependencies are detected
        """
        cycles = self.detect_cycles()
        if cycles:
            cycle_str = str(cycles[0])
            raise ValueError(f"Circular dependency detected: {cycle_str}")

        # Calculate out-degree (number of dependencies each resource has)
        out_degree = {node: len(self.edges.get(node, [])) for node in self.nodes}

        # Start with nodes that have no dependencies (out-degree 0)
        queue = deque([node for node in self.nodes if out_degree[node] == 0])
        result = []

        while queue:
            node = queue.popleft()
            result.append(node)

            # Find nodes that depend on this one and decrease their out-degree
            for other_node in self.nodes:
                if node in self.edges.get(other_node, []):
                    out_degree[other_node] -= 1
                    if out_degree[other_node] == 0:
                        queue.append(other_node)

        if len(result) != len(self.nodes):
            raise ValueError("Graph has cycles (topological sort incomplete)")

        return result

    def get_deployment_waves(self) -> List[List[str]]:
        """
        Return deployment order as a list of "waves".

        Resources in the same wave have no dependencies on each other
        and can be deployed in parallel. Each wave depends on all previous waves.

        Example:
            Wave 1: [saved_search.A, lookup_file.B]  # No dependencies
            Wave 2: [detection.C]                     # Depends on A and B
            Wave 3: [workflow.D]                      # Depends on C

        Returns:
            List of waves, where each wave is a list of resource IDs

        Raises:
            ValueError: If circular dependencies are detected
        """
        sorted_nodes = self.topological_sort()

        waves = []
        deployed = set()

        while len(deployed) < len(self.nodes):
            wave = []

            # Find all resources whose dependencies have been deployed
            for node in sorted_nodes:
                if node in deployed:
                    continue

                # Check if all dependencies are deployed
                deps = self.edges.get(node, set())
                if deps.issubset(deployed):
                    wave.append(node)

            if not wave:
                # This shouldn't happen if topological_sort succeeded,
                # but check anyway
                remaining = [n for n in sorted_nodes if n not in deployed]
                raise ValueError(
                    f"Cannot determine deployment order. "
                    f"Remaining nodes: {remaining}"
                )

            waves.append(wave)
            deployed.update(wave)

        return waves

    def get_subgraph(self, resource_ids: List[str]) -> 'ResourceGraph':
        """
        Create a subgraph containing only specified resources and their dependencies.

        Useful for filtering deployments to specific resources while maintaining
        dependency order.

        Args:
            resource_ids: Resources to include in subgraph

        Returns:
            New ResourceGraph with only specified resources and their transitive dependencies
        """
        subgraph = ResourceGraph()

        # BFS to find all transitive dependencies
        to_visit = set(resource_ids)
        visited = set()

        while to_visit:
            resource_id = to_visit.pop()
            if resource_id in visited:
                continue

            visited.add(resource_id)
            subgraph.add_node(resource_id)

            # Add dependencies
            for dep in self.edges.get(resource_id, set()):
                subgraph.add_dependency(resource_id, dep)
                if dep not in visited:
                    to_visit.add(dep)

        return subgraph

    def to_dict(self) -> Dict[str, List[str]]:
        """
        Export graph to dictionary format for serialization.

        Returns:
            Dictionary mapping each node to its list of dependencies
        """
        return {
            node: list(self.edges.get(node, set()))
            for node in self.nodes
        }

    @classmethod
    def from_dict(cls, data: Dict[str, List[str]]) -> 'ResourceGraph':
        """
        Import graph from dictionary format.

        Args:
            data: Dictionary mapping nodes to their dependencies

        Returns:
            New ResourceGraph instance
        """
        graph = cls()
        for node, deps in data.items():
            graph.add_node(node)
            for dep in deps:
                graph.add_dependency(node, dep)
        return graph

    def __len__(self) -> int:
        """Return the number of nodes in the graph"""
        return len(self.nodes)

    def __contains__(self, resource_id: str) -> bool:
        """Check if a resource is in the graph"""
        return resource_id in self.nodes

    def __repr__(self) -> str:
        """String representation of the graph"""
        return f"ResourceGraph(nodes={len(self.nodes)}, edges={sum(len(deps) for deps in self.edges.values())})"
