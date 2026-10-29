"""Verify the current platform's installed runtime/test dependency closure is pinned.

Run with the server test venv after installing requirements.lock and server[test].
This is a version-closure check, not a wheel-hash or provenance verification.
"""
import importlib.metadata
from pathlib import Path
import unittest

from packaging.requirements import Requirement
from packaging.utils import canonicalize_name


class DependencyLockTests(unittest.TestCase):
    def test_installed_runtime_and_test_dependency_closure_is_pinned(self):
        lock_path = Path(__file__).resolve().parents[1] / 'server/requirements.lock'
        locked = {}
        for line in lock_path.read_text().splitlines():
            if not line.strip() or line.lstrip().startswith('#'):
                continue
            requirement = Requirement(line)
            if requirement.marker and not requirement.marker.evaluate({'extra': ''}):
                continue
            pins = list(requirement.specifier)
            self.assertEqual(len(pins), 1, f'exact version required: {requirement.name}')
            self.assertEqual(pins[0].operator, '==')
            self.assertNotIn('*', pins[0].version)
            locked[canonicalize_name(requirement.name)] = pins[0].version
        queue = [('orangespace-node', frozenset({'test'}))]
        visited = set()
        while queue:
            name, extras = queue.pop()
            key = canonicalize_name(name), extras
            if key in visited:
                continue
            visited.add(key)
            distribution = importlib.metadata.distribution(name)
            for value in distribution.requires or []:
                requirement = Requirement(value)
                if requirement.marker and not any(
                    requirement.marker.evaluate({'extra': extra}) for extra in {'', *extras}
                ):
                    continue
                dependency = canonicalize_name(requirement.name)
                self.assertIn(dependency, locked, f'unpinned required dependency: {requirement.name}')
                actual = importlib.metadata.version(requirement.name)
                self.assertEqual(actual, locked[dependency], f'installed version drift: {requirement.name}')
                self.assertIn(actual, requirement.specifier, f'incompatible dependency: {requirement.name}')
                queue.append((requirement.name, frozenset(requirement.extras)))


if __name__ == '__main__':
    unittest.main()
