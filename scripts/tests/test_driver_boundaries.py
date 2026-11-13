"""The gate must reject indirect/optional edges, while allowing host fixtures."""
import importlib.util
from pathlib import Path
import unittest

path = Path(__file__).resolve().parents[1] / 'check-driver-boundaries.py'
spec = importlib.util.spec_from_file_location('boundaries', path)
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


def package(name, directory, *dependencies):
    return {'name': name, 'manifest_path': str(gate.ROOT / directory / 'Cargo.toml'),
            'dependencies': list(dependencies)}


def edge(name, **flags):
    return {'name': name, 'kind': None, **flags}


class Boundaries(unittest.TestCase):
    def test_indirect_optional_driver_dependency_is_rejected(self):
        packages = [package('kernel', 'kernel', edge('service')),
                    package('service', 'services/test', edge('hw', optional=True, rename='alias')),
                    package('hw', 'drivers/test')]
        self.assertEqual(gate.violations(packages), ['kernel -> service -> hw'])

    def test_build_dependency_on_bsp_is_rejected(self):
        packages = [package('hw', 'drivers/test', edge('board', kind='build')),
                    package('board', 'boards/test')]
        self.assertEqual(gate.violations(packages), ['hw -> board'])

    def test_host_fixtures_and_protocol_contract_are_allowed(self):
        packages = [package('kernel', 'kernel', edge('protocol')),
                    package('protocol', 'contracts/test', edge('hw', kind='dev')),
                    package('hw', 'drivers/test', edge('protocol'))]
        self.assertEqual(gate.violations(packages), [])


if __name__ == '__main__':
    unittest.main()
