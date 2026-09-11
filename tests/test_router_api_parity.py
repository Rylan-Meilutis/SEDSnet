import pathlib
import re
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]


class RouterApiParity(unittest.TestCase):
    """Keep the language bindings on the unified Rust Router architecture."""

    def test_removed_router_modes_are_not_public(self) -> None:
        header = (ROOT / "C-Headers" / "sedsnet.h").read_text(encoding="utf-8")
        python_api = (ROOT / "src" / "python_api.rs").read_text(encoding="utf-8")
        wrapper = (ROOT / "c-wrapper" / "sedsnet_c_wrapper.h").read_text(encoding="utf-8")
        for source in (header, python_api, wrapper):
            self.assertNotIn("SedsRouterMode", source)
            self.assertNotIn("RouterMode", source)
            self.assertNotIn("relay_sink", source.lower())

        constructor = re.search(
            r"SedsRouter \* seds_router_new\((.*?)\);", header, re.DOTALL
        )
        self.assertIsNotNone(constructor)
        self.assertNotIn("mode", constructor.group(1).lower())

    def test_core_router_features_exist_in_rust_c_and_python(self) -> None:
        rust = (ROOT / "src" / "router.rs").read_text(encoding="utf-8")
        c_api = (ROOT / "src" / "c_api.rs").read_text(encoding="utf-8")
        header = (ROOT / "C-Headers" / "sedsnet.h").read_text(encoding="utf-8")
        python_api = (ROOT / "src" / "python_api.rs").read_text(encoding="utf-8")

        features = [
            ("set_preferred_discovery_master", "set_preferred_discovery_master", "seds_router_set_preferred_discovery_master"),
            ("set_address_assignment", "configure_address", "seds_router_configure_address"),
            ("enable_network_variable", "enable_network_variable", "seds_router_enable_network_variable"),
            ("seed_managed_variable", "seed_managed_variable", "seds_router_seed_managed_variable_packed"),
            ("request_managed_variable", "request_managed_variable", "seds_router_request_managed_variable"),
            ("bind_p2p_port", "bind_p2p_port", "seds_router_bind_p2p_port"),
            ("set_timesync_config", "configure_timesync", "seds_router_configure_timesync"),
            ("process_all_queues", "process_all_queues", "seds_router_process_all_queues"),
        ]
        for rust_name, python_name, c_name in features:
            with self.subTest(feature=rust_name):
                self.assertIn(rust_name, rust)
                self.assertIn(f"fn {python_name}", python_api)
                self.assertIn(f"fn {c_name}", c_api)
                self.assertIn(c_name, header)


if __name__ == "__main__":
    unittest.main()
