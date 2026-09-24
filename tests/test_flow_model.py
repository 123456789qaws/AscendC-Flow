import unittest
import copy
import xml.etree.ElementTree as ET

from tools.ascend_flow.model import analyze, compile_net, export_pnml


def spec(instructions):
    return {"schema": "ascend-program/1", "target": {"soc": "Ascend910B4", "cann": "9.1.x"},
            "provenance": {"kind": "manual_semantic_model", "hardware_validated": False},
            "resources": [{"id": "X0", "kind": "buffer"}], "flags": [],
            "programs": [{"id": "p", "pipe": "MTE2", "instructions": instructions}]}


class FlowModelTests(unittest.TestCase):
    def flag_spec(self, ops):
        model = spec([{"op": op, "flag": "ready"} for op in ops])
        model["flags"] = [{"id": "ready", "core": 0, "src": "MTE2", "dst": "V", "event_id": 0, "initial": 0}]
        return model

    def test_flag_wait_and_protocol_errors_are_distinct(self):
        matched = self.flag_spec(["set"])
        matched["programs"].append({"id": "q", "pipe": "V", "instructions": [{"op": "wait", "flag": "ready"}]})
        self.assertEqual(analyze(matched)["counts"]["normal_final"], 1)
        waiting = self.flag_spec([])
        waiting["programs"].append({"id": "q", "pipe": "V", "instructions": [{"op": "wait", "flag": "ready"}]})
        dead = analyze(waiting)
        self.assertEqual(dead["status"], "deadlock_found")
        self.assertTrue(dead["witnesses"]["deadlock"]["replay_verified"])
        bad = analyze(self.flag_spec(["set", "set"]))
        self.assertEqual(bad["counts"]["protocol_error"], 1)
        self.assertEqual(bad["counts"]["deadlock"], 0)

    def test_balanced_resource_lifecycle_completes(self):
        model = spec([{"op": "acquire", "resource": "X0"}, {"op": "work", "label": "copy"},
                      {"op": "release", "resource": "X0"}])
        result = analyze(model)
        self.assertEqual(result["status"], "no_deadlock_in_finite_model")
        self.assertEqual(result["counts"]["normal_final"], 1)
        self.assertEqual(result["counts"]["states"], 4)
        self.assertTrue(result["complete"])

    def test_nonowner_release_stops_with_diagnostic(self):
        model = spec([{"op": "release", "resource": "X0", "source": {"symbol": "bad_release"}}])
        result = analyze(model)
        self.assertEqual(result["status"], "protocol_error_found")
        self.assertEqual(result["counts"]["deadlock"], 0)
        self.assertEqual(result["witnesses"]["protocol_error"]["steps"][0]["transition"]["source"], {"symbol": "bad_release"})

    def test_unreleased_resource_and_residual_signal_are_termination_errors(self):
        for model in [spec([{"op": "acquire", "resource": "X0"}]), self.flag_spec(["set"])]:
            with self.subTest(model=model):
                result = analyze(model)
                self.assertEqual(result["status"], "termination_protocol_error_found")
                self.assertEqual(result["counts"]["deadlock"], 0)

    def test_state_limit_cannot_certify_safety(self):
        result = analyze(spec([{"op": "work"}]), state_limit=1)
        self.assertEqual(result["status"], "unknown")
        self.assertFalse(result["complete"])

    def test_circular_resource_wait_has_replayable_counterexample(self):
        model = spec([{"op": "acquire", "resource": "X0"}, {"op": "acquire", "resource": "Y0"}])
        model["resources"].append({"id": "Y0", "kind": "buffer"})
        model["programs"].append({"id": "q", "pipe": "V", "instructions": [
            {"op": "acquire", "resource": "Y0"}, {"op": "acquire", "resource": "X0"}]})
        result = analyze(model)
        self.assertGreater(result["counts"]["deadlock"], 0)
        self.assertTrue(result["witnesses"]["deadlock"]["replay_verified"])
        self.assertTrue(result["invariants"]["all_stored_states_hold"])

    def test_pnml_is_parseable_and_preserves_markings_and_arcs(self):
        net = compile_net(spec([{"op": "work", "source": {"symbol": "copy<>&"}}]))
        xml = ET.fromstring(export_pnml(net))
        self.assertEqual(xml.tag, "pnml")
        self.assertEqual(len(xml.findall(".//place")), len(net["places"]))
        self.assertEqual(len(xml.findall(".//transition")), len(net["transitions"]))
        identifiers = {e.attrib["id"] for e in xml.findall(".//place") + xml.findall(".//transition")}
        self.assertTrue(all(a.attrib["source"] in identifiers and a.attrib["target"] in identifiers for a in xml.findall(".//arc")))

    def test_rejects_invalid_and_unsupported_input_instead_of_ignoring(self):
        cases = []
        m = spec([]); m["resources"].append(copy.deepcopy(m["resources"][0])); cases.append(m)
        m = self.flag_spec([]); f = dict(m["flags"][0], id="alias"); m["flags"].append(f); cases.append(m)
        for instruction in [{"op": "if"}, {"op": "acquire", "resource": "absent"},
                            {"op": "wait", "flag": "absent"}, {"op": "work", "guard": True},
                            {"op": "work", "loop": 3}, {"op": "work", "label": 5},
                            {"op": "work", "source": []}]:
            cases.append(spec([instruction]))
        m = spec([]); m["loops"] = []; cases.append(m)
        m = self.flag_spec([]); m["flags"][0]["initial"] = 2; cases.append(m)
        m = self.flag_spec([]); m["flags"][0]["event_id"] = True; cases.append(m)
        m = self.flag_spec([]); m["flags"][0]["event_id"] = 8; cases.append(m)
        m = self.flag_spec([]); m["flags"][0]["core"] = -1; cases.append(m)
        m = spec([]); m["provenance"]["hardware_validated"] = True; cases.append(m)
        m = spec([]); m["programs"][0]["instructions"] = "work"; cases.append(m)
        m = self.flag_spec(["wait"]); cases.append(m)  # producer pipe cannot consume V's wait
        for invalid in cases:
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                compile_net(invalid)
        for limit in [0, -1, True, 1.1, "10"]:
            with self.subTest(limit=limit), self.assertRaises(ValueError):
                analyze(spec([]), limit)

    def test_owned_release_cannot_destroy_another_programs_token(self):
        model = spec([{"op": "acquire", "resource": "X0"}])
        model["programs"].append({"id": "q", "pipe": "V", "instructions": [{"op": "release", "resource": "X0"}]})
        result = analyze(model)
        self.assertGreater(result["counts"]["protocol_error"], 0)
        self.assertTrue(result["invariants"]["all_stored_states_hold"])

    def test_export_keeps_physical_flag_identity_and_model_provenance(self):
        model = self.flag_spec(["set"])
        net = compile_net(model)
        root = ET.fromstring(export_pnml(net))
        import json
        saved = json.loads(root.find(".//model_metadata_json").text)
        self.assertEqual(saved["flags"][0]["src"], "MTE2")
        self.assertEqual(saved["flags"][0]["dst"], "V")
        self.assertIs(saved["provenance"]["hardware_validated"], False)
        self.assertEqual(analyze(model)["target"], model["target"])

    def test_accepts_observed_cann_beta_version_without_dropping_suffix(self):
        for version in ["9.1.0-beta.1", "9.1.0.beta.1", "9.1.0-RC1"]:
            model = spec([])
            model["target"]["cann"] = version
            self.assertEqual(analyze(model)["target"]["cann"], version)


if __name__ == "__main__":
    unittest.main()
