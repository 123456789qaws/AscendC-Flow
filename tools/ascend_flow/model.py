"""Finite identity-color expansion and explicit-state analysis; no hardware proof."""
from collections import deque
import json
import math
import re
import xml.etree.ElementTree as ET

METHOD = "explicit_state_space_on_color_expanded_net"
SCOPE = "Finite manual semantic model only; no actual Ascend hardware deadlock-freedom claim."


def _validate(spec):
    def obj(value, required, optional=()):
        if not isinstance(value, dict):
            raise ValueError("Expected an object")
        if set(value) - set(required) - set(optional) or set(required) - set(value):
            raise ValueError(f"Unsupported or missing fields; required={required}, optional={optional}, got={list(value)}")
    def string(value):
        if not isinstance(value, str) or not value.strip():
            raise ValueError("Expected a nonempty string")
    def integer(value, minimum=0, maximum=None):
        if type(value) is not int or value < minimum or (maximum is not None and value > maximum):
            raise ValueError("Integer outside supported bounds")
    def json_value(value):
        if value is None or type(value) in {str, bool, int}:
            return
        if type(value) is float and math.isfinite(value):
            return
        if isinstance(value, list):
            for item in value:
                json_value(item)
            return
        if isinstance(value, dict) and all(isinstance(k, str) for k in value):
            for item in value.values():
                json_value(item)
            return
        raise ValueError("source must contain only finite JSON values")
    obj(spec, ("schema", "target", "provenance", "resources", "flags", "programs"))
    if spec["schema"] != "ascend-program/1":
        raise ValueError("Unsupported schema")
    obj(spec["target"], ("soc", "cann"))
    target = spec["target"]
    if target["soc"] != "Ascend910B4" or not isinstance(target["cann"], str) or not re.fullmatch(r"9\.1\.(?:x|\d+(?:[-.](?:beta|rc)[.-]?\d+)?)", target["cann"], re.IGNORECASE):
        raise ValueError("This model backend is scoped to Ascend910B4 / CANN 9.1.x")
    obj(spec["provenance"], ("kind", "hardware_validated"))
    if spec["provenance"]["kind"] != "manual_semantic_model" or spec["provenance"]["hardware_validated"] is not False:
        raise ValueError("Only unvalidated manual semantic models are supported")
    for collection in ("resources", "flags", "programs"):
        if not isinstance(spec[collection], list):
            raise ValueError(f"{collection} must be a list")
    resources, flags, physical_keys, programs = set(), {}, set(), set()
    for resource in spec["resources"]:
        obj(resource, ("id", "kind"))
        string(resource["id"]); string(resource["kind"])
        if resource["id"] in resources:
            raise ValueError("Duplicate resource id")
        resources.add(resource["id"])
    for flag in spec["flags"]:
        obj(flag, ("id", "core", "src", "dst", "event_id", "initial"))
        for key in ("id", "src", "dst"):
            string(flag[key])
        integer(flag["core"])
        integer(flag["event_id"], maximum=7)
        integer(flag["initial"], maximum=0)
        if flag["src"] == flag["dst"]:
            raise ValueError("Flag requires distinct source and destination pipelines")
        key = (flag["core"], flag["src"], flag["dst"], flag["event_id"])
        if flag["id"] in flags or key in physical_keys:
            raise ValueError("Duplicate flag id or physical flag key")
        flags[flag["id"]] = flag
        physical_keys.add(key)
    for program in spec["programs"]:
        obj(program, ("id", "pipe", "instructions"), ("core",))
        string(program["id"]); string(program["pipe"])
        integer(program.get("core", 0))
        if program["id"] in programs:
            raise ValueError("Duplicate program id")
        programs.add(program["id"])
        if not isinstance(program["instructions"], list):
            raise ValueError("instructions must be a finite list")
        for instruction in program["instructions"]:
            if not isinstance(instruction, dict):
                raise ValueError("Instruction must be an object")
            op = instruction.get("op")
            if not isinstance(op, str) or op not in {"work", "acquire", "release", "set", "wait"}:
                raise ValueError("Unsupported operation; loops and conditions must not be silently erased")
            parameter = "resource" if op in {"acquire", "release"} else "flag" if op in {"set", "wait"} else None
            obj(instruction, ("op", parameter) if parameter else ("op",), ("source", "label"))
            if "label" in instruction:
                string(instruction["label"])
            if "source" in instruction:
                if not isinstance(instruction["source"], dict):
                    raise ValueError("source must be an object")
                json_value(instruction["source"])
            if parameter:
                string(instruction[parameter])
                if instruction[parameter] not in (resources if parameter == "resource" else flags):
                    raise ValueError(f"Unknown {parameter}")
            if parameter == "flag":
                flag = flags[instruction["flag"]]
                expected_pipe = flag["src" if op == "set" else "dst"]
                if program["pipe"] != expected_pipe or program.get("core", 0) != flag["core"]:
                    raise ValueError("Flag use must match its source/destination pipeline and core")


def _place(*parts):
    return json.dumps(parts, ensure_ascii=False, separators=(",", ":"))


def compile_net(spec):
    """Compile validated finite programs into a one-safe ordinary P/T net.

    Source objects are opaque provenance, not interpreted program semantics.
    Guards, loops and undeclared fields are rejected, never silently ignored.
    """
    _validate(spec)
    programs = spec["programs"]
    resources = spec["resources"]
    places, transitions, initial, final = [], [], {}, {}
    def add(place, start=0, end=0):
        if place not in places:
            places.append(place)
        if start:
            initial[place] = start
        if end:
            final[place] = end
        return place
    for r in resources:
        add(_place("free", r["id"]), 1, 1)
        for p in programs:
            add(_place("held", r["id"], p["id"]))
    active = add(_place("RUN"), 1, 1)
    error = add(_place("PROTOCOL_ERROR"))
    for flag in spec["flags"]:
        for value in (0, 1):
            add(_place("flag", flag["id"], value), int(value == flag["initial"]), int(value == 0))
    for p in programs:
        instructions = p["instructions"]
        for i in range(len(instructions) + 1):
            add(_place("pc", p["id"], i), int(i == 0), int(i == len(instructions)))
        for i, instruction in enumerate(instructions):
            pre = {_place("pc", p["id"], i): 1, active: 1}
            post = {_place("pc", p["id"], i + 1): 1, active: 1}
            op = instruction["op"]
            if op == "acquire":
                pre[_place("free", instruction["resource"])] = 1
                post[_place("held", instruction["resource"], p["id"])] = 1
            elif op == "release":
                pre[_place("held", instruction["resource"], p["id"])] = 1
                post[_place("free", instruction["resource"])] = 1
            elif op in {"set", "wait"}:
                before = 0 if op == "set" else 1
                pre[_place("flag", instruction["flag"], before)] = 1
                post[_place("flag", instruction["flag"], 1 - before)] = 1
            transitions.append({"id": f"t{len(transitions)}", "name": op, "pre": pre, "post": post,
                                "source": instruction.get("source"), "program": p["id"], "instruction_index": i})
            if op == "set":
                flag1 = _place("flag", instruction["flag"], 1)
                pc = _place("pc", p["id"], i)
                transitions.append({"id": f"t{len(transitions)}", "name": "set_flag_already_one",
                                    "pre": {pc: 1, active: 1, flag1: 1},
                                    "post": {pc: 1, error: 1, flag1: 1}, "diagnostic": "set_flag_already_one",
                                    "source": instruction.get("source"), "program": p["id"], "instruction_index": i})
            elif op == "release":
                pc = _place("pc", p["id"], i)
                r = instruction["resource"]
                other_locations = [_place("free", r)] + [_place("held", r, q["id"]) for q in programs if q["id"] != p["id"]]
                for location in other_locations:
                    transitions.append({"id": f"t{len(transitions)}", "name": "release_by_nonowner",
                                        "pre": {pc: 1, active: 1, location: 1},
                                        "post": {pc: 1, error: 1, location: 1}, "diagnostic": "release_by_nonowner",
                                        "source": instruction.get("source"), "program": p["id"], "instruction_index": i})
    invariant_groups = [[active, error]]
    invariant_groups += [[_place("free", r["id"])] + [_place("held", r["id"], p["id"]) for p in programs] for r in resources]
    invariant_groups += [[_place("flag", f["id"], 0), _place("flag", f["id"], 1)] for f in spec["flags"]]
    invariant_groups += [[_place("pc", p["id"], i) for i in range(len(p["instructions"]) + 1)] for p in programs]
    return {"places": places, "transitions": transitions, "initial": initial, "final": final,
            "error_place": error, "active_place": active,
            "invariant_groups": invariant_groups,
            "final_pc_places": [_place("pc", p["id"], len(p["instructions"])) for p in programs],
            "model_metadata": json.loads(json.dumps({k: spec[k] for k in ("schema", "target", "provenance", "resources", "flags")})),
            "method": METHOD, "scope": SCOPE}


def analyze(spec, state_limit=100000):
    if type(state_limit) is not int or state_limit < 1:
        raise ValueError("state_limit must be a positive integer")
    net = compile_net(spec)
    canonical = lambda m: tuple(sorted((p, n) for p, n in m.items() if n))
    start = canonical(net["initial"])
    parents = {start: None}
    queue = deque([start])
    counts = {"states": 1, "normal_final": 0, "deadlock": 0, "protocol_error": 0,
              "termination_protocol_error": 0, "edges_examined": 0, "omitted_successor_edges": 0}
    witnesses = {}
    def fire(m, t):
        successor = dict(m)
        for p, n in t["pre"].items():
            successor[p] -= n
        for p, n in t["post"].items():
            successor[p] = successor.get(p, 0) + n
        return canonical(successor)
    while queue:
        state = queue.popleft()
        m = dict(state)
        if not all(n == 1 for n in m.values()) or not all(sum(m.get(p, 0) for p in group) == 1 for group in net["invariant_groups"]):
            raise RuntimeError("Compiled net violated its one-safe conservation invariants")
        enabled = [t for t in net["transitions"] if all(m.get(p, 0) >= n for p, n in t["pre"].items())]
        if not enabled:
            if m.get(net["error_place"]):
                category = "protocol_error"
            elif m == net["final"]:
                category = "normal_final"
            elif all(m.get(p) == 1 for p in net["final_pc_places"]):
                category = "termination_protocol_error"
            else:
                category = "deadlock"
            counts[category] += 1
            if category not in witnesses:
                path = []
                cursor = state
                while parents[cursor] is not None:
                    previous, transition = parents[cursor]
                    assert all(dict(previous).get(p, 0) >= n for p, n in transition["pre"].items())
                    assert fire(dict(previous), transition) == cursor
                    path.append({"transition": transition, "before": dict(previous), "after": dict(cursor), "enabled": True})
                    cursor = previous
                assert cursor == start
                witnesses[category] = {"initial": dict(start), "steps": list(reversed(path)), "terminal": m,
                                       "terminal_enabled_transitions": [], "replay_verified": True}
        for t in enabled:
            counts["edges_examined"] += 1
            target = fire(m, t)
            if target not in parents:
                if len(parents) >= state_limit:
                    counts["omitted_successor_edges"] += 1
                    continue
                parents[target] = (state, t)
                queue.append(target)
    counts["states"] = len(parents)
    complete = counts["omitted_successor_edges"] == 0
    status = "no_deadlock_in_finite_model" if complete else "unknown"
    for category in ("termination_protocol_error", "deadlock", "protocol_error"):
        if counts[category]:
            status = category + "_found"
    return {"status": status,
            "witnesses": witnesses,
            "counts": counts, "complete": complete, "state_limit": state_limit, "method": METHOD, "scope": SCOPE,
            "target": dict(spec["target"]), "provenance": dict(spec["provenance"]),
            "invariants": {"all_stored_states_hold": True, "checked": ["one_safety", "resource_conservation", "flag_mutual_exclusion", "program_counter_uniqueness", "run_error_exclusion"]},
            "limitations": ["No hardware validation, timed behavior, compiler-generated synchronization, or Petri-net unfolding.",
                            "No source-order consecutive-Set static rule; Set at flag=1 is a diagnostic boundary, not predicted undefined hardware behavior.",
                            "Work is an atomic abstract completion, not an issued asynchronous hardware instruction.",
                            "Programs interleave independently; shared pipeline arbitration/order and actual HardEvent support are not verified.",
                            "RUN self-loops preserve state behavior but introduce artificial structural dependencies; do not use this net to claim hardware concurrency or unfolding reduction."]}


def export_pnml(net):
    root = ET.Element("pnml")
    element = ET.SubElement(root, "net", id="ascend_finite_model", type="http://www.pnml.org/version-2009/grammar/ptnet")
    ET.SubElement(ET.SubElement(element, "name"), "text").text = "Finite identity-color expansion; not behavior unfolding or cutoff prefix"
    metadata = ET.SubElement(element, "toolspecific", tool="ascend-flow", version="1")
    ET.SubElement(metadata, "method").text = METHOD
    ET.SubElement(metadata, "scope").text = SCOPE
    ET.SubElement(metadata, "model_metadata_json").text = json.dumps(net["model_metadata"], ensure_ascii=False)
    ET.SubElement(metadata, "final_marking_json").text = json.dumps(net["final"], ensure_ascii=False)
    page = ET.SubElement(element, "page", id="page0")
    place_ids = {p: f"p{i}" for i, p in enumerate(net["places"])}
    for p, pid in place_ids.items():
        item = ET.SubElement(page, "place", id=pid)
        ET.SubElement(ET.SubElement(item, "name"), "text").text = p
        ET.SubElement(ET.SubElement(item, "initialMarking"), "text").text = str(net["initial"].get(p, 0))
    arc_id = 0
    for t in net["transitions"]:
        item = ET.SubElement(page, "transition", id=t["id"])
        ET.SubElement(ET.SubElement(item, "name"), "text").text = t["name"]
        details = ET.SubElement(item, "toolspecific", tool="ascend-flow", version="1")
        ET.SubElement(details, "source_json").text = json.dumps(t["source"], ensure_ascii=False)
        for direction in ("pre", "post"):
            for p, weight in t[direction].items():
                source, target = (place_ids[p], t["id"]) if direction == "pre" else (t["id"], place_ids[p])
                arc = ET.SubElement(page, "arc", id=f"a{arc_id}", source=source, target=target)
                ET.SubElement(ET.SubElement(arc, "inscription"), "text").text = str(weight)
                arc_id += 1
    ET.indent(root)
    return ET.tostring(root, encoding="unicode", xml_declaration=True)
