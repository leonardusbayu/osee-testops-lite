"""Bounded, exact-owned, synthetic-only Caddy ingress qualification."""
import datetime
import importlib.util
import json
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.request import ProxyHandler, build_opener

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("candidate_control", ROOT / "scripts/candidate-control.py")
if spec is None or spec.loader is None:
    raise RuntimeError("Candidate controller could not be loaded")
control = importlib.util.module_from_spec(spec)
spec.loader.exec_module(control)


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def ready():
    with build_opener(ProxyHandler({})).open("http://127.0.0.1:8091/health/ready", timeout=3) as response:
        require(response.status == 200, "Real proxy readiness failed")
        require(json.loads(response.read(1024)) == {"database": "ready"}, "Unexpected readiness payload")


def wait_gateway(manifest, restarted_after=None):
    deadline = time.monotonic() + 45
    identifier = manifest["resources"]["gateway"]["id"]
    while time.monotonic() < deadline:
        actual = control.DockerClient().inspect("container", identifier)
        require(actual["Id"] == identifier, "Gateway identity changed")
        require(actual["Config"]["Labels"][control.SCOPE_LABEL] == manifest["scope_id"], "Gateway scope changed")
        if (actual["State"]["Running"] and actual["State"].get("Health", {}).get("Status") == "healthy"
                and (restarted_after is None or actual["RestartCount"] > restarted_after)):
            verified = control.verify_owned(manifest, "gateway")
            ready()
            return verified
        time.sleep(0.4)
    raise RuntimeError("Exact gateway recovery/readiness deadline exceeded")


def qualify():
    target = ROOT / "docs/campaign/evidence/r1/t01-ingress-runtime-qualification.json"
    require(not target.exists(), "Preserve historical qualification evidence")
    before = control._load_manifest()
    require(set(before["resources"]) == {"db"}, "Preserve existing services and manual stops")
    control.verify_owned(before, "db")
    result = {"utc": datetime.datetime.now(datetime.timezone.utc).isoformat(), "profile": "fixture",
              "live_actions": False, "local_release_accepted": False, "full_campaign_accepted": False}
    try:
        result["startup"] = control.start_candidate("fixture")
        manifest = control._load_manifest()
        result["scope_id"] = manifest["scope_id"]
        gateway = wait_gateway(manifest)
        result["gateway_id"] = gateway["Id"]
        result["runtime_ports"] = gateway["NetworkSettings"]["Ports"]
        result["frontend_members"] = sorted(control._verify_frontend(manifest)["Containers"])
        result["before_fault"] = {"restart_count": gateway["RestartCount"], "started_at": gateway["State"]["StartedAt"]}
        require(gateway["HostConfig"]["RestartPolicy"]["Name"] == "unless-stopped", "Intentional-stop policy missing")
        control.verify_owned(manifest, "gateway")
        control.DockerClient().call(["container", "exec", gateway["Id"], "sh", "-c", "kill -ABRT 1"], timeout=10)
        recovered = wait_gateway(manifest, gateway["RestartCount"])
        result["automatic_recovery"] = {"restart_count": recovered["RestartCount"], "started_at": recovered["State"]["StartedAt"],
                                        "health": recovered["State"]["Health"]["Status"], "readiness_json_checked": True}
        errors = []
        completed = 0
        soak_end = time.monotonic() + 20

        def request(index):
            path = ["/health/ready", "/", "/assets/app.css"][index % 3]
            try:
                with build_opener(ProxyHandler({})).open("http://127.0.0.1:8091" + path, timeout=3) as response:
                    require(response.status == 200, "Unexpected HTTP status")
                    if path == "/health/ready":
                        require(json.loads(response.read(1024)) == {"database": "ready"}, "Unexpected readiness body")
                    else:
                        require(bool(response.read(512)), "Empty real page/asset")
                return None
            except Exception as error:
                return type(error).__name__

        with ThreadPoolExecutor(max_workers=4) as executor:
            while time.monotonic() < soak_end:
                batch = list(executor.map(request, range(12)))
                completed += len(batch)
                errors.extend(error for error in batch if error is not None)
        result["bounded_http_soak"] = {"seconds_budget": 20, "workers": 4, "completed": completed, "errors": errors}
        require(not errors, "Actual HTTP soak failed")
        control.verify_owned(manifest, "gateway")
        control.DockerClient().call(["container", "stop", "--time", "3", gateway["Id"]], timeout=15)
        stopped = control.verify_owned(manifest, "gateway")
        require(not stopped["State"]["Running"], "Manual stop not applied")
        stop_end = time.monotonic() + 6
        observations = 0
        while time.monotonic() < stop_end:
            actual = control.verify_owned(manifest, "gateway")
            require(not actual["State"]["Running"], "Manual stop was overridden")
            observations += 1
            time.sleep(0.4)
        result["manual_stop_preserved"] = {"seconds_budget": 6, "observations": observations, "running": False}
        result["status"] = "PASS_ISOLATED_INGRESS_ONLY"
    finally:
        result["cleanup"] = control.stop_fixture("fixture")
        final = control._load_manifest()
        require(set(final["resources"]) == {"db"}, "Unexpected resources after exact fixture cleanup")
        require(control._verify_frontend(final)["Containers"] == {}, "Frontend is not empty after cleanup")
        require(control.verify_owned(final, "db")["State"]["Running"], "Owned DB was not retained running")
    result["completed_utc"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    control._save_metadata(target, result)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    qualify()
