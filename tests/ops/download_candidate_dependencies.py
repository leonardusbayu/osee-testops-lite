"""Download only approved public Go modules in a secret-free owned SDK."""
import datetime
import hashlib
import importlib.util
import json
import subprocess
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
loader = importlib.util.spec_from_file_location("candidate_control", ROOT / "scripts/candidate-control.py")
if loader is None or loader.loader is None:
    raise RuntimeError("Candidate controller loader unavailable")
control = importlib.util.module_from_spec(loader)
loader.loader.exec_module(control)
manifest = control._load_manifest()
control.verify_owned(manifest, "db")
docker = control.DockerClient()
cache = ROOT / ".local/public-modules"
marker = ROOT / ".local/public-modules.json"
control._no_reparse(cache.parent)
previous = ROOT / "docs/campaign/evidence/r1/t02-public-dependency-download.json"
if marker.exists():
    raise control.ScopeError("Completed public-cache marker already exists; no overwrite")
if cache.exists():
    control._no_reparse(cache)
    control._no_reparse(previous)
    prior = json.loads(previous.read_text(encoding="utf-8"))
    if (not cache.is_dir() or prior.get("scope_id") != manifest["scope_id"]
            or prior.get("candidate_root") != ROOT.as_posix() or prior.get("cache_root") != cache.as_posix()
            or prior.get("verified") is not True or prior.get("exact_sdk_removed") is not True
            or prior.get("private_mounts") is not False):
        raise control.ScopeError("Public cache not bound to the successful owned dependency step")
workspace = ROOT / ".local" / ("dependency-public-" + uuid.uuid4().hex)
workspace.mkdir()
if not cache.exists():
    cache.mkdir()
for name in ["go.mod", "go.sum"]:
    source = ROOT / name
    control._no_reparse(source)
    with (workspace / name).open("xb") as stream:
        stream.write(source.read_bytes())
if {path.name for path in workspace.iterdir()} != {"go.mod", "go.sum"}:
    raise control.ScopeError("Dependency workspace contains unexpected content")
name = manifest["network"]["name"] + "-deps"
if name in docker.call(["container", "ls", "-a", "--format", "{{.Names}}"] ).stdout.splitlines():
    raise control.ScopeError("Dependency SDK namespace collision")
image = docker.inspect("image", control.SDK)
if image["Id"] != manifest["images"]["sdk"]:
    raise control.ScopeError("Pinned dependency SDK identity changed")
environment = {
    "GOENV": "off", "GOTOOLCHAIN": "local", "GOFLAGS": "-buildvcs=false",
    "GOPROXY": "https://proxy.golang.org", "GOSUMDB": "sum.golang.org",
    "GOPRIVATE": "", "GONOPROXY": "", "GONOSUMDB": "",
    "GOMODCACHE": "/modules", "GOCACHE": "/tmp/go-cache", "GOPATH": "/tmp/gopath", "HOME": "/tmp",
}
command = (
    "set -eu; go get golang.org/x/crypto/argon2@v0.57.0 github.com/pquerna/otp@v1.5.0; "
    "go mod download all; go mod verify; go list -m -json all > /src/modules.json; "
    "go mod graph > /src/graph.txt; go mod edit -json > /src/module.json; "
    "go env -json GOENV GOTOOLCHAIN GOPROXY GOSUMDB GOPRIVATE GONOPROXY GONOSUMDB > /src/environment.json; "
    "go doc golang.org/x/crypto/argon2.IDKey > /src/argon2-api.txt; "
    "go doc github.com/pquerna/otp/hotp.GenerateCodeCustom > /src/hotp-api.txt; "
    "go doc github.com/pquerna/otp/hotp.ValidateOpts > /src/hotp-options.txt; "
    "go doc github.com/pquerna/otp.Key.Image > /src/local-qr-api.txt; "
    "cp /modules/golang.org/x/crypto@v0.57.0/LICENSE /src/crypto-LICENSE; "
    "cp /modules/github.com/pquerna/otp@v1.5.0/LICENSE /src/otp-LICENSE; "
    "printf 'APPROVED_PUBLIC_DEPENDENCIES_VERIFIED\\n'"
)
args = ["container", "create", "--pull=never", "--name", name,
        "--label", control.SCOPE_LABEL + "=" + manifest["scope_id"],
        "--label", control.ROLE_LABEL + "=deps", "--network", "bridge", "--read-only",
        "--user", "65532:65532", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
        "--tmpfs", "/tmp:rw,nosuid,size=512m", "-w", "/src"]
for key, value in environment.items():
    args += ["--env", key + "=" + value]
for source, destination in [(workspace, "/src"), (cache, "/modules")]:
    args += ["--mount", "type=bind,source=" + source.as_posix() + ",target=" + destination]
args += [control.SDK, "sh", "-ec", command]
identifier = docker.call(args).stdout.strip()


def verified_sdk():
    actual = docker.inspect("container", identifier)
    labels = actual["Config"].get("Labels") or {}
    host = actual["HostConfig"]
    expected = {"/src": workspace, "/modules": cache}
    if (actual["Id"] != identifier or actual["Name"] != "/" + name
            or actual["Image"] != image["Id"] or labels.get(control.SCOPE_LABEL) != manifest["scope_id"]
            or labels.get(control.ROLE_LABEL) != "deps" or actual["Config"]["User"] != "65532:65532"
            or host["ReadonlyRootfs"] is not True or host["Privileged"] or host.get("CapAdd")
            or set(host.get("CapDrop") or []) != {"ALL"}
            or "no-new-privileges:true" not in (host.get("SecurityOpt") or [])
            or host.get("PortBindings") or host.get("NetworkMode") != "bridge"
            or set(actual["NetworkSettings"]["Networks"]) != {"bridge"}
            or {m["Destination"] for m in actual["Mounts"] if m["Type"] == "bind"} != set(expected)):
        raise control.ScopeError("Dependency SDK ownership, isolation or security mismatch")
    for mount in actual["Mounts"]:
        if mount["Type"] == "tmpfs" and mount["Destination"] == "/tmp":
            continue
        if mount["Type"] != "bind" or mount["RW"] is not True or mount["Destination"] not in expected:
            raise control.ScopeError("Unexpected dependency SDK mount")
        source = mount["Source"].replace("\\", "/")
        for prefix in ["/run/desktop/mnt/host/", "/host_mnt/"]:
            if source.startswith(prefix):
                source = source[len(prefix)].upper() + ":/" + source[len(prefix) + 2:]
        if source.casefold() != expected[mount["Destination"]].as_posix().casefold():
            raise control.ScopeError("Dependency SDK mounted non-public source")
    env = dict(item.split("=", 1) for item in actual["Config"]["Env"] if "=" in item)
    if any(env.get(key) != value for key, value in environment.items()):
        raise control.ScopeError("Dependency SDK public environment mismatch")
    if any("DATABASE" in key or "TOKEN" in key or "PASSWORD" in key or "SECRET" in key for key in env):
        raise control.ScopeError("Dependency SDK private environment refused")
    return actual


report = {"scope_id": manifest["scope_id"], "candidate_root": ROOT.as_posix(),
          "cache_root": cache.as_posix(), "workspace": workspace.as_posix(), "dependency_step": "R1-T02",
          "sdk_id": identifier, "sdk_image_id": image["Id"], "goproxy": environment["GOPROXY"],
          "gosumdb": environment["GOSUMDB"], "private_mounts": False,
          "original_network_used": False, "candidate_network_used": False,
          "frontend_network_used": False, "verified": False, "exact_sdk_removed": False}
try:
    verified_sdk()
    completed = subprocess.run(control.DOCKER + ["container", "start", "-a", identifier],
                               capture_output=True, text=True, timeout=420)
    state = verified_sdk()["State"]
    output = completed.stdout + completed.stderr
    with (workspace / "download.log").open("x", encoding="utf-8") as stream:
        stream.write(output)
    report["exit_code"] = state["ExitCode"] if state["Status"] == "exited" else 1
    report["verified"] = completed.returncode == 0 and report["exit_code"] == 0 and "APPROVED_PUBLIC_DEPENDENCIES_VERIFIED" in output
finally:
    verified_sdk()
    docker.call(["container", "rm", "-f", identifier])
    report["exact_sdk_removed"] = identifier not in docker.call(["container", "ls", "-a", "--no-trunc", "--format", "{{.ID}}"] ).stdout.splitlines()
    report["observed_utc"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    target = ROOT / "docs/campaign/evidence/r1" / ("t02-public-dependency-complete-" + datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S%f") + ".json")
    with target.open("x", encoding="utf-8") as stream:
        json.dump(report, stream, indent=2)
        stream.write("\n")
print(json.dumps(report, indent=2))
if not report["verified"] or not report["exact_sdk_removed"]:
    raise control.ScopeError("Public dependency step failed; retain evidence, no private fallback")
