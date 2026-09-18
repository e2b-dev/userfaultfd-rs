#!/usr/bin/env python3
"""Asserts the shape of the security workflow that the consumed branch depends on.

The constants below are an allowlist, so a deliberate change to either workflow is expected to
fail here: the remedy is to update the matching constant in this file, in the same commit.
"""

import sys

# This file's own directory leads sys.path, so a module named beside it would be imported in
# place of the real one and could rewrite what is parsed below.
del sys.path[0]

import atexit  # noqa: E402
import pathlib  # noqa: E402
import re  # noqa: E402
import shlex  # noqa: E402

import yaml  # noqa: E402

ROOT = pathlib.Path(__file__).absolute().parents[2]
# Only what a commit can store: a link above the root is someone's own checkout path.
LINKED = [
    path
    for path in (ROOT / ".github", ROOT / ".github" / "scripts", ROOT / ".github" / "workflows",
                 ROOT / ".github" / "dependabot.yml",
                 *(ROOT / ".github" / "scripts").glob("*"), *(ROOT / ".github" / "workflows").glob("*"))
    if path.is_symlink()
]
if LINKED:
    print(f"{[str(p) for p in LINKED]} is a symlink, so the tree checked here is not the tree that ships")
    raise SystemExit(1)
WORKFLOW = ROOT / ".github" / "workflows" / "security.yml"

# Named in both workflows too; retarget all four together or the test is red in between.
BRANCH = "feat_write_protection"
SCAN_PERMISSIONS = {
    "codeql": {"contents": "read", "actions": "read", "security-events": "write"},
    "osv": {"contents": "read", "actions": "read", "security-events": "write"},
}
PACKS = {
    "rust": "codeql/rust-queries:codeql-suites/rust-code-scanning.qls",
    "c-cpp": "codeql/cpp-queries:codeql-suites/cpp-code-scanning.qls",
}
CATEGORIES = {f"/language:{language}" for language in PACKS} | {"osv-scanner"}
# Pinned by value, because a commit pushed to any fork is served by the repository itself —
# reproduced on this one — so a 40-hex that looks like an upstream release fetches whatever that
# fork wrote. A bump is red here until a human moves the constant.
ACTION_PINS = {
    "actions/checkout": "3d3c42e5aac5ba805825da76410c181273ba90b1",
    "github/codeql-action": "1c5b675653bb5c22dbe9b12b556ec555138e09fd",
}
# Pinned by value: nothing bumps a docker reference in an env:, unlike the uses: SHAs above.
SCANNER_REPO = "ghcr.io/google/osv-scanner"
SCANNER_DIGEST = "sha256:afd838850ac1a0fcc15ff4a041dc9ba11123c3f0d2666217a5f0fcf9222b55fa"
RESULTS_FILE = "results.sarif"
RUNNER_PATHS = {
    ".github/dependabot.yml",
    ".github/scripts/*",
    ".github/workflows/*",
}
# Allowlists, not denylists: a scan is emptied from whichever level nobody was reading.
SCAN_TOP_KEYS = {"name", "on", "jobs"}
RUNNER_TOP_KEYS = {"name", "on", "jobs"}
SCAN_EVENTS = {"push", "pull_request", "schedule", "workflow_dispatch"}
RUNNER_EVENTS = {"push", "pull_request"}
JOB_KEYS = {
    "codeql": {"runs-on", "timeout-minutes", "permissions", "strategy", "steps"},
    "osv": {"runs-on", "timeout-minutes", "permissions", "steps"},
}
RUNNER_JOB_KEYS = {"runs-on", "timeout-minutes", "steps"}
STEP_SHAPES = ({"name", "uses", "with"}, {"name", "run"}, {"name", "run", "env"})
JOB_STEPS = {
    "codeql": ("actions/checkout", "github/codeql-action/init", "github/codeql-action/analyze"),
    "osv": ("actions/checkout", "run", "run", "github/codeql-action/upload-sarif"),
}
# An action among these steps would be code no check here reads.
RUNNER_STEPS = "actions/checkout"
LINTER_REPO = "rhysd/actionlint"
LINTER_DIGEST = "sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667"
LINTER_BODY = """docker run --rm --volume "$GITHUB_WORKSPACE:$GITHUB_WORKSPACE" --workdir "$GITHUB_WORKSPACE" "$LINTER" \\
    -no-color \\
    -config-file /dev/null \\
    .github/workflows/security.yml \\
    .github/workflows/security-checks.yml"""
RUNNER_OS = "ubuntu-latest"
THIS = pathlib.Path(__file__).absolute().relative_to(ROOT).as_posix()
STRATEGY_KEYS = {"fail-fast", "matrix"}
MATRIX_KEYS = {"language", "include"}
GENERATE_BODY = 'cd "${RUNNER_TEMP:?}" && cargo generate-lockfile --manifest-path "${GITHUB_WORKSPACE:?}/Cargo.toml"'
SCAN_SCRIPT = ".github/scripts/scan.sh"
SCRIPTS = pathlib.Path(__file__).absolute().parent
TESTS = sorted(p.relative_to(ROOT).as_posix() for p in SCRIPTS.glob("*.test.*"))
SHELL_SCRIPTS = sorted(p.relative_to(ROOT).as_posix() for p in SCRIPTS.glob("*.sh"))
UNTESTED = [s for s in SHELL_SCRIPTS if not s.endswith(".test.sh") and s[:-3] + ".test.sh" not in TESTS]
BESIDE = sorted(q.relative_to(ROOT).as_posix() for q in SCRIPTS.iterdir())
EXPECTED_TESTS = [
    ".github/scripts/scan.test.sh",
    ".github/scripts/security-workflow.test.py",
]
SHELLCHECK_BODY = 'docker run --rm --volume "$GITHUB_WORKSPACE:$GITHUB_WORKSPACE" --workdir "$GITHUB_WORKSPACE" "$SHELLCHECK" \\\n' + " \\\n".join(["    --norc"] + [f"    {script}" for script in SHELL_SCRIPTS])
INTERPRETERS = {"sh": "bash", "py": "python3"}
SHELLCHECK_REPO = "koalaman/shellcheck"
SHELLCHECK_DIGEST = "sha256:61862eba1fcf09a484ebcc6feea46f1782532571a34ed51fedf90dd25f925a8d"
# Keyed by what the step runs: one of these switches discards the upload.
STEP_ENV = {
    SCAN_SCRIPT: {"SCANNER"},
    '"$LINTER"': {"LINTER"},
    '"$SHELLCHECK"': {"SHELLCHECK"},
}
INIT_KEYS = {"languages", "build-mode", "config"}
ANALYZE_KEYS = {"category"}
# Pinned: another ${{ }} naming matrix.language reads as per-language but resolves to one.
ANALYZE_CATEGORY = "/language:${{ matrix.language }}"
UPLOAD_KEYS = {"sarif_file", "category"}
UPDATE_KEYS = {"package-ecosystem", "directory", "schedule"}
INTERVALS = {"daily", "weekly", "monthly"}
# Dependabot's parser is YAML 1.1, where an unquoted 06:00 is the integer 21600 and the file is
# rejected, so a time: or timezone: is not allowed here until something quotes one.
SCHEDULE_KEYS = {"interval", "day"}
DAYS = {"monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"}

failures = []


def check(condition, message):
    if not condition:
        failures.append(message)


def report():
    print("\n".join(failures))
    print(f"{len(failures)} assertion(s) failed")


reached_the_end = False
atexit.register(lambda: failures and not reached_the_end and report())


class Strict(yaml.SafeLoader):
    """GitHub reads a key as the text it is written with, refuses a file that repeats one in any
    casing, and refuses a merge key. PyYAML folds bare `on:` to True, keeps the last of a duplicate
    pair, and expands `<<`, so the allowlists below would be describing a file GitHub will not run."""

    def construct_mapping(self, node, deep=False):
        mapping, seen = {}, set()
        for key_node, value_node in node.value:
            key = key_node.value if isinstance(key_node, yaml.ScalarNode) else self.construct_object(key_node, deep)
            folded = key.casefold() if isinstance(key, str) else key
            if folded in seen:
                raise yaml.constructor.ConstructorError(
                    None, None, f"{key!r} is defined twice", key_node.start_mark
                )
            seen.add(folded)
            mapping[key] = self.construct_object(value_node, deep)
        return mapping


def to_int(text):
    return int(text.removeprefix("+"))


def to_float(text):
    body = text.lower().removeprefix("+")
    if body.endswith("inf"):
        return float("-inf") if body.startswith("-") else float("inf")
    return float("nan") if body.endswith("nan") else float(text)


# GitHub runs every scalar through its own matchers, so `no`, `4_5` and `0400` are text or decimal
# to it and the file is refused for the type they land in; PyYAML reads False, 45 and 256. Hex and
# octal are numbers to GitHub and refused by the pinned actionlint, so only what both take is
# allowed here. An implicit resolve sees only a plain scalar, so a quoted one with a tag was tagged
# by hand.
SCALARS = (
    ("bool", r"true|True|TRUE|false|False|FALSE", "tTfF", lambda t: t.lower() == "true"),
    ("int", r"[0-9]+|[-+][0-9]+", "-+0123456789", to_int),
    (
        "float",
        r"[-+]?(?:\.[0-9]+|[0-9]+(?:\.[0-9]*)?)(?:[eE][-+]?[0-9]+)?|[-+]?\.(?:inf|Inf|INF)|\.(?:nan|NaN|NAN)",
        "-+.0123456789",
        to_float,
    ),
    ("null", r"~|null|Null|NULL|", ["~", "n", "N", ""], lambda t: None),
)


def scalar_constructor(pattern, build):
    def construct(loader, node):
        if node.style is not None:
            raise yaml.constructor.ConstructorError(
                None, None, f"{node.tag} written on a quoted scalar", node.start_mark
            )
        if not re.fullmatch(pattern, node.value):
            raise yaml.constructor.ConstructorError(
                None, None, f"{node.value!r} is not a {node.tag}", node.start_mark
            )
        return build(node.value)

    return construct


Strict.yaml_implicit_resolvers = {}
Strict.yaml_constructors = dict(yaml.SafeLoader.yaml_constructors)
for tag, pattern, starts, build in SCALARS:
    Strict.add_implicit_resolver(f"tag:yaml.org,2002:{tag}", re.compile(rf"^(?:{pattern})$"), list(starts))
    Strict.add_constructor(f"tag:yaml.org,2002:{tag}", scalar_constructor(pattern, build))
for unsupported in ("set", "omap", "pairs", "binary", "timestamp"):
    del Strict.yaml_constructors[f"tag:yaml.org,2002:{unsupported}"]


def load(source):
    return yaml.load(source, Strict)


def commented(source, key, value):
    """Whether every line pinning this value names the release it is, in the comment the parser drops."""
    quoted = rf"[\"']?{re.escape(value)}[\"']?"
    pins = [line for line in source.splitlines() if re.match(rf"^\s*(-\s+)?{key}:\s*{quoted}\s*(#.*)?$", line)]
    return bool(pins) and all(re.search(r"\s#\s*v\d", line) for line in pins)


try:
    text = WORKFLOW.read_text()
    workflow = load(text)
except (OSError, yaml.YAMLError) as error:
    print(f"{WORKFLOW.name} is not a workflow this test can read, so nothing is vouched for: {error}")
    sys.exit(1)


def globs_of(spec, key):
    """A filter list, or the bare string GitHub also accepts there."""
    value = (spec or {}).get(key) or []
    return [value] if isinstance(value, str) else value


def launches(body, script=None):
    """Whether a run: body executes this script under the interpreter it is pinned to, rather than
    merely naming it — a `cat` does not, and a bare path would read a shebang nothing here checks."""
    script = script or THIS
    try:
        argv = shlex.split(body.replace("\\\n", "").strip())
    except ValueError:
        return False
    return argv == [INTERPRETERS[script.rsplit(".", 1)[-1]], script]


triggers = workflow.get("on")
if not isinstance(triggers, dict) or "jobs" not in workflow:
    print(f"the workflow declares {sorted(workflow)}; it needs on: and jobs:")
    sys.exit(1)
jobs = workflow["jobs"]


def steps_using(job, suffix):
    for step in job.get("steps", []):
        if str(step.get("uses", "")).split("@")[0].endswith(suffix):
            yield step


def workflow_files():
    directory = ROOT / ".github" / "workflows"
    return sorted(p for p in directory.iterdir() if p.suffix.lower() in (".yml", ".yaml"))


parsed = {}


def parse(path):
    if path not in parsed:
        parsed[path] = read(path)
    return parsed[path]


def read(path):
    try:
        doc = load(path.read_text()) or {}
        if isinstance(doc, dict) and isinstance(doc.get("jobs", {}), dict):
            return doc
    except yaml.YAMLError:
        pass
    check(False, f"{path.name} is not a workflow this test can read, so it cannot be vouched for")
    return None


def expr(value):
    """A GitHub expression with its inner whitespace normalised; formatters drop it."""
    return re.sub(r"\$\{\{\s*(.*?)\s*\}\}", r"${{ \1 }}", str(value))


def normalise(value):
    """The same structure with every expression's inner whitespace normalised."""
    if isinstance(value, dict):
        return {k: normalise(v) for k, v in value.items()}
    if isinstance(value, list):
        return [normalise(v) for v in value]
    return expr(value) if isinstance(value, str) else value


def signature(steps):
    return tuple(str(s.get("uses", "")).split("@")[0] or "run" for s in steps)


def shape(where, steps):
    for step in steps:
        check(
            set(step) in STEP_SHAPES,
            f"{where}: step {step.get('name')!r} takes {sorted(str(k) for k in step)}; only "
            f"{[sorted(sh) for sh in STEP_SHAPES]} are allowed, so an unlisted key is red until this "
            "file says what it does",
        )
        check(
            isinstance(step.get("name"), str) and isinstance(step.get("env", {}), dict),
            f"{where}: step {step.get('name')!r} names itself with a {type(step.get('name')).__name__} "
            f"and sets a {type(step.get('env', {})).__name__}; GitHub wants a string and a mapping",
        )
        allowed = {n for marker, names in STEP_ENV.items() if marker in str(step.get("run", "")) for n in names}
        check(
            set(step.get("env") or {}) <= allowed,
            f"{where}: step {step.get('name')!r} sets {sorted(set(step.get('env') or {}) - allowed)}; "
            f"only {sorted(allowed)} are read by what it runs, and the actions in this file take switches from "
            "the environment, one of which discards the upload",
        )


for event in ("push", "pull_request"):
    spec = triggers.get(event) or {}
    check(
        set(spec) == {"branches"},
        f"{event} is filtered by {sorted(spec)}, not just branches; a paths filter skips the scan on "
        "a commit it should read, a tag trigger scans a tagged commit, and branches-ignore leaves no "
        "list saying which branches are in",
    )
    globs = globs_of(spec, "branches")
    check(
        globs == [BRANCH],
        f"{event} is filtered by {globs}, not exactly [{BRANCH!r}]; GitHub's own glob grammar "
        "decides what a pattern reaches, and nothing here can read it",
    )

def weekly(fields):
    """A five-field cron that comes round at least once a week; actionlint has the field ranges."""
    return len(fields) == 5 and fields[2] == "*" and fields[3] == "*"


def minutes(value):
    """Why this is not a job timeout, or "" if it is one."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return "only a literal number is read here, and GitHub takes an expression nothing here can evaluate"
    if not isinstance(value, int):
        return "a job is given whole minutes"
    if not 0 < value < 360:
        return "it has to sit between 1 and 359, so a wedged job cannot hold the check-run all day"
    return ""


crons = [str(s.get("cron", "")).split() for s in triggers.get("schedule", [])]
check(
    crons and all(weekly(c) for c in crons),
    f"every schedule has to be a five-field cron whose day-of-month and month are both *, so it "
    f"comes round at least weekly; these are {[' '.join(c) for c in crons]}",
)

for required in ("codeql", "osv"):
    if required not in jobs:
        print(f"the {required} job is gone")
        sys.exit(1)

checkouts = []
check(set(workflow) == SCAN_TOP_KEYS, f"the workflow takes {sorted(workflow)}, not {sorted(SCAN_TOP_KEYS)}")
check(isinstance(workflow.get("name"), str), f"the workflow name is a {type(workflow.get('name')).__name__}, not a string")
check(set(triggers) == SCAN_EVENTS, f"the scan runs on {sorted(triggers)}, not {sorted(SCAN_EVENTS)}")
check(set(jobs) == set(JOB_KEYS), f"the workflow declares {sorted(jobs)}, not {sorted(JOB_KEYS)}")

for name, job in jobs.items():
    if name not in JOB_KEYS:
        continue
    check(set(job) == JOB_KEYS[name], f"{name}: the job takes {sorted(job)}, not {sorted(JOB_KEYS[name])}")
    perms = job.get("permissions")
    check(perms == SCAN_PERMISSIONS[name], f"{name}: permissions are {perms}, not {SCAN_PERMISSIONS[name]}")
    check(job.get("runs-on") == RUNNER_OS, f"{name}: runs on {job.get('runs-on')!r}, not {RUNNER_OS}")
    timeout = job.get("timeout-minutes")
    check(not minutes(timeout), f"{name}: timeout-minutes is {timeout!r}; {minutes(timeout)}")
    steps = job.get("steps") or []
    check(
        signature(steps) == JOB_STEPS[name],
        f"{name}: its steps are {list(signature(steps))}, not {list(JOB_STEPS[name])}",
    )
    shape(name, steps)
    checkouts.extend((name, step) for step in steps_using(job, "/checkout"))

matrix = jobs["codeql"]["strategy"]["matrix"]
fail_fast = jobs["codeql"]["strategy"].get("fail-fast")
check(
    fail_fast is False,
    f"codeql: fail-fast is {fail_fast!r}; "
    + (
        "GitHub reads a boolean in six spellings of true and false, and text in anything else"
        if fail_fast is not None and not isinstance(fail_fast, bool)
        else "one red language cancels the rest"
    ),
)
check(set(jobs["codeql"]["strategy"]) == STRATEGY_KEYS, f"codeql: strategy takes {sorted(jobs['codeql']['strategy'])}")
check(set(matrix) == MATRIX_KEYS, f"codeql: matrix takes {sorted(matrix)}, not {sorted(MATRIX_KEYS)}")
check(set(matrix["language"]) == set(PACKS), f"codeql: languages are {matrix['language']}, not {sorted(PACKS)}")
check(
    all(set(e) == {"language", "pack"} for e in matrix["include"]),
    f"codeql: an include entry takes {[sorted(e) for e in matrix['include']]}, not ['language', "
    "'pack'] — this is the one mapping a merge key could hide in",
)
if all(set(e) == {"language", "pack"} for e in matrix["include"]):
    include = {e["language"]: e["pack"] for e in matrix["include"]}
    check(include == PACKS, f"codeql: the per-language query packs are {include}, not {PACKS}")

init = next(steps_using(jobs["codeql"], "/init"), None)
if init:
    with_ = init.get("with") or {}
    check(set(with_) == INIT_KEYS, f"codeql: init takes {sorted(with_)}, not {sorted(INIT_KEYS)}")
    check(expr(with_.get("languages")) == "${{ matrix.language }}", f"codeql: init languages is {with_.get('languages')!r}")
    check(with_.get("build-mode") == "none", f"codeql: init build-mode is {with_.get('build-mode')!r}, not none")
    check(
        normalise(load(with_.get("config", "") or "{}")) == {"disable-default-queries": True, "packs": ["${{ matrix.pack }}"]},
        f"codeql: the init config is {with_.get('config')!r}, which is not exactly the pinned suite",
    )

uploads = {}
categories = set()
for job_name, suffix, keys in (("codeql", "/analyze", ANALYZE_KEYS), ("osv", "/upload-sarif", UPLOAD_KEYS)):
    step = next(steps_using(jobs[job_name], suffix), None)
    if step:
        with_ = step.get("with") or {}
        check(set(with_) == keys, f"{job_name}: {suffix} takes {sorted(with_)}, not {sorted(keys)}")
        uploads[job_name] = with_
        category = with_.get("category", "")
        check(
            job_name != "codeql" or expr(category) == ANALYZE_CATEGORY,
            f"codeql: analyze files under {category!r}, not {ANALYZE_CATEGORY!r}; an expression that "
            "collapses to one category makes each leg close the other's alerts",
        )
        category = expr(category)
        if "matrix.language" in category:
            for language in jobs[job_name]["strategy"]["matrix"]["language"]:
                categories.add(re.sub(r"\$\{\{.*?\}\}", language, category))
        else:
            categories.add(category)

check(
    categories == CATEGORIES,
    f"the upload categories are {sorted(categories)}, not {sorted(CATEGORIES)}; each tool and language "
    "needs its own so one cannot close another's alerts",
)
check(
    uploads.get("osv", {}).get("sarif_file") == RESULTS_FILE,
    f"osv: the upload reads {uploads.get('osv', {}).get('sarif_file')!r}, not the "
    f"{RESULTS_FILE!r} the scan is told to write",
)


osv_steps = jobs["osv"]["steps"]
gen_i = next((i for i, s in enumerate(osv_steps) if "generate-lockfile" in str(s.get("run", ""))), None)
scan_i = next((i for i, s in enumerate(osv_steps) if SCAN_SCRIPT in str(s.get("run", ""))), None)
check(gen_i is not None, "osv: no cargo generate-lockfile step; the crate ships no lockfile")
if gen_i is not None:
    check(
        osv_steps[gen_i]["run"].strip() == GENERATE_BODY,
        f"osv: the lockfile step runs {osv_steps[gen_i]['run'].strip()!r}, not {GENERATE_BODY!r} — "
        "anything more can replace the lockfile the scan is about to read",
    )
check(scan_i is not None, f"osv: no step runs {SCAN_SCRIPT}")
if gen_i is not None and scan_i is not None:
    check(gen_i < scan_i, "osv: the lockfile is generated after the scan has already read it")

scan_run = osv_steps[scan_i]["run"] if scan_i is not None else ""
check(
    launches(scan_run, SCAN_SCRIPT),
    f"osv: the scan step runs {scan_run.strip()!r}; it has to run {SCAN_SCRIPT} and nothing else, "
    "because a second line can blank the results the gate just vouched for",
)

scanner = (osv_steps[scan_i].get("env") or {}).get("SCANNER") if scan_i is not None else None
check(scanner, "osv: the scan step names no SCANNER, so nothing here says which image runs")
if scanner is not None:
    check(
        scanner and commented(text, "SCANNER", scanner),
        f"osv: the pin the scan uses ({scanner!r}) carries no version comment, so no reader can tell "
        "which release it is",
    )
    scanner_repo, _, scanner_digest = scanner.partition("@")
    check(
        scanner_repo.split(":")[0] == SCANNER_REPO and scanner_digest == SCANNER_DIGEST,
        f"osv: the scan pulls {scanner!r}, not {SCANNER_REPO} at {SCANNER_DIGEST}; a digest names one "
        "exact image, so changing it here means changing what runs over the workspace",
    )

try:
    dependabot = load((ROOT / ".github" / "dependabot.yml").read_text())
except (OSError, yaml.YAMLError) as error:
    check(False, f"dependabot.yml cannot be read, so nothing keeps the action pins moving: {error}")
    dependabot = {}
check(dependabot.get("version") == 2, f"dependabot.yml is version {dependabot.get('version')!r}, not 2")
updates = dependabot.get("updates") or []
check(updates, "dependabot.yml lists no updates")
check(
    {u.get("package-ecosystem") for u in updates} == {"github-actions"},
    f"Dependabot watches {sorted(str(u.get('package-ecosystem')) for u in updates)}; only github-actions "
    "belongs here, because the consuming fork's lockfile owns dependency versions",
)
targets = []
for u in updates:
    name = u.get("package-ecosystem")
    check(
        set(u) == UPDATE_KEYS,
        f"the {name!r} entry adds {sorted(set(u) - UPDATE_KEYS)} and drops "
        f"{sorted(UPDATE_KEYS - set(u))}; only {sorted(UPDATE_KEYS)} are read here, so anything else "
        "is refused until this file says what it does"
        + (
            " — and of those, ignore: and open-pull-requests-limit: 0 stop the bump outright, while "
            "target-branch: decides which branch it lands on"
            if {"ignore", "open-pull-requests-limit", "target-branch"} & set(u)
            else ""
        ),
    )
    check(u.get("directory") == "/", f"the {name!r} entry watches {u.get('directory')!r}")
    targets.append((name, u.get("directory")))
    schedule = u.get("schedule") or {}
    check(
        set(schedule) <= SCHEDULE_KEYS
        and schedule.get("day", "monday") in DAYS
        and ("day" not in schedule or schedule.get("interval") == "weekly"),
        f"the {name!r} entry schedules {schedule}: keys are limited to "
        f"{sorted(SCHEDULE_KEYS)}, day: to {sorted(DAYS)}, and day: only means anything under "
        "interval: weekly",
    )
    interval = schedule.get("interval")
    check(
        interval in INTERVALS,
        f"the {name!r} entry runs on {interval!r}, not one of {sorted(INTERVALS)}; "
        "a cron: interval can name a date that never comes, and nothing goes red when it doesn't",
    )

check(
    len(targets) == len(set(targets)),
    f"dependabot.yml aims two entries at the same ecosystem and directory ({targets}); it has to be "
    "unique per target or Dependabot refuses the file and nothing gets bumped",
)

runner_files = set()
runners = []
mentions = []
for path in workflow_files():
    doc = parse(path)
    if doc is None:
        continue
    # A sibling GitHub cannot run is passed over rather than crashing the sweeps below.
    for job_name, job in (doc.get("jobs") or {}).items():
        for step in (job.get("steps") or []) if isinstance(job, dict) else []:
            if not isinstance(step, dict):
                continue
            body = str(step.get("run", ""))
            if launches(body):
                runners.append((path.name, doc, job_name, job, step))
            elif THIS in body:
                mentions.append(f"{path.name}: {body.strip()!r}")

# GitHub does not follow a link here, so the file it would read is not the one checked below.
for path in workflow_files():
    check(not path.is_symlink(), f"{path.name} is a symlink, and GitHub reads no workflow through one")

# Another workflow uploading under a category this file pins would close the alerts behind it.
for path in workflow_files():
    if path.name == WORKFLOW.name:
        continue
    doc = parse(path)
    if doc is None:
        continue
    grants = [doc.get("permissions")] + [
        j.get("permissions") for j in (doc.get("jobs") or {}).values() if isinstance(j, dict)
    ]
    granted = sorted(
        {
            scope
            for g in grants
            for scope in ("security-events", "actions", "contents")
            if g == "write-all" or (g if isinstance(g, dict) else {}).get(scope) == "write"
        }
    )
    check(
        not granted,
        f"{path.name} grants {granted} at write, by name or via write-all; actions: disables this "
        "scan and the check that reads it, contents: rewrites either file without the bot's own "
        "push running anything, and security-events: closes the alerts behind them — add the "
        "workflow here before granting it",
    )
    # A reusable workflow or a composite action can call upload-sarif from code this test never
    # reads; owner/repo resolve case-insensitively on GitHub, so the comparison does too.
    delegated = []
    for job in (doc.get("jobs") or {}).values():
        if not isinstance(job, dict):
            continue
        if "uses" in job:
            delegated.append(job["uses"])
        for step in job.get("steps") or []:
            uses = str(step.get("uses", "")) if isinstance(step, dict) else ""
            if uses.lower().startswith(("github/codeql-action/", "./")):
                delegated.append(uses)
    undeclared = [
        name
        for name, job in (doc.get("jobs") or {}).items()
        if isinstance(job, dict) and "permissions" not in job
    ] if "permissions" not in doc else []
    check(
        not undeclared,
        f"{path.name} leaves {undeclared} on whatever the repository's default token is, which is a "
        "setting no file here can read — declare permissions: on the workflow or on every job",
    )
    check(
        not delegated,
        f"{path.name} hands the workflow token to {delegated}; that code is not read here, so it "
        "cannot be vouched for — only the scan uploads to code scanning",
    )

check(
    runners,
    f"no workflow runs {THIS} as a plain command, so its verdict is not what any check reports"
    + (f"; these name it in some other shape: {mentions}" if mentions else ""),
)
for file_name, doc, job_name, job, step in runners:
    where = f"{file_name}:{job_name}"
    doc_text = (ROOT / ".github" / "workflows" / file_name).read_text()
    events = doc.get("on") or {}
    for event in ("push", "pull_request"):
        globs = globs_of(events.get(event), "branches")
        check(
            globs == [BRANCH],
            f"{where}: its {event} filter is {globs}, not exactly [{BRANCH!r}], so what it reaches "
            "is decided by a glob grammar nothing here can read",
        )
    push_paths = set(globs_of(events.get("push"), "paths"))
    check(
        RUNNER_PATHS <= push_paths and not any(g.startswith("!") for g in push_paths),
        f"{where}: its push paths are {sorted(push_paths)}, so a commit changing "
        f"{sorted(RUNNER_PATHS - push_paths) or 'a file this test reads'} lands without running it; "
        "GitHub lets the last matching pattern win, so a ! entry takes a path back out",
    )
    check(
        set(events.get("pull_request") or {}) == {"branches"},
        f"{where}: the pull_request trigger is filtered by {sorted(events.get('pull_request') or {})}; "
        "anything beyond branches skips runs, and a skipped required check stays \"Expected\" and "
        "blocks the merge",
    )
    check(
        set(doc) - {"permissions"} == RUNNER_TOP_KEYS,
        f"{where}: the workflow takes {sorted(doc)}, not {sorted(RUNNER_TOP_KEYS)} "
        "(permissions: may sit here or on the job)",
    )
    check(isinstance(doc.get("name"), str), f"{where}: the workflow name is a {type(doc.get('name')).__name__}, not a string")
    check(set(events) == RUNNER_EVENTS, f"{where}: it runs on {sorted(events)}, not {sorted(RUNNER_EVENTS)}")
    check(set(doc["jobs"]) == {job_name}, f"{where}: the file also declares {sorted(set(doc['jobs']) - {job_name})}")
    check(
        set(events.get("push") or {}) == {"branches", "paths"},
        f"{where}: its push trigger is filtered by {sorted(events.get('push') or {})}",
    )
    check(
        set(job) - {"permissions"} == RUNNER_JOB_KEYS,
        f"{where}: the job takes {sorted(job)}, not {sorted(RUNNER_JOB_KEYS)} — an if: or a needs: on a "
        "skipped job reports success, which is what a required check reads",
    )
    check(
        job.get("runs-on") == RUNNER_OS,
        f"{where}: runs on {job.get('runs-on')!r}, not {RUNNER_OS}",
    )
    timeout = job.get("timeout-minutes")
    check(not minutes(timeout), f"{where}: timeout-minutes is {timeout!r}; {minutes(timeout)}")
    # A job-level block overrides the workflow's, and declaring neither inherits the repo default.
    effective = job["permissions"] if "permissions" in job else doc.get("permissions")
    check(
        effective == {"contents": "read"},
        f"{where}: the job's effective permissions are {effective}, not {{'contents': 'read'}}",
    )
    steps = job.get("steps") or []
    check(
        signature(steps)[:1] == (RUNNER_STEPS,) and set(signature(steps)[1:]) <= {"run"},
        f"{where}: its steps are {list(signature(steps))}, not {RUNNER_STEPS} followed by commands",
    )
    check(not UNTESTED, f"{where}: {UNTESTED} have no sibling test, so deleting one is silent")
    check(
        BESIDE == sorted(set(TESTS) | set(SHELL_SCRIPTS)),
        f"{where}: {sorted(set(BESIDE) - set(TESTS) - set(SHELL_SCRIPTS))} sit beside these scripts "
        "and are neither run nor linted, and a script can source one",
    )
    check(
        TESTS == EXPECTED_TESTS,
        f"{where}: the tests beside this file are {TESTS}, not {EXPECTED_TESTS}; a step added for a "
        "new one runs before these and can leave them asserting what it just wrote",
    )
    for test in TESTS:
        check(
            any(launches(str(st.get("run", "")), test) for st in steps),
            f"{where}: no step runs {test}, so what it asserts is not what any check reports",
        )
    # The bodies are an allowlist too: another step runs before these and can rewrite them.
    for step in steps[1:]:
        body = str(step.get("run", "")).strip()
        check(
            body in (LINTER_BODY, SHELLCHECK_BODY) or any(launches(body, test) for test in TESTS),
            f"{where}: step {step.get('name')!r} runs {body.splitlines()[:1]}, which is neither a "
            "test beside this file nor one of the two pinned lints",
        )
    lint_scripts = next((st for st in steps if "SHELLCHECK" in (st.get("env") or {})), {})
    check(
        str(lint_scripts.get("run", "")).strip() == SHELLCHECK_BODY,
        f"{where}: the script-lint body is not the pinned text, so what it lints is not what it names",
    )
    shellcheck = (lint_scripts.get("env") or {}).get("SHELLCHECK", "")
    repo, _, digest = str(shellcheck).partition("@")
    check(
        repo.split(":")[0] == SHELLCHECK_REPO and digest == SHELLCHECK_DIGEST,
        f"{where}: the script lint pulls {shellcheck!r}, not {SHELLCHECK_REPO} at {SHELLCHECK_DIGEST}",
    )
    check(
        re.search(rf"^\s*SHELLCHECK:\s*{re.escape(str(shellcheck))}\s+#\s*v\d", doc_text, re.M),
        f"{where}: the script-lint pin carries no version comment, so no reader can tell which "
        "release it is",
    )
    lint = next((st for st in steps if "LINTER" in (st.get("env") or {})), {})
    check(
        str(lint.get("run", "")).strip() == LINTER_BODY,
        f"{where}: the lint body is not the pinned text, so what it reads is not what it names",
    )
    linter = (lint.get("env") or {}).get("LINTER", "")
    repo, _, digest = str(linter).partition("@")
    check(
        repo.split(":")[0] == LINTER_REPO and digest == LINTER_DIGEST,
        f"{where}: the lint pulls {linter!r}, not {LINTER_REPO} at {LINTER_DIGEST}",
    )
    check(
        re.search(rf"^\s*LINTER:\s*{re.escape(str(linter))}\s+#\s*v\d", doc_text, re.M),
        f"{where}: the lint pin carries no version comment, so no reader can tell which release it is",
    )
    shape(where, steps)
    checkouts.extend((where, step) for step in steps_using(job, "/checkout"))
    runner_files.add(file_name)

for where, step in checkouts:
    with_ = step.get("with") or {}
    check(
        with_ == {"persist-credentials": False},
        f"{where}: checkout takes {with_}; persist-credentials: false is required and is the only key "
        "allowed — a kept token rides into a third-party container, and a ref: scans one tree while "
        "the results name another",
    )

# Read from the parsed documents: a flow mapping and a quoted key are both uses: to GitHub.
sources = [(WORKFLOW.name, workflow, text)]
for file_name in sorted(runner_files):
    path = ROOT / ".github" / "workflows" / file_name
    sources.append((file_name, parse(path), path.read_text()))

for file_name, source, body in sources:
    references = []
    for job in ((source or {}).get("jobs") or {}).values():
        if not isinstance(job, dict):
            continue
        references += [job["uses"]] if "uses" in job else []
        references += [step["uses"] for step in job.get("steps") or [] if "uses" in step]
    for ref in sorted(set(map(str, references))):
        check(re.fullmatch(r"[^@\s]+@[0-9a-f]{40}", ref), f"{file_name}: not pinned to a commit: {ref}")
        check(
            commented(body, "uses", ref),
            f"{file_name}: not every uses: line naming {ref} carries a version comment, so a reader "
            "there cannot tell which release it is",
        )
        action, _, revision = ref.partition("@")
        repo = "/".join(action.split("/")[:2])
        check(
            ACTION_PINS.get(repo) == revision,
            f"{file_name}: {ref} is not {repo}@{ACTION_PINS[repo]}"
            if repo in ACTION_PINS
            else f"{file_name}: nothing here vouches for {repo}, so {ref} is refused",
        )

reached_the_end = True
if failures:
    report()
    sys.exit(1)
print("ok")
