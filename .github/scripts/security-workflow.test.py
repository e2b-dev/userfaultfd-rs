#!/usr/bin/env python3
"""Asserts the shape of the security workflow that the consumed branch depends on.

The constants below are an allowlist, so a deliberate change to either workflow is expected to
fail here: the remedy is to update the matching constant in this file, in the same commit.
"""

import sys

# This file's own directory leads sys.path, so a module named beside it would be imported in
# place of the real one and could rewrite what is parsed below.
del sys.path[0]

import pathlib  # noqa: E402
import re  # noqa: E402
import shlex  # noqa: E402

import yaml  # noqa: E402

ROOT = pathlib.Path(__file__).absolute().parents[2]
# Only what a commit can store: a link above the root is someone's own checkout path.
# The whole subtree: a named path that has become a link is still the named path, so the list below
# matches and only this says otherwise. rglob does not descend a linked directory, which is why the
# link itself has to be what is reported.
LINKED = [path for path in (ROOT / ".github", *(ROOT / ".github").rglob("*")) if path.is_symlink()]
if LINKED:
    print(f"{[str(p) for p in LINKED]} is a symlink, so the tree checked here is not the tree that ships")
    raise SystemExit(1)
WORKFLOW = ROOT / ".github" / "workflows" / "security.yml"

# Named on four lines across the two workflows; retarget those and this together, or the test is red
# in between.
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
# reproduced on this one — so a 40-hex that looks like an upstream release fetches what that fork wrote.
ACTION_PINS = {
    "actions/checkout": "3d3c42e5aac5ba805825da76410c181273ba90b1",
    "github/codeql-action": "1c5b675653bb5c22dbe9b12b556ec555138e09fd",
}
# Pinned by value: nothing bumps a docker reference in an env:, unlike the uses: SHAs above.
SCANNER_REPO = "ghcr.io/google/osv-scanner"
SCANNER_DIGEST = "sha256:afd838850ac1a0fcc15ff4a041dc9ba11123c3f0d2666217a5f0fcf9222b55fa"
RESULTS_FILE = "results.sarif"
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
JOB_ACTIONS = {
    "codeql": ("actions/checkout", "github/codeql-action/init", "github/codeql-action/analyze"),
    "osv": ("actions/checkout", "github/codeql-action/upload-sarif"),
    "verify": ("actions/checkout",),
}
# An action among these steps would be code no check here reads.
RUNNER_STEPS = "actions/checkout"
LINTER_REPO = "rhysd/actionlint"
LINTER_DIGEST = "sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667"
LINTER_BODY = """docker run --rm --user "$(id -u):$(id -g)" --volume "$GITHUB_WORKSPACE:$GITHUB_WORKSPACE:ro" --workdir "$GITHUB_WORKSPACE" "$LINTER" \\
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
SCAN_BODIES = (GENERATE_BODY, f"bash {SCAN_SCRIPT}")
SCRIPTS = pathlib.Path(__file__).absolute().parent
TESTS = sorted(p.relative_to(ROOT).as_posix() for p in SCRIPTS.glob("*.test.*"))
SHELL_SCRIPTS = sorted(p.relative_to(ROOT).as_posix() for p in SCRIPTS.glob("*.sh"))
# A `# shellcheck disable=` line silences the lint from inside the file it lints, so what any of them may silence is pinned here.
SILENCED = []
UNTESTED = [s for s in SHELL_SCRIPTS if not s.endswith(".test.sh") and s[:-3] + ".test.sh" not in TESTS]
EXPECTED_TESTS = [
    ".github/scripts/scan.test.sh",
    ".github/scripts/security-workflow.test.py",
]
SHELLCHECK_BODY = 'docker run --rm --user "$(id -u):$(id -g)" --volume "$GITHUB_WORKSPACE:$GITHUB_WORKSPACE:ro" --workdir "$GITHUB_WORKSPACE" "$SHELLCHECK" \\\n' + " \\\n".join(["    --norc"] + [f"    {script}" for script in SHELL_SCRIPTS])
INTERPRETERS = {"sh": "bash", "py": "python3"}
SHELLCHECK_REPO = "koalaman/shellcheck"
SHELLCHECK_DIGEST = "sha256:61862eba1fcf09a484ebcc6feea46f1782532571a34ed51fedf90dd25f925a8d"
# Keyed by what the step runs: the env names that step may set. The runner sets the rest.
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
# The whole file, compared as one value: only github-actions belongs here, the consuming fork's
# lockfile owning dependency versions.
DEPENDABOT = {
    "version": 2,
    "updates": [{"package-ecosystem": "github-actions", "directory": "/", "schedule": {"interval": "weekly", "day": "monday"}}],
}

failures = []


def check(condition, message):
    if not condition:
        failures.append(message)


def report():
    print("\n".join(failures))
    print(f"{len(failures)} assertion(s) failed")


def _crashed(kind, value, traceback):
    sys.__excepthook__(kind, value, traceback)
    print(f"::error::{THIS} stopped on a shape it does not read; the traceback above names the line")
    if failures:
        report()


sys.excepthook = _crashed


class Strict(yaml.SafeLoader):
    """GitHub reads a key as the text it is written with and refuses a file that repeats one in any
    casing, while PyYAML folds bare `on:` to True, keeps the last of a duplicate pair, and expands
    `<<`, so the allowlists below would be describing a file GitHub will not run. A merge key is
    left as the literal key it is: the exact allowlists reject it where they are exact, and the
    pinned actionlint refuses it anywhere in either linted workflow."""

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


# GitHub runs every scalar through its own matchers, so `no`, `4_5` and `0400` are text or decimal
# to it where PyYAML reads False, 45 and 256. These stay narrower than GitHub's, so a value they
# leave as text fails the numeric checks here rather than passing them.
SCALARS = (
    ("bool", r"true|True|TRUE|false|False|FALSE", "tTfF", lambda t: t.lower() == "true"),
    ("int", r"[0-9]+|[-+][0-9]+", "-+0123456789", to_int),
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
    """Whether every `key: value` line pinning this value carries a `# v…` comment, which the parser
    drops. That the comment names the release the digest resolves to is not decidable here — only
    online — so this requires one to be there, not that it is right. A pin written across two lines,
    or in flow style, is not one of those lines."""
    quoted = rf"[\"']?{re.escape(value)}[\"']?"
    pins = [line for line in source.splitlines() if re.match(rf"^\s*(-\s+)?{key}:\s*{quoted}\s*(#.*)?$", line)]
    return bool(pins) and all(re.match(r"^[^#]*\s#\s*v\d", line) for line in pins)


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


def prop(mapping, name):
    """`mapping[name]` where a workflow may legally carry a scalar instead of a block: `permissions:
    write-all` arrives here as something with no keys."""
    return mapping.get(name) if isinstance(mapping, dict) else None


def read(path):
    try:
        doc = load(path.read_text()) or {}
        if isinstance(doc, dict) and isinstance(prop(doc, "jobs") or {}, dict):
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
        # A script is a marker only where the body runs it: the lint step passes both as arguments.
        body = str(step.get("run", ""))
        allowed = set().union(
            *(names for marker, names in STEP_ENV.items()
              if (launches(body, marker) if marker.endswith(".sh") else marker in body)),
            set(),
        )
        check(
            set(step.get("env") or {}) <= allowed,
            f"{where}: step {step.get('name')!r} sets {sorted(set(step.get('env') or {}) - allowed)}; "
            f"only {sorted(allowed)} may be set here; another name either does nothing or repoints "
            "what it runs",
        )


def filtered(where, events):
    """Both triggers filtered by exactly branches: [BRANCH]. A paths filter skips a commit it should
    read (and a skipped required check stays "Expected"), a tag trigger scans a tagged commit,
    branches-ignore leaves no list saying which branches are in, and GitHub's own glob grammar
    decides what a pattern reaches."""
    if not isinstance(events, dict):
        check(False, f"{where}: on: is {events!r}; a bare event or a list of them names no filter at all")
        return
    for event in ("push", "pull_request"):
        spec = events.get(event) or {}
        check(set(spec) == {"branches"}, f"{where}: {event} is filtered by {sorted(spec)}, not just branches")
        globs = globs_of(spec, "branches")
        check(globs == [BRANCH], f"{where}: {event} is filtered by {globs}, not exactly [{BRANCH!r}]")


filtered(WORKFLOW.name, triggers)

def weekly(fields):
    """A five-field cron that comes round at least once a week; actionlint has the field ranges."""
    return len(fields) == 5 and fields[2] == "*" and fields[3] == "*"


def minutes(value):
    """Why this is not a job timeout, or "" if it is one."""
    if isinstance(value, bool) or not isinstance(value, int):
        return "only a whole decimal number is read here, and anything else is refused, not guessed at"
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
    # Widening JOB_STEPS is what the message above asks for, and on its own it used to admit a step
    # nothing below reads. So every step here is an action this job has a check for, at most once
    # since each check reads the first of its kind, or one of the three pinned bodies.
    used = [str(step.get("uses", "")).split("@")[0] for step in steps if step.get("uses")]
    check(
        set(used) <= set(JOB_ACTIONS[name]),
        f"{name}: {sorted(set(used) - set(JOB_ACTIONS[name]))} is used here and read by nothing; "
        f"only {list(JOB_ACTIONS[name])} have checks in this job",
    )
    check(len(used) == len(set(used)), f"{name}: {used} repeats an action, and each is read once")
    for step in steps:
        body = str(step.get("run", "")).strip()
        check(
            not body or body in SCAN_BODIES,
            f"{name}: step {step.get('name')!r} runs {body.splitlines()[:1]}, which is not one of the "
            "three pinned bodies; a step beside them runs before or after what they are checked for",
        )
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

# Every upload step, not the first: a second one is what the step-list message invites a reader to
# add, and it files under whatever category it names. Collected as a list, because a repeat of a
# category already here is the merge this exists to refuse and a set would swallow it.
filed = []
for job_name, suffix, keys in (("codeql", "/analyze", ANALYZE_KEYS), ("osv", "/upload-sarif", UPLOAD_KEYS)):
    for step in steps_using(jobs[job_name], suffix):
        with_ = step.get("with") or {}
        check(set(with_) == keys, f"{job_name}: {suffix} takes {sorted(with_)}, not {sorted(keys)}")
        category = with_.get("category", "")
        check(
            job_name != "codeql" or expr(category) == ANALYZE_CATEGORY,
            f"codeql: analyze files under {category!r}, not {ANALYZE_CATEGORY!r}; an expression that "
            "collapses to one category makes each leg close the other's alerts",
        )
        check(
            job_name != "osv" or with_.get("sarif_file") == RESULTS_FILE,
            f"osv: an upload reads {with_.get('sarif_file')!r}, not the "
            f"{RESULTS_FILE!r} the scan is told to write",
        )
        category = expr(category)
        if "matrix.language" in category:
            for language in jobs[job_name]["strategy"]["matrix"]["language"]:
                filed.append(re.sub(r"\$\{\{.*?\}\}", language, category))
        else:
            filed.append(category)

check(
    sorted(filed) == sorted(CATEGORIES),
    f"the upload categories are {sorted(filed)}, not {sorted(CATEGORIES)}; each tool and language "
    "needs its own so one cannot close another's alerts, and filing one twice hides the earlier",
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
        "exact image, so changing it here means changing what reads the lockfile",
    )

try:
    dependabot = load((ROOT / ".github" / "dependabot.yml").read_text())
except (OSError, yaml.YAMLError) as error:
    check(False, f"dependabot.yml cannot be read, so nothing keeps the action pins moving: {error}")
    dependabot = {}
check(
    dependabot == DEPENDABOT,
    f"dependabot.yml is {dependabot}, not {DEPENDABOT}; anything else is refused until this file "
    "says what it does — ignore: and open-pull-requests-limit: 0 stop the bump outright, "
    "target-branch: decides which branch it lands on, and a cron: interval can name a date that "
    "never comes with nothing going red when it doesn't",
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

# Another workflow uploading under a category this file pins would close the alerts behind it.
for path in workflow_files():
    if path.name == WORKFLOW.name:
        continue
    doc = parse(path)
    if doc is None:
        continue
    grants = [prop(doc, "permissions")] + [
        prop(j, "permissions") for j in (prop(doc, "jobs") or {}).values() if isinstance(j, dict)
    ]
    granted = sorted(
        {
            scope
            for g in grants
            for scope in ("security-events", "actions", "contents", "checks", "statuses")
            if str(g).casefold() == "write-all" or str(prop(g, scope)).casefold() == "write"
        }
    )
    check(
        not granted,
        f"{path.name} grants {granted} at write, by name or via write-all; actions: disables this "
        "scan and the check that reads it, contents: rewrites the scripts they run without the "
        "bot's own push running anything, security-events: closes the alerts behind them, and "
        f"checks or statuses: file a passing result under the name a branch rule requires. There is "
        f"no exemption list: a sibling that must hold one of these is a change to {THIS}",
    )
    # Whether a sibling may name a job after a check this files is a branch-protection question:
    # GitHub files under a job's display name and expands matrix legs, so job ids are the wrong set.
    undeclared = [
        name
        for name, job in (prop(doc, "jobs") or {}).items()
        if isinstance(job, dict) and prop(job, "permissions") is None
    ] if prop(doc, "permissions") is None else []
    check(
        not undeclared,
        f"{path.name} leaves {undeclared} on whatever the repository's default token is, which is a "
        "setting no file here can read — declare permissions: on the workflow or on every job",
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
    filtered(where, events)
    check(
        set(doc) - {"permissions"} == RUNNER_TOP_KEYS,
        f"{where}: the workflow takes {sorted(doc)}, not {sorted(RUNNER_TOP_KEYS)} "
        "(permissions: may sit here or on the job)",
    )
    check(isinstance(doc.get("name"), str), f"{where}: the workflow name is a {type(doc.get('name')).__name__}, not a string")
    check(set(events) == RUNNER_EVENTS, f"{where}: it runs on {sorted(events)}, not {sorted(RUNNER_EVENTS)}")
    check(set(doc["jobs"]) == {job_name}, f"{where}: the file also declares {sorted(set(doc['jobs']) - {job_name})}")
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
    check(not UNTESTED, f"{where}: {UNTESTED} name no sibling test, so each can change with nothing asserting it")
    present = sorted(p.name for p in (ROOT / ".github" / "scripts").iterdir())
    check(
        present == sorted(pathlib.Path(s).name for s in SHELL_SCRIPTS + [THIS]),
        f"{where}: .github/scripts holds {present}; a script the lists above do not name is linted "
        "by nothing and tested by nothing, and a listed one can reach it",
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
            "test beside this file nor one of the two pinned lints. Only those may be steps here, "
            "so running anything else is a change to this check",
        )
    named = [st for st in steps if "SHELLCHECK" in (st.get("env") or {})]
    check(len(named) == 1, f"{where}: {len(named)} steps name a SHELLCHECK image and the pins read one")
    lint_scripts = named[0] if named else {}
    check(
        str(lint_scripts.get("run", "")).strip() == SHELLCHECK_BODY,
        f"{where}: the script-lint body is not the pinned text, so what it lints is not what it "
        f"names; SHELLCHECK_BODY is\n{SHELLCHECK_BODY}",
    )
    shellcheck = (lint_scripts.get("env") or {}).get("SHELLCHECK", "")
    repo, _, digest = str(shellcheck).partition("@")
    check(
        repo.split(":")[0] == SHELLCHECK_REPO and digest == SHELLCHECK_DIGEST,
        f"{where}: the script lint pulls {shellcheck!r}, not {SHELLCHECK_REPO} at {SHELLCHECK_DIGEST}",
    )
    check(
        commented(doc_text, "SHELLCHECK", str(shellcheck)),
        f"{where}: the script-lint pin carries no version comment, so no reader can tell which "
        "release it is",
    )
    silenced = [
        f"{script}:{code}"
        for script in SHELL_SCRIPTS
        for code in re.findall(r"#\s*shellcheck\s+[^\n]*?(?:disable|source|source-path)=(\S+)", (ROOT / script).read_text())
    ]
    check(
        silenced == SILENCED,
        f"{where}: the scripts silence {silenced}, not {SILENCED}; a script that disables the lint "
        "inside itself, or points it at a file it is not reading, is linted by nothing",
    )
    named = [st for st in steps if "LINTER" in (st.get("env") or {})]
    check(len(named) == 1, f"{where}: {len(named)} steps name a LINTER image and the pins read one")
    lint = named[0] if named else {}
    check(
        str(lint.get("run", "")).strip() == LINTER_BODY,
        f"{where}: the lint body is {str(lint.get('run', '')).strip()!r}, not {LINTER_BODY!r}, so "
        "what it reads is not what it names",
    )
    linter = (lint.get("env") or {}).get("LINTER", "")
    repo, _, digest = str(linter).partition("@")
    check(
        repo.split(":")[0] == LINTER_REPO and digest == LINTER_DIGEST,
        f"{where}: the lint pulls {linter!r}, not {LINTER_REPO} at {LINTER_DIGEST}",
    )
    check(
        commented(doc_text, "LINTER", str(linter)),
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
        "allowed — a kept token is left in .git/config for whatever runs next, including a container "
        "given the checkout, and a ref: scans one tree while the results name another",
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
            f"{file_name}: {ref} has to carry a `# v…` comment on every one-line `uses:` that "
            "names it, so a reader there is told which release it is",
        )
        action, _, revision = ref.partition("@")
        repo = "/".join(action.split("/")[:2])
        check(
            ACTION_PINS.get(repo) == revision,
            f"{file_name}: {ref} is not {repo}@{ACTION_PINS[repo]}; the two move together, so "
            f"whichever is behind is the one to bump, here or in ACTION_PINS in {THIS}"
            if repo in ACTION_PINS
            else f"{file_name}: nothing here vouches for {repo}, so {ref} is refused",
        )

if failures:
    report()
    sys.exit(1)
print("ok")
