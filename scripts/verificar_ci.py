"""Verificar la base de desarrollo localmente y en CI.

Español: comprueba empaquetado Python o construcción Rust.
English: check Python packaging or the Rust build.
"""

import argparse
import hashlib
import json
import os
import platform
import subprocess
import sys
import tempfile
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
UV_VERSION = "0.12.13"


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def run(args, *, cwd=ROOT, env=None):
    result = subprocess.run(
        [str(arg) for arg in args],
        cwd=cwd,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    for output in (result.stdout, result.stderr):
        if output.strip():
            print(output.rstrip(), flush=True)
    require(
        result.returncode == 0,
        f"Comando fallido / Command failed: {args[0]} {args[1]}",
    )
    return result.stdout.strip()


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify_python():
    expected = (ROOT / ".python-version").read_text().strip()
    require(
        platform.python_version() == expected,
        "Versión Python incorrecta / Incorrect Python version",
    )
    uv_version = run(["uv", "--version"]).split()[1]
    require(
        uv_version == UV_VERSION,
        "Versión uv incorrecta / Incorrect uv version",
    )
    project = tomllib.loads((ROOT / "pyproject.toml").read_text())
    package_version = project["project"]["version"]
    lock_before = digest(ROOT / "uv.lock")

    with tempfile.TemporaryDirectory(prefix="ardrec-ci-python-") as temp:
        directory = Path(temp)
        build_env = directory / "build-env"
        install_env = directory / "install-env"
        output = directory / "dist"
        env = os.environ.copy()
        env.pop("VIRTUAL_ENV", None)
        env["UV_PROJECT_ENVIRONMENT"] = str(build_env)
        env["UV_PYTHON_DOWNLOADS"] = "never"
        env["UV_LINK_MODE"] = "copy"

        run([
            "uv", "sync", "--locked", "--group", "build",
            "--no-install-project", "--python", sys.executable,
        ], env=env)
        run([
            "uv", "build", "--no-build-isolation",
            "--python", build_env / "bin/python",
            "--out-dir", output,
        ], env=env)

        wheels = list(output.glob("*.whl"))
        sources = list(output.glob("*.tar.gz"))
        require(
            len(wheels) == 1 and len(sources) == 1,
            "Artefactos inesperados / Unexpected build artifacts",
        )
        run([
            sys.executable, "-I", "-m", "venv",
            "--without-pip", install_env,
        ], cwd=directory, env=env)
        run([
            "uv", "pip", "install", "--no-index", "--no-deps",
            "--python", install_env / "bin/python", wheels[0],
        ], cwd=directory, env=env)

        probe = """
import sys
from importlib.metadata import version
from pathlib import Path
import ardrec

if sys.prefix == sys.base_prefix:
    raise RuntimeError("Entorno no aislado / Environment not isolated")
if not Path(ardrec.__file__).resolve().is_relative_to(
    Path(sys.prefix).resolve()
):
    raise RuntimeError("Importación externa / Import outside environment")
if version("ardrec") != sys.argv[1]:
    raise RuntimeError("Metadatos incorrectos / Incorrect metadata")
if ardrec.__version__ != sys.argv[1]:
    raise RuntimeError("Versión incorrecta / Incorrect version")
print("ARDREC_CLEAN_INSTALL_AND_IMPORT=PASS")
"""
        run([
            install_env / "bin/python", "-I",
            "-c", probe, package_version,
        ], cwd=directory, env=env)

    require(
        digest(ROOT / "uv.lock") == lock_before,
        "uv.lock cambió / uv.lock changed",
    )
    return {
        "component": "python",
        "python": expected,
        "uv": uv_version,
        "package_version": package_version,
        "sdist": "PASS",
        "wheel_from_sdist": "PASS",
        "clean_install_and_import": "PASS",
        "lock_unchanged": True,
    }


def verify_rust():
    config = tomllib.loads((ROOT / "rust-toolchain.toml").read_text())
    expected = config["toolchain"]["channel"]
    compiler = run(["rustc", "--version", "--verbose"])
    require(
        f"release: {expected}" in compiler.splitlines(),
        "Versión Rust incorrecta / Incorrect Rust version",
    )
    lock_before = digest(ROOT / "Cargo.lock")
    commands = [
        ["cargo", "fmt", "--all", "--", "--check"],
        [
            "cargo", "build", "--workspace", "--all-targets",
            "--locked", "--offline",
        ],
        [
            "cargo", "clippy", "--workspace", "--all-targets",
            "--locked", "--offline", "--", "-D", "warnings",
        ],
    ]
    with tempfile.TemporaryDirectory(prefix="ardrec-ci-rust-") as temp:
        env = os.environ.copy()
        env["CARGO_TARGET_DIR"] = str(Path(temp) / "target")
        env["CARGO_TERM_COLOR"] = "never"
        for command in commands:
            run(command, env=env)
    require(
        digest(ROOT / "Cargo.lock") == lock_before,
        "Cargo.lock cambió / Cargo.lock changed",
    )
    return {
        "component": "rust",
        "rust": expected,
        "format": "PASS",
        "build": "PASS",
        "clippy": "PASS",
        "lock_unchanged": True,
    }


def main():
    parser = argparse.ArgumentParser(
        description="Verificar la base / Verify the baseline"
    )
    parser.add_argument("component", choices=("python", "rust"))
    args = parser.parse_args()
    result = (
        verify_python() if args.component == "python" else verify_rust()
    )
    run(["git", "diff", "--exit-code"])
    run(["git", "diff", "--cached", "--exit-code"])
    result["algorithm_tests"] = "NOT_RUN"
    result["functional_tests"] = "NOT_RUN"
    print(json.dumps(result, ensure_ascii=False, indent=2))
    print(f"ARDREC_CI_{args.component.upper()}_BASELINE=PASS")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(
            f"ARDREC_CI_BASELINE=FAIL: {error}",
            file=sys.stderr,
        )
        sys.exit(1)
