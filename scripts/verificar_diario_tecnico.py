"""Verificar el diario técnico, sus interrupciones y el intercambio con Python."""
from copy import deepcopy
import json
import os
from pathlib import Path
import re
import selectors
import signal
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "src"), str(ROOT / "tests/unit")]
POINTS = tuple("record:" + point for point in (
    "created", "partial", "written", "synced", "linked", "installed", "durable",
)) + tuple("head:" + point for point in (
    "created", "partial", "written", "synced", "before_replace", "replaced", "durable",
)) + ("commit:acknowledge",)


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def probe(binary, operation, path, data=None, *, success=True):
    result = subprocess.run(
        [str(binary), operation, str(path)], input=json.dumps(data or {}) + "\n",
        capture_output=True, text=True, timeout=20,
    )
    if not success:
        require(result.returncode != 0, "La sonda debía rechazar la operación")
        return result.stderr
    require(result.returncode == 0, result.stderr)
    return json.loads(result.stdout)


def blocked_child(binary, operation, path, data, point):
    child = subprocess.Popen(
        [str(binary), operation, str(path), point], stdin=subprocess.PIPE,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    try:
        child.stdin.write(json.dumps(data) + "\n")
        child.stdin.flush()
        with selectors.DefaultSelector() as selector:
            selector.register(child.stdout, selectors.EVENT_READ)
            require(selector.select(timeout=10), f"No se alcanzó el punto: {point}")
        require(child.stdout.readline().strip() == f"ARDREC_FAULT_POINT={point}",
                f"Punto de interrupción inesperado: {point}")
        return child
    except BaseException:
        if child.poll() is None:
            child.kill()
        child.communicate(timeout=10)
        raise


def kill(child):
    os.kill(child.pid, signal.SIGKILL)
    child.communicate(timeout=10)
    require(child.returncode == -signal.SIGKILL, "El hijo no terminó por SIGKILL")


def verify(binary, directory):
    from ardrec.messages import correlate_status, decode_message, encode_message
    from ardrec.persistence import DurableStore
    from ardrec.reconciliation import begin_query, complete_query, inspect_recovery
    from test_persistence import INITIAL, prepare, reserve, reopen

    fixtures = json.loads((ROOT / "tests/fixtures/messages-v2.json").read_text())
    request = fixtures["request"]

    def create(path, register=True, result=False):
        probe(binary, "create", path)
        if register:
            probe(binary, "register", path, request)
        if result:
            probe(binary, "report", path, report(path))

    def report(path):
        result = deepcopy(fixtures["result_completed"])
        snapshot = probe(binary, "inspect", path)["snapshot"]
        result["payload"]["snapshot"]["journal_reference"] = snapshot["journal_reference"]
        return result

    crashes = 0
    for operation in ("register", "observe", "report", "answer"):
        for index, point in enumerate(POINTS):
            path = directory / f"crash-{operation}-{index}"
            create(path, register=operation != "register", result=operation == "answer")
            if operation == "register":
                data = request
            elif operation == "observe":
                data = deepcopy(fixtures["status_running"]["payload"]["snapshot"])
                data["journal_reference"] = probe(binary, "inspect", path)["snapshot"]["journal_reference"]
            elif operation == "report":
                data = report(path)
            else:
                data = fixtures["query"]
            before = probe(binary, "inspect", path)
            child = blocked_child(binary, operation, path, data, point)
            kill(child)
            published = point in {"head:replaced", "head:durable", "commit:acknowledge"}
            for _ in range(2):
                recovered = probe(binary, "inspect", path)
                require(recovered["sequence"] == before["sequence"] + int(published), "Confirmación parcial")
                if not published:
                    require(recovered == before, "Un registro huérfano alteró el estado")
                if operation == "report":
                    require((recovered["result"] is not None) == published, "Resultado y estado separados")
                if recovered["snapshot"]:
                    require(recovered["snapshot"]["new_execution_authorized"] is False, "Ejecución autorizada")
            retry = probe(binary, operation, path, data)
            if operation == "answer":
                require(retry["replay"] is published, "Respuesta repetida incorrecta")
            else:
                require(retry["recorded"] == ("Replay" if published else "New"), "Registro repetido incorrecto")
            require(probe(binary, "inspect", path)["sequence"] == before["sequence"] + 1,
                    "Una repetición duplicó la operación")
            crashes += 1
        print(f"ARDREC_TECHNICAL_JOURNAL_SIGKILL_PROGRESS={crashes}/60", flush=True)

    # Un segundo proceso no puede abrir el mismo diario mientras el primero mantiene el bloqueo.
    path = directory / "lock"
    create(path)
    holder = blocked_child(binary, "hold", path, {}, "LOCK_HELD")
    try:
        require("lock_busy" in probe(binary, "inspect", path, success=False), "Bloqueo no confirmado")
    finally:
        kill(holder)
    require(probe(binary, "inspect", path)["sequence"] == 1, "El bloqueo alteró el diario")

    # Conciliar una consulta Python con la respuesta y el resultado originales del diario Rust.
    rust_path, python_path = directory / "rust-pair", directory / "python-pair"
    create(rust_path, result=True)
    result = report(rust_path)
    with DurableStore.create(python_path, INITIAL) as store:
        prepare(store)
        reserve(store)
        raw_query = begin_query(store, message_id="QUERY-PAIR", created_at="2026-10-19T12:00:20Z")
        reply = probe(binary, "answer", rust_path, decode_message(raw_query))
        correlate_status(request, decode_message(raw_query), reply["response"])
        require(reply["result"] == result, "El resultado Rust cambió")
        decision = complete_query(store, raw_query, encode_message(reply["response"]),
                                  result=encode_message(reply["result"]))
        require(decision.action == "READY_FOR_VALIDATION" and not decision.new_execution_authorized,
                "Conciliación Python inesperada")
        require(store.state.confirmed.generation == 1 and store.state.incorporated_execution_count == 0,
                "La consulta publicó efectos analíticos")
    with reopen(python_path) as store:
        decision = inspect_recovery(store)
        require(decision.action == "READY_FOR_VALIDATION" and decision.result == encode_message(result),
                "La conciliación no sobrevivió al reinicio")
    replay = probe(binary, "answer", rust_path, decode_message(raw_query))
    require(replay["replay"] and replay["response"] == reply["response"] and replay["result"] == reply["result"],
            "El diario no recuperó la respuesta exacta")
    return {"rust_test_methods": 34, "sigkill_cases": crashes, "process_lock": "PASS",
            "python_rust_durable_exchange": "PASS", "new_execution_authorized": False,
            "real_tools": "NOT_RUN", "power_loss": "NOT_SIMULATED"}


def main():
    with tempfile.TemporaryDirectory(prefix="ardrec-technical-journal-") as temporary:
        directory = Path(temporary)
        env = dict(os.environ, CARGO_TARGET_DIR=str(directory / "target"), CARGO_TERM_COLOR="never")
        result = subprocess.run(
            ["cargo", "test", "--locked", "--offline", "--workspace", "--lib", "journal::"],
            cwd=ROOT, env=env, text=True, capture_output=True, timeout=300,
        )
        print(result.stdout + result.stderr, flush=True)
        require(result.returncode == 0 and re.search(r"test result: ok\. 34 passed; 0 failed; 0 ignored;", result.stdout),
                "No se confirmaron las 34 pruebas Rust del diario")
        subprocess.run(["cargo", "build", "--locked", "--offline", "--package", "ardrec-executor",
                        "--example", "journal_probe"], cwd=ROOT, env=env, check=True, timeout=300)
        evidence = verify(directory / "target/debug/examples/journal_probe", directory)
        print(json.dumps(evidence, ensure_ascii=False, indent=2))
        print("ARDREC_TECHNICAL_JOURNAL_VERIFICATION=PASS")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"ARDREC_TECHNICAL_JOURNAL_VERIFICATION=FAIL: {error}", file=sys.stderr)
        sys.exit(1)
