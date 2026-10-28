"""Probar consultas Unix entre procesos y recuperación sin repetir herramientas."""
from copy import deepcopy
import json
import os
import re
from pathlib import Path
import selectors
import signal
import socket
import subprocess
import sys
import tempfile
import threading

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "src"), str(ROOT / "tests/unit"), str(ROOT / "scripts")]
from ardrec.messages import decode_message, encode_message
from ardrec.reconciliation import begin_query, inspect_recovery
from ardrec.reconciliation_transport import ExchangeError, exchange_query
from ardrec.transport import read_frame, write_frame
from test_persistence import INITIAL, DurableStore, prepare, reserve, reopen
from test_reconciliation import POINTS as PYTHON_POINTS
from verificar_diario_tecnico import POINTS as RUST_POINTS, probe, require


def line(child, expected):
    with selectors.DefaultSelector() as selector:
        selector.register(child.stdout, selectors.EVENT_READ)
        require(selector.select(10), f"Sin señal: {expected}")
    actual = child.stdout.readline().strip()
    require(actual == expected, f"Señal inesperada: {actual!r}; esperada: {expected}")


def stop(child):
    if child.poll() is None:
        child.kill()
    out, err = child.communicate(timeout=10)
    return out, err


def server(binary, journal, point="none"):
    client, peer = socket.socketpair()
    try:
        child = subprocess.Popen([str(binary), str(journal), point], stdin=peer,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    except BaseException:
        client.close()
        raise
    finally:
        peer.close()
    try:
        line(child, "READY")
        return child, client
    except BaseException as error:
        client.close()
        out, err = stop(child)
        raise RuntimeError(f"{error}; {out}; {err}") from error


CLIENT = '''
import os, signal, socket, sys
from test_persistence import reopen
from ardrec.reconciliation_transport import exchange_query
path, point = sys.argv[1:]
def crash(current):
    if current == point: os.kill(os.getpid(), signal.SIGKILL)
with reopen(path, fault=crash) as store:
    connection = socket.socket(fileno=0)
    exchange_query(store, connection)
raise RuntimeError("No se alcanzó el punto de interrupción")
'''


def verify(journal_binary, channel_binary, directory):
    fixtures = json.loads((ROOT / "tests/fixtures/messages-temporal-v1.json").read_text())
    def setup(label, phase="completed", exact=False):
        rust, python = directory / (label + "-r"), directory / (label + "-p")
        probe(journal_binary, "create", rust)
        probe(journal_binary, "register", rust, fixtures["request"])
        result = None
        if phase != "uncertain":
            result = deepcopy(fixtures["result_" + phase])
            result["payload"]["snapshot"]["journal_reference"] = probe(journal_binary, "inspect", rust)["snapshot"]["journal_reference"]
            if exact:
                result["payload"]["outcome"]["duration_ms"] = 9_007_199_254_740_993
            probe(journal_binary, "report", rust, result)
        with DurableStore.create(python, INITIAL) as store:
            prepare(store)
            reserve(store)
            raw = begin_query(store, message_id="QUERY-SOCKET", created_at="2026-10-19T12:00:20Z")
        return rust, python, raw, (encode_message(result) if result is not None
                                  and result["payload"]["snapshot"]["result"]["status"] == "DISPONIBLE" else None)

    def pending(python, raw):
        with reopen(python) as store:
            decision = inspect_recovery(store)
            require(decision.open_query == raw and decision.queries_used == 1, "Consulta alterada")
            require(decision.action == "QUERY_INCOMPLETE", "Confirmación parcial")
            require(store.state.confirmed.generation == 1 and store.state.incorporated_execution_count == 0,
                    "Efectos analíticos inesperados")

    def finish(rust, python, expected):
        child, connection = server(channel_binary, rust)
        try:
            with reopen(python) as store:
                result = exchange_query(store, connection)
                require(result.result == expected and result.queries_used == 1, "Resultado o presupuesto distinto")
                require(not result.new_execution_authorized, "Ejecución autorizada")
                require(store.state.confirmed.generation == 1 and store.state.incorporated_execution_count == 0,
                        "Una consulta aplicó efectos analíticos")
            out, err = child.communicate(timeout=10)
            require(child.returncode == 0, out + err)
            with reopen(python) as store:
                require(inspect_recovery(store) == result, "Recuperación Python distinta")
            return result
        finally:
            connection.close()
            stop(child)

    # Se conserva el resultado íntegro, incluyendo enteros superiores a 2**53.
    for phase in ("completed", "interrupted", "not_started", "uncertain"):
        rust, python, raw, expected = setup("variant-" + phase, phase, exact=phase == "completed")
        decision = finish(rust, python, expected)
        require(decision.action == ("QUERY_REQUIRED" if phase == "uncertain" else "READY_FOR_VALIDATION"),
                "Semántica de estado alterada")
        before = probe(journal_binary, "inspect", rust)["sequence"]
        # La conexión nueva repite la misma consulta y recupera exactamente los bytes guardados.
        child, connection = server(channel_binary, rust)
        try:
            with connection as peer, peer.makefile("rwb", buffering=0) as stream:
                write_frame(stream, raw.decode())
                peer.shutdown(socket.SHUT_WR)
                response = read_frame(stream).encode()
                full = read_frame(stream).encode() if expected is not None else None
                require(stream.read(1) == b"", "Bytes posteriores")
                require(full == expected, "Valores exactos perdidos")
            child.communicate(timeout=10)
            require(child.returncode == 0, "Falló el par Rust")
        finally:
            connection.close()
            stop(child)
        saved = probe(journal_binary, "answer", rust, decode_message(raw))
        require(response == encode_message(saved["response"]) and saved["replay"], "Respuesta no idéntica")
        require(probe(journal_binary, "inspect", rust)["sequence"] == before, "Repetición con efecto")

    # Matar Rust durante cada frontera durable deja la misma consulta abierta en Python.
    crashes = 0
    for index, point in enumerate(RUST_POINTS):
        rust, python, raw, expected = setup(f"rust-{index}")
        before = probe(journal_binary, "inspect", rust)["sequence"]
        child, connection = server(channel_binary, rust, point)
        errors = []
        def killer():
            try:
                line(child, "ARDREC_FAULT_POINT=" + point)
            except BaseException as error:
                errors.append(error)
            finally:
                child.kill()
        worker = threading.Thread(target=killer)
        worker.start()
        try:
            with reopen(python) as store:
                with_error = False
                try:
                    exchange_query(store, connection)
                except ExchangeError:
                    with_error = True
                require(with_error, "El canal interrumpido fue confirmado")
            worker.join(12)
            require(not worker.is_alive() and not errors, f"Interrupción fallida: {errors}")
            child.communicate(timeout=10)
            require(child.returncode == -signal.SIGKILL, "Rust no terminó por SIGKILL")
        finally:
            connection.close()
            stop(child)
            worker.join(12)
        pending(python, raw)
        published = point in {"head:replaced", "head:durable", "commit:acknowledge"}
        require(probe(journal_binary, "inspect", rust)["sequence"] == before + int(published),
                "Respuesta Rust parcialmente confirmada")
        finish(rust, python, expected)
        require(probe(journal_binary, "inspect", rust)["sequence"] == before + 1, "Respuesta duplicada")
        crashes += 1
    print(f"ARDREC_CHANNEL_RUST_SIGKILL={crashes}", flush=True)

    # Matar Python al confirmar la respuesta deja ambos lados recuperables sin nuevos envíos de ejecución.
    for index, point in enumerate(PYTHON_POINTS):
        rust, python, raw, expected = setup(f"python-{index}")
        child, connection = server(channel_binary, rust)
        try:
            env = dict(os.environ, PYTHONPATH=os.pathsep.join((str(ROOT / "src"), str(ROOT / "tests/unit"))))
            client = subprocess.run([sys.executable, "-c", CLIENT, str(python), point],
                                    stdin=connection, env=env, capture_output=True, text=True, timeout=20)
            require(client.returncode == -signal.SIGKILL, client.stdout + client.stderr)
            out, err = child.communicate(timeout=10)
            require(child.returncode == 0, out + err)
        finally:
            connection.close()
            stop(child)
        before = probe(journal_binary, "inspect", rust)["sequence"]
        published = point in {"head:replaced", "head:durable", "commit:acknowledge"}
        with reopen(python) as store:
            decision = inspect_recovery(store)
            require((decision.action == "READY_FOR_VALIDATION") == published, "Confirmación Python parcial")
            require(decision.queries_used == 1 and not decision.new_execution_authorized, "Presupuesto alterado")
            if published:
                require(decision.result == expected, "Resultado recuperado distinto")
        if not published:
            pending(python, raw)
            finish(rust, python, expected)
        require(probe(journal_binary, "inspect", rust)["sequence"] == before, "Respuesta Rust repetida")
        crashes += 1
    print(f"ARDREC_CHANNEL_TOTAL_SIGKILL={crashes}", flush=True)
    return {"component": "durable_query_transport", "variants": 4, "rust_sigkill_cases": len(RUST_POINTS),
            "python_sigkill_cases": len(PYTHON_POINTS), "exact_integer_round_trip": "PASS",
            "historical_reply_replay": "PASS", "partial_confirmation": "REJECTED",
            "new_execution_authorized": False, "real_tools": "NOT_RUN", "power_loss": "NOT_SIMULATED"}


def main():
    # Cada par Unix se hereda de forma explícita; no se abre un servidor permanente.
    with tempfile.TemporaryDirectory(prefix="ardrec-f10-") as temporary:
        directory = Path(temporary)
        env = dict(os.environ, CARGO_TARGET_DIR=str(directory / "target"), CARGO_TERM_COLOR="never")
        tests = subprocess.run(["cargo", "test", "--locked", "--offline", "--workspace", "--lib", "reconciliation_transport::"],
                       cwd=ROOT, env=env, capture_output=True, text=True, timeout=300)
        print(tests.stdout + tests.stderr, flush=True)
        require(tests.returncode == 0 and re.search(r"test result: ok\. 10 passed; 0 failed; 0 ignored;", tests.stdout),
                "No se confirmaron las diez pruebas Rust del canal")
        subprocess.run(["cargo", "build", "--locked", "--offline", "--package", "ardrec-executor",
                        "--example", "journal_probe", "--example", "reconciliation_probe"],
                       cwd=ROOT, env=env, check=True, timeout=300)
        output = directory / "target/debug/examples"
        evidence = verify(output / "journal_probe", output / "reconciliation_probe", directory)
        print(json.dumps(evidence, ensure_ascii=False, indent=2))
        print("ARDREC_RECONCILIATION_TRANSPORT=PASS")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"ARDREC_RECONCILIATION_TRANSPORT=FAIL: {error}", file=sys.stderr)
        sys.exit(1)
