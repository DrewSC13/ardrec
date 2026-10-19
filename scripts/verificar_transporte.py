"""Ejecutar pruebas Rust y comprobar el intercambio Python–Rust por socket Unix."""

from fractions import Fraction
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from ardrec.contracts import encode_magnitude
from ardrec.transport import read_frame, write_frame


def main():
    with tempfile.TemporaryDirectory(prefix="ardrec-wire-") as temporary:
        folder = Path(temporary)
        env = os.environ.copy()
        env["CARGO_TARGET_DIR"] = str(folder / "target")
        env["CARGO_TERM_COLOR"] = "never"

        for args in [
            ["cargo", "test", "--workspace", "--all-targets", "--locked", "--offline"],
            ["cargo", "build", "--locked", "--offline", "-p", "ardrec-executor",
             "--example", "transport_probe"],
        ]:
            subprocess.run(args, cwd=ROOT, env=env, check=True, timeout=180)

        process = None
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
                path = folder / "channel.sock"
                # El directorio temporal es privado; el socket también queda restringido.
                os.chmod(folder, 0o700)
                listener.bind(str(path))
                os.chmod(path, 0o600)
                listener.listen(1)
                listener.settimeout(10)

                binary = folder / "target/debug/examples/transport_probe"
                process = subprocess.Popen(
                    [str(binary), str(path)], cwd=folder,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                )
                connection, _ = listener.accept()
                with connection:
                    connection.settimeout(5)
                    with connection.makefile("rwb", buffering=0) as stream:
                        cases = [
                            encode_magnitude(Fraction(1, 3)).decode("utf-8"),
                            json.dumps({"texto": "áλ🙂", "datos": "x" * 65536},
                                       ensure_ascii=False),
                        ]
                        for text in cases:
                            write_frame(stream, text)
                            if read_frame(stream) != text:
                                raise RuntimeError("El intercambio alteró el contenido")

                stdout, stderr = process.communicate(timeout=10)
                if process.returncode != 0:
                    raise RuntimeError(f"La sonda Rust falló: {stdout}{stderr}")
        finally:
            # Una prueba fallida no debe dejar un proceso auxiliar vivo.
            if process is not None and process.poll() is None:
                process.kill()
                process.communicate(timeout=5)

    print("ARDREC_RUST_TRANSPORT_TESTS=PASS")
    print("ARDREC_PYTHON_RUST_UNIX_EXCHANGE=PASS")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"ARDREC_TRANSPORT_CHECK=FAIL: {error}", file=sys.stderr)
        sys.exit(1)
