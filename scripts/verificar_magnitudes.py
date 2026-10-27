"""Contrastar magnitudes exactas con oráculos independientes y ambos lectores."""

from fractions import Fraction
import ast
import hashlib
import json
import os
from pathlib import Path
import random
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from ardrec.contracts import ContractError, decode_magnitude, encode_magnitude
from ardrec.persistence.codec import StorageError
from ardrec.persistence.magnitudes import decode_record, encode_record


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('ascii')


def corpus():
    cases = []
    def add(name, raw, expected, mode='m'):
        cases.append((name, mode, raw, expected))
    def rational(n, d):
        return {'status': 'DETERMINADO', 'value': {'numerator': n, 'denominator': d}}
    def pair(name, value):
        raw = canonical(value)
        add(name, raw, raw)
        envelope = canonical({'format': 'ardrec-magnitude-1', 'magnitude': value})
        add(name + '_record', envelope, envelope, 'r')
    def invalid(name, raw):
        add(name, raw, None)
        add(name + '_record', b'{"format":"ardrec-magnitude-1","magnitude":' + raw + b'}', None, 'r')

    for n, d in ((0, 1), (1, 1), (-1, 1), (1, 2), (1, 2**100 + 1),
                 (2**256 - 1, 1), (-(2**256 - 1), 1), (1, 2**256 - 1),
                 (2**255, 2**255 + 1), (2**256 - 2, 2**256 - 1)):
        pair(f'exact_{n}_{d}', rational(n, d))
    for reason in ('X', 'NO_EVIDENCE', 'INTERRUPTED', 'A' * 64, 'A0_Z'):
        pair('nd_' + reason, {'status': 'ND', 'reason_code': reason})

    # Fraction aporta el oráculo reducido sin invocar los lectores bajo prueba.
    rng = random.Random(20261026)
    for index in range(192):
        value = Fraction(rng.randrange(-(2**256 - 1), 2**256), rng.randrange(1, 2**256))
        pair(f'seeded_{index}', rational(value.numerator, value.denominator))

    for index, (n, d) in enumerate(((True, 1), (1, False), (1, 0), (1, -2), (2, 4),
                                   (0, 2), (3, 9), (2**256, 1), (-(2**256), 1),
                                   (1, 2**256), (1.0, 2), ('1', 2), (None, 1),
                                   (2**128 + 1, 2**128 + 1))):
        invalid(f'bad_rational_{index}', canonical(rational(n, d)))
    for index, reason in enumerate(('', 'a', 'A' * 65, 'Á', 'A-B', 'A\n', True, None, 4)):
        invalid(f'bad_nd_{index}', canonical({'status': 'ND', 'reason_code': reason}))

    raw_one = canonical(rational(1, 1))
    for index, raw in enumerate((b'', b'null', b'[]', b'1', b'{}', b'\xff', b'\xef\xbb\xbf' + raw_one,
                                raw_one + b'{}', b'{', b'[' * 130 + b'0' + b']' * 130,
                                raw_one.replace(b'"numerator":1', b'"numerator":1e0'),
                                raw_one.replace(b'"numerator":1', b'"numerator":NaN'),
                                raw_one.replace(b'"numerator":1', b'"numerator":01'),
                                raw_one.replace(b'"numerator":1', b'"numerator":+1'),
                                raw_one.replace(b'"numerator":1', b'"numerator":1,"numerator":1'),
                                raw_one.replace(b'"value":', b'"extra":0,"value":'),
                                raw_one.replace(b'"value":', b'"value":null,"value":'),
                                raw_one.replace(b'"numerator":1', b'"numerator":1,"extra":0'),
                                raw_one.replace(b'"numerator":1', b'"numerator":1,"num\\u0065rator":1'),
                                raw_one.replace(b'"DETERMINADO"', b'"UNKNOWN"'),
                                b'{"status":"ND","reason_code":"\\ud800"}')):
        invalid(f'malformed_{index}', raw)

    zero = canonical(rational(0, 1))
    add('negative_zero', zero.replace(b'"numerator":0', b'"numerator":-0'), zero)
    add('escaped_keys', raw_one.replace(b'"numerator"', b'"num\\u0065rator"'), raw_one)
    add('whitespace', b' \r\n\t' + raw_one + b' \n', raw_one)
    add('magnitude_limit', raw_one + b' ' * (4096 - len(raw_one)), raw_one)
    add('magnitude_over_limit', raw_one + b' ' * (4097 - len(raw_one)), None)
    record = canonical({'format': 'ardrec-magnitude-1', 'magnitude': rational(1, 1)})
    add('record_limit', record + b' ' * (8192 - len(record)), record, 'r')
    add('record_over_limit', record + b' ' * (8193 - len(record)), None, 'r')
    spaced = b'{"format":"ardrec-magnitude-1","magnitude":' + b' ' * 5000 + raw_one + b'}'
    add('record_inner_whitespace', spaced, record, 'r')
    for index, raw in enumerate((record.replace(b'magnitude-1', b'magnitude-2'),
                                record.replace(b'"format":', b'"extra":1,"format":'),
                                record.replace(b'"format":', b'"format":"x","format":'),
                                record.replace(b'"format":', b'"format":null,"format":'),
                                record.replace(b'"magnitude":', b'"magnitude":null,"magnitude":'),
                                b'{}', b'[]', b'null', b'\xff', record + b'{}')):
        add(f'record_bad_{index}', raw, None, 'r')
    return cases


def verify(probe):
    cases = corpus()
    for name, mode, raw, expected in cases:
        try:
            actual = (encode_magnitude(decode_magnitude(raw)) if mode == 'm'
                      else encode_record(decode_record(raw)))
        except (ContractError, StorageError):
            actual = None
        if actual != expected:
            raise RuntimeError(f'Oráculo Python distinto: {name}')
    payload = ''.join(mode + ' ' + raw.hex() + '\n' for _, mode, raw, _ in cases)
    result = subprocess.run([str(probe)], input=payload, text=True, capture_output=True, timeout=60)
    if result.returncode:
        raise RuntimeError('Falló el lector Rust: ' + result.stderr[-2000:])
    lines = result.stdout.splitlines()
    if len(lines) != len(cases):
        raise RuntimeError('Número de respuestas Rust inesperado')
    for (name, _, _, expected), line in zip(cases, lines, strict=True):
        wanted = 'ERR' if expected is None else 'OK ' + expected.hex()
        if line != wanted:
            raise RuntimeError(f'Oráculo Rust distinto: {name}: {line[:120]}')
    signature = hashlib.sha256()
    for name, mode, raw, expected in cases:
        signature.update(canonical([name, mode, raw.hex(), None if expected is None else expected.hex()]))
        signature.update(b'\n')
    result = {'cases': len(cases), 'accepted': sum(v is not None for _, _, _, v in cases),
            'rejected': sum(v is None for _, _, _, v in cases), 'corpus_sha256': signature.hexdigest(),
            'seed': 20261026, 'comparison': 'EXACT_CANONICAL_BYTES',
            'model_algorithms_executed': False, 'experimental_validation': 'NOT_RUN'}
    supplement = json.loads((ROOT / 'docs/traceability/exact-magnitudes-v1.json').read_text())
    planned = supplement['expected_verification']
    if any(result[key] != planned[name] for key, name in
           (('cases', 'parity_cases'), ('accepted', 'accepted'), ('rejected', 'rejected'),
            ('seed', 'corpus_seed'), ('corpus_sha256', 'corpus_sha256'))):
        raise RuntimeError('El corpus no coincide con la trazabilidad declarada')
    registry = json.loads((ROOT / 'docs/traceability/development-v1.json').read_text())
    registered = {item['id']: item for item in registry['requirements']}
    for requirement in supplement['requirements']:
        original = registered[requirement['id']]
        if requirement['algorithms'] != original['algorithms'] or requirement['fulfills_full_requirement']:
            raise RuntimeError('Vínculo de requisito o alcance incorrecto')
        for name in (*requirement['modules'], *requirement['checks']):
            file, _, symbol = name.partition('::')
            if '..' in Path(file).parts or Path(file).is_absolute() or not (ROOT / file).is_file():
                raise RuntimeError('Vínculo de archivo inválido: ' + file)
            if symbol:
                cls, method = symbol.split('.')
                tree = ast.parse((ROOT / file).read_text())
                if not any(isinstance(c, ast.ClassDef) and c.name == cls and
                           any(isinstance(n, ast.FunctionDef) and n.name == method for n in c.body)
                           for c in tree.body):
                    raise RuntimeError('Vínculo de prueba inexistente: ' + symbol)
    return result


def main():
    before = hashlib.sha256((ROOT / 'Cargo.lock').read_bytes()).hexdigest()
    with tempfile.TemporaryDirectory(prefix='ardrec-magnitudes-rust-') as directory:
        env = os.environ.copy()
        env['CARGO_TARGET_DIR'] = str(Path(directory) / 'target')
        env['CARGO_TERM_COLOR'] = 'never'
        commands = [
            ['cargo', 'test', '--lib', 'magnitudes::tests', '--locked', '--offline'],
            ['cargo', 'build', '--example', 'magnitude_probe', '--locked', '--offline'],
        ]
        for command in commands:
            subprocess.run(command, cwd=ROOT, env=env, check=True, timeout=300)
        result = verify(Path(env['CARGO_TARGET_DIR']) / 'debug/examples/magnitude_probe')
    if hashlib.sha256((ROOT / 'Cargo.lock').read_bytes()).hexdigest() != before:
        raise RuntimeError('Cargo.lock cambió durante la verificación')
    print(json.dumps(result, ensure_ascii=False, indent=2))
    print('ARDREC_MAGNITUDE_PYTHON_RUST_PARITY=PASS')


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print(f'ARDREC_MAGNITUDE_PARITY=FAIL: {error}', file=sys.stderr)
        sys.exit(1)
