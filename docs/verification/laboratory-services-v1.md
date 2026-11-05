# Verificación de servicios / Service verification

El recibo R8 acredita una ejecución local de desarrollo en 2026-11-04, sobre la base
93e1f4cdaff1bca621214d3a27798889baf03a86. Su SHA-256 es
`1af109e8d62277b5609c5b8db4535e2b8021b97381b50045b1cda27292787c86`.
El procedimiento tiene SHA-256
`1d43a43af92d1c1b3176b22657cabeda9ede32c42faead5a29cacc9e8a1ca6f3`.

| Comprobación / Check | Resultado / Result |
| --- | --- |
| ssh-identity | PASS |
| ssh-reference | PASS |
| ssh-limited-helper | PASS |
| ssh-restricted-denied | PASS |
| ssh-write | PASS |
| ssh-read-marker | PASS |
| ssh-cleanup | PASS |
| ftp-cleartext-login-denied | PASS |
| ftps-reference | PASS |
| ftps-write | PASS |
| ftps-read-marker | PASS |
| ftps-cleanup | PASS |
| smb-reference | PASS |
| smb-restricted-denied | PASS |
| smb-encrypted-write | PASS |
| smb-encrypted-read | PASS |
| smb-cleanup | PASS |

Los tres servicios mantuvieron listener y PID estable durante tres muestras
consecutivas; todos los paquetes/configuraciones esperados se comprobaron dentro
los invitados. FTP fue auditado nuevamente después de la corrección. Los archivos
leídos coincidieron con las referencias; las tres carpetas temporales quedaron vacías.
Apagado normal de cuatro VM, retirada de tres redes y reglas dedicadas, bases y
el overlay FTP del intento fallido conservados. `shutdown-state:NONZERO` tras apagar
un dominio transitorio no implica fallo si el inventario final confirma su ausencia;
el recibo de esta ejecución confirma dicha ausencia y no registra parada forzada.

The 17 checks passed in one host run. All three service listeners remained stable;
reference contents and temporary cleanup passed. Four VMs shut down gracefully and
three transient networks plus dedicated rules were removed. The immutable bases and
previous FTP runtime were preserved. This does not certify the current host state.

## Verificación en CI / CI verification

Ejecutar `python3 lab/verify_services.py`. Comprueba esquema, huellas de configuraciones
y procedimiento, inventario, resultados enumerados, límites de alcance y conservación
de obligaciones. No accede a libvirt, red ni recibos privados. La aceptación del registro
en CI no vuelve a ejecutar ni verifica independientemente las pruebas físicas.

Run `python3 lab/verify_services.py` for public record consistency. CI does not launch
VMs, access private receipts, or independently rerun physical service checks.

## Pendientes separados / Separate pending work

- Punto 5: aislamiento negativo con testigos propios, reinicios, restauración y custodia.
- Punto 6: separación material de desarrollo, piloto y experimento.
- Puntos 7–8: 25 familias convertidas a casos y perfiles autorizados.
- Puntos 9–29: ejecutor, algoritmos, aceptación integrada y reproducibilidad completa.
- Pilotaje, congelamiento y experimento: sin ejecutar.

These obligations retain their roadmap scope; service readiness is not full system
acceptance or experimental validation. Historical design and verification-plan files
remain unchanged; this newer record carries the measured service implementation state.

## Suite del registro / Record suite

Las nueve pruebas del registro viven en `lab/tests/test_service_record.py` y CI
las ejecuta explícitamente con `python3 -m unittest discover -s lab/tests -p test_service_record.py -v`.
Esta suite pertenece al registro del laboratorio. El inventario histórico de 405
pruebas base y 20 pruebas de trazabilidad en `tests/unit` se conserva sin modificar.
No se excluyen nuevos módulos mediante excepciones en el verificador histórico.

The nine laboratory-record tests run as an explicit CI suite. The historical
405 baseline tests plus 20 traceability tests retain their own inventory.
No discovery exemption is added to the historical checker.
