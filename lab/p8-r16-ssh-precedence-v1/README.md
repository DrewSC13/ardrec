# P8-R16-R6 — Modelo SSH de precedencia, CI y frontera de no ejecución

Se incorpora una **copia pública derivada y delimitada** del modelo R5, sin salidas privadas ni
textos completos de manuales. La matriz R15 sigue siendo obligatoria. Este artefacto no
interpreta archivos reales `ssh_config` ni ejecuta `ssh`, `sftp`, `ssh-keyscan`, `ssh -G`
o ninguna VM. La entrada son **diez casos JSON sintéticos** congelados por SHA-256.

- Modelo: `lab/p8_r16_ssh_precedence.py` (funciones puras y ayudas locales sin llamadas de red).
- Fixture R5 íntegro: `cases.json`, SHA-256 `406cfeaf7fbd677235a520a56c4d324792b58996b9f1e8fe007f92798ba6fd5f`.
- Verificación: `python3 lab/verify_p8_r16_ssh_precedence.py` (incluye validación de R15).
- Regresiones: `python3 -m unittest discover -s lab/tests -p test_p8_r16_ssh_precedence.py -v`.

La atestación de R4/R5 fue efectuada previamente en Prometheus: el informe R5 privado tiene
SHA-256 `54e73fb46fd834d947de5deb8663910f049d0140251c10d70c633061e4741844`.
**La CI no vuelve a autenticar esos archivos privados**, sino que verifica el artefacto público
contra su fixture congelado y la cadena R15. El pin es evidencia de procedencia declarada,
no prueba de equivalencia con OpenSSH. Se conservan los estados cero de autorización.

## Frontera y criterio de salida

Una simulación sin contradicciones no habilita ejecución. El trabajo posterior requiere
un procedimiento separado de obtención y verificación de configuración efectiva por binario
específico, configuración, dependencias, entorno, destino, material de confianza y caso.
Ninguna operación con un cliente SSH —incluso `ssh -G`— está permitida por este incremento.
`Match exec`, `Include`, token expansion, canonización y procesos auxiliares quedan fuera de la
semántica sintetizada. El P8 completo permanece abierto; P9 y A1–A10 no han comenzado.

**EN:** CI-integrated, strictly synthetic and denial-only SSH precedence model. No private
manuals or receipts in Git, no SSH execution, no runtime attestation, no argv and no authorization.
