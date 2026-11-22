# R134 — Auditoría autónoma de liberación

## Estado

Fuente candidata, sin instalación root y sin tráfico.

## Reutilización

- B4 V2: f64ce5f8c31cd80f98d07f47eb99728e15e406a66b697044e3d5eefd6a3f73e8
- B9 V2: c3c840f66476f3f0bbd87e48f657fdc6270e09b57b130eaf9c5b3cb68980cbd3
- R116 guard y F3 conservan sus identidades históricas.

## Comprobaciones

La auditoría verifica firmas Ed25519, revocación, ventana de
vigencia, identidad de arranque, fuentes fijadas, manifiestos,
inventario, separación de claves y ubicación del agente.

La confianza se lee desde archivos root declarados. Su instalación
independiente debe ser acreditada por el operador responsable.

La coincidencia criptográfica no demuestra por sí sola la procedencia
humana de las autoridades ni la validación semántica integral de
todos los documentos operacionales.

## Prohibiciones

No invocar --audit-root desde el checkout.
No copiar esta fuente a /opt sin release y revisión independiente.
No generar claves operacionales automáticamente.
No instalar B4/B9 ni abrir tráfico durante la auditoría.
No cambiar P8 de NO-GO.
No cambiar A6 de ND.

## Pendientes

- Agente instalador transaccional privilegiado.
- Provisión independiente del agente y confianza.
- Validación completa de documentos operacionales.
- Revalidación de revocación antes de cada mutación.
- Recuperación root tras publicación parcial.
- Recibo durable y readback de destinos reales.
- Aceptación física autorizada.
