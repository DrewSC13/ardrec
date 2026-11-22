# R132 — Recuperación parcial B4/B9

## Alcance

R132 implementa conciliación durable de dos publicaciones privadas,
reutilizando exactamente las fuentes B4/B9 V2 y la revisión R130.

Su propósito es comprobar los casos de recuperación antes de adaptar
la lógica al instalador root independiente.

## Garantías comprobables por las pruebas

- Diario durable previo a la publicación.
- Dos renombrados separados.
- Verificación de bytes y metadatos.
- Reanudación desde B4 únicamente publicado.
- Recuperación cuando ambos destinos existen sin recibo.
- Rechazo de recibos, fuentes y journal alterados.
- Bloqueo de concurrencia.
- Idempotencia sin repetir operaciones.
- Conservación de estados parciales.
- Sin borrado automático de B4.

## Limitaciones de autoridad

El entorno es una caja privada del usuario, no los destinos root reales.

Los manifiestos son los borradores R130, con autorización falsa.
No existe instalación root, habilitación de tráfico ni ejecución FTP.

El código no constituye una versión autorizada de R131.

## Pendientes de instalación real

- Agente independiente fuera del checkout.
- Provisión externa de confianza.
- Firma Ed25519 de liberación.
- Revocación actual verificable.
- Exclusiones de autoridades operacionales.
- Vinculación al HEAD, árbol, boot y destinos.
- Pruebas de fallos del instalador privilegiado.
- Recibos root con readback y aceptación física.

P8=NO-GO. A6=ND. A9 no acreditado.
