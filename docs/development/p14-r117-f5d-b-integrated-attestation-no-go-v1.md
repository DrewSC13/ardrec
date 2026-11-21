# R117-F5D-B — Atestación integrada de snapshots

## Implementación

Se integran tres verificadores previamente desarrollados:

1. F5D-A: lectura segura de árboles mediante descriptores,
   propietario, modos, enlaces y alcance exacto.
2. F5C: autenticidad de 39 archivos frente al candidato F5A,
   recibo de release y cinco registros transaccionales.
3. F5D-A: Ed25519 auténtico para aprobación y revocación,
   utilizando dos claves distintas.

## Pruebas

Veinte pruebas offline con archivos temporales y firmas
Ed25519 reales generadas durante la prueba.

Se cubren interrupciones representadas por registros
ausentes, modificación de archivos, permisos, enlaces,
suplantación de claves, caducidad y revocación.

Los directorios son independientes para cada caso.
Las claves privadas temporales no se incorporan a Git.

## Límite de confianza

Un descriptor suministrado por el llamador no demuestra
que proceda de /var/lib/ardrec.

Una clave pública suministrada por el llamador no demuestra
que sea una raíz de confianza aprovisionada externamente.

El contenido de complete.json es evidencia estructural:
su existencia no demuestra por sí sola fsync, supervivencia
ante cortes de energía ni integridad de la transacción.

Por ello, incluso con las veinte pruebas aprobadas, el
resultado mantiene:

root_ownership_attested=false
trusted_key_provenance_attested=false
transaction_durability_attested=false
root_release_accepted=false
boot_authorized=false

F5B --apply continúa bloqueado. F4 no se modifica.
El historial R116 permanece inalterado.

## Próxima frontera

F5D-C debe autenticar el origen de los descriptores,
anclar las claves de confianza y establecer una puerta
root de solo lectura bajo un despliegue independiente.

No se debe conceder P8 ni ejecutar el piloto mediante
un resultado de F5D-B.

P7=DRAFT; A6=ND; P8=NO-GO.
