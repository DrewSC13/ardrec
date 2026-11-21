# R117-F5D-D — Contrato de bootstrap firmado, SOURCE_ONLY

## Alcance y cadena de confianza

Este incremento verifica una política canónica Ed25519 que vincula:

- un HEAD Git de 40 caracteres hexadecimales;
- los SHA-256 de diez fuentes de F4, F5A, F5B, F5C y F5D;
- las tres identidades de clave pública (bootstrap, aprobación y revocación);
- las rutas operativas fijas y un alcance sin privilegios;
- un intervalo UTC de validez de diez minutos como máximo.

Las claves privadas de las pruebas se generan en directorios temporales y no se agregan a Git. El contrato requiere tres claves distintas. La comprobación criptográfica utiliza OpenSSL con entradas regulares de tamaño conocido.

## Límites explícitos

El hash de la clave de bootstrap es suministrado por el llamador. Aunque coincida y la firma sea válida, **no acredita aprovisionamiento independiente de confianza**. Los hashes de fuentes solo son comprobaciones sobre el árbol local suministrado; tampoco acreditan una imagen instalada en root ni su durabilidad.

`SOURCE_ONLY` nunca significa permiso de instalación, arranque, tráfico o P8. El resultado conserva `host_root_provenance_attested=false`, `independent_trust_provisioned=false`, `transaction_durability_attested=false`, `root_release_accepted=false`, `install_authorized=false`, `boot_authorized=false`, `network_authorized=false`, `A6=ND`, `P8=NO-GO`.

F5B `--apply` permanece bloqueado; no se alteran F4, F5A-F5D-C ni R116.

## Pruebas y continuidad

Diecinueve pruebas offline comprueban firma Ed25519, pin de clave, identidad, alcance, expiración, fuentes alteradas, fuente ausente, symlink, JSON canónico y claves independientes.

**F5D-E** debe instalar un ejecutable auditor *independientemente* de un checkout modificable, fijar su hash y las claves fuera de Git, autenticar los descriptores de root, y demostrar respuesta segura ante transacciones incompletas y cambios concurrentes. No habilitar root ni el piloto hasta que esa validación y una autorización separada lo permitan.
