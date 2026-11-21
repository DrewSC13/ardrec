# R117-F5D-A — Ed25519 y lector root seguro

## Alcance

Implementación SOURCE_ONLY de comprobación criptográfica
Ed25519 y lectura segura de árboles de archivos por
descriptores de directorio, como preparación para el
agente root independiente.

No instala código ni autoriza una release.

## Criptografía

Se verifica la aprobación F5B y una afirmación de
revocación F5D mediante dos claves públicas Ed25519
diferentes. Ambas declaraciones están vinculadas al
mismo HEAD y SHA-256 del candidato.

La afirmación de revocación dura como máximo 90 segundos.
Una revocación positiva, caducada, futura o con identidad
incorrecta se rechaza.

La verificación emplea archivos temporales regulares
0600, dentro de un directorio privado 0700, porque
OpenSSL requiere conocer el tamaño del mensaje Ed25519.

Ninguna clave privada forma parte del repositorio.
Las pruebas generan claves efímeras y se destruyen
al concluir.

## Lector seguro

El lector recibe un descriptor de directorio previamente
autenticado. Comprueba propietario, modo, tipos de archivo,
enlaces duros, enlaces simbólicos, límites de tamaño
y coincidencia exacta del conjunto esperado.

El directorio raíz operativo solo puede ser abierto por
un agente privilegiado de confianza. Este incremento
no implementa ni ejecuta el despliegue de ese agente.

## Limitaciones

La validación criptográfica offline no acredita por sí sola
la propiedad root, durabilidad, ausencia de modificación
simultánea ni aprobación operacional.

La futura puerta F5D-B debe combinar las pruebas F5C
y F5D-A en una inspección root autenticada, añadir la
comprobación del diario completo y vincular el resultado
a una interfaz no privilegiada con revocación.

F5B --apply continúa bloqueado.

P7=DRAFT, A6=ND, P8=NO-GO.

## Aislamiento de pruebas

Cada prueba crea un directorio privado independiente mediante tempfile.mkdtemp dentro del entorno temporal de la clase. La limpieza ocurre en tearDownClass.

La prueba de enlaces duros crea un enlace adicional fuera del árbol inspeccionado, garantizando que el rechazo se produzca por st_nlink y no por la detección de archivos inesperados.

Se incorpora una prueba explícita de aislamiento de fixtures. Total: 17 pruebas offline.

No se modifica el motor criptográfico ni se habilita F5B --apply. P8=NO-GO.
