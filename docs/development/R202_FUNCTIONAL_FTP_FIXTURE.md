# R202 - Fixture funcional FTP aislado

Ensayo funcional de transferencia autorizada de un archivo
sintetico mediante FTP, con servidor y cliente dentro
del mismo espacio de nombres de red aislado.

Reutiliza las dependencias fijadas de R194D.

La identidad de acceso es temporal, se genera dentro
del proceso aislado y dispone de permisos de solo lectura.
No se suministran destinos externos ni archivos del usuario.

Se registra un plan y un intento antes de ejecutar.
Se verifica el espacio de nombres, la interfaz loopback,
los codigos FTP y las huellas SHA-256 del archivo inicial,
los bytes recibidos y el archivo final.

La comprobacion funcional no equivale a una prueba de
vulnerabilidad ni a una admision operacional A5/A6.

El nuevo fixture difiere del perfil restrictivo R199.
Las valoraciones R200 no se transfieren automaticamente
como linea de base cerrada.

No se cambian contratos historicos ni se habilita P8.
No se incorporan observaciones experimentales.

Las pruebas unitarias verifican recibos artificiales.
El ensayo local requiere consentimiento explicito.
