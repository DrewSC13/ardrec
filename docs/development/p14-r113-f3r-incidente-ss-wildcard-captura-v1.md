# R113-F3R — Reparación del analizador `ss` y preservación de incidente

El intento `inspect-gccubwyi` está incompleto: el guard `SS_ADDRESS_NOT_IPV4` se ejecutó después de al menos un `guest-exec` iniciado, sin registro de salida `ss` persistida. **No** se considera observación acreditada. Su directorio y los marcadores permanecen inmutables.

La variante de `ss -H -ltn4` puede expresar el comodín IPv4 como `*:puerto`, que se normaliza a `0.0.0.0` exclusivamente para esta captura IPv4. Se siguen rechazando tokens ambiguos, IPv6 y ámbitos de interfaz no previstos.

Antes de clasificar cada respuesta QGA, F3R persiste `capture-<rol>.json` con la respuesta original del arranque y de su terminación. El replay valida esos registros, el manifiesto, la clasificación y la huella del incidente anterior. Si una clasificación falla, **el intento se detiene**, pero la captura disponible permanece para análisis forense. Ningún estado incompleto equivale a `PASS`.

Una nueva inspección requiere autorización expresa de tres nuevas ejecuciones locales `/usr/bin/ss -H -ltn4`, una por VM. Esta autorización no implica apertura de tráfico, cambios de firewall, reinicios, aprobación P8, ni validez de SSH/FTP/SMB como protocolos.

Después de su replay exitoso se podrán diseñar reglas R113-F4 de comunicación limitada y revocable, sujetas a aprobación independiente.
