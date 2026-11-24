# R206 - Despacho local prospectivo integrado

Integra R205 con el fixture FTP acotado R202.

El despacho requiere un plan nuevo, identidad de codigo,
consentimiento explicito y reserva vigente. Se registra
DISPATCH_CLAIMED una sola vez por intento, bajo una
transaccion SQLite inmediata.

La reserva permanece consumida ante un resultado incierto.
No existe reintento automatico.

Se comprueba el recibo funcional y se conserva un vinculo
entre plan, intento, recibo y registro transaccional.

El controlador opera bajo un UID cooperativo. No es un
mecanismo de seguridad frente a un operador malicioso del
mismo UID. Una revocacion posterior al inicio no garantiza
la interrupcion de un proceso ya iniciado.

Las valoraciones R200 corresponden a otro perfil.
El calculo A7 con sus magnitudes es contrafactual,
no una estimacion confirmada del fixture funcional.

A6 permanece ND. A8 emite una recomendacion conservadora.
A9 operacional no se publica. Se genera un reporte local
sin admitir observaciones experimentales.

No se modifican B4/B9 ni los contratos historicos.
