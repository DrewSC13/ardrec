# ARDREC R164-F5 — Frontera de identidad y evidencia

## Objetivo

Comprobar la compatibilidad entre el motor ejecutable offline
R104–R109 y el expediente experimental R148/R149.

No se autoriza emparejar ambas poblaciones por tener 54 elementos.

## Poblaciones

- Modelo: 16 SSH, 20 FTP y 18 SMB, exclusivamente sintéticos.
- Experimento: 18 SSH, 18 FTP y 18 SMB, inicialmente sin asignar.
- Catálogo común: 25 familias; compartir catálogo no demuestra
  identidad de servicio, escenario, intento o resultado.

## Funcionamiento

El adaptador reconstruye las fuentes R104, R106, R107, R108 y R109.
Revalida matemáticamente la salida R109.

Después abre el expediente privado R164-F3, verifica R148/R149,
reconcilia las 54 posiciones y clasifica cada selección como:

- UNASSIGNED
- PARTIAL_UNVERIFIED
- CANDIDATE_ONLY_UNVERIFIED

No construye correspondencias automáticas entre identidades del modelo
y casos experimentales. No admite evidencias físicas ni resultados A6.
No calcula un Rf confirmado ni publica generaciones A9.

El documento resultante se comprueba por reconstrucción determinista.

## Persistencia

El modo `--audit` no crea expedientes.
El modo `--save` crea un nuevo recibo privado fuera del repositorio,
con relectura del reporte y su manifiesto. No sobrescribe recibos.

Los hashes son controles de integridad; no firmas de autoridad externa.

## Condiciones futuras para emparejar casos

Exigir identidad verificable de servicio y escenario, alcance,
autorización P8 independiente, estado físico atestiguado,
referencia del intento, A5 con procedencia comprobada, admisión A6,
congelamiento P7 y de la estimación estática, y recibo A9 admisible.

Hasta entonces:

P7=DRAFT_NOT_FROZEN, P8=NO-GO, A6=ND,
A9=NOT_PUBLISHED, observaciones físicas=0.

## Alcance de seguridad

No inicia VM, no instala root, no cambia nftables ni envía tráfico
SSH/FTP/SMB. No convierte datos de fixtures en resultados de tesis.
