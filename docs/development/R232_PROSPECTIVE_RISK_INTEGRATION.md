# R232 - Integracion prospectiva del riesgo

## Alcance

Integra R228 con R58-D, R58-E y A8.
No reproduce una segunda implementacion matematica.

Uso:

python -m ardrec estudio --registro REGISTRO \
    --seleccion SELECCION --preparar-i2 \
    --revisar-riesgo --texto

Para calcular un candidato documental se agregan:

--entrada-i2 ENTRADA --soportes-i2 DIRECTORIO

Sin linea de base candidata no se genera un intervalo.

Con una linea de base candidata se conserva evidencia
no determinada en [0,1]. Se reutilizan los pesos de
desarrollo 1/3,1/3,1/3; no se declaran congelados.

La identidad del slot se utiliza exclusivamente como
identificador matematico DEV en el dominio nativo R58-E.
La identidad experimental original se conserva por separado.

No se declara Rf confirmado, seleccion operacional A4,
ejecucion A5, acreditacion A6 ni publicacion A9.

## Infraestructura

R231 observa una diferencia de almacenamiento del runner
respecto a R33. La ruta observada coincide con el overlay
previsto en la documentacion R48.

La coincidencia documental no acredita la integridad
actual de las imagenes ni sus cadenas de respaldo.

ROOT_READ_FAILED no equivale a contencion DENY verificada.
No se amplian permisos ni se ejecutan reparaciones.

## English summary

Reuse the prospective initial assessment and native exact
risk interval and stopping engines without changing
mathematical semantics or operational authority.

The existing runner overlay has historical documentary
provenance. Its current integrity remains unverified.

P7=DRAFT_NOT_FROZEN.
P8=NO-GO.
