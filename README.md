# RootMe — TryHackMe Writeup

## Objetivo

Documentar las vulnerabilidades identificadas en el laboratorio RootMe, la cadena que permitió obtener acceso privilegiado y las medidas recomendadas para reducir el riesgo en un entorno real. Los valores de las flags y la IP de la máquina no se incluyen.

## Herramientas utilizadas

- `curl` para realizar solicitudes HTTP durante la validación.
- Python 2.7, identificado como intérprete con el bit SUID activo.

## Metodología

### Reconocimiento

La revisión identificó el listado de directorios habilitado en `/uploads/`, una validación insuficiente en la subida de archivos y un intérprete Python 2.7 con permisos SUID.

### Explotación

La blacklist incompleta de extensiones permitió que un archivo subido se interpretara como código ejecutable por el servidor web. La ejecución se validó en el contexto del proceso web.

### Escalada de privilegios

Un intérprete Python con el bit SUID activo y propiedad de `root` puede permitir la ejecución de código con privilegios elevados si el proceso conserva o recupera esos privilegios. En el laboratorio, se comprobó la escalada desde el contexto de `www-data`.

**Evidencia:** `evidencias/privesc/01-suid-enumeration.png`

#### Validación de la escalada

```bash
curl -s "http://<IP>/uploads/cmd.phtml?cmd=python2.7+-c+%22import+os%3Bos.setuid(0)%3Bos.system('id')%22"
# → uid=0(root) gid=33(www-data) groups=33(www-data)
```

La salida confirmó la ejecución del proceso con UID efectivo de `root`.

**Evidencia:** `evidencias/privesc/02-privesc-root-confirmado.png`

#### Obtención de flags

Las flags de usuario y de `root` se obtuvieron y validaron en la plataforma. Sus valores se omiten de este write-up.

```bash
# user.txt
curl -s "http://<IP>/uploads/cmd.phtml?cmd=cat+/var/www/user.txt"

# root.txt
curl -s "http://<IP>/uploads/cmd.phtml?cmd=python2.7+-c+%22import+os%3Bos.setuid(0)%3Bos.system('cat+/root/root.txt')%22"
```

**Evidencia:** `evidencias/99-room-completed-100.png`

## Vulnerabilidades y su impacto

| # | Vulnerabilidad | CWE | Impacto potencial |
|---|---|---|---|
| 1 | Subida de archivos protegida por una blacklist incompleta | CWE-434 | Puede permitir la ejecución remota de código y comprometer el servicio web. |
| 2 | Listado de directorios habilitado en `/uploads/` | CWE-548 | Expone nombres y contenido de archivos, lo que facilita el reconocimiento y la localización de información sensible. |
| 3 | Intérprete `python2.7` con SUID innecesario | CWE-250 / CWE-269 | Un usuario local o un proceso comprometido podría usar el intérprete para elevar privilegios. |

En conjunto, la subida ejecutable y el binario SUID permitieron pasar del acceso al servicio web al control de `root` en el laboratorio.

## Remediaciones recomendadas

| Vulnerabilidad | Remediación recomendada |
|---|---|
| Subida de archivos sin validación robusta | Validar el contenido real además de la extensión, aplicar una allowlist estricta y almacenar las subidas fuera del webroot o en un directorio donde no se ejecuten scripts. |
| Extensiones alternativas interpretadas por Apache | Revisar las asociaciones de `mod_mime` y `mod_php`; habilitar solo los manejadores necesarios y evitar que extensiones de subida se interpreten como código. |
| Listado de directorios habilitado | Deshabilitar el listado de directorios en `/uploads/` (por ejemplo, retirando `Indexes` de la configuración de Apache). |
| Binario SUID innecesario | Retirar el bit SUID de `/usr/bin/python2.7` si no existe una necesidad documentada. Para elevaciones puntuales, usar reglas `sudo` específicas y de mínimo privilegio. |
| Servicio web sin aislamiento suficiente | Ejecutar Apache/PHP con privilegios mínimos y, cuando sea viable, aislar el servicio para limitar el impacto de una vulnerabilidad de ejecución de código. |

## Conclusiones y aprendizajes

- La validación basada solo en la extensión declarada no es suficiente; una blacklist incompleta puede dejar pasar extensiones que el servidor interpreta como código.
- Un fallo de ejecución remota en un proceso de bajo privilegio (`www-data`) puede escalar a compromiso del sistema si hay binarios SUID peligrosos.
- Verificar la ejecución efectiva del archivo subido permitió confirmar el impacto sin depender de una conexión saliente.
- Las evidencias y la descripción clara del impacto ayudan a reproducir y corregir los hallazgos; las flags y la IP se mantienen fuera del informe.

---

*Informe elaborado como actividad académica. Los valores de las flags y la IP de la máquina se omiten; la finalización del laboratorio queda acreditada mediante las evidencias incluidas.*
