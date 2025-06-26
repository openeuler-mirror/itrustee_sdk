# iTrustee SDK

#### 介绍
itrustee sdk是指开发人发人员基于安全OS编译TA时所依赖的接口、函数库等。

#### 操作系统
支持ARM服务器，比如鲲鹏920。

#### 编译教程

1）下载libboundscheck库，下载地址：<https://gitee.com/openeuler/libboundscheck> 。

2）将libboundscheck解压到**thirdparty/open_source**目录。

3）通过以下命令可编译demo TA：

```
cd test/CA/helloworld
make
cd test/TA/helloworld
make
```

4)也可通过cmake的方式编译TA:

```
cd test/TA/helloworld
bash config.sh
```

5）将编译出来的TA二进制文件(xxx.sec)拷贝到服务器的/var/itrustee/ta目录下。

6）将编译出来的CA拷贝到服务器的/vendor/bin目录下。（ca的执行路径可能会随着用户配置发生变化，请确保CA的执行路径与TA中配置的路径一致）

7）执行demo CA：

```
/vendor/bin/demo_hello
```

#### 使用说明
更多细节请参考"iTrustee SDKֲ.chm"。

#### 参与贡献
    如果您想为本仓库贡献代码，请向本仓库任意maintainer发送邮件
    如果您找到产品中的任何Bug，欢迎您提出ISSUE
