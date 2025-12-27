# Tee-env Pre-Service RPM

## 简介

Tee-env Pre-Service是一个systemd服务，用于自动加载TEE（可信执行环境）内核模块并启动teecd守护进程。服务会监控这些组件，并在异常时自动恢复。

主要功能

• 自动加载TEE内核模块（tzdriver.ko, tee_upgrade.ko）

• 自动启动teecd守护进程

• 监控进程状态，异常时自动恢复

• 完整的日志记录

## 前置要求

• 需要文件：tzdriver.ko, tee_upgrade.ko, teecd

• 文件放置目录：/lib/modules/$(uname -r)/kernel/drivers/trustzone/

## 构建RPM
```shell
sudo yum install -y rpm-build rpmdevtools
rpmdev-setuptree
chmod +x build-rpm.sh
./build-rpm.sh
```
构建出来的rpm包位置：/root/rpmbuild/RPMS/aarch64/

## 安装RPM
```shell
sudo rpm -ivh tee-env-pre-1.0.0-1.aarch64.rpm
```
## 启动tee-env-pre服务
```shell
sudo systemctl start tee-env-pre.service
```
## 日志
• 位置：/var/log/tee-env-pre.log
