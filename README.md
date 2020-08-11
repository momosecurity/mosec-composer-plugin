# MOSEC-COMPOSER-PLUGIN

用于检测composer项目的第三方依赖组件是否存在安全漏洞。



## 关于我们

Website：https://security.immomo.com

WeChat:

<img src="https://momo-mmsrc.oss-cn-hangzhou.aliyuncs.com/img-1c96a083-7392-3b72-8aec-bad201a6abab.jpeg" width="200" hegiht="200" align="center" /><br>



## 版本要求

Composer >= 1.7.0



## 安装

#### 全局安装

```shell script
> composer config -g repo.gh-momo-plugin git https://github.com/momosecurity/mosec-composer-plugin.git
> composer global require --dev momo/mosec-composer-plugin
```



## 使用

首先运行 [MOSEC-X-PLUGIN Backend](https://github.com/momosecurity/mosec-x-plugin-backend.git)

```shell script
> cd your_php_project_dir/
> composer mosec:test \
  --endpoint=http://127.0.0.1:9000/api/plugin \
  --onlyProvenance
```



## 卸载

#### 全局卸载

```shell script
> composer global remove momo/mosec-composer-plugin
> composer config -g --unset repo.gh-momo-plugin
```



## 帮助

```shell script
> composer mosec:test --help

Usage:
  mosec:test [options]

Options:
      --endpoint=ENDPOINT              上报API [default: ""]
      --severityLevel[=SEVERITYLEVEL]  设置威胁等级 [High|Medium|Low] [default: "High"]
      --onlyProvenance                 仅检查直接依赖
      --noExcept                       发现漏洞不抛出异常
  -h, --help                           Display this help message

Help:
  shell> composer mosec:test --onlyProvenance --endpoint=http://your/api
```



## 使用效果

以 test/vuln-project 项目为例。

红色部分给出漏洞警告，From: 为漏洞依赖链，Fix version 为组件安全版本。

程序返回值为1，表示发现漏洞。返回值为0，即为未发现问题。

![usage](https://github.com/momosecurity/mosec-composer-plugin/blob/master/static/usage.jpg)



## 检测原理

MOSEC-COMPOSER-PLUGIN 内部是对 composer show 命令程序的扩展，利用其返回当前项目所安装的依赖构建依赖树。

因此需要项目先`compoesr install`后才可进行检测。否则抛出`No dependencies installed. Try running composer install or update.`异常。

最终依赖树会交由 [MOSEC-X-PLUGIN-BACKEND](https://github.com/momosecurity/mosec-x-plugin-backend.git) 检测服务进行检测，并返回结果。

相关数据结构请参考 MOSEC-X-PLUGIN-BACKEND [README.md](https://github.com/momosecurity/mosec-x-plugin-backend/blob/master/README.md).



## 开发

#### PHPStorm 调试 Composer 插件

1.git clone mosec-composer-plugin

2.composer install 安装项目依赖

3.PHPStorm 中新建 PHP Sript Configuration 并填入如下信息

注意File选择项目vendor目录下的composer

注意环境变量填写`COMPOSER_ALLOW_XDEBUG=1`

![debug-configuration](https://github.com/momosecurity/mosec-composer-plugin/blob/master/static/debug-configuration.jpg)

4.下断点，开始Debug
