# MOSEC-COMPOSER-PLUGIN

用于检测composer项目的第三方依赖组件是否存在安全漏洞。


## 关于我们

Website：https://security.immomo.com

WeChat:

<img src="https://momo-mmsrc.oss-cn-hangzhou.aliyuncs.com/img-1c96a083-7392-3b72-8aec-bad201a6abab.jpeg" width="200" hegiht="200" align="center" /><br>


## 版本支持

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

## 开发

#### PHPStorm 调试 Composer 插件

1.git clone mosec-composer-plugin

2.composer install 安装项目依赖

3.PHPStorm 中新建 PHP Sript Configuration 并填入如下信息

注意File选择项目vendor目录下的composer

注意环境变量填写`COMPOSER_ALLOW_XDEBUG=1`

![debug-configuration](https://github.com/momosecurity/mosec-composer-plugin/blob/master/static/debug-configuration.jpg)

4.下断点，开始Debug
