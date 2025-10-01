# Fornicaras
平平无奇的远程shellcode加载器



## 简介

项目名字 [Fornicarás] 取自动漫 [BLEACH] 中的第八十刃萨尔阿波罗的斩魄刀。

基于libcurl库和原生WinAPI两种方式远程加载shellcode的加载器/注入器模板，shellcode本体和远程加载地址采用自定义RC4+BASE64加密。



## 结构

--Loader

​	--CreateThreadPoolWait.Load：利用线程池加载

​	--DechainViaHotKey.Load：热键断链加载

​	--Direct.Load：直接加载

​	--Dynamic.Load：动态获取API加载，懒得写了

​	--EarlyBirdAPC.Load：一种APC注入

​	--Fiber.Load：纤程加载

​	--Fornicaras.TEST：测试单元

​	--GhostFart.Load：间接系统调用Unhook后加载

​	--HWSyscalls.Load：硬件断点系统调用加载

​	--ModuleStomping.Inject：经典技术，模块踩踏，懒得写了

​	--NtCreateSection.Inject：不创建远程线程注入

​	--NtTestAlert.Load：一种APC注入

​	--ProcessHollowing.Inject：经典技术，进程镂空，懒得写了

​	--QueueUserAPC.Inject：一种APC注入

​	--SEHException.Load：异常加载

​	--SysWhispers.Load：经典系统调用

​	--ThreadHijack.Inject：线程劫持，懒得写了

​	--VEHSleepMask.Load：一个有趣的睡眠技术（适用部分环境，看代码，懂得都懂）

​	--Public.hpp：加载器通用功能（远程HTTP请求、反沙箱、shellcode解密）

--Tools

​	--encryptFile：加密shellcode文件

​	--encryptString： 加密远程URL路径



## 特点

平平无奇，没什么特点，大部分加载/注入技术都是开源项目。

1. 自定义RC4+HEX+BASE64加密
2. 利用某些环境无法访问Google的特性实现睡眠延时



## 声明

该工具仅用于网络安全学习。

由于传播、利用此工具所提供的信息而造成的后果损失，均由使用者负责，作者不为此承担任何责任。

未经网络安全部门及相关部门允许，不得善自使用本工具进行任何攻击活动。

该工具只用于个人学习，请勿用于非法用途，请遵守网络安全法，否则后果作者概不负责。
