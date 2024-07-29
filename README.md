# Certificateless-Authorization-System

CAS应用了基于身份基的无证书身份认证算法，同时为其引入了为多层级应用节点的分布式认证功能。区别于传统基于CA证书的身份认证，CAS原型系统无需依赖第三方机构来颁发证书。多层级分布式认证框架所进行的私钥生成，可有效避免应用用户规模扩大所带来的系统阻塞。同时，系统也具备了注册、登录、审核和撤销的基础管理功能。

The distributed certificateless identity authentication prototype system is designed with multi-level distributed architecture, and the encryption algorithm is designed based on identity-based signature. It can be run in Ubuntu16.

## 使用说明

### 1、 系统数据库部署

在sql中运行以下代码部署KGCM的节点KGC数据库：

```
create table KGC_table
(KGCid varchar(10)  not null primary key,
K_pw varchar(20),
Ti char(70) not null,
Idi char(10) not null,
Ri char(70) not null);
```

部署对接节点KGC的用户数据库：

```
create table User_table
(ac_number varchar(10)  not null primary key,
U_pw varchar(20),
KGCid char(10),
Ti char(70) not null,
Idi char(10) not null,
```

`Ri char(70) not null)``；```

### 2、 网络地址配置

（1）   更改KGCMserver.py中的ADDRESS为KGCM所在地址并运行；

（2）   更改KGC_client.py中的ADDRESS为KGCM所在地址，address_self为该节点KGC所在地址，target_addresslist中地址为同级KGC节点所在地址；

（3）   更改user_client.py中ADDRESS为上级节点KGC所在地址，address_self为该用户所在地址，target_addresslist中地址为其他用户节点所在地址；

### 3、 注册操作

首先在菜单中选择“1”并输入用户名，在上级节点操作同意后，可输入密码完成注册，获取部分私钥，生成节点的公私钥。

### 4、 登录操作

在菜单中选择“2”，输入用户名与密码以验证登录。

### 5、 身份认证

登录后选择对应的用户节点编号进行认证。

### 6、 审核

在收到注册请求时进行审核，输入“y”或“Y”通过审核，不同意节点接入则输入“n”或“N”。

### 7、 节点撤销

上级节点在选择撤销后，输入对应下属节点的编号，以进行撤销。

## 系统接口及字段说明

### 密钥生成中心接口

| 函数                      | 功能介绍                                   |
| ------------------------- | ------------------------------------------ |
| partialKeyExtract()       | 生成二级节点的部分私钥。                   |
| Register_handle  ()       | 接收注册请求并判断是否同意。               |
| KGCpara_handle()          | 处理二级节点的注册参数并为其生成部分私钥。 |
| PkeyVerify_handle()       | 处理部分私钥验证结果。                     |
| Login_handle()            | 处理登录请求。                             |
| delete_kgc()              | 将二级节点撤销。                           |
| Authenticate_req_handle() | 处理二级节点的认证请求。                   |

### 次级密钥生成中心接口

| 函数                      | 功能介绍                                   |
| ------------------------- | ------------------------------------------ |
| partialKeyExtract()       | 生成用户节点的部分私钥。                   |
| Register_handle  ()       | 接收注册请求并判断是否同意。               |
| USERpara_handle()         | 处理用户节点的注册参数并为其生成部分私钥。 |
| PkeyVerify_handle()       | 处理部分私钥验证结果。                     |
| Login_handle()            | 处理登录请求。                             |
| delete_user()             | 将用户撤销                                 |
| Authenticate_req_handle() | 处理用户节点的认证请求。                   |
| Authenticate_to_KGC()     | 对同级节点发起身份认证请求。               |
| Authenticate_in_KGC()     | 处理同级节点的身份认证请求。               |
| setSecretValue()          | 设置自己的秘密值。                         |
| setPrivateKey()           | 生成私钥。                                 |
| gen_CT()                  | 获取认证验证值及加密验证值。               |
| rekeygen()                | 生成特定对象的解密密钥。                   |
| decryption2 ()            | 解密加密验证值。                           |
| Register()                | 注册。                                     |
| Login()                   | 登录。                                     |

### 用户节点接口

| 函数                   | 功能介绍                     |
| ---------------------- | ---------------------------- |
| setSecretValue()       | 设置自己的秘密值。           |
| setPrivateKey()        | 生成私钥。                   |
| gen_CT()               | 获取认证验证值及加密验证值。 |
| rekeygen()             | 生成特定对象的解密密钥。     |
| decryption2 ()         | 解密加密验证值。             |
| Register()             | 注册。                       |
| Login()                | 登录。                       |
| Authenticate_to_User() | 对同级用户发起身份认证请求。 |
| Authenticate_in_User() | 处理同级用户的身份认证请求。 |

### 系统通信字段

| 请求字段 | 说明                           |
| -------- | ------------------------------ |
| R_0      | 登录请求。                     |
| R_1      | 注册请求。                     |
| R_2      | 发送自己的参数给上一级节点。   |
| R_3      | 告知上级节点部分私钥验证结果。 |
| R_4      | 发送请求认证的字段给上级节点。 |
| R_A      | 请求认证字段，同级节点间发送。 |

## 原型系统视图

次级节点公私钥生成

![](image\7.png)

User 公私钥生成

![](image\8.png)

User 间身份认证过程

![](image\9.png)

![](image\10.png)
## 身份认证算法设计

初始设置阶段

![](image\1.png)

节点KGC密钥生成

![](image\3.png)

用户密钥生成

![](image\2.png)

加密验证值生成

![](image\4.png)

解密密钥生成

![](image\5.png)

验证值解密

![](image\6.png)
