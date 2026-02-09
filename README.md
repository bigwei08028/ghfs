# GHFS
A lightweight, high-performance web file server, expert in intranet file sharing.

GoHttpFileServer /GHFS — 项目说明
==============================

简介
----
一个用 Go 实现的轻量文件服务器，兼容 ghfs 习惯，内置前端页面（React + 本地静态资源），支持多用户、目录权限、只读控制、断点续传式大文件上传、整目录压缩下载与在线解压上传。单文件 exe 即可跨平台运行（Windows/macOS/Linux，需目标机器有 Go 构建产物即可）。

核心特性
--------
- 内置前端：React 单页，暗/亮主题切换，本地 libs 优先（无外网也可用）。
- 用户/权限：管理员可新增/编辑/删除用户；支持只读、读写删；可限制用户根目录（home）。
- 认证：HTTP Basic Auth，默认 admin/admin（首次运行会生成 config.json）。
- 上传：
  - 多文件与整目录上传，保持原有层级。
  - ZIP 上传后端自动解压保持结构。
  - 大文件分片上传与合并。
  - 拖拽/按钮选择，实时 toast 提示。
- 下载：单文件直下；目录可打包 ZIP 下载；只读用户仅可下载。
- 文件操作：新建文件夹、重命名、删除（依据权限隐藏前端按钮并后端阻止）。
- 路径导航：面包屑逐级返回，显示当前路径，支持只读标记。
- 日志：所有关键操作写入 temp/access.log，包括登录失败/成功、列表、上传、下载、删除、重命名、建目录等。
- 嵌入静态资源：使用 go:embed 打包 web/，部署时无需额外文件。

目录结构（关键部分）
------------------
- main.go          后端入口，API 与静态文件服务
- web/             前端静态资源（已嵌入）
- config.json      运行配置（首次启动自动生成）
- data/            默认存储根目录
- tmp/ 或 .tmp     临时目录，存放分片、日志、临时 ZIP

运行与配置
----------
1. 直接运行（已内置静态资源）：
   `
   ghfs.exe
   `
   首次启动会生成 config.json 与数据目录。

2. 访问：
   - 默认监听：http://127.0.0.1:8901
   - 默认账户：admin/admin

3. 配置 config.json（示例）：
   `json
   {
     "listen": ":8901",
     "root": "./data",
     "tempDir": "./tmp",
     "enableAuth": true,
     "maxUploadMB": 512,
     "corsOrigins": ["*"],
     "users": [
       {"username": "admin", "password": "admin", "home": "", "isAdmin": true, "readOnly": false}
     ]
   }
   `
   - password 支持明文，程序启动时会转为 MD5 存储。
   - home 留空表示根目录；设置子目录则用户只能看到该子树。
   - readOnly=true 时仅可下载。

4. 构建（可选，若需在其它平台重编）：
   `
   go build -trimpath -ldflags "-s -w" -o ghfs.exe
   `

操作说明
--------
- 登录：首次打开即登录页，输入用户名/密码进入文件管理界面；右上角头像处显示用户名并可退出。
- 切换主题：右上角“太阳/月亮”图标。
- 路径导航：面包屑点击逐级返回；目录名后若显示“(只读)”则当前目录为只读。
- 上传：
  - “上传文件” 选多文件。
  - “上传文件夹” 选目录，保留层级。
  - 拖拽到工具栏右侧的拖拽区域亦可上传。
- 下载：行操作列点击“下载”；目录点击“下载 ZIP”。
- 新建文件夹：点击“新建文件夹”，输入名称。
- 重命名/删除：仅非只读用户可见按钮；后端同样校验权限。
- 用户管理（仅管理员可见右上角“用户管理”图标）：
  - 新建/编辑用户：设置密码（MD5 自动生成）、home 目录、是否只读、是否管理员。
  - 删除用户：列表操作列。

日志与排查
-----------
- 路径：	empDir/access.log（默认 ./tmp/access.log）。
- 示例：
  - AUTH_FAIL user=- ip=127.0.0.1:52111 path=/api/me
  - LIST user=admin path=/docs count=5
  - UPLOAD_FILE user=admin path=imgs/a.png bytes=20480
  - DOWNLOAD user=guest path=report.pdf bytes=102400
  - RENAME user=admin from=old.txt to=new.txt
- 如无法访问：检查端口占用、防火墙或 config.json。

权限与只读策略
---------------
- readOnly 用户：隐藏上传/新建/删除/重命名按钮；后端拒绝写操作；仅能下载。
- home 目录：用户仅能看到其 home 及子目录；越界访问后端会拒绝。

常见问题
--------
- 双击 exe 后闪退：请在命令行运行以查看错误（端口占用/权限不足）。
- 外网不可访问：检查防火墙或修改 listen 为 0.0.0.0:端口。
- 中文文件名下载乱码：已设置 UTF-8 Content-Disposition；若仍异常，检查浏览器版本或代理。

版权与许可证
------------
本项目为示例/内部使用代码，可按需修改和分发；如需开源许可证请自行补充。
