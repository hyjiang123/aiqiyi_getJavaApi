# **Java API获取**

任务描述：

- 输入： 给定一个 Java 服务，项目地址为 https://github.com/javaweb-rasp/javaweb-vuln
- 输出： 通过 JavaAgent 技术实现对该服务中 Java API 的获取（需要能获取GET和POST请求参数），并将所获取的 API 信息以 JSON 格式写入本地文件。你可以参考开源项目 https://github.com/HXSecurity/DongTai-agent-java （注意：要能支持两种方式获取API，启动时获取和启动后获取API）
  输出示例
      /CMD/cookie/cmd.do post [{"in":"Cookie","name":"cmd","required":true,"schema":{"type":"string"}}] org.javaweb.vuln.controller.CMDController {"200":{"content":{"*/*":{"schema":{"type":"","$ref":"#/components/schemas/Map"}}},"description":"ok"}} 



## 1.实现过程

为了实现可以在启动和运行获取API，新建了一个 vuln-agent 模块；

首先介绍该模块各个文件的作用：

### 1.VulnAgent.java

这是 Java Agent 的入口类，主要功能包括：

- 提供 premain 方法：在 JVM 启动时加载 agent

- 提供 agentmain 方法：支持动态附加 agent 到运行中的 JVM

- initializeAgent 方法负责：

- 解析命令行参数（outputPath, autoSave）

- 配置 API 信息输出路径

- 配置自动保存间隔

- 注册字节码转换器

- 调用 API 扫描

- 重新转换已加载的类

### 2.APITransformer.java

字节码转换器类，负责拦截和修改类加载过程：

- 实现 ClassFileTransformer 接口

- 使用 ASM 库进行字节码增强

- 包含内部类：

- APIClassVisitor：访问类文件

- APIMethodVisitor：访问方法，在方法入口处注入收集 API 信息的代码

- 主要功能：

- 过滤目标类（controller 包下的类）

- 在方法执行时收集 API 信息

### 3.APICollector.java

核心功能类，负责收集和管理 API 信息;

- 功能特性：

- 支持启动时扫描和运行时收集

- 支持自动保存和手动保存

- 支持自定义输出路径

- 支持多种参数来源（Cookie, Header, Path）

- 线程安全的实现

- 优雅的程序退出处理

### 4.APICollectorFilter.java

Servlet 过滤器，用于拦截 HTTP 请求：

- 实现 Filter 接口

- 在请求处理时收集运行时的 API 信息

- 主要用于补充动态生成的 API 信息

### 5.AttachTool.java

动态附加工具类：

- 提供命令行接口

- 支持列出可用的 Java 进程

- 支持动态附加 agent 到运行中的进程

- 处理 tools.jar 依赖



## 2.启动方法

启动时加载： 

java -javaagent:vuln-agent-3.0.3.jar -jar vuln-springboot2-3.0.3.jar

或者在idea编译器中增加参数：

![image-20250310200555834](C:\Users\Hgj\AppData\Roaming\Typora\typora-user-images\image-20250310200555834.png)



运行时加载：

java -jar attach-tool.jar <pid> vuln-agent.jar

pid 为需要获取API服务运行的pid，可以通过 jps 获取



## 3.自测

根据上述两种方式可以获取 vuln-springboot2 服务的API，并且存储在 api_info.json 文件

下列为自测结果展示：

```
[ {
  "uri" : "/Expression/POST",
  "method" : "post",
  "parameters" : [ {
    "name" : "arg0",
    "in" : "parameter",
    "required" : true,
    "schema" : {
      "type" : "Map"
    }
  } ],
  "responses" : {
    "200" : {
      "description" : "ok"
    }
  }
}, {
  "uri" : "/Patch//readFileTest.do",
  "method" : "get",
  "parameters" : [ {
    "name" : "arg0",
    "in" : "parameter",
    "required" : true,
    "schema" : {
      "type" : "Map"
    }
  } ],
  "responses" : {
    "200" : {
      "description" : "ok"
    }
  }
}, {
  "uri" : "/DisableMethod//log4j.do",
  "method" : "get",
  "parameters" : [ {
    "name" : "arg0",
    "in" : "parameter",
    "required" : true,
    "schema" : {
      "type" : "Map"
    }
  } ],
  "responses" : {
    "200" : {
      "description" : "ok"
    }
  }
}, {
  "uri" : "/CMD/POST",
  "method" : "post",
  "parameters" : [ {
    "name" : "arg0",
    "in" : "parameter",
    "required" : true,
    "schema" : {
      "type" : "MultipartFile"
    }
  } ],
  "responses" : {
    "200" : {
      "description" : "ok"
    }
  }
}, {
  "uri" : "/SQL/POST",
  "method" : "post",
  "parameters" : [ {
    "name" : "arg0",
    "in" : "parameter",
    "required" : true,
    "schema" : {
      "type" : "MultipartFile"
    }
  } ],
  "responses" : {
    "200" : {
      "description" : "ok"
    }
  }
}, {
  "uri" : "/FileSystem/POST",
  "method" : "post",
  "parameters" : [ {
    "name" : "arg0",
    "in" : "parameter",
    "required" : true,
    "schema" : {
      "type" : "MultipartFile"
    }
  } ],
  "responses" : {
    "200" : {
      "description" : "ok"
    }
  }
}, {
  "uri" : "/Test/GET",
  "method" : "get",
  "parameters" : [ {
    "name" : "arg0",
    "in" : "parameter",
    "required" : true,
    "schema" : {
      "type" : "String"
    }
  } ],
  "responses" : {
    "200" : {
      "description" : "ok"
    }
  }
}, {
  "uri" : "/Request/POST",
  "method" : "post",
  "parameters" : [ {
    "name" : "arg0",
    "in" : "parameter",
    "required" : true,
    "schema" : {
      "type" : "Map"
    }
  } ],
  "responses" : {
    "200" : {
      "description" : "ok"
    }
  }
}, {
  "uri" : "/XStream/POST",
  "method" : "post",
  "parameters" : [ {
    "name" : "arg0",
    "in" : "parameter",
    "required" : true,
    "schema" : {
      "type" : "Map"
    }
  } ],
  "responses" : {
    "200" : {
      "description" : "ok"
    }
  }
}, {
  "uri" : "/SSRF/POST",
  "method" : "post",
  "parameters" : [ {
    "name" : "arg0",
    "in" : "parameter",
    "required" : true,
    "schema" : {
      "type" : "String"
    }
  } ],
  "responses" : {
    "200" : {
      "description" : "ok"
    }
  }
}, {
  "uri" : "/XSS/POST",
  "method" : "post",
  "parameters" : [ {
    "name" : "arg0",
    "in" : "parameter",
    "required" : true,
    "schema" : {
      "type" : "MultipartFile"
    }
  } ],
  "responses" : {
    "200" : {
      "description" : "ok"
    }
  }
}, {
  "uri" : "/Yaml/POST",
  "method" : "post",
  "parameters" : [ {
    "name" : "arg0",
    "in" : "parameter",
    "required" : true,
    "schema" : {
      "type" : "Map"
    }
  } ],
  "responses" : {
    "200" : {
      "description" : "ok"
    }
  }
}, {
  "uri" : "/Deserialization/GET",
  "method" : "get",
  "parameters" : [ ],
  "responses" : {
    "200" : {
      "description" : "ok"
    }
  }
}, {
  "uri" : "/FastJson//fastJsonParseObject.do",
  "method" : "get",
  "parameters" : [ {
    "name" : "arg0",
    "in" : "parameter",
    "required" : true,
    "schema" : {
      "type" : "String"
    }
  } ],
  "responses" : {
    "200" : {
      "description" : "ok"
    }
  }
}, {
  "uri" : "/Jackson//readValue.do",
  "method" : "get",
  "parameters" : [ {
    "name" : "arg0",
    "in" : "parameter",
    "required" : true,
    "schema" : {
      "type" : "String"
    }
  } ],
  "responses" : {
    "200" : {
      "description" : "ok"
    }
  }
}, {
  "uri" : "/XXE/POST",
  "method" : "post",
  "parameters" : [ {
    "name" : "arg0",
    "in" : "parameter",
    "required" : true,
    "schema" : {
      "type" : "MultipartFile"
    }
  } ],
  "responses" : {
    "200" : {
      "description" : "ok"
    }
  }
}, {
  "uri" : "/Test/POST",
  "method" : "post",
  "parameters" : [ {
    "name" : "arg0",
    "in" : "parameter",
    "required" : true,
    "schema" : {
      "type" : "Map"
    }
  } ],
  "responses" : {
    "200" : {
      "description" : "ok"
    }
  }
}, {
  "uri" : "/JNDI/POST",
  "method" : "post",
  "parameters" : [ {
    "name" : "arg0",
    "in" : "parameter",
    "required" : true,
    "schema" : {
      "type" : "String"
    }
  } ],
  "responses" : {
    "200" : {
      "description" : "ok"
    }
  }
}, {
  "uri" : "/Blacklist//blacklist.do",
  "method" : "get",
  "parameters" : [ ],
  "responses" : {
    "200" : {
      "description" : "ok"
    }
  }
}, {
  "uri" : "/Whitelist//url.do",
  "method" : "get",
  "parameters" : [ {
    "name" : "arg0",
    "in" : "parameter",
    "required" : true,
    "schema" : {
      "type" : "String"
    }
  } ],
  "responses" : {
    "200" : {
      "description" : "ok"
    }
  }
}, {
  "uri" : "/ScriptEngine//scriptEngineEval.do",
  "method" : "get",
  "parameters" : [ {
    "name" : "arg0",
    "in" : "parameter",
    "required" : true,
    "schema" : {
      "type" : "String"
    }
  } ],
  "responses" : {
    "200" : {
      "description" : "ok"
    }
  }
}, {
  "uri" : "/Blacklist//url.do",
  "method" : "get",
  "parameters" : [ ],
  "responses" : {
    "200" : {
      "description" : "ok"
    }
  }
}, {
  "uri" : "/Velocity//template.do",
  "method" : "get",
  "parameters" : [ {
    "name" : "arg0",
    "in" : "parameter",
    "required" : true,
    "schema" : {
      "type" : "String"
    }
  } ],
  "responses" : {
    "200" : {
      "description" : "ok"
    }
  }
}, {
  "uri" : "/Deserialization/POST",
  "method" : "post",
  "parameters" : [ {
    "name" : "arg0",
    "in" : "parameter",
    "required" : true,
    "schema" : {
      "type" : "Map"
    }
  } ],
  "responses" : {
    "200" : {
      "description" : "ok"
    }
  }
}, {
  "uri" : "/FileUpload//upload.do",
  "method" : "get",
  "parameters" : [ {
    "name" : "arg0",
    "in" : "parameter",
    "required" : true,
    "schema" : {
      "type" : "MultipartFile"
    }
  }, {
    "name" : "arg1",
    "in" : "parameter",
    "required" : true,
    "schema" : {
      "type" : "String"
    }
  } ],
  "responses" : {
    "200" : {
      "description" : "ok"
    }
  }
} ]
```

