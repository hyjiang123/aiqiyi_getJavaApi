package org.javaweb.vuln.agent;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.jetbrains.annotations.Nullable;

import javax.servlet.http.HttpServletRequest;
import java.io.File;
import java.io.IOException;
import java.lang.annotation.Annotation;
import java.lang.reflect.Method;
import java.lang.reflect.Parameter;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

public class APICollector {
    private static final Map<String, APIInfo> apiInfoMap = new ConcurrentHashMap<>();
    private static final ObjectMapper objectMapper = new ObjectMapper();
    private static String outputPath;
    private static final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor();
    private static volatile boolean autoSaveEnabled = false;
    private static final Set<String> scannedPackages = new HashSet<>(Arrays.asList(
        "org.javaweb.vuln.controller"
    ));

    static {
        String userDir = System.getProperty("user.dir");
        outputPath = new File(userDir, "api_info.json").getAbsolutePath();
        
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            autoSaveEnabled = false;
            saveToFile();
            scheduler.shutdown();
        }));
    }

    public static void scanAllApis() {
        try {
            System.out.println("Starting API scanning...");
            for (String basePackage : scannedPackages) {
                scanPackage(basePackage);
            }
            saveToFile();
            System.out.println("API scanning completed.");
        } catch (Exception e) {
            System.err.println("Error scanning APIs: " + e.getMessage());
        }
    }

    private static void scanPackage(String packageName) {
        try {
            String path = packageName.replace('.', '/');
            ClassLoader classLoader = Thread.currentThread().getContextClassLoader();
            Enumeration<java.net.URL> resources = classLoader.getResources(path);

            while (resources.hasMoreElements()) {
                java.net.URL resource = resources.nextElement();
                File directory = new File(java.net.URLDecoder.decode(resource.getFile(), "UTF-8"));
                scanDirectory(directory, packageName);
            }
        } catch (Exception e) {
            System.err.println("Error scanning package " + packageName + ": " + e.getMessage());
        }
    }

    private static void scanDirectory(File directory, String packageName) {
        if (!directory.exists()) {
            return;
        }

        File[] files = directory.listFiles();
        if (files == null) {
            return;
        }

        for (File file : files) {
            String fileName = file.getName();
            if (file.isDirectory()) {
                scanDirectory(file, packageName + "." + fileName);
            } else if (fileName.endsWith(".class")) {
                String className = packageName + "." + fileName.substring(0, fileName.length() - 6);
                scanClass(className);
            }
        }
    }

    private static void scanClass(String className) {
        try {
            Class<?> clazz = Class.forName(className);
            if (!clazz.isInterface() && hasControllerAnnotation(clazz)) {
                String classMapping = getClassMapping(clazz);
                Method[] methods = clazz.getDeclaredMethods();
                
                for (Method method : methods) {
                    if (shouldSkipMethod(method.getName())) {
                        continue;
                    }

                    String methodMapping = getRequestMapping(method);
                    if (methodMapping == null) {
                        continue;
                    }

                    APIInfo apiInfo = new APIInfo();
                    apiInfo.setClassName(className);
                    apiInfo.setMethodName(method.getName());
                    apiInfo.setUri(classMapping + methodMapping);
                    apiInfo.setMethod(getRequestMethod(method));
                    
                    Parameter[] parameters = method.getParameters();
                    List<ParameterInfo> parameterInfos = new ArrayList<>();
                    
                    for (Parameter parameter : parameters) {
                        ParameterInfo paramInfo = new ParameterInfo();
                        paramInfo.setName(parameter.getName());
                        paramInfo.setType(parameter.getType().getSimpleName());
                        paramInfo.setRequired(!parameter.isAnnotationPresent(Nullable.class));

                        for (Annotation annotation : parameter.getAnnotations()) {
                            String annotationName = annotation.annotationType().getName();
                            if (annotationName.endsWith("CookieValue")) {
                                paramInfo.setIn("Cookie");
                                break;
                            } else if (annotationName.endsWith("RequestHeader")) {
                                paramInfo.setIn("header");
                                break;
                            } else if (annotationName.endsWith("PathVariable")) {
                                paramInfo.setIn("path");
                                break;
                            }
                        }

                        parameterInfos.add(paramInfo);
                    }
                    
                    apiInfo.setParameters(parameterInfos);
                    String key = apiInfo.getUri() + "#" + apiInfo.getMethod();
                    apiInfoMap.put(key, apiInfo);
                }
            }
        } catch (Exception e) {
            System.err.println("Error scanning class " + className + ": " + e.getMessage());
        }
    }

    private static boolean hasControllerAnnotation(Class<?> clazz) {
        for (Annotation annotation : clazz.getAnnotations()) {
            String name = annotation.annotationType().getName();
            if (name.endsWith("Controller") || name.endsWith("RestController")) {
                return true;
            }
        }
        return false;
    }

    private static String getClassMapping(Class<?> clazz) {
        try {
            for (Annotation annotation : clazz.getAnnotations()) {
                if (annotation.annotationType().getName().endsWith("Mapping")) {
                    Method valueMethod = annotation.annotationType().getMethod("value");
                    String[] values = (String[]) valueMethod.invoke(annotation);
                    if (values != null && values.length > 0) {
                        return values[0];
                    }
                }
            }
        } catch (Exception e) {

        }
        return "";
    }

    public static void setOutputPath(String path) {
        outputPath = path;
    }

    public static String getOutputPath() {
        return outputPath;
    }

    public static void enableAutoSave(long intervalSeconds) {
        if (!autoSaveEnabled) {
            autoSaveEnabled = true;
            scheduler.scheduleAtFixedRate(() -> {
                if (autoSaveEnabled) {
                    saveToFile();
                }
            }, intervalSeconds, intervalSeconds, TimeUnit.SECONDS);
        }
    }

    public static void disableAutoSave() {
        autoSaveEnabled = false;
    }

    private static boolean shouldSkipMethod(String methodName) {
        return methodName.contains("init") || 
               methodName.contains("CGLIB") || 
               methodName.equals("<clinit>") || 
               methodName.equals("<init>") ||
               methodName.startsWith("set") ||
               methodName.startsWith("get");
    }

    private static String getRequestMapping(Method method) {
        try {
            for (Annotation annotation : method.getAnnotations()) {
                String annotationName = annotation.annotationType().getName();
                if (annotationName.endsWith("Mapping")) {
                    if (annotationName.contains("GetMapping")) {
                        return "GET";
                    } else if (annotationName.contains("PostMapping")) {
                        return "POST";
                    } else if (annotationName.contains("PutMapping")) {
                        return "PUT";
                    } else if (annotationName.contains("DeleteMapping")) {
                        return "DELETE";
                    } else if (annotationName.contains("PatchMapping")) {
                        return "PATCH";
                    }
                    
                    try {
                        Method valueMethod = annotation.annotationType().getMethod("value");
                        String[] values = (String[]) valueMethod.invoke(annotation);
                        if (values != null && values.length > 0) {
                            return values[0];
                        }
                    } catch (Exception e) {

                    }

                    try {
                        Method pathMethod = annotation.annotationType().getMethod("path");
                        String[] paths = (String[]) pathMethod.invoke(annotation);
                        if (paths != null && paths.length > 0) {
                            return paths[0];
                        }
                    } catch (Exception e) {

                    }
                }
            }
        } catch (Exception e) {
            // �����쳣
        }
        return null;
    }

    private static String getRequestMethod(Method method) {
        try {
            for (Annotation annotation : method.getAnnotations()) {
                String annotationName = annotation.annotationType().getName();
                if (annotationName.endsWith("Mapping")) {
                    if (annotationName.contains("GetMapping")) {
                        return "GET";
                    } else if (annotationName.contains("PostMapping")) {
                        return "POST";
                    } else if (annotationName.contains("PutMapping")) {
                        return "PUT";
                    } else if (annotationName.contains("DeleteMapping")) {
                        return "DELETE";
                    } else if (annotationName.contains("PatchMapping")) {
                        return "PATCH";
                    }
                    
                    try {
                        Method methodAttr = annotation.annotationType().getMethod("method");
                        Object[] methods = (Object[]) methodAttr.invoke(annotation);
                        if (methods != null && methods.length > 0) {
                            return methods[0].toString();
                        }
                    } catch (Exception e) {

                    }
                }
            }
        } catch (Exception e) {
            // �����쳣
        }
        return "GET"; // Ĭ��ΪGET
    }

    public static void collectAPIInfo(String className, String methodName) {
        try {
            if (shouldSkipMethod(methodName)) {
                return;
            }

            String originalClassName = className;
            if (className.contains("$$")) {
                originalClassName = className.substring(0, className.indexOf("$$"));
            }

            Class<?> clazz = null;
            try {
                clazz = Class.forName(originalClassName.replace('/', '.'));
            } catch (ClassNotFoundException e) {
                try {
                    clazz = Class.forName(className.replace('/', '.'));
                } catch (ClassNotFoundException ex) {
                    return;
                }
            }

            if (clazz == null) {
                return;
            }


            String classMapping = "";
            try {
                for (Annotation annotation : clazz.getAnnotations()) {
                    if (annotation.annotationType().getName().endsWith("Mapping")) {
                        Method valueMethod = annotation.annotationType().getMethod("value");
                        String[] values = (String[]) valueMethod.invoke(annotation);
                        if (values != null && values.length > 0) {
                            classMapping = values[0];
                            break;
                        }
                    }
                }
            } catch (Exception e) {
                // �����쳣
            }

            Method[] methods = clazz.getDeclaredMethods();
            for (Method method : methods) {
                if (method.getName().equals(methodName)) {
                    String methodMapping = getRequestMapping(method);
                    if (methodMapping == null) {
                        continue;
                    }

                    APIInfo apiInfo = new APIInfo();
                    apiInfo.setClassName(originalClassName);
                    apiInfo.setMethodName(methodName);
                    apiInfo.setUri(classMapping + methodMapping);
                    apiInfo.setMethod(getRequestMethod(method));
                    
                    Parameter[] parameters = method.getParameters();
                    List<ParameterInfo> parameterInfos = new ArrayList<>();
                    
                    for (Parameter parameter : parameters) {
                        ParameterInfo paramInfo = new ParameterInfo();
                        paramInfo.setName(parameter.getName());
                        paramInfo.setType(parameter.getType().getSimpleName());
                        paramInfo.setRequired(!parameter.isAnnotationPresent(Nullable.class));

                        // ������ע����ȷ��������Դ
                        for (Annotation annotation : parameter.getAnnotations()) {
                            String annotationName = annotation.annotationType().getName();
                            if (annotationName.endsWith("CookieValue")) {
                                paramInfo.setIn("Cookie");
                                break;
                            } else if (annotationName.endsWith("RequestHeader")) {
                                paramInfo.setIn("header");
                                break;
                            } else if (annotationName.endsWith("PathVariable")) {
                                paramInfo.setIn("path");
                                break;
                            }
                        }

                        parameterInfos.add(paramInfo);
                    }
                    
                    apiInfo.setParameters(parameterInfos);
                    
                    String key = apiInfo.getUri() + "#" + apiInfo.getMethod();
                    apiInfoMap.put(key, apiInfo);

                    if (!autoSaveEnabled) {
                        saveToFile();
                    }
                    break;
                }
            }
        } catch (Exception e) {
            // �����쳣
        }
    }

    public static void collectRequestInfo(HttpServletRequest request) {
        try {
            String uri = request.getRequestURI();
            String method = request.getMethod();
            
            Map<String, String[]> parameterMap = request.getParameterMap();
            List<ParameterInfo> parameters = new ArrayList<>();
            

            for (Map.Entry<String, String[]> entry : parameterMap.entrySet()) {
                ParameterInfo paramInfo = new ParameterInfo();
                paramInfo.setName(entry.getKey());
                paramInfo.setType("string");
                paramInfo.setRequired(true);
                parameters.add(paramInfo);
            }
            
            // �ռ�Cookie����
            javax.servlet.http.Cookie[] cookies = request.getCookies();
            if (cookies != null) {
                for (javax.servlet.http.Cookie cookie : cookies) {
                    ParameterInfo paramInfo = new ParameterInfo();
                    paramInfo.setName(cookie.getName());
                    paramInfo.setType("string");
                    paramInfo.setRequired(true);
                    paramInfo.setIn("Cookie");
                    parameters.add(paramInfo);
                }
            }
            
            APIInfo apiInfo = new APIInfo();
            apiInfo.setUri(uri);
            apiInfo.setMethod(method);
            apiInfo.setParameters(parameters);
            
            String key = uri + "#" + method;
            apiInfoMap.put(key, apiInfo);
            
            if (!autoSaveEnabled) {
                saveToFile();
            }
        } catch (Exception e) {
            System.err.println("Error collecting request info: " + e.getMessage());
        }
    }

    private static synchronized void saveToFile() {
        try {
            ArrayNode apiArray = objectMapper.createArrayNode();
            
            for (APIInfo apiInfo : apiInfoMap.values()) {
                if (apiInfo.getUri() == null || apiInfo.getMethod() == null) {
                    continue;
                }

                ObjectNode apiNode = objectMapper.createObjectNode();
                apiNode.put("uri", apiInfo.getUri());
                apiNode.put("method", apiInfo.getMethod().toLowerCase());
                
                ArrayNode paramsArray = objectMapper.createArrayNode();
                if (apiInfo.getParameters() != null) {
                    for (ParameterInfo param : apiInfo.getParameters()) {
                        ObjectNode paramNode = objectMapper.createObjectNode();
                        paramNode.put("name", param.getName());
                        paramNode.put("in", param.getIn() != null ? param.getIn() : "parameter");
                        paramNode.put("required", param.isRequired());
                        
                        ObjectNode schemaNode = objectMapper.createObjectNode();
                        schemaNode.put("type", param.getType());
                        paramNode.set("schema", schemaNode);
                        
                        paramsArray.add(paramNode);
                    }
                }
                apiNode.set("parameters", paramsArray);
                
                ObjectNode responsesNode = objectMapper.createObjectNode();
                ObjectNode okResponse = objectMapper.createObjectNode();
                okResponse.put("description", "ok");
                responsesNode.set("200", okResponse);
                apiNode.set("responses", responsesNode);
                
                apiArray.add(apiNode);
            }
            
            File outputFile = new File(outputPath);
            if (outputFile.getParentFile() != null) {
                outputFile.getParentFile().mkdirs();
            }
            objectMapper.writerWithDefaultPrettyPrinter().writeValue(outputFile, apiArray);
            System.out.println("API information saved to: " + outputPath);
        } catch (IOException e) {
            System.err.println("Error saving API information: " + e.getMessage());
        }
    }

    private static class APIInfo {
        private String className;
        private String methodName;
        private String uri;
        private String method;
        private List<ParameterInfo> parameters;

        // Getters and setters
        public String getClassName() { return className; }
        public void setClassName(String className) { this.className = className; }
        public String getMethodName() { return methodName; }
        public void setMethodName(String methodName) { this.methodName = methodName; }
        public String getUri() { return uri; }
        public void setUri(String uri) { this.uri = uri; }
        public String getMethod() { return method; }
        public void setMethod(String method) { this.method = method; }
        public List<ParameterInfo> getParameters() { return parameters; }
        public void setParameters(List<ParameterInfo> parameters) { this.parameters = parameters; }
    }

    private static class ParameterInfo {
        private String name;
        private String type;
        private boolean required;
        private String in;

        // Getters and setters
        public String getName() { return name; }
        public void setName(String name) { this.name = name; }
        public String getType() { return type; }
        public void setType(String type) { this.type = type; }
        public boolean isRequired() { return required; }
        public void setRequired(boolean required) { this.required = required; }
        public String getIn() { return in; }
        public void setIn(String in) { this.in = in; }
    }
} 