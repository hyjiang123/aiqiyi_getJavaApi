package org.javaweb.vuln.agent;

import java.io.File;
import java.lang.reflect.Method;
import java.net.URL;
import java.net.URLClassLoader;
import java.util.List;

public class AttachTool {
    public static void main(String[] args) {
        try {

            addToolsJarToClasspath();

            if (args.length != 2) {
                System.out.println("Usage: java -jar attach-tool.jar <pid> <agent-jar-path>");
                System.out.println("Example: java -jar attach-tool.jar 1234 vuln-agent.jar");
                System.out.println("\nAvailable Java processes:");
                listAvailableJavaProcesses();
                return;
            }

            String pid = args[0];
            String agentPath = new File(args[1]).getAbsolutePath();

            System.out.println("Attaching to process " + pid + " with agent " + agentPath);
            

            Class<?> vmClass = Class.forName("com.sun.tools.attach.VirtualMachine");
            Method attachMethod = vmClass.getMethod("attach", String.class);
            Method loadAgentMethod = vmClass.getMethod("loadAgent", String.class);
            Method detachMethod = vmClass.getMethod("detach");
            
            Object vm = attachMethod.invoke(null, pid);
            loadAgentMethod.invoke(vm, agentPath);
            detachMethod.invoke(vm);
            
            System.out.println("Agent attached successfully!");

        } catch (Exception e) {
            System.err.println("Error attaching agent: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private static void listAvailableJavaProcesses() {
        try {
            Class<?> vmClass = Class.forName("com.sun.tools.attach.VirtualMachine");
            Method listMethod = vmClass.getMethod("list");
            List<?> vms = (List<?>) listMethod.invoke(null);
            
            for (Object vm : vms) {
                Method idMethod = vm.getClass().getMethod("id");
                Method displayNameMethod = vm.getClass().getMethod("displayName");
                String id = (String) idMethod.invoke(vm);
                String displayName = (String) displayNameMethod.invoke(vm);
                System.out.println("PID: " + id + "\tDisplay name: " + displayName);
            }
        } catch (Exception e) {
            System.err.println("Error listing Java processes: " + e.getMessage());
        }
    }

    private static void addToolsJarToClasspath() throws Exception {
        String javaHome = System.getProperty("java.home");
        File toolsJar = new File(javaHome, "../lib/tools.jar");
        
        if (!toolsJar.exists()) {
            toolsJar = new File(javaHome, "lib/tools.jar");
        }
        
        if (!toolsJar.exists()) {
            // JDK 9+ doesn't need tools.jar
            String javaVersion = System.getProperty("java.version");
            if (javaVersion.startsWith("1.")) {
                throw new RuntimeException("Could not find tools.jar in: " + toolsJar);
            }
            return;
        }

        URLClassLoader sysloader = (URLClassLoader) ClassLoader.getSystemClassLoader();
        Method method = URLClassLoader.class.getDeclaredMethod("addURL", URL.class);
        method.setAccessible(true);
        method.invoke(sysloader, toolsJar.toURI().toURL());
    }
} 