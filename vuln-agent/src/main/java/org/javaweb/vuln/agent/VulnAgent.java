package org.javaweb.vuln.agent;

import java.io.File;
import java.lang.instrument.Instrumentation;
import java.lang.instrument.UnmodifiableClassException;

public class VulnAgent {
    private static Instrumentation instrumentation;

    public static void premain(String args, Instrumentation inst) {
        instrumentation = inst;
        initializeAgent(args);
    }

    public static void agentmain(String args, Instrumentation inst) {
        instrumentation = inst;
        initializeAgent(args);
    }

    private static void initializeAgent(String args) {
        if (args != null && !args.trim().isEmpty()) {
            String[] argPairs = args.split(",");
            for (String argPair : argPairs) {
                String[] keyValue = argPair.split("=");
                if (keyValue.length == 2) {
                    String key = keyValue[0].trim();
                    String value = keyValue[1].trim();
                    
                    switch (key) {
                        case "outputPath":
                            APICollector.setOutputPath(value);
                            break;
                        case "autoSave":
                            try {
                                int interval = Integer.parseInt(value);
                                if (interval > 0) {
                                    APICollector.enableAutoSave(interval);
                                }
                            } catch (NumberFormatException e) {
                                System.err.println("Invalid autoSave interval: " + value);
                            }
                            break;
                    }
                }
            }
        }


        System.out.println("API information will be saved to: " + APICollector.getOutputPath());


        APITransformer transformer = new APITransformer();
        instrumentation.addTransformer(transformer, true);


        APICollector.scanAllApis();


        Class<?>[] loadedClasses = instrumentation.getAllLoadedClasses();
        for (Class<?> clazz : loadedClasses) {
            if (clazz.getName().startsWith("org.javaweb.vuln.controller")) {
                try {
                    instrumentation.retransformClasses(clazz);
                } catch (UnmodifiableClassException e) {
                    e.printStackTrace();
                }
            }
        }
    }
} 