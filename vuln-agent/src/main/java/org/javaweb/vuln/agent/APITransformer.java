package org.javaweb.vuln.agent;

import org.objectweb.asm.*;
import org.objectweb.asm.commons.AdviceAdapter;

import java.lang.instrument.ClassFileTransformer;
import java.security.ProtectionDomain;
import java.util.ArrayList;
import java.util.List;

public class APITransformer implements ClassFileTransformer {
    @Override
    public byte[] transform(ClassLoader loader, String className, Class<?> classBeingRedefined,
                          ProtectionDomain protectionDomain, byte[] classfileBuffer) {
        
        if (className == null || !className.startsWith("org/javaweb/vuln/controller")) {
            return classfileBuffer;
        }

        try {
            ClassReader cr = new ClassReader(classfileBuffer);
            ClassWriter cw = new ClassWriter(cr, ClassWriter.COMPUTE_MAXS);
            ClassVisitor cv = new APIClassVisitor(cw);
            cr.accept(cv, ClassReader.EXPAND_FRAMES);
            return cw.toByteArray();
        } catch (Exception e) {
            e.printStackTrace();
            return classfileBuffer;
        }
    }

    private static class APIClassVisitor extends ClassVisitor {
        private String className;

        public APIClassVisitor(ClassVisitor cv) {
            super(Opcodes.ASM9, cv);
        }

        @Override
        public void visit(int version, int access, String name, String signature,
                         String superName, String[] interfaces) {
            this.className = name;
            super.visit(version, access, name, signature, superName, interfaces);
        }

        @Override
        public MethodVisitor visitMethod(int access, String name, String descriptor,
                                       String signature, String[] exceptions) {
            MethodVisitor mv = super.visitMethod(access, name, descriptor, signature, exceptions);
            return new APIMethodVisitor(mv, access, name, descriptor, className);
        }
    }

    private static class APIMethodVisitor extends AdviceAdapter {
        private final String className;
        private final String methodName;
        private final String descriptor;

        protected APIMethodVisitor(MethodVisitor mv, int access, String name,
                                 String descriptor, String className) {
            super(Opcodes.ASM9, mv, access, name, descriptor);
            this.className = className;
            this.methodName = name;
            this.descriptor = descriptor;
        }

        @Override
        protected void onMethodEnter() {
            Type[] argumentTypes = Type.getArgumentTypes(descriptor);
            List<String> parameterNames = new ArrayList<>();
            
            for (int i = 0; i < argumentTypes.length; i++) {
                parameterNames.add("arg" + i);
            }

            mv.visitLdcInsn(className);
            mv.visitLdcInsn(methodName);
            mv.visitMethodInsn(INVOKESTATIC, "org/javaweb/vuln/agent/APICollector",
                    "collectAPIInfo", "(Ljava/lang/String;Ljava/lang/String;)V", false);
        }
    }
} 