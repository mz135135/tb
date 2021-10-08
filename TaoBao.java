import android.content.Context;
import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.arm.HookStatus;
import com.github.unidbg.file.FileResult;
import com.github.unidbg.file.IOResolver;
import com.github.unidbg.file.linux.AndroidFileIO;
import com.github.unidbg.hook.HookContext;
import com.github.unidbg.hook.ReplaceCallback;
import com.github.unidbg.hook.hookzz.HookZz;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.android.dvm.*;
import com.github.unidbg.linux.android.dvm.array.ByteArray;
import com.github.unidbg.linux.android.dvm.jni.ProxyDvmObject;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.pointer.UnidbgPointer;
import com.github.unidbg.spi.SyscallHandler;
import com.taobao.tao.TaobaoApplication;
import org.json.JSONObject;
 
import java.io.File;
import java.io.IOException;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
 
public class TaoBao extends AbstractJni implements IOResolver<AndroidFileIO> {
    private final AndroidEmulator emulator;
    private final VM vm;
    private final Context context;
    private final HookZz zz;
    private final JSONObject data;
    private Module libc;
    private long slot;
 
//    private int num = 0;
 
    private TaoBao(File apk) throws  Exception{
        emulator = AndroidEmulatorBuilder.for32Bit()
                .setRootDir(new File("D:\\DesktopTemp\\tb\\rootfs"))
                .build();
 
        Map<String, Integer> iNode = new LinkedHashMap<>();
        iNode.put("/data/system", 671745);
        iNode.put("/data/app", 327681);
        iNode.put("/sdcard/android", 294915);
        iNode.put("/data/user/0/com.taobao.taobao", 655781);
        iNode.put("/data/user/0/com.taobao.taobao/files", 655864);
        emulator.set("inode", iNode);
        emulator.set("uid", 10074);
 
        Memory memory = emulator.getMemory();
        memory.setLibraryResolver(new AndroidResolver(23));
        SyscallHandler<AndroidFileIO> handler = emulator.getSyscallHandler();
        handler.setVerbose(false);
        handler.addIOResolver(this);
        vm = emulator.createDalvikVM(apk);
        vm.setJni(this);
        vm.setVerbose(true);
 
        zz = HookZz.getInstance(emulator);
        context = new TaobaoApplication(vm);
        data = new JSONObject("{\"Soft_SGTMAGIC\":\"4I1q9PXiORQGtBivoqf4hSwMk9pwm1D8o4NitR+kvgA=\",\"dynamicreid_dynamicreid\":\"d0666b5b6022eb0\",\"dynamicrsid_dynamicrsid\":\"e1a2607877e260b\",\"SgDyUpdate_ac7123c301ca455b\":\"1621600637\",\"LOCAL_DEVICE_INFO_982c1b269b8e023e5aede2421cbf9c48\":\"YKepcS4SY+ADAIS37Xj5c7s+\",\"DynamicData_accs_ssl_key2_https:\\/\\/ossgw.alicdn.com_21646297%[B\":\"nRWwrMQ\\/jz+oOTWkAZ5FOjhnS1k48SqJdb3w3u\\/ImZJMSXQnlxpD8g0Lyi4kEfgHy5Me33VQ8fyLfqHjPk5PXZ3SwQDtSG4Km7fj9RhEav6NeP85kaWorOA8KTx9u9MHnXdbQa4GVOpBTln\\/GKsPje5gRpmCtWUb71auNwVEO\\/s9LUhH\\/HOcH\\/fwdPixaJAi\\/wNKYYlijdORJgVTOwrtSls1DeUr61NyCDUQa0SkVhw6\\/8PI8gdM1JNt8QEcBIemgI0sM4zA3yyRxFTb0wwcu8CpLsBmIqxqZbvHA+2081dfYDIKuKguH9vYy4s\\/q++odPRvTB25RuEfvXWW\\/+IPtScYQXMx9\\/MG4RW7t80WR0+DOWZXHtkpVlPhTDcU9P2fI4bcQdRSTOIcaI6uFmnOdmb5b9QdtwU3qXgSOuBTh2Bdd6yTeyydRLChBzlWRtcZm6+tYgHOTJIWRNoDg8CxEw==\",\"llc-local_2c3c7f544c159842\":\"1621600921\",\"llc-local_abv2\":\"his:0\",\"llc-local_tcv2\":\"source:0,0,0\"}");
 
        for (Module each : memory.getLoadedModules()) {
            if ("libc.so".equals(each.getPath())) {
                libc = each;
                break;
            }
        }
    }
 
    public static void main(String[] args) throws Exception {
//        Logger.getLogger(DvmClass.class).setLevel(Level.OFF);
//        Logger.getLogger(ARM32SyscallHandler.class).setLevel(Level.OFF);
        TaoBao taobao = new TaoBao(new File("D:\\DesktopTemp\\tb\\tb.apk"));
 
        AndroidEmulator emulator = taobao.emulator;
        String methodSign = "doCommandNative(I[Ljava/lang/Object;)Ljava/lang/Object;";
 
        DvmClass targetClass = taobao.vm.resolveClass("com/taobao/wireless/security/adapter/JNICLibrary");
        DalvikModule main = taobao.vm.loadLibrary("sgmainso-6.5.25", true);
 
        taobao.loadLibHook();
        taobao.loadTestHook();
        taobao.loadTestHook(main.getModule());
 
        main.callJNI_OnLoad(emulator);
 
        targetClass.callStaticJniMethodObject(emulator, methodSign,
                10101, ProxyDvmObject.createObject(taobao.vm, new Object[]{
                        taobao.context, 3, "", "/data/user/0/com.taobao.taobao/app_SGLib", ""
                }));
 
 
        targetClass.callStaticJniMethodObject(emulator, methodSign,
                10102, ProxyDvmObject.createObject(taobao.vm, new Object[]{
                        "main", "6.5.25", "/data/app/com.taobao.taobao-1/lib/arm/libsgmainso-6.5.25.so"
                }));
 
 
        DalvikModule security = taobao.vm.loadLibrary("sgsecuritybodyso-6.5.33", true);
        security.callJNI_OnLoad(emulator);
 
 
        targetClass.callStaticJniMethodObject(emulator, methodSign,
                10102, ProxyDvmObject.createObject(taobao.vm, new Object[]{
                        "securitybody", "6.5.33", "/data/app/com.taobao.taobao-1/lib/arm/libsgsecuritybodyso-6.5.33.so"
                }));
 
        DalvikModule middletier = taobao.vm.loadLibrary("sgmiddletierso-6.5.27", true);
        middletier.callJNI_OnLoad(emulator);
 
        targetClass.callStaticJniMethodObject(emulator, methodSign,
                10102, ProxyDvmObject.createObject(taobao.vm, new Object[]{
                        "middletier", "6.5.27", "/data/app/com.taobao.taobao-1/lib/arm/libsgmiddletierso-6.5.27.so"
                }));
 
        taobao.loadTest3Hook(middletier.getModule());
 
        DvmObject<?> dvmObject1 = targetClass.callStaticJniMethodObject(emulator, methodSign,
                70102, ProxyDvmObject.createObject(taobao.vm, new Object[]{
                        "丢失", "丢失",
                        false, 0, "mtop.alibaba.cro.umid.networksdk.savewb", "pageName=com.taobao.tao.welcome.Welcome&pageId=", null, null, null, "r_6"
                }));
 
        System.out.println(dvmObject1.getValue().toString());
        try {
            emulator.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
 
    private void loadTestHook(Module main) {
 
        zz.replace(main.base + 0x94584 | 1, new ReplaceCallback() {
            @Override
            public HookStatus onCall(Emulator<?> emulator, long originFunction) {
                return HookStatus.LR(emulator, 0x98764321);
            }
        });
 
//        zz.replace(main.base + 0x78248 | 1, new ReplaceCallback() {
//            @Override
//            public HookStatus onCall(Emulator<?> emulator, HookContext context, long originFunction) {
//                UnidbgPointer pointerArg = context.getPointerArg(0);
//                Inspector.inspect(pointerArg.getPointer(0).getByteArray(0, pointerArg.getInt(4)), "MD5");
//                return super.onCall(emulator, context, originFunction);
//            }
//        });
    }
 
    private void loadTest3Hook(Module middletier) {
//        emulator.traceCode(middletier.base + 0x00047AEA | 1, middletier.base + 0x00047AEC | 1, new TraceCodeListener() {
//            @Override
//            public void onInstruction(Emulator<?> emulator, long address, Capstone.CsInsn insn) {
//                num++;
//            }
//        }).setRedirect(new NullPrintStream());
    }
 
 
    private void loadTestHook() {
        zz.replace(libc.findSymbolByName("time"), new ReplaceCallback() {
            @Override
            public HookStatus onCall(Emulator<?> emulator, long originFunction) {
                return HookStatus.LR(emulator, 1618558999);
            }
        });
        zz.replace(libc.findSymbolByName("lrand48"), new ReplaceCallback() {
            @Override
            public HookStatus onCall(Emulator<?> emulator, long originFunction) {
                return HookStatus.LR(emulator, 0);
            }
        });
        zz.replace(libc.findSymbolByName("arc4random"), new ReplaceCallback() {
            @Override
            public HookStatus onCall(Emulator<?> emulator, long originFunction) {
                return HookStatus.LR(emulator, 0x71BDF95F);
            }
        });
        zz.replace(libc.findSymbolByName("gettimeofday"), new ReplaceCallback() {
            @Override
            public HookStatus onCall(Emulator<?> emulator, HookContext context, long originFunction) {
                UnidbgPointer pointerArg = context.getPointerArg(0);
                pointerArg.write(0, new int[]{1618558999, 31231}, 0, 2);
                return HookStatus.LR(emulator, 0);
            }
        });
    }
 
    private void loadLibHook() {
        zz.replace(libc.findSymbolByName("pthread_create"), new ReplaceCallback() {
            @Override
            public HookStatus onCall(Emulator<?> emulator, long originFunction) {
                return HookStatus.LR(emulator, 0);
            }
        });
 
        zz.replace(libc.findSymbolByName("getuid"), new ReplaceCallback() {
            @Override
            public HookStatus onCall(Emulator<?> emulator, long originFunction) {
                return HookStatus.LR(emulator, emulator.<Integer>get("uid"));
            }
        });
 
        zz.replace(libc.findSymbolByName("stat64"), new ReplaceCallback() {
            private String path;
            private UnidbgPointer buff;
 
            @Override
            public HookStatus onCall(Emulator<?> emulator, HookContext context, long originFunction) {
                path = context.getPointerArg(0).getString(0);
                buff = context.getPointerArg(1);
                return super.onCall(emulator, context, originFunction);
            }
 
            @Override
            public void postCall(Emulator<?> emulator, HookContext context) {
                Object inode = emulator.get("inode");
                if (inode != null) {
                    Object integer = ((Map<?, ?>) inode).get(this.path);
                    if (integer != null) {
                        int[] ints = {(int) integer};
                        buff.write(12, ints, 0, 1);
                        buff.write(0x60, ints, 0, 1);
                    }
                }
                super.postCall(emulator, context);
            }
        }, true);
    }
 
    @Override
    public DvmObject<?> newObject(BaseVM vm, DvmClass dvmClass, String signature, VarArg varArg) {
        switch (signature) {
            case "java/lang/Integer-><init>(I)V":
                return ProxyDvmObject.createObject(vm, varArg.getIntArg(0));
            case "java/lang/Long-><init>(J)V":
                return ProxyDvmObject.createObject(vm, varArg.getLongArg(0));
            case "java/util/HashMap-><init>(I)V":
                return ProxyDvmObject.createObject(vm, new HashMap<>());
        }
        return super.newObject(vm, dvmClass, signature, varArg);
    }
 
    @Override
    public int getStaticIntField(BaseVM vm, DvmClass dvmClass, String signature) {
        if ("android/os/Build$VERSION->SDK_INT:I".equals(signature)) {
            return 23;
        }
        return super.getStaticIntField(vm, dvmClass, signature);
    }
 
    @Override
    public long getStaticLongField(BaseVM vm, DvmClass dvmClass, String signature) {
        if ("com/alibaba/wireless/security/framework/SGPluginExtras->slot:J".equals(signature)) {
            return slot;
        }
        return super.getStaticLongField(vm, dvmClass, signature);
    }
 
    @Override
    public DvmObject<?> getObjectField(BaseVM vm, DvmObject<?> dvmObject, String signature) {
        if ("android/content/pm/ApplicationInfo->nativeLibraryDir:Ljava/lang/String;".equals(signature)) {
            return new StringObject(vm, "/data/app/com.taobao.taobao-1/lib/arm");
        } else if ("android/content/pm/ApplicationInfo->sourceDir:Ljava/lang/String;".equals(signature)) {
            return new StringObject(vm, this.context.getPackageCodePath());
        }
        return super.getObjectField(vm, dvmObject, signature);
    }
 
    @Override
    public void setStaticLongField(BaseVM vm, DvmClass dvmClass, String signature, long value) {
        if ("com/alibaba/wireless/security/framework/SGPluginExtras->slot:J".equals(signature)) {
            slot = value;
            return;
        }
        super.setStaticLongField(vm, dvmClass, signature, value);
    }
 
    @Override
    public DvmObject<?> callStaticObjectMethod(BaseVM vm, DvmClass dvmClass, String signature, VarArg varArg) {
        switch (signature) {
            case "com/alibaba/wireless/security/securitybody/SecurityGuardSecurityBodyPlugin->getPluginClassLoader()Ljava/lang/ClassLoader;":
                return vm.resolveClass("dalvik/system/PathClassLoader").newObject(this.getClass().getClassLoader());
            case "com/taobao/dp/util/CallbackHelper->getInstance()Lcom/taobao/dp/util/CallbackHelper;":
                return vm.resolveClass("com/taobao/dp/util/CallbackHelper").newObject(null);
            case "com/taobao/wireless/security/adapter/common/SPUtility2->readFromSPUnified(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;": {
                String temp = null;
                String key = varArg.getObjectArg(0).getValue() + "_" + varArg.getObjectArg(1).getValue();
                try {
                    temp = data.getString(key);
                } catch (Exception ignored) {
                }
                return temp == null ? varArg.getObjectArg(2) : new StringObject(vm, temp);
            }
            case "com/taobao/wireless/security/adapter/datacollection/DeviceInfoCapturer->doCommandForString(I)Ljava/lang/String;": {
                String temp;
                switch (varArg.getIntArg(0)) {
                    case 122:
                        temp = "com.taobao.taobao";
                        break;
                    case 123:
                        temp = "9.23.0";
                        break;
                    case 135:
                        temp = "YKepcS4SY+ADAIS37Xj5c7s+";
                        break;
                    default:
                        return null;
                }
                return new StringObject(vm, temp);
            }
            case "java/net/NetworkInterface->getNetworkInterfaces()Ljava/util/Enumeration;":
                try {
                    return Context.getNetworkInterfaces(vm);
                } catch (Exception e) {
                    e.printStackTrace();
                }
                return null;
            case "com/alibaba/wireless/security/securitybody/SecurityBodyAdapter->doAdapter(I)Ljava/lang/String;": {
                String value;
                switch (varArg.getIntArg(0)) {
                    case 6:
                        value = "100";
                        break;
                    case 8:
                        value = "1";
                        break;
                    case 9:
                        value = "1618558999";
                        break;
                    case 10:
                        value = "0";
                        break;
                    case 11:
                        value = "4.97";
                        break;
                    default:
                        return null;
                }
                return new StringObject(vm, value);
            }
            case "java/lang/Thread->currentThread()Ljava/lang/Thread;":
                return ProxyDvmObject.createObject(vm, Thread.currentThread());
        }
        return super.callStaticObjectMethod(vm, dvmClass, signature, varArg);
    }
 
    @Override
    public void callStaticVoidMethod(BaseVM vm, DvmClass dvmClass, String signature, VarArg varArg) {
        switch (signature) {
            case "com/alibaba/wireless/security/open/edgecomputing/ECMiscInfo->registerAppLifeCyCleCallBack()V":
            case "com/alibaba/wireless/security/securitybody/LifeCycle->setAccessibilityDelegateToView()V":
                return;
        }
        super.callStaticVoidMethod(vm, dvmClass, signature, varArg);
    }
 
    @Override
    public int callStaticIntMethod(BaseVM vm, DvmClass dvmClass, String signature, VarArg varArg) {
        switch (signature) {
            case "com/taobao/wireless/security/adapter/common/SPUtility2->saveToFileUnifiedForNative(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)I":
                return 2;
            case "com/alibaba/wireless/security/framework/utils/UserTrackMethodJniBridge->utAvaiable()I":
            case "com/uc/crashsdk/JNIBridge->registerInfoCallback(Ljava/lang/String;IJI)I":
                return 1;
            case "android/provider/Settings$Secure->getInt(Landroid/content/ContentResolver;Ljava/lang/String;I)I":
                return context.getInt(varArg.getObjectArg(1).getValue().toString(), varArg.getIntArg(2));
        }
        return super.callStaticIntMethod(vm, dvmClass, signature, varArg);
    }
 
    @Override
    public boolean callBooleanMethod(BaseVM vm, DvmObject<?> dvmObject, String signature, VarArg varArg) {
        switch (signature) {
            case "java/lang/Boolean->booleanValue()Z":
                return (Boolean) dvmObject.getValue();
            case "android/view/accessibility/AccessibilityManager->isEnabled()Z":
            case "android/view/accessibility/AccessibilityManager->isTouchExplorationEnabled()Z":
                return false;
            case "java/util/Enumeration->hasMoreElements()Z":
                return ((Enumeration) dvmObject).hasMoreElements();
            case "java/net/NetworkInterface->isUp()Z":
                return ((Context.mNetworkInterface) dvmObject.getValue()).isUp();
        }
        return super.callBooleanMethod(vm, dvmObject, signature, varArg);
    }
 
    @Override
    public void callVoidMethod(BaseVM vm, DvmObject<?> dvmObject, String signature, VarArg varArg) {
        if ("com/taobao/dp/util/CallbackHelper->onUpdated(IILjava/lang/String;)V".equals(signature)) {
            return;
        }
        super.callVoidMethod(vm, dvmObject, signature, varArg);
    }
 
    @Override
    public int callIntMethod(BaseVM vm, DvmObject<?> dvmObject, String signature, VarArg varArg) {
        if ("java/lang/Integer->intValue()I".equals(signature)) {
            return (Integer) dvmObject.getValue();
        } else if ("android/telephony/TelephonyManager->getSimState()I".equals(signature)) {
            return ((Context) dvmObject.getValue()).getSimState();
        }
        return super.callIntMethod(vm, dvmObject, signature, varArg);
    }
 
    @Override
    public DvmObject<?> callObjectMethod(BaseVM vm, DvmObject<?> dvmObject, String signature, VarArg varArg) {
        switch (signature) {
            case "java/lang/String->getBytes()[B":
                return new ByteArray(vm, ((String) dvmObject.getValue()).getBytes());
            case "com/taobao/tao/TaobaoApplication->getPackageCodePath()Ljava/lang/String;":
                return new StringObject(vm, ((Context) dvmObject.getValue()).getPackageCodePath());
            case "com/taobao/tao/TaobaoApplication->getFilesDir()Ljava/io/File;":
            case "android/content/Context->getFilesDir()Ljava/io/File;":
                return ProxyDvmObject.createObject(vm, ((Context) dvmObject.getValue()).getFilesDir());
            case "java/io/File->getAbsolutePath()Ljava/lang/String;":
                return new StringObject(vm, ((File) dvmObject.getValue()).getPath().replace('\\', '/'));
            case "com/taobao/tao/TaobaoApplication->getApplicationInfo()Landroid/content/pm/ApplicationInfo;":
                return super.callObjectMethod(vm, dvmObject,
                        "android/content/Context->getApplicationInfo()Landroid/content/pm/ApplicationInfo;", varArg);
            case "android/content/Context->getSystemService(Ljava/lang/String;)Ljava/lang/Object;":
                return ((TaobaoApplication) dvmObject.getValue()).getSystemService(varArg.getObjectArg(0).getValue().toString());
            case "dalvik/system/PathClassLoader->findClass(Ljava/lang/String;)Ljava/lang/Class;":
                return vm.resolveClass(varArg.getObjectArg(0).getValue().toString());
            case "java/util/Enumeration->nextElement()Ljava/lang/Object;":
                return ((Enumeration) dvmObject).nextElement();
            case "android/content/Context->getContentResolver()Landroid/content/ContentResolver;":
                return ((Context) dvmObject.getValue()).getContentResolver();
            case "java/net/NetworkInterface->getName()Ljava/lang/String;":
                return new StringObject(vm, ((Context.mNetworkInterface) dvmObject.getValue()).getName());
            case "java/lang/Thread->getStackTrace()[Ljava/lang/StackTraceElement;":
                return ProxyDvmObject.createObject(vm, ((Thread) dvmObject.getValue()).getStackTrace());
            case "java/lang/StackTraceElement->toString()Ljava/lang/String;":
                return new StringObject(vm, ((StackTraceElement) dvmObject.getValue()).toString());
            case "java/util/HashMap->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;":
                return ProxyDvmObject.createObject(vm, ((HashMap<Object, Object>) dvmObject.getValue())
                        .put(varArg.getObjectArg(0).getValue(), varArg.getObjectArg(1).getValue()));
        }
        return super.callObjectMethod(vm, dvmObject, signature, varArg);
    }
 
    @Override
    public DvmObject<?> callObjectMethodV(BaseVM vm, DvmObject<?> dvmObject, String signature, VaList vaList) {
        switch (signature) {
            case "android/content/Context->getClassLoader()Ljava/lang/ClassLoader;":
                return ProxyDvmObject.createObject(vm, this.getClass().getClassLoader());
            case "android/content/Context->getPackageResourcePath()Ljava/lang/String;":
                return ProxyDvmObject.createObject(vm, ((Context) dvmObject.getValue()).getPackageResourcePath());
            case "android/content/Context->getFilesDir()Ljava/io/File;":
                return ProxyDvmObject.createObject(vm, ((Context) dvmObject.getValue()).getFilesDir());
            case "java/io/File->getPath()Ljava/lang/String;":
                return ProxyDvmObject.createObject(vm, ((File) dvmObject.getValue()).getPath().replace('\\', '/'));
        }
        return super.callObjectMethodV(vm, dvmObject, signature, vaList);
    }
 
    @Override
    public FileResult<AndroidFileIO> resolve(Emulator<AndroidFileIO> emulator, String pathname, int oflags) {
        switch (pathname) {
            case "/data/app/com.taobao.taobao-1/base.apk":
            case "/data/user/0/com.taobao.taobao/files/sg_oc.lock":
            case "/data/user/0/com.taobao.taobao/files/ab914f43b8296c2c.lock":
            case "/data/user/0/com.taobao.taobao/files/0a231bd8575dcf72.txt":
            case "/data/user/0/com.taobao.taobao/files/.ba2f9c85.lock":
            case "/data/user/0/com.taobao.taobao/files/JX0WDG83P1ZN.txt":
            case "/data/user/0/com.taobao.taobao/files/sgFile.lock":
            case "/data/user/0/com.taobao.taobao/app_SGLib/SG_INNER_DATA":
                return FileResult.success(emulator.getFileSystem().createSimpleFileIO(
                        new File("D:\\DesktopTemp\\tb\\rootfs", pathname), oflags, pathname));
            case "/data/data/com.taobao.taobao/app_SGLib/sec":
            case "/data/user/0/com.taobao.taobao/app_SGLib/sec":
            case "/data/user/0/com.taobao.taobao/app_SGLib/lvmreport":
                return FileResult.success(emulator.getFileSystem().createDirectoryFileIO(
                        new File("D:\\DesktopTemp\\tb\\rootfs", pathname), oflags, pathname));
            default:
                return null;
        }
    }
 
}
