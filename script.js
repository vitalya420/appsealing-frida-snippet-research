const state = {
    moduleBaseAddress: 0x0,
    moduleEndAddress: 0x0,
    checkDeviceThreadId: 0x0,
}

const triggerWords = ['frida', 'magisk', 'emula', 'ANDROID_EMU', 'AMD Radeon', 'qemu'];


const getNativeFunctions = () => {
    return {
        getpid: new NativeFunction(Module.getExportByName(null, 'getpid'), 'int', []),
        gettid: new NativeFunction(Module.getExportByName(null, 'gettid'), 'int', []),
        sleep: new NativeFunction(Module.getExportByName(null, 'sleep'), 'int', ['int']),
        pthread_exit: new NativeFunction(Module.getExportByName(null, 'pthread_exit'), 'void', ['pointer'])
    };
};

const log = (...args) => {
    const { gettid, getpid } = getNativeFunctions();
    const tid = gettid();
    const pid = getpid();

    // console.log(`[+][tid: ${tid}][pid: ${pid}]`, ...args);   
};


const fuckThisShit = () => {
    const name = "libcovault-appsec.so";
    const module = Process.getModuleByName(name);
    log("BASE ADDRESS", module.base);

    const bytesToReplace = {
        0x144c7: [0xb8, 0x00, 0x00, 0x00, 0x00, 0xc3], // MOV EAX,0x0, RET
        0x7a210: [0xc3],
        0x3fc60: [0xb8, 0x00, 0x00, 0x00, 0x00, 0xc3],
        0x15c40: [0xb8, 0x00, 0x00, 0x00, 0x00, 0xc3],
    }

    for (const [offset, bytes] of Object.entries(bytesToReplace)) {
        const addr = module.base.add(ptr(offset));
        
        Memory.protect(addr, bytes.length, 'rwx');
        addr.writeByteArray(bytes);
        
        console.log(`Patched at ${addr.toString()}:`, bytes.map(b => b.toString(16)).join(' '));
    }


    const fuckingFunction = {
        0x0c640: "Hmm",
    }

    const open = Module.getExportByName(null, 'open');
    const fgets = Module.getExportByName(null, 'fgets');

    Object.keys(fuckingFunction).map(addr => {
        const text = fuckingFunction[addr];
        Interceptor.attach(module.base.add(addr), {
            onEnter(args){
                log(`Entered ${text}`);
            },
            onLeave(ret){
                log(`Left ${text}`);
            }
        })
    });



    Interceptor.attach(open, {
        onEnter(args){
            const path = args[0].readCString();
            if (path.includes(".sealing_reports" || path.includes("seale"))){
                log("open", path);
                // const trace = Thread.backtrace(this.context, Backtracer.FUZZY).map(DebugSymbol.fromAddress);
                // for (let t in trace){
                //     console.log("[*] Traceline", trace[t]);
                // }
            }
        }
    });



    Interceptor.attach(module.base.add(0xb156f), {
        onEnter(args){
            log("FUCK YEAH ");
            // const trace = Thread.backtrace(this.context, Backtracer.FUZZY).map(DebugSymbol.fromAddress);
            // for (let t in trace){
            //     console.log("[*] Traceline", trace[t]);
            // }
        }
    });

    Interceptor.attach(fgets, {
        onEnter: (args) => {
            this.args0 = args[0];
            this.args1 = args[1];
        },
        onLeave: (ret) => {
            let readResult = ret.readCString()
            
            for(let i = 0; i < triggerWords.length; i++){
                const triggerWord = triggerWords[i];
                if (readResult && readResult.includes(triggerWord)){
                    const replacedWith = 'x'.repeat(triggerWord.length);
                    readResult = readResult.replaceAll(triggerWord, replacedWith);
                    readResult = readResult.slice(0, this.args1);
                    var p = Memory.allocUtf8String(readResult);
                    Memory.copy(this.args0, p, readResult.length);
                }
            }
        }
    });

}

const hookLoadLibrary = () => {
    const System = Java.use('java.lang.System');
    const Runtime = Java.use('java.lang.Runtime');
    const VMStack = Java.use('dalvik.system.VMStack');
    const Base64 = Java.use('android.util.Base64');

    Base64['decode'].overload('java.lang.String', 'int').implementation = function(a, b){
        // console.log('get decoder', a, b);
        return  Base64['decode'](a, b);
    }

    let Process = Java.use("android.os.Process");
    Process.killProcess.implementation = function (i) {
        // console.log(`Process.killProcess is called: i=${i}`);
        Process.killProcess(i);
    };

    System.exit.implementation = function (i) {
        // console.log(`exit is called: i=${i}`);
        Process.killProcess(i);
    };

    

    System.loadLibrary.overload('java.lang.String').implementation = function(library){
        log('Loading library', library);

        
        Runtime.getRuntime().loadLibrary0(VMStack.getCallingClassLoader(), library);
        if (library == 'covault-appsec'){
            log('AppSealing native library loaded');
            state.moduleLoaded = true;
            fuckThisShit();
            
        }
        log(library, 'loaded');
    };

}

const hookLibC = () => {
    const pthread_create = Module.getExportByName(null, 'pthread_create');

    ['kill', 'exit', '_exit', 'tkill', 'tgkill'].forEach(f => {
        Interceptor.attach(Module.getExportByName(null, f), {
            onEnter(args) {
                log(f, 'called!');
            }
        });
    });


    Interceptor.replace(Module.getExportByName(null, 'alarm'), new NativeCallback((t) => {
        log("ALARM");
        return 0;
    }, 'int',['int']));
    Interceptor.attach(pthread_create, {
        onEnter: (args) => {
            this.start_routine = args[2];
            const debugSymbol = DebugSymbol.fromAddress(start_routine);
            const baseAddr = Process.getModuleByName(debugSymbol.moduleName).base
            const offset = Number(debugSymbol.address-baseAddr)
            const log_message = `pthread_create ${debugSymbol.moduleName} ${debugSymbol.address} 0x${offset.toString(16)}`
            if(![0x7a210, 0x3fc60, 0x58a60, 0x15c40, 0x144c7].includes(offset)){
                Interceptor.attach(start_routine, {
                    onEnter(args){
                        // log(`inside thread ${debugSymbol.moduleName} ${debugSymbol.address} 0x${offset.toString(16)}`)
                        // const trace = Thread.backtrace(this.context, Backtracer.FUZZY).map(DebugSymbol.fromAddress);
                        // for (let t in trace){
                        //     console.log("[*] Traceline", trace[t]);
                        // }
                    }
                });
            }
            // log(log_message, args[3]);
        },
    });
}

Java.perform(() => {
    hookLibC();
    hookLoadLibrary();
});
