# AppSealing Reverse Engineering Research
How to bypass appsealing VM detection and root detection.

## Disclaimer
This research is intended for educational purposes only. The techniques discussed herein should not be used for malicious activities or to compromise the security of applications without proper authorization.

## Environment
For this research, we will be utilizing an Android Virtual Device (AVD) configured with x86 architecture and root access. The tools selected for this analysis include:

- [Ghidra](https://ghidra-sre.org/): Ghidra will be used for disassembling native code, allowing us to analyze the low-level operations of the application.
- [Jadx GUI](https://github.com/skylot/jadx): This tool will help us examine the Java code and understand the application’s logic and flow.
- [Frida](https://frida.re/): Frida will be instrumental in modifying the behavior of the application at runtime, particularly for bypassing detection mechanisms.

## Introducing
AppSealing is a security solution designed to protect mobile applications from reverse engineering, tampering, and other forms of attacks. It employs various techniques to detect whether an application is running in a virtualized environment or if it has been modified (e.g., rooted). This research aims to explore methods to bypass these detection mechanisms, providing insights into the security measures employed by AppSealing and the potential vulnerabilities that may exist.

## Application startup
The application enters the `attachBaseContext(Context context)` method during its startup sequence. Within this method, several critical operations take place:

1. Native Library Loading: The application calls `System.loadLibrary("covault-appsec")`, which loads the native library responsible for various security checks.
2. Native Function Calls: Immediately after loading the library, several native functions are invoked to perform checks related to the device's environment. These functions assess whether the device is rooted or running in an emulator.
3. Process Termination: If any of these checks indicate that the device is compromised (i.e., rooted or emulated), the process is terminated with a `SIGTERM` signal. Notably, this termination occurs before the `attachBaseContext` method has completed its execution. This behavior was confirmed using Frida, which allowed us to observe the application's runtime and the point at which the termination occurs.

This rapid termination highlights the effectiveness of AppSealing's security measures, as it prevents the application from proceeding further if it detects an insecure environment. Understanding this flow is crucial for developing strategies to bypass these checks during reverse engineering efforts.

## An analysis of what leads to the killing process
Upon starting the application, it initially appears to function normally for a brief period before unexpectedly closing. This behavior suggests that the application may be executing various tasks in separate threads, such as rendering and validation processes.

### Thread Management and Execution
- Thread Creation: It is likely that the application spawns multiple threads to handle different functionalities concurrently. For instance, one thread may be dedicated to rendering the user interface, while another handles validation checks related to security and environment integrity.
- Monitoring for Security Violations: During its operation, the application continuously monitors the state of the device. This includes checking for signs of rooting or virtualization. These checks may be performed in a separate thread to ensure that the main application thread remains responsive to user interactions.
- Triggering Termination: If the validation thread detects any anomalies—such as the presence of root access or the application running in an emulator—it can trigger a termination sequence. This is likely implemented as a signal to the main application thread, which results in the process being killed.

### Observations from Runtime Analysis

Using tools like Frida, we can observe the application's behavior in real-time. One effective way to gain insights into the application's threading behavior is to create a hook function that intercepts calls to `pthread_create`, which is responsible for creating new threads in a POSIX-compliant environment.

<details>
  <summary>See frida snippet</summary>

```javascript
const getNativeFunctions = () => {
    return {
        getpid: new NativeFunction(Module.getExportByName(null, 'getpid'), 'int', []),
        gettid: new NativeFunction(Module.getExportByName(null, 'gettid'), 'int', []),
    };
};

// Log function that prints thread id and process id
const log = (...args) => {
    const { gettid, getpid } = getNativeFunctions();
    const tid = gettid();
    const pid = getpid();

    console.log(`[+][tid: ${tid}][pid: ${pid}]`, ...args);   
};


const pthread_create = Module.getExportByName(null, 'pthread_create');
Interceptor.attach(pthread_create, {
    onEnter: (args) => {
        this.start_routine = args[2];
        const debugSymbol = DebugSymbol.fromAddress(start_routine);
        const baseAddr = Process.getModuleByName(debugSymbol.moduleName).base;
        const offset = Number(debugSymbol.address - baseAddr);
        const log_message = `pthread_create ${debugSymbol.moduleName} ${debugSymbol.address} 0x${offset.toString(16)}`
        Interceptor.attach(start_routine, {
            onEnter(args){
                log(`inside thread ${debugSymbol.moduleName} ${debugSymbol.address} 0x${offset.toString(16)}`)
            }
        });
        log(log_message);
    },
});
```

### Explanation of the Frida Snippet

1. Native Function Retrieval:
The `getNativeFunctions` function retrieves the native functions `getpid` and `gettid`, which are used to obtain the process ID and thread ID, respectively. This information is useful for logging and tracking the execution context.

2. Logging Function:
The `log` function formats and prints messages to the console, including the current thread ID and process ID. This helps in identifying which thread is executing at any given time.

3. Hooking pthread_create:
The script hooks into the `pthread_create` function using `Interceptor.attach`. When a new thread is created, the onEnter callback is triggered.

4. Capturing Thread Routine:
Inside the `onEnter` callback, the address of the thread's start routine is captured from the arguments. The `DebugSymbol.fromAddress` function is used to retrieve the debug symbol information for the start routine, which includes the module name and address.

5. Calculating Offset:
The base address of the module is obtained, and the offset of the start routine from this base address is calculated. This information is useful for understanding the context of the thread's execution.

6. Attaching to the Start Routine:
The script attaches another interceptor to the start routine of the newly created thread. When the thread begins execution, the `onEnter` callback logs a message indicating that the thread has started, along with its module name and address.

7. Logging the Creation:
A log message is generated when `pthread_create` is called, providing details about the thread being created, including the module name and address.

</details>

\
However, the application closes after a few seconds without even creating threads. This behavior is likely due to the application detecting Frida's presence. To bypass this detection, we can implement a method to manipulate the output of functions that the application uses to check for active processes.

<details>
    <summary>Bypass Frida detect</summary>
    
AppSealing, in their release notes, mentions improvements related to process detection. [Source](https://docs.appsealing.com/Release%20Notes/1.Android/2.32.0.0.html)

One of the methods AppSealing uses is to open and read the list of active processes. We can circumvent this by hooking into the `fgets` function and replacing any occurrence of the word "frida" with "xxxxx" in the returned string. This approach effectively hides Frida's presence from the application.

Here’s how to implement this bypass using Frida:
```javascript
const triggerWords = ['frida'];

const fgets = Module.getExportByName(null, 'fgets');

Interceptor.attach(fgets, {
    onEnter(args){
        this.args0 = args[0];
        this.args1 = args[1];
    },
    onLeave(ret){
        let readResult = ret.readCString();
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
```

</details>

Additionally, we can implement a helper function to monitor when the application creates a report file in the event of a compromised device. This will help us identify which thread was responsible for the application's termination.

<details>
    <summary>See Frida Snippet</summary>

```javascript
const open = Module.getExportByName(null, 'open');
Interceptor.attach(open, {
    onEnter(args){
        const path = args[0].readCString();
        if (path.includes(".sealing_reports")){
            log("open", path);
        }
    }
});
```

The output from this logging will provide insights into the threads and processes involved when the application creates a report. For example:

```
[+][tid: 14133][pid: 14133] pthread_create libart.so 0xe429d100 0x697100
[+][tid: 14162][pid: 14133] inside thread libart.so 0xe429d100 0x697100
[+][tid: 14133][pid: 14133] pthread_create libcovault-appsec.so 0xb93034c7 0x144c7
[+][tid: 14133][pid: 14133] open /data/user/0/your.package.name/.sealing_reports_info/150061
[+][tid: 14133][pid: 14133] open /data/user/0/your.package.name/.sealing_reports_info/150061
[+][tid: 14163][pid: 14133] inside thread libcovault-appsec.so 0xb93034c7 0x144c7
[+][tid: 14133][pid: 14133] open /data/user/0/your.package.name/.sealing_reports/your_package_name/2024-08-29PM080547.hkr 
```

This example shows what happens without the frida bypass mentioned earlier.

From the logged output, we can conclude that the process was likely terminated in the same thread that initiated the report creation. This is a crucial observation, as it indicates that the thread responsible for the security checks and the subsequent report generation is the same one that encounters the termination condition.

By monitoring the creation of these report files, we can gain valuable insights into the application's behavior and identify the specific threads involved in the termination process. 

</details>

### Function that writes report?
<details>
    <summary>Explanation</summary>

To identify the function responsible for writing the report, we can utilize a combination of Frida's tracing capabilities and Ghidra's disassembly features. By hooking into the open function and capturing the call stack, we can trace back to the function that initiates the report creation.

Using the traceback feature in Frida, we can capture the call stack when the application attempts to open a report file. Here’s how we can implement this:

```javascript
Interceptor.attach(open, {
    onEnter(args){
        const path = args[0].readCString();
        if (path.includes(".sealing_reports" || path.includes("seale"))){
            log("open", path);
            const trace = Thread.backtrace(this.context, Backtracer.FUZZY).map(DebugSymbol.fromAddress);
            for (let t in trace){
                console.log("[*] Traceline", trace[t]);
            }
        }
    }
});
```

When the application attempts to open a report file, the output might look like this (I removed everything extra that doesn't belong to our `libcovault-appsec.so` library):

```
[+][tid: 14368][pid: 14368] open /data/user/0/io.smscash/.sealing_reports/io_smscash/2024-08-29PM082355.hkr
[*] Traceline 0xb938c643 libcovault-appsec.so!0xb1643
[*] Traceline 0xb936adbd libcovault-appsec.so!0x8fdbd
[*] Traceline 0xb9388d2c libcovault-appsec.so!0xadd2c
[*] Traceline 0xb938c9f9 libcovault-appsec.so!0xb19f9
[*] Traceline 0xb938cd3f libcovault-appsec.so!0xb1d3f
[*] Traceline 0xb92f1479 libcovault-appsec.so!0x16479
[*] Traceline 0xb92f0ce8 libcovault-appsec.so!0x15ce8

```

### Analyzing the Call Chain

From the output, we can observe the call chain leading to the report creation:
- `0x15ce8`: This function likely performs some checks and initiates the report creation process.

- `0xb1643`: This function appears to return a file pointer, suggesting that it is responsible for creating or opening the report file.

### Using Ghidra for Further Analysis

To confirm assumptions, let's analyze the functions in Ghidra:

- Locate Function `0xb1643`: In Ghidra, we can navigate to the address `0xb1643` and examine the disassembled code. This function should provide insights into how the report file is created and what parameters it uses.

- Investigate Function `0x15ce8`: Similarly, we can look at the function at `0x15ce8` to understand what checks it performs before initiating the report creation. This function may contain logic that determines whether the device is compromised and triggers the report generation.

</details>

### Bypass Emulator Detect

When we run the application with the previously described hooks and bypass techniques, we can observe that the system still detects the emulator. The logs indicate that this detection occurs in a separate thread, specifically in a function associated with the address `0x7a210`.

Here is example output:

```
[+][tid: 15379][pid: 15379] Loading library covault-appsec
[+][tid: 15379][pid: 15379] AppSealing native library loaded
[+][tid: 15379][pid: 15379] covault-appsec loaded
        ...truncated
[+][tid: 15379][pid: 15379] pthread_create libcovault-appsec.so 0xb934d210 0x7a210
[+][tid: 15418][pid: 15379] inside thread libcovault-appsec.so 0xb934d210 0x7a210
        ...truncated
[+][tid: 15418][pid: 15379] open /data/user/0/io.smscash/.sealing_reports_info/19
[+][tid: 15418][pid: 15379] open /data/user/0/io.smscash/.sealing_reports_info/19
[+][tid: 15418][pid: 15379] open /data/user/0/io.smscash/.sealing_reports/io_smscash/2024-08-29PM085435.str
[+][tid: 15418][pid: 15379] Doing some checks? Emulator detected (d8498968)

```

From the logs, we can see that the main thread (ID 15379) creates a child thread (ID 15418) that executes the function at address `0x7a210`. This function is likely responsible for performing the emulator detection checks.

Let's modify this function to do no checks. See Analysis of function 0x7a210. (Checks if the device is an emulator).


## Functions that founds

| Address | Description |
| --------| ------- |
| 0x15c40 | Handles when something detected |
| 0x7a210 | Checks if the device is an emulator |
| 0xb156f | Creates report file |


<details>
    <summary>Analysis of function 0x15c40. (Handles when something detected)</summary>

In our analysis of the function at address `0x15c40`, Ghidra has inferred a signature for this function as follows:

`longdouble * FUNCTION(longdouble *__return_storage_ptr__)`.

To further investigate the behavior of this function, we can hook it using Frida. Through this process, we can observe the arguments passed to the function and its return value. Here’s how we can implement the hook:


```javascript
const name = 'libcovault-appsec.so';
const baseAddr = Module.getBaseAddress(name);

Interceptor.attach(baseAddr.add(0x15c40), {
    onEnter(args){
        log("Doing some checks?", args[0].readCString());
    },
    onLeave(ret){
        log("Checks done!", ret);
    }
});
```

When we run the application with this hook in place, we can capture the output, which provides insights into the function's behavior. Example outputs might look like this:

```
[+][tid: 15183][pid: 15183] Doing some checks? Name:	pool-frida
```

or
```
[+][tid: 15418][pid: 15379] Doing some checks? Emulator detected (d8498968)
```

From our analysis, we can conclude that this function is responsible for initiating the creation of a report based on the reason for the application's termination. The first argument, a `char*` named reason, contains the specific reason for the termination, such as detecting Frida or identifying an emulator.


</details>
    

<details>
    <summary>Analysis of function 0x7a210. (Checks if the device is an emulator)</summary>

The function at address `0x7a210` is responsible for checking whether the device is an emulator. It is not called directly; instead, it is invoked via `pthread_create`, which creates a new thread to execute this function. According to Ghidra, the signature of this function is: `void FUNCTION(void)`.

Given that this function returns void, we can effectively bypass the emulator detection by modifying its assembly code. Instead of preventing the thread from being created, we can alter the function's behavior to immediately return without performing any checks. To achieve this, we can replace the function's code with a simple `RET` instruction. The opcode for `RET` in `x86` architecture is `0xc3`. By injecting this opcode into the function, we can ensure that when the function is called, it will exit immediately without executing any of the emulator detection logic.

</details>

## Patching using Frida
For functions that return int we can use
```
MOV EAX, 0x0
RET
```

For void function
```
RET
```
