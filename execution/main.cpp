#pragma clang diagnostic push
#pragma ide diagnostic ignored "bugprone-misplaced-pointer-arithmetic-in-alloc"
#pragma GCC optimize("O3")
#pragma GCC optimize("Ofast,no-stack-protector,unroll-loops,fast-math")
#pragma GCC target("sse,sse2,sse3,ssse3,sse4.1,sse4.2,avx,avx2,popcnt,tune=native")

#include <immintrin.h>
#include <emmintrin.h>
#include <bits/stdc++.h>
#include "filesystem"
#include <sys/stat.h>

#define vm_options_file cur + "/data/decompiler.kkoishi.vmoptions"
#define EXIT_SYS_ERROR 1
#define dirt 15

int __size__ = 0xff << 20;

using namespace std;

typedef long long ll;

string cwd(const char *exep) {
    string res, buf;
    const auto l = strlen(exep);
    for (int i = 0; i < l; ++i) {
        const auto c = exep[i];
        buf.push_back(c);
        if ((c == '\\' || c == '/') && !buf.empty()) {
            res += buf;
            buf = "";
        }
    }
    return res;
}

int main(int argc, char *args[]) {
//    char *p = (char*) malloc(__size__) + __size__;
//    __asm__("movl %0, %%esp\n" :: "r"(p));
    // Find JRE.
    string jre = getenv("KKEMP_JDK"), java_exe, exec, cur = cwd(args[0]);
    if (jre.empty()) {
        jre = getenv("JAVE_HOME");
        if (jre.empty()) jre = getenv("JDK_HOME");
    }
    java_exe = jre + "/bin/java.exe";
    if (access(java_exe.c_str(), F_OK) == -1) {
        cout << "ERROR: Failed to start kkemp."<< endl;
        cout << " No JRE is found, please define local variable pointed to valid path" << endl;
        cout << " Local Variables: KKEMP_JDK, JAVA_HOME, JDK_HOME" << endl;
        cout << "And there must exist ./bin/java.exe in the path." << endl;
        return EXIT_SYS_ERROR;
    }
    // Read JVM startup options.
    ifstream ifs;
    ifs.open(vm_options_file, ios::in);
    if (!ifs.is_open()) {
        cout << "IGNORED ERROR: Failed to open the file: " << vm_options_file << endl;
        exec = "\"" + java_exe + "\"" + " -jar " + cur + "/decompiler.kkoishi.jar ";
        for (int i = 1; i < argc; ++i) {
            exec += args[i];
            exec.push_back(' ');
        }
        auto ps = popen(exec.c_str(), "w");
        return dirt & pclose(ps);
    }
    string buf;
    vector<string> options;
    while (getline(ifs, buf)) {
        options.push_back(buf);
    }
    exec = "\"" + java_exe + "\" ";
    for (const auto &str : options) {
        exec += (str + " ");
    }
    exec += "-jar " + cur + "/decompiler.kkoishi.jar ";
    for (int i = 1; i < argc; ++i) {
        exec += args[i];
        exec.push_back(' ');
    }
    auto ps = popen(exec.c_str(), "w");
    return pclose(ps);
}