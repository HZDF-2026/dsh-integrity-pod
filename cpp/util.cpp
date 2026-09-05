// util.cpp — see util.h.
#include "util.h"

#include "sha256.h"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <functional>
#include <thread>

#ifdef _WIN32
#include <windows.h>
#else
#include <cerrno>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <unistd.h>
#include <sys/wait.h>
#endif

namespace dship {

namespace {

bool envKeyStripped(const std::string& key) {
    if (key == "TZ" || key == "LANG" || key == "TERM" || key == "COLUMNS" ||
        key == "LINES" || key == "SESSIONNAME" || key == "SESSION") {
        return true;
    }
    if (key.rfind("LC_", 0) == 0 && key.size() > 3) {
        for (size_t i = 3; i < key.size(); i++) {
            char c = key[i];
            if (!((c >= 'A' && c <= 'Z') || c == '_')) return false;
        }
        return true;
    }
    return false;
}

struct EnvVar {
    std::string name;
    std::string value;
};

// The sanitized environment bitwin/provenance run commands under: locale and
// terminal variables stripped, deterministic ones pinned.
std::vector<EnvVar> sanitizedEnv() {
    std::vector<EnvVar> vars;
#ifdef _WIN32
    wchar_t* block = GetEnvironmentStringsW();
    if (block) {
        for (wchar_t* p = block; *p; p += std::wcslen(p) + 1) {
            wchar_t* eq = std::wcschr(p, L'=');
            if (!eq) continue;
            std::wstring name(p, eq);
            std::wstring value(eq + 1);
            if (name.empty()) continue;
            auto narrow = [](const std::wstring& w) {
                int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), static_cast<int>(w.size()),
                                            nullptr, 0, nullptr, nullptr);
                std::string s(static_cast<size_t>(n > 0 ? n : 0), '\0');
                if (n > 0) {
                    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), static_cast<int>(w.size()), &s[0],
                                        n, nullptr, nullptr);
                }
                return s;
            };
            std::string k = narrow(name);
            if (envKeyStripped(k)) continue;
            vars.push_back({k, narrow(value)});
        }
        FreeEnvironmentStringsW(block);
    }
#else
    for (char** e = environ; e && *e; e++) {
        const char* begin = *e;
        const char* eq = std::strchr(begin, '=');
        if (!eq) continue;
        std::string name(begin, eq);
        if (envKeyStripped(name)) continue;
        vars.push_back({name, std::string(eq + 1)});
    }
#endif
    vars.push_back({"TZ", "UTC"});
    vars.push_back({"LC_ALL", "C"});
    vars.push_back({"SOURCE_DATE_EPOCH", "946684800"});
    vars.push_back({"PYTHONHASHSEED", "0"});
    return vars;
}

bool skipDirName(const std::string& name) {
    return name == ".git" || name == "node_modules" || name == ".integrity";
}

std::string jsTrim(const std::string& s) {
    size_t b = 0, e = s.size();
    auto isWs = [](char c) {
        return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v';
    };
    while (b < e && isWs(s[b])) b++;
    while (e > b && isWs(s[e - 1])) e--;
    return s.substr(b, e - b);
}

}  // namespace

std::string nowIso() {
    using namespace std::chrono;
    auto now = system_clock::now();
    auto ms = duration_cast<milliseconds>(now.time_since_epoch()).count();
    time_t secs = static_cast<time_t>(ms / 1000);
    int msec = static_cast<int>(ms % 1000);
    std::tm tmv{};
#ifdef _WIN32
    gmtime_s(&tmv, &secs);
#else
    gmtime_r(&secs, &tmv);
#endif
    char buf[40];
    std::snprintf(buf, sizeof buf, "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ", tmv.tm_year + 1900,
                  tmv.tm_mon + 1, tmv.tm_mday, tmv.tm_hour, tmv.tm_min, tmv.tm_sec, msec);
    return buf;
}

long long nowMs() {
    using namespace std::chrono;
    return duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
}

std::optional<std::string> sha256FileIfExists(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) return std::nullopt;
    std::string data((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    return sha256Hex(data);
}

// ---------------------------------------------------------------- path helpers

namespace {

#ifdef _WIN32
bool hasDriveSpec(const std::string& s) {
    return s.size() >= 2 && s[1] == ':' &&
           ((s[0] >= 'A' && s[0] <= 'Z') || (s[0] >= 'a' && s[0] <= 'z'));
}
#endif

std::string normalizeNative(const std::string& p) {
    namespace fs = std::filesystem;
    fs::path out = fs::path(p).lexically_normal();
#ifdef _WIN32
    out.make_preferred();
#endif
    return out.string();
}

// Node's path.resolve drops trailing separators — except on roots ("C:\",
// "/"), where the separator is the whole path.
std::string stripTrailingSeps(const std::string& p) {
    if (p.size() == 1 && (p[0] == '/' || p[0] == '\\')) return p;
#ifdef _WIN32
    if (p.size() == 3 && p[1] == ':' && (p[2] == '/' || p[2] == '\\')) return p;
#endif
    size_t end = p.size();
    while (end > 0 && (p[end - 1] == '/' || p[end - 1] == '\\')) end--;
    return p.substr(0, end);
}

}  // namespace

std::string cwd() {
    std::error_code ec;
    std::string c = std::filesystem::current_path(ec).string();
    return ec ? std::string() : c;
}

std::string pathResolve(const std::string& target) {
    if (target.empty()) return normalizeNative(cwd());
#ifdef _WIN32
    if (hasDriveSpec(target)) return stripTrailingSeps(normalizeNative(target));
    std::string base = cwd();
    if (!target.empty() && (target[0] == '/' || target[0] == '\\')) {
        std::string drive;
        if (base.size() >= 2 && base[1] == ':') drive = base.substr(0, 2);
        return stripTrailingSeps(normalizeNative(drive + target));
    }
    return stripTrailingSeps(normalizeNative(base + "\\" + target));
#else
    if (!target.empty() && target[0] == '/') return stripTrailingSeps(normalizeNative(target));
    return stripTrailingSeps(normalizeNative(cwd() + "/" + target));
#endif
}

std::string pathDirname(const std::string& p) {
    return std::filesystem::path(p).parent_path().string();
}

bool fileExists(const std::string& p) {
    std::error_code ec;
    std::filesystem::file_status st = std::filesystem::status(std::filesystem::path(p), ec);
    return !ec && st.type() == std::filesystem::file_type::regular;
}

void writeFileBytes(const std::string& path, const std::string& data) {
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out) throw std::runtime_error("EACCES: cannot write '" + path + "'");
    out.write(data.data(), static_cast<std::streamsize>(data.size()));
}

void appendFileBytes(const std::string& path, const std::string& data) {
    std::ofstream out(path, std::ios::binary | std::ios::app);
    if (!out) throw std::runtime_error("EACCES: cannot append '" + path + "'");
    out.write(data.data(), static_cast<std::streamsize>(data.size()));
}

void mkdirRecursive(const std::string& path) {
    if (path.empty() || path == "." || path == "/") return;
    std::error_code ec;
    std::filesystem::create_directories(std::filesystem::path(path), ec);
}

// ------------------------------------------------------------------ hash tree

std::map<std::string, std::string> hashTree(const std::string& root, long long maxFileBytes,
                                             size_t maxFiles) {
    namespace fs = std::filesystem;
    std::map<std::string, std::string> files;
    std::function<void(const fs::path&)> walk = [&](const fs::path& dir) {
        std::error_code lec;
        fs::directory_iterator it(dir, fs::directory_options::skip_permission_denied, lec);
        if (lec) return;
        for (const auto& entry : it) {
            if (files.size() >= maxFiles) return;
            std::string name = entry.path().filename().string();
            if (skipDirName(name)) continue;
            std::error_code tec;
            fs::file_status es = entry.symlink_status(tec);
            if (tec) continue;
            if (es.type() == fs::file_type::directory) {
                walk(entry.path());
            } else if (es.type() == fs::file_type::regular) {
                std::error_code sec;
                auto size = fs::file_size(entry.path(), sec);
                if (sec || size > static_cast<uintmax_t>(maxFileBytes)) continue;
                std::ifstream in(entry.path(), std::ios::binary);
                if (!in) continue;
                std::string data((std::istreambuf_iterator<char>(in)),
                                 std::istreambuf_iterator<char>());
                std::string r;
                try {
                    r = fs::path(entry.path()).lexically_relative(fs::path(root)).string();
                } catch (...) {
                    continue;
                }
                for (auto& c : r) {
                    if (c == '\\') c = '/';
                }
                files[r] = sha256Hex(data);
            }
        }
    };
    std::error_code ec;
    fs::path abs(root);
    if (!fs::exists(abs, ec) || ec) return files;
    walk(abs);
    return files;
}

// ------------------------------------------------------------------ spawning

#ifdef _WIN32

namespace {

std::wstring toWide(const std::string& s) {
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), static_cast<int>(s.size()), nullptr, 0);
    std::wstring w(static_cast<size_t>(n), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), static_cast<int>(s.size()), &w[0], n);
    return w;
}

struct PipePair {
    HANDLE read = nullptr;
    HANDLE write = nullptr;
};

// Node spawn(cmd, {shell:true}): cmd.exe /d /s /c "<command>" with the command
// always wrapped in literal double quotes.
std::wstring shellCommandLine(const std::string& command) {
    wchar_t sysdir[MAX_PATH];
    GetSystemDirectoryW(sysdir, MAX_PATH);
    return std::wstring(sysdir) + L"\\cmd.exe /d /s /c \"" + toWide(command) + L"\"";
}

void drainCapped(HANDLE h, std::string& sink, long long capBytes) {
    char buf[8192];
    DWORD got = 0;
    for (;;) {
        if (!ReadFile(h, buf, sizeof buf, &got, nullptr) || got == 0) break;
        if (static_cast<long long>(sink.size()) < capBytes) sink.append(buf, got);
    }
}

void drainAll(HANDLE h, std::string& sink) {
    char buf[8192];
    DWORD got = 0;
    for (;;) {
        if (!ReadFile(h, buf, sizeof buf, &got, nullptr) || got == 0) break;
        sink.append(buf, got);
    }
}

}  // namespace

ShellResult runShellSanitized(const std::string& command, const std::string& cwdDir,
                              long long timeoutMs, long long capBytes) {
    ShellResult r;
    long long startedAt = nowMs();

    std::vector<EnvVar> env = sanitizedEnv();
    std::wstring envBlock;
    for (const auto& v : env) {
        envBlock += toWide(v.name) + L"=" + toWide(v.value) + L'\0';
    }
    envBlock += L'\0';

    SECURITY_ATTRIBUTES sa{};
    sa.nLength = sizeof sa;
    sa.bInheritHandle = TRUE;
    PipePair outP, errP;
    if (!CreatePipe(&outP.read, &outP.write, &sa, 0) ||
        !CreatePipe(&errP.read, &errP.write, &sa, 0)) {
        r.spawnError = true;
        r.exitCode = 126;
        r.stderrHash = sha256Hex("[spawn error] spawn EPIPE\n");
        r.durationMs = nowMs() - startedAt;
        return r;
    }
    SetHandleInformation(outP.read, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(errP.read, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOW si{};
    si.cb = sizeof si;
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = outP.write;
    si.hStdError = errP.write;
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    PROCESS_INFORMATION pi{};
    std::wstring cwdW = toWide(cwdDir);
    std::wstring cmdline = shellCommandLine(command);
    std::vector<wchar_t> cmdBuf(cmdline.begin(), cmdline.end());
    cmdBuf.push_back(L'\0');
    BOOL ok = CreateProcessW(nullptr, cmdBuf.data(), nullptr, nullptr, TRUE,
                             CREATE_UNICODE_ENVIRONMENT, envBlock.data(),
                             cwdDir.empty() ? nullptr : cwdW.c_str(), &si, &pi);
    if (!ok) {
        CloseHandle(outP.read);
        CloseHandle(outP.write);
        CloseHandle(errP.read);
        CloseHandle(errP.write);
        r.spawnError = true;
        r.exitCode = 126;
        r.stderrHash = sha256Hex("[spawn error] spawn ENOENT\n");
        r.durationMs = nowMs() - startedAt;
        return r;
    }
    CloseHandle(pi.hThread);
    CloseHandle(outP.write);
    CloseHandle(errP.write);

    std::string outBytes, errBytes;
    std::thread t1(drainCapped, outP.read, std::ref(outBytes), capBytes);
    std::thread t2(drainCapped, errP.read, std::ref(errBytes), capBytes);

    DWORD wait = WaitForSingleObject(pi.hProcess, static_cast<DWORD>(timeoutMs));
    if (wait == WAIT_TIMEOUT) {
        r.timedOut = true;
        TerminateProcess(pi.hProcess, 1);
        WaitForSingleObject(pi.hProcess, INFINITE);
    }
    DWORD code = 0;
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hProcess);
    t1.join();
    t2.join();
    CloseHandle(outP.read);
    CloseHandle(errP.read);

    r.exitCode = static_cast<long long>(code);
    r.codeNull = false;
    r.stdoutHash = sha256Hex(outBytes);
    r.stderrHash = sha256Hex(errBytes);
    r.stdoutBytes = static_cast<long long>(outBytes.size());
    r.stderrBytes = static_cast<long long>(errBytes.size());
    r.durationMs = nowMs() - startedAt;
    return r;
}

std::optional<std::string> runShellCapture(const std::string& command, const std::string& cwdDir) {
    long long startedAt = nowMs();
    SECURITY_ATTRIBUTES sa{};
    sa.nLength = sizeof sa;
    sa.bInheritHandle = TRUE;
    PipePair outP;
    if (!CreatePipe(&outP.read, &outP.write, &sa, 0)) return std::nullopt;
    SetHandleInformation(outP.read, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOW si{};
    si.cb = sizeof si;
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = outP.write;
    si.hStdError = outP.write;  // git diagnostics also flow to stdout here
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    PROCESS_INFORMATION pi{};
    std::wstring cwdW = toWide(cwdDir);
    std::wstring cmdline = shellCommandLine(command);
    std::vector<wchar_t> cmdBuf(cmdline.begin(), cmdline.end());
    cmdBuf.push_back(L'\0');
    BOOL ok = CreateProcessW(nullptr, cmdBuf.data(), nullptr, nullptr, TRUE, 0, nullptr,
                             cwdDir.empty() ? nullptr : cwdW.c_str(), &si, &pi);
    if (!ok) {
        CloseHandle(outP.read);
        CloseHandle(outP.write);
        return std::nullopt;
    }
    CloseHandle(pi.hThread);
    CloseHandle(outP.write);

    std::string outBytes;
    std::thread t(drainAll, outP.read, std::ref(outBytes));
    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD code = 0;
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hProcess);
    t.join();
    CloseHandle(outP.read);
    (void)startedAt;
    if (code != 0) return std::nullopt;
    return jsTrim(outBytes);
}

#else  // POSIX

namespace {

void drainCappedPosix(int fd, std::string& sink, long long capBytes) {
    char buf[8192];
    for (;;) {
        ssize_t got = read(fd, buf, sizeof buf);
        if (got <= 0) break;
        if (static_cast<long long>(sink.size()) < capBytes) sink.append(buf, got);
    }
}

}  // namespace

ShellResult runShellSanitized(const std::string& command, const std::string& cwdDir,
                              long long timeoutMs, long long capBytes) {
    ShellResult r;
    long long startedAt = nowMs();

    int outp[2], errp[2];
    if (pipe(outp) != 0 || pipe(errp) != 0) {
        r.spawnError = true;
        r.exitCode = 126;
        r.stderrHash = sha256Hex("[spawn error] spawn EPIPE\n");
        r.durationMs = nowMs() - startedAt;
        return r;
    }

    std::vector<EnvVar> env = sanitizedEnv();
    std::vector<std::string> envStorage;
    std::vector<char*> envp;
    for (const auto& v : env) {
        envStorage.push_back(v.name + "=" + v.value);
    }
    for (auto& s : envStorage) envp.push_back(&s[0]);
    envp.push_back(nullptr);

    std::string shCmd = "/bin/sh";
    std::string shArg = "-c";
    pid_t pid = fork();
    if (pid == 0) {
        while ((dup2(outp[1], STDOUT_FILENO) == -1) && (errno == EINTR)) {}
        while ((dup2(errp[1], STDERR_FILENO) == -1) && (errno == EINTR)) {}
        int devnull = open("/dev/null", O_RDONLY);
        if (devnull != -1) {
            dup2(devnull, STDIN_FILENO);
            close(devnull);
        }
        close(outp[0]);
        close(outp[1]);
        close(errp[0]);
        close(errp[1]);
        if (!cwdDir.empty()) chdir(cwdDir.c_str());
        char* argv[] = {&shCmd[0], &shArg[0], const_cast<char*>(command.c_str()), nullptr};
        execve("/bin/sh", argv, envp.data());
        _exit(127);
    }
    if (pid < 0) {
        close(outp[0]);
        close(outp[1]);
        close(errp[0]);
        close(errp[1]);
        r.spawnError = true;
        r.exitCode = 126;
        r.stderrHash = sha256Hex("[spawn error] spawn EAGAIN\n");
        r.durationMs = nowMs() - startedAt;
        return r;
    }
    close(outp[1]);
    close(errp[1]);

    std::string outBytes, errBytes;
    std::thread t1(drainCappedPosix, outp[0], std::ref(outBytes), capBytes);
    std::thread t2(drainCappedPosix, errp[0], std::ref(errBytes), capBytes);

    int status = 0;
    long long deadline = nowMs() + timeoutMs;
    for (;;) {
        pid_t waited = waitpid(pid, &status, WNOHANG);
        if (waited == pid) break;
        if (waited == -1) break;
        if (nowMs() >= deadline) {
            r.timedOut = true;
            kill(pid, SIGTERM);
            waitpid(pid, &status, 0);
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }
    t1.join();
    t2.join();
    close(outp[0]);
    close(errp[0]);

    if (WIFEXITED(status)) {
        r.exitCode = WEXITSTATUS(status);
        r.codeNull = false;
    } else {
        r.codeNull = true;
        r.exitCode = 0;
    }
    r.stdoutHash = sha256Hex(outBytes);
    r.stderrHash = sha256Hex(errBytes);
    r.stdoutBytes = static_cast<long long>(outBytes.size());
    r.stderrBytes = static_cast<long long>(errBytes.size());
    r.durationMs = nowMs() - startedAt;
    return r;
}

std::optional<std::string> runShellCapture(const std::string& command, const std::string& cwdDir) {
    int outp[2];
    if (pipe(outp) != 0) return std::nullopt;
    pid_t pid = fork();
    if (pid == 0) {
        while ((dup2(outp[1], STDOUT_FILENO) == -1) && (errno == EINTR)) {}
        int devnull = open("/dev/null", O_RDONLY);
        if (devnull != -1) {
            dup2(devnull, STDIN_FILENO);
            dup2(devnull, STDERR_FILENO);
            close(devnull);
        }
        close(outp[0]);
        close(outp[1]);
        if (!cwdDir.empty()) chdir(cwdDir.c_str());
        std::string shArg = "-c";
        char* argv[] = {const_cast<char*>("/bin/sh"), &shArg[0],
                        const_cast<char*>(command.c_str()), nullptr};
        execv("/bin/sh", argv);
        _exit(127);
    }
    if (pid < 0) {
        close(outp[0]);
        close(outp[1]);
        return std::nullopt;
    }
    close(outp[1]);
    std::string out;
    char buf[8192];
    ssize_t got;
    while ((got = read(outp[0], buf, sizeof buf)) > 0) out.append(buf, got);
    close(outp[0]);
    int status = 0;
    waitpid(pid, &status, 0);
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) return std::nullopt;
    return jsTrim(out);
}

#endif  // _WIN32

}  // namespace dship
